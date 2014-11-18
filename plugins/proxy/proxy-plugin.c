/* $%BEGINLICENSE%$
                            
 Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.

 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License as
 published by the Free Software Foundation; version 2 of the
 License.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 02110-1301  USA

 $%ENDLICENSE%$ */
 

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/** 
 * @page page-plugin-proxy Proxy plugin
 *
 * The MySQL Proxy implements the MySQL Protocol in its own way. 
 *
 *   -# connect @msc
 *   client, proxy, backend;
 *   --- [ label = "connect to backend" ];
 *   client->proxy  [ label = "INIT" ];
 *   proxy->backend [ label = "CONNECT_SERVER", URL="\ref proxy_connect_server" ];
 * @endmsc
 *   -# auth @msc
 *   client, proxy, backend;
 *   --- [ label = "authenticate" ];
 *   backend->proxy [ label = "READ_HANDSHAKE", URL="\ref proxy_read_handshake" ];
 *   proxy->client  [ label = "SEND_HANDSHAKE" ];
 *   client->proxy  [ label = "READ_AUTH", URL="\ref proxy_read_auth" ];
 *   proxy->backend [ label = "SEND_AUTH" ];
 *   backend->proxy [ label = "READ_AUTH_RESULT", URL="\ref proxy_read_auth_result" ];
 *   proxy->client  [ label = "SEND_AUTH_RESULT" ];
 * @endmsc
 *   -# query @msc
 *   client, proxy, backend;
 *   --- [ label = "query result phase" ];
 *   client->proxy  [ label = "READ_QUERY", URL="\ref proxy_read_query" ];
 *   proxy->backend [ label = "SEND_QUERY" ];
 *   backend->proxy [ label = "READ_QUERY_RESULT", URL="\ref proxy_read_query_result" ];
 *   proxy->client  [ label = "SEND_QUERY_RESULT", URL="\ref proxy_send_query_result" ];
 * @endmsc
 *
 *   - network_mysqld_proxy_connection_init()
 *     -# registers the callbacks 
 *   - proxy_connect_server() (CON_STATE_CONNECT_SERVER)
 *     -# calls the connect_server() function in the lua script which might decide to
 *       -# send a handshake packet without contacting the backend server (CON_STATE_SEND_HANDSHAKE)
 *       -# closing the connection (CON_STATE_ERROR)
 *       -# picking a active connection from the connection pool
 *       -# pick a backend to authenticate against
 *       -# do nothing 
 *     -# by default, pick a backend from the backend list on the backend with the least active connctions
 *     -# opens the connection to the backend with connect()
 *     -# when done CON_STATE_READ_HANDSHAKE 
 *   - proxy_read_handshake() (CON_STATE_READ_HANDSHAKE)
 *     -# reads the handshake packet from the server 
 *   - proxy_read_auth() (CON_STATE_READ_AUTH)
 *     -# reads the auth packet from the client 
 *   - proxy_read_auth_result() (CON_STATE_READ_AUTH_RESULT)
 *     -# reads the auth-result packet from the server 
 *   - proxy_send_auth_result() (CON_STATE_SEND_AUTH_RESULT)
 *   - proxy_read_query() (CON_STATE_READ_QUERY)
 *     -# reads the query from the client 
 *   - proxy_read_query_result() (CON_STATE_READ_QUERY_RESULT)
 *     -# reads the query-result from the server 
 *   - proxy_send_query_result() (CON_STATE_SEND_QUERY_RESULT)
 *     -# called after the data is written to the client
 *     -# if scripts wants to close connections, goes to CON_STATE_ERROR
 *     -# if queries are in the injection queue, goes to CON_STATE_SEND_QUERY
 *     -# otherwise goes to CON_STATE_READ_QUERY
 *     -# does special handling for COM_BINLOG_DUMP (go to CON_STATE_READ_QUERY_RESULT) 

 */

#ifdef HAVE_SYS_FILIO_H
/**
 * required for FIONREAD on solaris
 */
#include <sys/filio.h>
#endif

#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <time.h>
#include <stdio.h>
#include <execinfo.h>

#include <errno.h>

#include <glib.h>

#ifdef HAVE_LUA_H
/**
 * embedded lua support
 */
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#endif

/* for solaris 2.5 and NetBSD 1.3.x */
#ifndef HAVE_SOCKLEN_T
typedef int socklen_t;
#endif


#include <mysqld_error.h> /** for ER_UNKNOWN_ERROR */

#include <math.h>
#include <openssl/evp.h>
#include <regex.h>
#include <sys/types.h>

#include "network-mysqld.h"
#include "network-mysqld-proto.h"
#include "network-mysqld-packet.h"

#include "network-mysqld-lua.h"

#include "network-conn-pool.h"
#include "network-conn-pool-lua.h"

#include "sys-pedantic.h"
#include "network-injection.h"
#include "network-injection-lua.h"
#include "network-backend.h"
#include "glib-ext.h"
#include "lua-env.h"

#include "proxy-plugin.h"

#include "lua-load-factory.h"

#include "chassis-timings.h"
#include "chassis-gtimeval.h"

#include "lib/sql-tokenizer.h"
#include "chassis-event-thread.h"
#include "chassis-shard.h"


#define C(x) x, sizeof(x) - 1
#define S(x) x->str, x->len

#define HASH_INSERT(hash, key, expr) \
		do { \
			GString *hash_value; \
			if ((hash_value = g_hash_table_lookup(hash, key))) { \
				expr; \
			} else { \
				hash_value = g_string_new(NULL); \
				expr; \
				g_hash_table_insert(hash, g_strdup(key), hash_value); \
			} \
		} while(0);

#define CRASHME() do { char *_crashme = NULL; *_crashme = 0; } while(0);

static gboolean online = TRUE;

typedef enum {
	OFF,
	ON,
	REALTIME
} SQL_LOG_TYPE;

SQL_LOG_TYPE sql_log_type = OFF;

extern char* charset[64];
extern chassis *srv;
/**
 * call the lua function to intercept the handshake packet
 *
 * @return PROXY_SEND_QUERY  to send the packet from the client
 *         PROXY_NO_DECISION to pass the server packet unmodified
 */
static network_mysqld_lua_stmt_ret proxy_lua_read_handshake(network_mysqld_con *con) {
	network_mysqld_lua_stmt_ret ret = PROXY_NO_DECISION; /* send what the server gave us */
#ifdef HAVE_LUA_H
	network_mysqld_con_lua_t *st = con->plugin_con_state;

	lua_State *L;

	/* call the lua script to pick a backend
	   ignore the return code from network_mysqld_con_lua_register_callback, because we cannot do anything about it,
	   it would always show up as ERROR 2013, which is not helpful.
	 */
	(void)network_mysqld_con_lua_register_callback(con, con->config->lua_script);

	if (!st->L) return ret;

	L = st->L;

	g_assert(lua_isfunction(L, -1));
	lua_getfenv(L, -1);
	g_assert(lua_istable(L, -1));
	
	lua_getfield_literal(L, -1, C("read_handshake"));
	if (lua_isfunction(L, -1)) {
		/* export
		 *
		 * every thing we know about it
		 *  */

		if (lua_pcall(L, 0, 1, 0) != 0) {
			g_critical("(read_handshake) %s", lua_tostring(L, -1));

			lua_pop(L, 1); /* errmsg */

			/* the script failed, but we have a useful default */
		} else {
			if (lua_isnumber(L, -1)) {
				ret = lua_tonumber(L, -1);
			}
			lua_pop(L, 1);
		}
	
		switch (ret) {
		case PROXY_NO_DECISION:
			break;
		case PROXY_SEND_QUERY:
			g_warning("%s.%d: (read_handshake) return proxy.PROXY_SEND_QUERY is deprecated, use PROXY_SEND_RESULT instead",
					__FILE__, __LINE__);

			ret = PROXY_SEND_RESULT;
		case PROXY_SEND_RESULT:
			/**
			 * proxy.response.type = ERR, RAW, ...
			 */

			if (network_mysqld_con_lua_handle_proxy_response(con, con->config->lua_script)) {
				/**
				 * handling proxy.response failed
				 *
				 * send a ERR packet
				 */
		
				network_mysqld_con_send_error(con->client, C("(lua) handling proxy.response failed, check error-log"));
			}

			break;
		default:
			ret = PROXY_NO_DECISION;
			break;
		}
	} else if (lua_isnil(L, -1)) {
		lua_pop(L, 1); /* pop the nil */
	} else {
		g_message("%s.%d: %s", __FILE__, __LINE__, lua_typename(L, lua_type(L, -1)));
		lua_pop(L, 1); /* pop the ... */
	}
	lua_pop(L, 1); /* fenv */

	g_assert(lua_isfunction(L, -1));
#endif
	return ret;
}


/**
 * parse the hand-shake packet from the server
 *
 *
 * @note the SSL and COMPRESS flags are disabled as we can't 
 *       intercept or parse them.
 */
NETWORK_MYSQLD_PLUGIN_PROTO(proxy_read_handshake) {
	network_packet packet;
	network_socket *recv_sock, *send_sock;
	network_mysqld_auth_challenge *challenge;
	GString *challenge_packet;
	guint8 status = 0;
	int err = 0;

	send_sock = con->client;
	recv_sock = con->server;

	packet.data = g_queue_peek_tail(recv_sock->recv_queue->chunks);
	packet.offset = 0;

	err = err || network_mysqld_proto_skip_network_header(&packet);
	if (err) return NETWORK_SOCKET_ERROR;

	err = err || network_mysqld_proto_peek_int8(&packet, &status);
	if (err) return NETWORK_SOCKET_ERROR;

	/* handle ERR packets directly */
	if (status == 0xff) {
		/* move the chunk from one queue to the next */
		guint16 errcode;
		gchar *errmsg = NULL;

		// get error message from packet
		packet.offset += 1; // skip 0xff
		err = err || network_mysqld_proto_get_int16(&packet, &errcode);
		if (packet.offset < packet.data->len) {
		    err = err || network_mysqld_proto_get_string_len(&packet, &errmsg, packet.data->len - packet.offset);
		}

		g_warning("[%s]: error packet from server (%s -> %s): %s(%d)", G_STRLOC, recv_sock->dst->name->str, recv_sock->src->name->str, errmsg, errcode);
		if (errmsg) g_free(errmsg);

		network_mysqld_queue_append_raw(send_sock, send_sock->send_queue, g_queue_pop_tail(recv_sock->recv_queue->chunks));

		network_mysqld_con_lua_t *st = con->plugin_con_state;
		if (st->backend->state != BACKEND_STATE_OFFLINE) st->backend->state = BACKEND_STATE_DOWN;
	//	chassis_gtime_testset_now(&st->backend->state_since, NULL);
		network_socket_free(con->server);
		con->server = NULL;

		return NETWORK_SOCKET_ERROR; /* it sends what is in the send-queue and hangs up */
	}

	challenge = network_mysqld_auth_challenge_new();
	if (network_mysqld_proto_get_auth_challenge(&packet, challenge)) {
 		g_string_free(g_queue_pop_tail(recv_sock->recv_queue->chunks), TRUE);

		network_mysqld_auth_challenge_free(challenge);

		return NETWORK_SOCKET_ERROR;
	}

 	con->server->challenge = challenge;

	/* we can't sniff compressed packets nor do we support SSL */
	challenge->capabilities &= ~(CLIENT_COMPRESS);
	challenge->capabilities &= ~(CLIENT_SSL);

	switch (proxy_lua_read_handshake(con)) {
	case PROXY_NO_DECISION:
		break;
	case PROXY_SEND_RESULT:
		/* the client overwrote and wants to send its own packet
		 * it is already in the queue */

 		g_string_free(g_queue_pop_tail(recv_sock->recv_queue->chunks), TRUE);

		return NETWORK_SOCKET_ERROR;
	default:
		g_error("%s.%d: ...", __FILE__, __LINE__);
		break;
	} 

	challenge_packet = g_string_sized_new(packet.data->len); /* the packet we generate will be likely as large as the old one. should save some reallocs */
	network_mysqld_proto_append_auth_challenge(challenge_packet, challenge);
	network_mysqld_queue_sync(send_sock, recv_sock);
	network_mysqld_queue_append(send_sock, send_sock->send_queue, S(challenge_packet));

	g_string_free(challenge_packet, TRUE);

	g_string_free(g_queue_pop_tail(recv_sock->recv_queue->chunks), TRUE);

	/* copy the pack to the client */
	con->state = CON_STATE_SEND_HANDSHAKE;

	return NETWORK_SOCKET_SUCCESS;
}

static network_mysqld_lua_stmt_ret proxy_lua_read_auth(network_mysqld_con *con) {
	network_mysqld_lua_stmt_ret ret = PROXY_NO_DECISION;

#ifdef HAVE_LUA_H
	network_mysqld_con_lua_t *st = con->plugin_con_state;
	lua_State *L;

	/* call the lua script to pick a backend
	   ignore the return code from network_mysqld_con_lua_register_callback, because we cannot do anything about it,
	   it would always show up as ERROR 2013, which is not helpful.	
	*/
	(void)network_mysqld_con_lua_register_callback(con, con->config->lua_script);

	if (!st->L) return 0;

	L = st->L;

	g_assert(lua_isfunction(L, -1));
	lua_getfenv(L, -1);
	g_assert(lua_istable(L, -1));
	
	lua_getfield_literal(L, -1, C("read_auth"));
	if (lua_isfunction(L, -1)) {

		/* export
		 *
		 * every thing we know about it
		 *  */

		if (lua_pcall(L, 0, 1, 0) != 0) {
			g_critical("(read_auth) %s", lua_tostring(L, -1));

			lua_pop(L, 1); /* errmsg */

			/* the script failed, but we have a useful default */
		} else {
			if (lua_isnumber(L, -1)) {
				ret = lua_tonumber(L, -1);
			}
			lua_pop(L, 1);
		}

		switch (ret) {
		case PROXY_NO_DECISION:
			break;
		case PROXY_SEND_RESULT:
			/* answer directly */

			if (network_mysqld_con_lua_handle_proxy_response(con, con->config->lua_script)) {
				/**
				 * handling proxy.response failed
				 *
				 * send a ERR packet
				 */
		
				network_mysqld_con_send_error(con->client, C("(lua) handling proxy.response failed, check error-log"));
			}

			break;
		case PROXY_SEND_QUERY:
			/* something is in the injection queue, pull it from there and replace the content of
			 * original packet */

			if (st->injected.queries->length) {
				ret = PROXY_SEND_INJECTION;
			} else {
				ret = PROXY_NO_DECISION;
			}
			break;
		default:
			ret = PROXY_NO_DECISION;
			break;
		}

		/* ret should be a index into */

	} else if (lua_isnil(L, -1)) {
		lua_pop(L, 1); /* pop the nil */
	} else {
		g_message("%s.%d: %s", __FILE__, __LINE__, lua_typename(L, lua_type(L, -1)));
		lua_pop(L, 1); /* pop the ... */
	}
	lua_pop(L, 1); /* fenv */

	g_assert(lua_isfunction(L, -1));
#endif
	return ret;
}

NETWORK_MYSQLD_PLUGIN_PROTO(proxy_read_auth) {
	/* read auth from client */
	network_packet packet;
	network_socket *recv_sock, *send_sock;
	chassis_plugin_config *config = con->config;
	network_mysqld_auth_response *auth;
	int err = 0;
	gboolean free_client_packet = TRUE;
	network_mysqld_con_lua_t *st = con->plugin_con_state;

	recv_sock = con->client;
	send_sock = con->server;

	packet.data = g_queue_pop_tail(recv_sock->recv_queue->chunks);
	packet.offset = 0;

	err = err || network_mysqld_proto_skip_network_header(&packet);
	if (err) return NETWORK_SOCKET_ERROR;

	auth = network_mysqld_auth_response_new();

	err = err || network_mysqld_proto_get_auth_response(&packet, auth);

	g_string_free(packet.data, TRUE);

	if (err) {
		network_mysqld_auth_response_free(auth);
		return NETWORK_SOCKET_ERROR;
	}
	if (!(auth->capabilities & CLIENT_PROTOCOL_41)) {
		/* should use packet-id 0 */
		network_mysqld_queue_append(con->client, con->client->send_queue, C("\xff\xd7\x07" "4.0 protocol is not supported"));
		network_mysqld_auth_response_free(auth);
		return NETWORK_SOCKET_ERROR;
	}

	con->client->response = auth;

//	g_string_assign_len(con->client->default_db, S(auth->database));

	con->state = CON_STATE_SEND_AUTH_RESULT;
        GString *hashed_password = NULL;
        hashed_password = g_hash_table_lookup(con->config->pwd_table[config->pwdtable_index], auth->username->str);
	if (hashed_password) {
		GString *expected_response = g_string_sized_new(20);
		network_mysqld_proto_password_scramble(expected_response, S(con->challenge), S(hashed_password));
		if (g_string_equal(expected_response, auth->response)) {
			g_string_assign_len(recv_sock->default_db, S(auth->database));

			char *client_charset = NULL;
			if (con->config->charset == NULL) client_charset = charset[auth->charset];
			else client_charset = con->config->charset;

			g_string_assign(recv_sock->charset_client,     client_charset);
			g_string_assign(recv_sock->charset_results,    client_charset);
			g_string_assign(recv_sock->charset_connection, client_charset);

			network_mysqld_con_send_ok(recv_sock);
		} else {
			GString *error = g_string_sized_new(64);
			g_string_printf(error, "Access denied for user '%s'@'%s' (using password: YES)", auth->username->str, recv_sock->src->name->str);
			network_mysqld_con_send_error_full(recv_sock, S(error), ER_ACCESS_DENIED_ERROR, "28000");
			g_string_free(error, TRUE);
		}
		g_string_free(expected_response, TRUE);
	} else {
		GString *error = g_string_sized_new(64);
		g_string_printf(error, "Access denied for user '%s'@'%s' (using password: YES)", auth->username->str, recv_sock->src->name->str);
		network_mysqld_con_send_error_full(recv_sock, S(error), ER_ACCESS_DENIED_ERROR, "28000");
		g_string_free(error, TRUE);
	}

	return NETWORK_SOCKET_SUCCESS;
}

NETWORK_MYSQLD_PLUGIN_PROTO(proxy_read_auth_result) {
	GString *packet;
	GList *chunk;
	network_socket *recv_sock, *send_sock;

	recv_sock = con->server;
	send_sock = con->client;

	chunk = recv_sock->recv_queue->chunks->tail;
	packet = chunk->data;

	/* send the auth result to the client */
	if (con->server->is_authed) {
		/**
		 * we injected a COM_CHANGE_USER above and have to correct to 
		 * packet-id now 
         * if config->pool_change_user is false, we don't inject a COM_CHANGE_USER and jump to send_auth_result directly,
         * will not reach here.
		 */
		packet->str[3] = 2;
	}

	/**
	 * copy the 
	 * - default-db, 
        * - charset,
	 * - username, 
	 * - scrambed_password
	 *
	 * to the server-side 
	 */
       g_string_assign_len(recv_sock->charset_client, S(send_sock->charset_client));
       g_string_assign_len(recv_sock->charset_connection, S(send_sock->charset_connection));
       g_string_assign_len(recv_sock->charset_results, S(send_sock->charset_results));
	g_string_assign_len(recv_sock->default_db, S(send_sock->default_db));

	if (con->server->response) {
		/* in case we got the connection from the pool it has the response from the previous auth */
		network_mysqld_auth_response_free(con->server->response);
		con->server->response = NULL;
	}
	con->server->response = network_mysqld_auth_response_copy(con->client->response);
	if (packet->str[NET_HEADER_SIZE] == MYSQLD_PACKET_OK) {
		network_connection_pool_lua_add_connection(con, 0);
	}
	network_mysqld_queue_append_raw(
			send_sock,
			send_sock->send_queue,
			packet);
	/**
	 * we handled the packet on the server side, free it
	 */
	g_queue_delete_link(recv_sock->recv_queue->chunks, chunk);
	
	/* the auth phase is over
	 *
	 * reset the packet-id sequence
	 */
	network_mysqld_queue_reset(send_sock);
	network_mysqld_queue_reset(recv_sock);
	//g_mutex_unlock(&mutex);

	con->state = CON_STATE_SEND_AUTH_RESULT;

	return NETWORK_SOCKET_SUCCESS;
}

int rw_split(GPtrArray* tokens, network_mysqld_con* con) {
	if (tokens->len < 2 || g_hash_table_size(con->locks) > 0) return idle_rw(con);

	sql_token* first_token = tokens->pdata[1];
	sql_token_id token_id = first_token->token_id;

	if (token_id == TK_COMMENT) {
		if (strcasecmp(first_token->text->str, "MASTER") == 0) {
			return idle_rw(con);
		} else {
			guint i = 1; 
			while (token_id == TK_COMMENT && ++i < tokens->len) {
				first_token = tokens->pdata[i];
				token_id = first_token->token_id;
			}    
		}    
	}

	if (token_id == TK_SQL_SELECT || token_id == TK_SQL_SET || token_id == TK_SQL_USE || token_id == TK_SQL_SHOW || token_id == TK_SQL_DESC || token_id == TK_SQL_EXPLAIN) {
		return wrr_ro(con);
	} else {
		return idle_rw(con);
	}    
}

void modify_user(network_mysqld_con* con) {
	if (con->server == NULL) return;

	GString* client_user = con->client->response->username;
	GString* server_user = con->server->response->username;

	if (!g_string_equal(client_user, server_user)) {
		GString* com_change_user = g_string_new(NULL);

		g_string_append_c(com_change_user, COM_CHANGE_USER);
		g_string_append_len(com_change_user, client_user->str, client_user->len + 1);
                GString *hashed_password = NULL;
                hashed_password = g_hash_table_lookup(con->config->pwd_table[con->config->pwdtable_index], client_user->str);
		if (!hashed_password) return;

		GString* expected_response = g_string_sized_new(20);
		network_mysqld_proto_password_scramble(expected_response, S(con->server->challenge->challenge), S(hashed_password));

		g_string_append_c(com_change_user, (expected_response->len & 0xff));
		g_string_append_len(com_change_user, S(expected_response));
		g_string_append_c(com_change_user, 0);

		injection* inj = injection_new(6, com_change_user);
		inj->resultset_is_needed = TRUE;
		network_mysqld_con_lua_t* st = con->plugin_con_state;
		g_queue_push_head(st->injected.queries, inj);

		g_string_truncate(con->client->response->response, 0);
		g_string_assign(con->client->response->response, expected_response->str);
		g_string_free(expected_response, TRUE);
	}
}

void modify_db(network_mysqld_con* con) {
	char* default_db = con->client->default_db->str;

	if (default_db != NULL && strcmp(default_db, "") != 0) {
		char cmd = COM_INIT_DB;
		GString* query = g_string_new_len(&cmd, 1);
		g_string_append(query, default_db);
		injection* inj = injection_new(2, query);
		inj->resultset_is_needed = TRUE;
		network_mysqld_con_lua_t* st = con->plugin_con_state;
		g_queue_push_head(st->injected.queries, inj);
	}
}

void modify_charset(GPtrArray* tokens, network_mysqld_con* con) {
	g_string_truncate(con->charset_client, 0);
	g_string_truncate(con->charset_results, 0);
	g_string_truncate(con->charset_connection, 0);

	if (con->server == NULL) return;

	gboolean is_set_client     = FALSE;
	gboolean is_set_results    = FALSE;
	gboolean is_set_connection = FALSE;

	//1.检查第一个词是不是SET
	if (tokens->len > 3) {
		sql_token* token = tokens->pdata[1];
		if (token->token_id == TK_SQL_SET) {
			//2.检查第二个词是不是NAMES或CHARACTER_SET_CLIENT或CHARACTER_SET_RESULTS或CHARACTER_SET_CONNECTION
			token = tokens->pdata[2];
			char* str = token->text->str;
			if (strcasecmp(str, "NAMES") == 0) {
				is_set_client = is_set_results = is_set_connection = TRUE;

				str = ((sql_token*)(tokens->pdata[3]))->text->str;
				g_string_assign(con->charset_client, str);
				g_string_assign(con->charset_results, str);
				g_string_assign(con->charset_connection, str);
			} else if (tokens->len > 4 && ((sql_token*)(tokens->pdata[3]))->token_id == TK_EQ) {
				if (strcasecmp(str, "CHARACTER_SET_RESULTS") == 0) {
					is_set_results = TRUE;

					str = ((sql_token*)(tokens->pdata[4]))->text->str;
					g_string_assign(con->charset_results, str);
				} else if (strcasecmp(str, "CHARACTER_SET_CLIENT") == 0) {
					is_set_client = TRUE;

					str = ((sql_token*)(tokens->pdata[4]))->text->str;
					g_string_assign(con->charset_client, str);
				} else if (strcasecmp(str, "CHARACTER_SET_CONNECTION") == 0) {
					is_set_connection = TRUE;

					str = ((sql_token*)(tokens->pdata[4]))->text->str;
					g_string_assign(con->charset_connection, str);
				}
			}
		}
	}

	//3.检查client和server两端的字符集是否相同
	network_socket* client = con->client;
	network_socket* server = con->server;
	GString* empty_charset = g_string_new("");
	char cmd = COM_QUERY;
	network_mysqld_con_lua_t* st = con->plugin_con_state;

	if (!is_set_client && !g_string_equal(client->charset_client, server->charset_client)) {
		GString* query = g_string_new_len(&cmd, 1);
		g_string_append(query, "SET CHARACTER_SET_CLIENT=");
		g_string_append(query, client->charset_client->str);
		g_string_assign(con->charset_client, client->charset_client->str);

		injection* inj = injection_new(3, query);
		inj->resultset_is_needed = TRUE;
		g_queue_push_head(st->injected.queries, inj);
	}
	if (!is_set_results && !g_string_equal(client->charset_results, server->charset_results)) {
		GString* query = g_string_new_len(&cmd, 1);
		g_string_append(query, "SET CHARACTER_SET_RESULTS=");
		g_string_append(query, client->charset_results->str);
		g_string_assign(con->charset_results, client->charset_results->str);

		injection* inj = injection_new(4, query);
		inj->resultset_is_needed = TRUE;
		g_queue_push_head(st->injected.queries, inj);
	}
	if (!is_set_connection && !g_string_equal(client->charset_connection, server->charset_connection)) {
		GString* query = g_string_new_len(&cmd, 1);
		g_string_append(query, "SET CHARACTER_SET_CONNECTION=");
		g_string_append(query, client->charset_connection->str);
		g_string_assign(con->charset_connection, client->charset_connection->str);

		injection* inj = injection_new(5, query);
		inj->resultset_is_needed = TRUE;
		g_queue_push_head(st->injected.queries, inj);
	}

	g_string_free(empty_charset, TRUE);
}

void check_flags(GPtrArray* tokens, network_mysqld_con* con, int* need_keep_conn, int* is_write_sql) {
	guint i;
       con->is_in_select_calc_found_rows = FALSE;
	sql_token** ts = (sql_token**)(tokens->pdata);
	guint len = tokens->len;
       guint64 now;
	if (len > 2) {
		if (ts[1]->token_id == TK_SQL_SELECT && strcasecmp(ts[2]->text->str, "GET_LOCK") == 0) {
			gchar* key = ts[4]->text->str;
			if (!g_hash_table_lookup(con->locks, key)) g_hash_table_add(con->locks, g_strdup(key));
		}
		if (ts[1]->token_id == TK_SQL_LOCK)
			con->is_lock_table = TRUE;
		else if (ts[1]->token_id == TK_SQL_UNLOCK)
			con->is_lock_table = FALSE;
		if (len > 4) {	//SET AUTOCOMMIT = {0 | 1}
			if (ts[1]->token_id == TK_SQL_SET && ts[3]->token_id == TK_EQ) {
				if (strcasecmp(ts[2]->text->str, "AUTOCOMMIT") == 0) {
					char* str = ts[4]->text->str;
					if (strcmp(str, "0") == 0) con->is_not_autocommit = TRUE;
					else if (strcmp(str, "1") == 0) con->is_not_autocommit = FALSE;
				}
			}
		}
              if(ts[1]->token_id == TK_SQL_SELECT || ts[1]->token_id == TK_SQL_SET || ts[1]->token_id == TK_SQL_USE || ts[1]-> token_id == TK_SQL_SHOW || ts[1]->token_id == TK_SQL_DESC || ts[1]->token_id == TK_SQL_EXPLAIN)
                     *is_write_sql = 0;
              else
                     *is_write_sql = 1;
	}
	for (i = 1; i < len; ++i) {
		sql_token* token = ts[i];
		if (ts[i]->token_id == TK_SQL_SQL_CALC_FOUND_ROWS) {
			con->is_in_select_calc_found_rows = TRUE;
			break;
		}
	}
       if(con->is_in_transaction || con->is_not_autocommit || con->is_in_select_calc_found_rows || con->is_lock_table || g_hash_table_size(con->locks) != 0) {
              *need_keep_conn = 0;
              *is_write_sql = 0;
              return;
       }

       now = my_timer_microseconds();
       if(now > con->write_sql_time + con->config->keep_connection_time * 1000) { 
              *need_keep_conn = 0;
       }else { 
              *need_keep_conn = 1;
       }
       if(*is_write_sql) con->write_sql_time = now;
}

gboolean is_in_blacklist(network_mysqld_con* con, GString* packets) {
       int i, status;
       char ebuf[128];
       chassis_plugin_config *config = con->config;
       for(i = 0; i < config->reg_array->len; i++) {
              regex_t *reg = g_ptr_array_index(config->reg_array, i);
              status = regexec(reg, packets->str, 0, NULL, 0);
              if(status == 0) {
                     g_message("C:%s Forbidden Sql:\"%s\"", con->client->src->name->str, packets->str + 1);
                     return TRUE;
              }else if(status == REG_NOMATCH) {
                     continue;
              }else if(status == REG_ESPACE) {
                     regerror(status, reg, ebuf, sizeof(ebuf));
                     g_message("%s:regexec fail, error message:%s",G_STRLOC, ebuf);
                     return FALSE;
              }
       }
       return FALSE;
}

int parse_stmt_prepare_result(network_packet *packet, network_mysqld_con* con) {
    	int err = 0;
    	guint i;
    	guint8 status = 0;
    	guint32 db_stmt_id;
    	network_socket *recv_sock, *send_sock;

    	if (!packet) return -1;
    
    	send_sock = con->client;
    	recv_sock = con->server;
   
    	err = err || network_mysqld_proto_skip_network_header(packet);
    	err = err || network_mysqld_proto_get_int8(packet, &status);
    	//err packet
    	if (status == 0xff) {
        	guint16 errcode;
        	gchar *errmsg = NULL;
        
        	//packet->offset += 1; // skip 0xff
        	err = err || network_mysqld_proto_get_int16(packet, &errcode);
        	packet->offset += 6;
        	if (packet->offset < packet->data->len) {
            		err = err || network_mysqld_proto_get_string_len(packet, &errmsg, packet->data->len - packet->offset);
        	}
        	g_warning("[%s]: error packet from server (%s -> %s): %s(%d)", G_STRLOC,recv_sock->dst->name->str, recv_sock->src->name->str, errmsg, errcode);
        	if (errmsg) g_free(errmsg);
        	return -1; 
    	}
    	err = err || network_mysqld_proto_get_int32(packet, &db_stmt_id);
    	return err==0 ? db_stmt_id : err;
}

void send_close_prepare(network_mysqld_con* con) {
   	int offset,to_write;
   	char tmp[] = {05,0,0,0};

   	GString *close_packet = g_string_new(NULL);

   	g_string_append_len(close_packet,tmp,4);
   	network_mysqld_proto_append_int8(close_packet, COM_STMT_CLOSE);
   	if (con->parse.command == COM_STMT_PREPARE)
       		network_mysqld_proto_append_int32(close_packet, con->close_stmt_id);
   	else 
       		network_mysqld_proto_append_int32(close_packet, con->execute_stmt_id);
   
   	to_write = close_packet->len;
   	offset = 0;
   	while (to_write > 0) {
       		ssize_t len = send(con->server->fd, close_packet->str + offset, to_write, 0);
       		if (len == -1) {
           		g_string_free(close_packet, TRUE);
           	g_message("%s:send_close_prepare error",G_STRLOC);
           	return;
       		}
       		offset += len;
       		to_write -= len;
   	}
   	g_string_free(close_packet, TRUE);
}
network_mysqld_lua_stmt_ret handle_stmt_prepare_packet(GString *packet,network_mysqld_con* con) {
	stmt_params_t *sp;
	injection* inj_prepare = NULL;
	network_mysqld_con_lua_t *st = con->plugin_con_state;

	inj_prepare = injection_new(1, packet);
	inj_prepare->resultset_is_needed = TRUE;
	g_queue_push_tail(st->injected.queries, inj_prepare);

	sp = network_mysqld_stmt_params_new(con->global_stmt_id);
	con->global_stmt_id++;
	sp->query = g_strdup(packet->str+1);
	con->proxy_stmt_id = sp->stmt_id;
	g_hash_table_insert(con->stmt_hash_table, GINT_TO_POINTER(&(sp->stmt_id)), sp);
	
	return PROXY_SEND_INJECTION;
}

network_mysqld_lua_stmt_ret handle_stmt_execute_packet(GString *packet,network_mysqld_con *con, GPtrArray *tokens) {
	int ret;
	guint32 stmt_id;
	stmt_params_t *sp;
	network_packet np;
	GString *prepare_packet;
       sql_token** ts;
	injection *inj_execute = NULL,*inj_prepare = NULL;
	
	network_mysqld_con_lua_t *st = con->plugin_con_state;
	np.data = packet;
	np.offset = 0;

	ret = network_mysqld_proto_get_stmt_execute_packet_stmt_id(&np, &stmt_id);
	if (ret == -1) {
		g_message("%s:handle_stmt_execute_packet error",G_STRLOC);
		return PROXY_NO_DECISION;
	}
	sp = (stmt_params_t*)g_hash_table_lookup(con->stmt_hash_table, GINT_TO_POINTER(&stmt_id));
	if (!sp) {
		g_message("%s:can't find stmt in hash table",G_STRLOC);
		return PROXY_NO_DECISION;
	}

	prepare_packet = g_string_new(NULL);
	network_mysqld_proto_append_int8(prepare_packet, COM_STMT_PREPARE);
	g_string_append_len(prepare_packet, sp->query, strlen(sp->query));
	inj_prepare = injection_new(1, prepare_packet);
	inj_prepare->resultset_is_needed = TRUE;
	g_queue_push_head(st->injected.queries, inj_prepare);

       sql_tokenizer(tokens, prepare_packet->str, prepare_packet->len);
       inj_execute = injection_new(1, packet);
       ts = (sql_token**)(tokens->pdata);
       if (ts[1]->token_id == TK_SQL_SELECT || (ts[1]->token_id == TK_COMMENT && ts[2]->token_id == TK_SQL_SELECT))
              inj_execute->resultset_is_needed = FALSE;
       else
              inj_execute->resultset_is_needed = TRUE;
	g_queue_push_tail(st->injected.queries, inj_execute);
	
	return PROXY_SEND_INJECTION;
}

int handle_stmt_close_packet(GString *packet,network_mysqld_con* con) {
	int err = 0;
	guint32 stmt_id;
	network_packet np;
	gboolean flag = FALSE;

	np.data = packet;
	np.offset = 1;//skip COM_STMT_CLOSE
	err = err || network_mysqld_proto_get_int32(&np, &stmt_id);
	if (err < 0) {
		g_critical("%s:get COM_STMT_CLOSE stmt_id err",G_STRLOC);
		return err;
	}
	flag = g_hash_table_remove(con->stmt_hash_table, GINT_TO_POINTER(&stmt_id));
	if (flag == FALSE) {
		g_critical("%s:can't remove stmt in hash table",G_STRLOC);
		err = -1;
	}
	if (con->client) 
		network_mysqld_queue_reset(con->client);
	con->state = CON_STATE_READ_QUERY;
	return err;
}

/**
 * gets called after a query has been read
 *
 * - calls the lua script via network_mysqld_con_handle_proxy_stmt()
 *
 * @see network_mysqld_con_handle_proxy_stmt
 */
NETWORK_MYSQLD_PLUGIN_PROTO(proxy_read_query) {
	GString *packet;
	network_socket *recv_sock, *send_sock;
	network_mysqld_con_lua_t *st = con->plugin_con_state;
	int proxy_query = 1, err = 0, need_keep_conn = 0, is_write_sql = 0;
	network_mysqld_lua_stmt_ret ret;

	NETWORK_MYSQLD_CON_TRACK_TIME(con, "proxy::ready_query::enter");

	send_sock = NULL;
	recv_sock = con->client;
	st->injected.sent_resultset = 0;

	NETWORK_MYSQLD_CON_TRACK_TIME(con, "proxy::ready_query::enter_lua");
	network_injection_queue_reset(st->injected.queries);

	GString* packets = g_string_new(NULL);
	int i;
	for (i = 0; NULL != (packet = g_queue_peek_nth(recv_sock->recv_queue->chunks, i)); i++) {
		g_string_append_len(packets, packet->str + NET_HEADER_SIZE, packet->len - NET_HEADER_SIZE);
	}

	char type = packets->str[0];
    	if (type == COM_QUIT || type == COM_PING) {
		g_string_free(packets, TRUE);
		network_mysqld_con_send_ok_full(con->client, 0, 0, 0x0002, 0);
		ret = PROXY_SEND_RESULT;
	} else { 
		GPtrArray *tokens = sql_tokens_new();
		sql_tokenizer(tokens, packets->str, packets->len);
              check_flags(tokens, con, &need_keep_conn, &is_write_sql);
	    	
              if (type == COM_QUERY && con->config->reg_array->len && is_in_blacklist(con, packets)) {	
            		g_string_free(packets, TRUE);
			network_mysqld_con_send_error_full(con->client, C("Proxy Warning - Syntax Forbidden"), ER_UNKNOWN_ERROR, "07000");
			ret = PROXY_SEND_RESULT;
		} else {
			if (type == COM_STMT_PREPARE) {
				ret = handle_stmt_prepare_packet(packets, con);
			} else if (type == COM_STMT_EXECUTE) {
				//token the insert prepare query
				injection* inj_tmp = NULL;
				sql_tokens_free(tokens);
				tokens = sql_tokens_new();
                            ret = handle_stmt_execute_packet(packets, con, tokens);
                            if (ret == PROXY_NO_DECISION) {
                                   sql_tokens_free(tokens);
                                   return NETWORK_SOCKET_ERROR;
                            }
                            inj_tmp = g_queue_peek_head(st->injected.queries);
				type = COM_STMT_PREPARE;
			} else if (type == COM_STMT_CLOSE) {
				int err;
				err = handle_stmt_close_packet(packets, con);
				if (err == -1)
					return NETWORK_SOCKET_ERROR;
				else
					return NETWORK_SOCKET_SUCCESS;
			} else {
                            GPtrArray* sqls = NULL;
                            if (type == COM_QUERY && con->config->rule_table) {
                                   sqls = sql_parse(con, tokens, con->config->rule_table);
                            }

				ret = PROXY_SEND_INJECTION;
				injection* inj = NULL;
				if (sqls == NULL) {
				    inj = injection_new(1, packets);
                                sql_token** ts = (sql_token**)(tokens->pdata);
                                if (ts[1]->token_id == TK_SQL_SELECT || (ts[1]->token_id == TK_COMMENT && ts[2]->token_id == TK_SQL_SELECT))
                                       inj->resultset_is_needed = FALSE;
                                else
                                       inj->resultset_is_needed = TRUE;
				    g_queue_push_tail(st->injected.queries, inj);
				} else {
				    g_string_free(packets, TRUE);

				    if (sqls->len == 1) {
					inj = injection_new(1, sqls->pdata[0]);
					inj->resultset_is_needed = TRUE;
					g_queue_push_tail(st->injected.queries, inj);
				    } else {
					merge_res_t* merge_res = con->merge_res;

					merge_res->sub_sql_num = sqls->len;
					merge_res->sub_sql_exed = 0;
					merge_res->affect_row_count = 0;
					merge_res->limit = G_MAXINT;

					sql_token** ts = (sql_token**)(tokens->pdata);
					for (i = tokens->len-2; i >= 0; --i) {
					    if (ts[i]->token_id == TK_SQL_LIMIT && ts[i+1]->token_id == TK_INTEGER) {
						merge_res->limit = atoi(ts[i+1]->text->str);
						break;
					    }
					}

					GPtrArray* rows = merge_res->rows;
					for (i = 0; i < rows->len; ++i) {
					    GPtrArray* row = g_ptr_array_index(rows, i);
					    guint j;
					    for (j = 0; j < row->len; ++j) {
						g_free(g_ptr_array_index(row, j));
					    }
					    g_ptr_array_free(row, TRUE);
					}
					g_ptr_array_set_size(rows, 0);

					for (i = 0; i < sqls->len; ++i) {
					    inj = injection_new(7, sqls->pdata[i]);
					    inj->resultset_is_needed = TRUE;
					    g_queue_push_tail(st->injected.queries, inj);
					}
				    }

				    g_ptr_array_free(sqls, TRUE);
				}
            }

			if (con->server == NULL) {
				int backend_ndx = -1;

                            if (!con->is_in_transaction && !con->is_not_autocommit && !con->is_lock_table && g_hash_table_size(con->locks) == 0 && need_keep_conn == 0) {
                                   if (type == COM_QUERY || type == COM_STMT_PREPARE) {
                                          backend_ndx = rw_split(tokens, con);
                                          con->backend_ndx = backend_ndx;
                                          send_sock = network_connection_pool_lua_swap(con, backend_ndx, need_keep_conn, &err);
                                          if (send_sock == NULL) {
                                                 network_backend_t *backend = network_backends_get(con->srv->priv->backends, backend_ndx);
                                                 network_backend_t *master = network_get_backend_by_type(con->srv->priv->backends, BACKEND_TYPE_RW);
                                                 if ((backend && backend->type == BACKEND_TYPE_RW && errno == ECONNREFUSED) || (backend_ndx == -1 && master->state == BACKEND_STATE_DOWN)) {
                                                        change_standby_to_master(con->srv->priv->backends);
                                                 }
                                          }
                                   } else if (type == COM_INIT_DB || type == COM_SET_OPTION || type == COM_FIELD_LIST) {
                                          backend_ndx = wrr_ro(con);
                                          con->backend_ndx = backend_ndx;
                                          send_sock = network_connection_pool_lua_swap(con, backend_ndx, need_keep_conn, &err);
                                   }
                            }

                            if (send_sock == NULL) {
                                   backend_ndx = idle_rw(con);
                                   con->backend_ndx = backend_ndx;
                                   send_sock = network_connection_pool_lua_swap(con, backend_ndx, need_keep_conn, &err);
                            }
                            con->server = send_sock;
			}

			modify_db(con);
			modify_charset(tokens, con);
			modify_user(con);
		}

		sql_tokens_free(tokens);
	}
	NETWORK_MYSQLD_CON_TRACK_TIME(con, "proxy::ready_query::leave_lua");

	/**
	 * if we disconnected in read_query_result() we have no connection open
	 * when we try to execute the next query 
	 *
	 * for PROXY_SEND_RESULT we don't need a server
	 */
	if (ret != PROXY_SEND_RESULT &&
	    con->server == NULL) {
              if(err == 0) {
                     g_critical("%s.%d: I have no server backend, closing connection", __FILE__, __LINE__);
                     con->backend_ndx = -1;
                     return NETWORK_SOCKET_ERROR;
              } else if(err == -1) {
                     g_message("%s: the connection count reach the max_connections(%d)", G_STRLOC, con->config->max_connections);
                     guint thread_id = chassis_event_thread_index_get();
                     chassis_event_thread_t *thread = g_ptr_array_index(srv->threads, thread_id);
                     g_queue_push_tail(thread->block_con_queue, con);
                     return NETWORK_SOCKET_WAIT_FOR_EVENT;
              }
	}
	
	switch (ret) {
	case PROXY_NO_DECISION:
	case PROXY_SEND_QUERY:
		send_sock = con->server;

		/* no injection, pass on the chunks as is */
		while ((packet = g_queue_pop_head(recv_sock->recv_queue->chunks))) {
			network_mysqld_queue_append_raw(send_sock, send_sock->send_queue, packet);
		}
		con->resultset_is_needed = FALSE; /* we don't want to buffer the result-set */

		break;
	case PROXY_SEND_RESULT: {
		gboolean is_first_packet = TRUE;
		proxy_query = 0;

		send_sock = con->client;

		/* flush the recv-queue and track the command-states */
		while ((packet = g_queue_pop_head(recv_sock->recv_queue->chunks))) {
			if (is_first_packet) {
				network_packet p;

				p.data = packet;
				p.offset = 0;

				network_mysqld_con_reset_command_response_state(con);

				if (0 != network_mysqld_con_command_states_init(con, &p)) {
					g_debug("%s: ", G_STRLOC);
				}

				is_first_packet = FALSE;
			}

			g_string_free(packet, TRUE);
		}

		break; }
	case PROXY_SEND_INJECTION: {
		injection *inj;
		
              inj = g_queue_peek_head(st->injected.queries);
		con->resultset_is_needed = inj->resultset_is_needed; /* let the lua-layer decide if we want to buffer the result or not */

		send_sock = con->server;

		network_mysqld_queue_reset(send_sock);
		network_mysqld_queue_append(send_sock, send_sock->send_queue, S(inj->query));

		while ((packet = g_queue_pop_head(recv_sock->recv_queue->chunks))) g_string_free(packet, TRUE);

		break; }
	default:
		g_error("%s.%d: ", __FILE__, __LINE__);
	}

	if (proxy_query) {
		con->state = CON_STATE_SEND_QUERY;
	} else {
		GList *cur;

		/* if we don't send the query to the backend, it won't be tracked. So track it here instead 
		 * to get the packet tracking right (LOAD DATA LOCAL INFILE, ...) */

		for (cur = send_sock->send_queue->chunks->head; cur; cur = cur->next) {
			network_packet p;
			int r;

			p.data = cur->data;
			p.offset = 0;

			r = network_mysqld_proto_get_query_result(&p, con);
		}

		con->state = CON_STATE_SEND_QUERY_RESULT;
		con->resultset_is_finished = TRUE; /* we don't have more too send */
	}
	NETWORK_MYSQLD_CON_TRACK_TIME(con, "proxy::ready_query::done");

	return NETWORK_SOCKET_SUCCESS;
}

/**
 * decide about the next state after the result-set has been written 
 * to the client
 * 
 * if we still have data in the queue, back to proxy_send_query()
 * otherwise back to proxy_read_query() to pick up a new client query
 *
 * @note we should only send one result back to the client
 */
NETWORK_MYSQLD_PLUGIN_PROTO(proxy_send_query_result) {
	network_socket *recv_sock, *send_sock;
	injection *inj;
	network_mysqld_con_lua_t *st = con->plugin_con_state;

	send_sock = con->server;
	recv_sock = con->client;

	if (st->connection_close) {
		con->state = CON_STATE_ERROR;

		return NETWORK_SOCKET_SUCCESS;
	}

	if (con->parse.command == COM_BINLOG_DUMP) {
		/**
		 * the binlog dump is different as it doesn't have END packet
		 *
		 * @todo in 5.0.x a NON_BLOCKING option as added which sends a EOF
		 */
		con->state = CON_STATE_READ_QUERY_RESULT;

		return NETWORK_SOCKET_SUCCESS;
	}

	/* if we don't have a backend, don't try to forward queries
	 */
	if (!send_sock) {
		network_injection_queue_reset(st->injected.queries);
	}

	if (st->injected.queries->length == 0) {
		/* we have nothing more to send, let's see what the next state is */

		con->state = CON_STATE_READ_QUERY;

		return NETWORK_SOCKET_SUCCESS;
	}

	/* looks like we still have queries in the queue, 
	 * push the next one 
	 */
	inj = g_queue_peek_head(st->injected.queries);
	con->resultset_is_needed = inj->resultset_is_needed;

	if (!inj->resultset_is_needed && st->injected.sent_resultset > 0) {
		/* we already sent a resultset to the client and the next query wants to forward it's result-set too, that can't work */
		g_critical("%s: proxy.queries:append() in %s can only have one injected query without { resultset_is_needed = true } set. We close the client connection now.",
				G_STRLOC,
				con->config->lua_script);

		return NETWORK_SOCKET_ERROR;
	}

	g_assert(inj);
	g_assert(send_sock);

	network_mysqld_queue_reset(send_sock);
	network_mysqld_queue_append(send_sock, send_sock->send_queue, S(inj->query));

	network_mysqld_con_reset_command_response_state(con);

	con->state = CON_STATE_SEND_QUERY;

	return NETWORK_SOCKET_SUCCESS;
}

void merge_rows(network_mysqld_con* con, injection* inj) {
	if (!inj->resultset_is_needed || !con->server->recv_queue->chunks || inj->qstat.binary_encoded) return;

	proxy_resultset_t* res = proxy_resultset_new();

	res->result_queue = con->server->recv_queue->chunks;
	res->qstat = inj->qstat;
	res->rows  = inj->rows;
	res->bytes = inj->bytes;

	parse_resultset_fields(res);

	GList* res_row = res->rows_chunk_head;
	while (res_row) {
		network_packet packet;
		packet.data = res_row->data;
		packet.offset = 0;

		network_mysqld_proto_skip_network_header(&packet);
		network_mysqld_lenenc_type lenenc_type;
		network_mysqld_proto_peek_lenenc_type(&packet, &lenenc_type);

		switch (lenenc_type) {
			case NETWORK_MYSQLD_LENENC_TYPE_ERR:
			case NETWORK_MYSQLD_LENENC_TYPE_EOF:
				proxy_resultset_free(res);
				return;

			case NETWORK_MYSQLD_LENENC_TYPE_INT:
			case NETWORK_MYSQLD_LENENC_TYPE_NULL:
				break;
		}

		GPtrArray* row = g_ptr_array_new();

		guint len = res->fields->len;
		guint i;
		for (i = 0; i < len; i++) {
			guint64 field_len;

			network_mysqld_proto_peek_lenenc_type(&packet, &lenenc_type);

			switch (lenenc_type) {
				case NETWORK_MYSQLD_LENENC_TYPE_NULL:
                                   g_ptr_array_add(row, NULL);
					network_mysqld_proto_skip(&packet, 1);
					break;

				case NETWORK_MYSQLD_LENENC_TYPE_INT:
					network_mysqld_proto_get_lenenc_int(&packet, &field_len);
					g_ptr_array_add(row, g_strndup(packet.data->str + packet.offset, field_len));
					network_mysqld_proto_skip(&packet, field_len);
					break;

				default:
					break;
			}
		}

		g_ptr_array_add(con->merge_res->rows, row);
		if (con->merge_res->rows->len >= con->merge_res->limit) break;
		res_row = res_row->next;
	}

	proxy_resultset_free(res);
}

void log_sql(network_mysqld_con* con, injection* inj) {
	if (sql_log_type == OFF) return;

	chassis_plugin_config *config = con->config;
       double latency_ms = (inj->ts_read_query_result_last - inj->ts_read_query)/1000.0;
       if ((gint)latency_ms < config->sql_log_slow_ms) return;

	GString* message = g_string_new(NULL);
	time_t t = time(NULL);
	struct tm* tm = localtime(&t);
	g_string_printf(message, "[%02d/%02d/%d %02d:%02d:%02d] C:%s S:", tm->tm_mon+1, tm->tm_mday, tm->tm_year+1900, tm->tm_hour, tm->tm_min, tm->tm_sec, con->client->src->name->str);

	if (inj->qstat.query_status == MYSQLD_PACKET_OK) {
		g_string_append_printf(message, "%s OK %.3f \"%s\"\n", con->server->dst->name->str, latency_ms, inj->query->str+1);
	} else {
		g_string_append_printf(message, "%s ERR %.3f \"%s\"\n", con->server->dst->name->str, latency_ms, inj->query->str+1);
	}

	fwrite(message->str, message->len, 1, config->sql_log);
	g_string_free(message, TRUE);

	if (sql_log_type == REALTIME) fflush(config->sql_log);
}

/**
 * handle the query-result we received from the server
 *
 * - decode the result-set to track if we are finished already
 * - handles BUG#25371 if requested
 * - if the packet is finished, calls the network_mysqld_con_handle_proxy_resultset
 *   to handle the resultset in the lua-scripts
 *
 * @see network_mysqld_con_handle_proxy_resultset
 */
NETWORK_MYSQLD_PLUGIN_PROTO(proxy_read_query_result) {
	int is_finished = 0;
	network_packet packet;
	network_socket *recv_sock, *send_sock;
	network_mysqld_con_lua_t *st = con->plugin_con_state;
	injection *inj = NULL;

	NETWORK_MYSQLD_CON_TRACK_TIME(con, "proxy::ready_query_result::enter");

	recv_sock = con->server;
	send_sock = con->client;

	/* check if the last packet is valid */
	packet.data = g_queue_peek_tail(recv_sock->recv_queue->chunks);
	packet.offset = 0;

	if (0 != st->injected.queries->length) {
		inj = g_queue_peek_head(st->injected.queries);
	}

	if (inj && inj->ts_read_query_result_first == 0) {
		/**
		 * log the time of the first received packet
		 */
		inj->ts_read_query_result_first = chassis_get_rel_microseconds();
		/* g_get_current_time(&(inj->ts_read_query_result_first)); */
	}

	if (con->parse.command == COM_STMT_PREPARE) {
		guint8 packet_id;
		packet_id = network_mysqld_proto_get_packet_id(packet.data);
		if (packet_id == 1) {
			int db_stmt_id;
			db_stmt_id = parse_stmt_prepare_result(&packet, con);
			if (db_stmt_id < 0) {
				g_message("%s:stmt_id < 0",G_STRLOC);
				return NETWORK_SOCKET_ERROR;
			}
			if (st->injected.queries->length == 1) {
				con->close_stmt_id = db_stmt_id;//return stmt_id in the backend
				//use proxy_stmt_id replace the stmt_id in packet
				unsigned char *header = (unsigned char *)((packet.data)->str);
				header[5] = (con->proxy_stmt_id >> 0) & 0xFF;
				header[6] = (con->proxy_stmt_id >> 8) & 0xFF;
				header[7] = (con->proxy_stmt_id >> 16) & 0xFF;
				header[8] = (con->proxy_stmt_id >> 24) & 0xFF;
			}else if (st->injected.queries->length > 1) {
				injection *inj_execute = NULL;
				inj_execute = g_queue_peek_nth(st->injected.queries, 1);
				if (!inj_execute){
					g_message("%s:get inj_execute err",G_STRLOC);
					return NETWORK_SOCKET_ERROR;
				}
				if (*(inj_execute->query->str) == COM_STMT_EXECUTE) {
					unsigned char *exe_header = (unsigned char *)(inj_execute->query->str);
					exe_header[1] = (db_stmt_id >> 0) & 0xFF;
					exe_header[2] = (db_stmt_id >> 8) & 0xFF;
					exe_header[3] = (db_stmt_id >> 16) & 0xFF;
					exe_header[4] = (db_stmt_id >> 24) & 0xFF;

					con->execute_stmt_id = db_stmt_id;
				}
			}
		}
		packet.offset = 0;
	}
	is_finished = network_mysqld_proto_get_query_result(&packet, con);
	if (is_finished == -1) return NETWORK_SOCKET_ERROR; /* something happend, let's get out of here */
    
	if (con->parse.command == COM_STMT_PREPARE && is_finished && st->injected.queries->length > 1) {
		//free prepare ok packet
		if (con->resultset_is_needed) {
			GString *p;
			while ((p = g_queue_pop_head(recv_sock->recv_queue->chunks))) g_string_free(p, TRUE);
		}
		// pop prepare inj
		inj = g_queue_pop_head(st->injected.queries);
		inj->ts_read_query_result_last = chassis_get_rel_microseconds();	
		log_sql(con, inj);
		//insert execute inj into con->server send queue
		inj = g_queue_peek_head(st->injected.queries);
		con->resultset_is_needed = inj->resultset_is_needed;
		if (con->server)
			network_mysqld_queue_reset(con->server);
		network_mysqld_queue_append(con->server, con->server->send_queue, S(inj->query));
		network_mysqld_con_reset_command_response_state(con);

		con->state = CON_STATE_SEND_QUERY;
		return NETWORK_SOCKET_SUCCESS;
	}

	con->resultset_is_finished = is_finished;

	/* copy the packet over to the send-queue if we don't need it */
	if (!con->resultset_is_needed) {
		network_mysqld_queue_append_raw(send_sock, send_sock->send_queue, g_queue_pop_tail(recv_sock->recv_queue->chunks));
	}

	if (is_finished) {
		network_mysqld_lua_stmt_ret ret;

		/**
		 * the resultset handler might decide to trash the send-queue
		 * 
		 * */
		//g_mutex_lock(&mutex);
		if (inj) {
			if (con->parse.command == COM_QUERY || con->parse.command == COM_STMT_EXECUTE) {
				network_mysqld_com_query_result_t *com_query = con->parse.data;

				inj->bytes = com_query->bytes;
				inj->rows  = com_query->rows;
				inj->qstat.was_resultset = com_query->was_resultset;
				inj->qstat.binary_encoded = com_query->binary_encoded;

				/* INSERTs have a affected_rows */
				if (!com_query->was_resultset) {
					inj->qstat.affected_rows = com_query->affected_rows;
					inj->qstat.insert_id     = com_query->insert_id;
				}
				inj->qstat.server_status = com_query->server_status;
				inj->qstat.warning_count = com_query->warning_count;
				inj->qstat.query_status  = com_query->query_status;
			}
			inj->ts_read_query_result_last = chassis_get_rel_microseconds();
			/* g_get_current_time(&(inj->ts_read_query_result_last)); */
		}

		network_mysqld_queue_reset(recv_sock); /* reset the packet-id checks as the server-side is finished */

		NETWORK_MYSQLD_CON_TRACK_TIME(con, "proxy::ready_query_result::enter_lua");
		GString* p;
		if (0 != st->injected.queries->length) {
			inj = g_queue_pop_head(st->injected.queries);
			char* str = inj->query->str + 1;
			if (inj->id == 1) {
				if (*(str-1) == COM_QUERY) 
					log_sql(con, inj);
				else if (*(str-1) == COM_STMT_PREPARE || *(str-1) == COM_STMT_EXECUTE) 
					send_close_prepare(con);
				ret = PROXY_SEND_RESULT;
			} else if (inj->id == 7) {
				log_sql(con, inj);
				if(strcasestr(str,"SELECT") != NULL) {
					merge_res_t* merge_res = con->merge_res;
					if (inj->qstat.query_status == MYSQLD_PACKET_OK && merge_res->rows->len < merge_res->limit) merge_rows(con, inj);

					if ((++merge_res->sub_sql_exed) < merge_res->sub_sql_num) {
						ret = PROXY_IGNORE_RESULT;
					} else {
						network_injection_queue_reset(st->injected.queries);
						ret = PROXY_SEND_RESULT;

						if (inj->qstat.query_status == MYSQLD_PACKET_OK) {
							proxy_resultset_t* res = proxy_resultset_new();

							if (inj->resultset_is_needed && !inj->qstat.binary_encoded) res->result_queue = con->server->recv_queue->chunks;
							res->qstat = inj->qstat;
							res->rows  = inj->rows;
							res->bytes = inj->bytes;
							parse_resultset_fields(res);

							while ((p = g_queue_pop_head(recv_sock->recv_queue->chunks))) g_string_free(p, TRUE);
							network_mysqld_con_send_resultset(send_sock, res->fields, merge_res->rows);

							proxy_resultset_free(res);
						}
					}
				} else {
					//对应update,delete使用in的情况
					int err=0;
					merge_res_t* merge_res = con->merge_res;
					network_mysqld_ok_packet_t *ok_packet;
					if (inj->qstat.query_status == MYSQLD_PACKET_OK) {
						ok_packet = network_mysqld_ok_packet_new();
						packet.offset=0;
						network_mysqld_proto_skip(&packet, NET_HEADER_SIZE);
						err = err || network_mysqld_proto_get_ok_packet(&packet, ok_packet);
						if (err) {
							network_mysqld_ok_packet_free(ok_packet);
							g_message("%s.%d:get ok packet error ", __FILE__, __LINE__);
							return NETWORK_SOCKET_ERROR;
						}
						merge_res->affect_row_count += ok_packet->affected_rows;
						if((++merge_res->sub_sql_exed) < merge_res->sub_sql_num) {
							network_mysqld_ok_packet_free(ok_packet);
							ret = PROXY_IGNORE_RESULT;
						} else {
							guint16 server_status;
							server_status=ok_packet->server_status;
							network_mysqld_con_send_ok_full(con->client,merge_res->affect_row_count,0,server_status, 0);
							network_injection_queue_reset(st->injected.queries);
							while ((p = g_queue_pop_head(recv_sock->recv_queue->chunks))) g_string_free(p, TRUE);
							network_mysqld_ok_packet_free(ok_packet);
							ret = PROXY_SEND_RESULT;
						}
					} else {
						//对应delete update err情况
						if((++merge_res->sub_sql_exed) < merge_res->sub_sql_num)
							ret = PROXY_IGNORE_RESULT;
						else
							ret = PROXY_SEND_RESULT;
					}
				}
			} else {
				ret = PROXY_IGNORE_RESULT;

				if (inj->id == 6) {
					if (con->server->response) {
						/* in case we got the connection from the pool it has the response from the previous auth */
						network_mysqld_auth_response_free(con->server->response);
						con->server->response = NULL;
					}    
					con->server->response = network_mysqld_auth_response_copy(con->client->response);
				}
			}

			switch (ret) {
			case PROXY_SEND_RESULT:
				if (!con->is_in_transaction || (inj->qstat.server_status & SERVER_STATUS_IN_TRANS)) {
					con->is_in_transaction = (inj->qstat.server_status & SERVER_STATUS_IN_TRANS);
				} else {
					if (strcasestr(str, "COMMIT") == str || strcasestr(str, "ROLLBACK") == str) con->is_in_transaction = FALSE;
					if(inj->qstat.server_status & SERVER_STATUS_AUTOCOMMIT) con->is_in_transaction = FALSE;
				}
				if (g_hash_table_size(con->locks) > 0 && strcasestr(str, "SELECT RELEASE_LOCK") == str) {
					gchar* b = strchr(str+strlen("SELECT RELEASE_LOCK"), '(') + 1;
					if (b) {
						while (*b == ' ') ++b;
						gchar* e = NULL;
						if (*b == '\'') {
							++b;
							e = strchr(b, '\'');
						} else if (*b == '\"') {
							++b;
							e = strchr(b+1, '\"');
						}
						if (e) {
							gchar* key = g_strndup(b, e-b);
							g_hash_table_remove(con->locks, key);
							g_free(key);
						}
					}
				}

				gboolean have_last_insert_id = inj->qstat.insert_id > 0;

				if (!con->is_in_transaction && !con->is_not_autocommit && !con->is_in_select_calc_found_rows && !have_last_insert_id && !con->is_lock_table && g_hash_table_size(con->locks) == 0) {
                                   guint64 now = my_timer_microseconds();
                                   if(now > con->write_sql_time + con->config->keep_connection_time * 1000)
                                          network_connection_pool_lua_add_connection(con, 0);
                                   else 
                                          network_connection_pool_lua_add_connection(con, 1);
                                   con->backend_ndx = -1;
                            }

				++st->injected.sent_resultset;
				if (st->injected.sent_resultset == 1) {
					while ((p = g_queue_pop_head(recv_sock->recv_queue->chunks))) network_mysqld_queue_append_raw(send_sock, send_sock->send_queue, p);
					break;
				}

			case PROXY_IGNORE_RESULT:
				if (con->resultset_is_needed) {
					while ((p = g_queue_pop_head(recv_sock->recv_queue->chunks))) g_string_free(p, TRUE);
				}

			default:
				break;
			}

			injection_free(inj);
		}

		NETWORK_MYSQLD_CON_TRACK_TIME(con, "proxy::ready_query_result::leave_lua");

		if (PROXY_IGNORE_RESULT != ret) {
			/* reset the packet-id checks, if we sent something to the client */
			network_mysqld_queue_reset(send_sock);
		}
		//g_mutex_unlock(&mutex);
		/**
		 * if the send-queue is empty, we have nothing to send
		 * and can read the next query */
		if (send_sock->send_queue->chunks) {
			con->state = CON_STATE_SEND_QUERY_RESULT;
		} else {
			g_assert_cmpint(con->resultset_is_needed, ==, 1); /* we already forwarded the resultset, no way someone has flushed the resultset-queue */

			con->state = CON_STATE_READ_QUERY;
		}
	}
	NETWORK_MYSQLD_CON_TRACK_TIME(con, "proxy::ready_query_result::leave");
	
	return NETWORK_SOCKET_SUCCESS;
}

/**
 * connect to a backend
 *
 * @return
 *   NETWORK_SOCKET_SUCCESS        - connected successfully
 *   NETWORK_SOCKET_ERROR_RETRY    - connecting backend failed, call again to connect to another backend
 *   NETWORK_SOCKET_ERROR          - no backends available, adds a ERR packet to the client queue
 */
NETWORK_MYSQLD_PLUGIN_PROTO(proxy_connect_server) {
	network_mysqld_con_lua_t *st = con->plugin_con_state;
	guint i;
	network_backend_t *cur;

	chassis_plugin_config *config = con->config;

	guint client_ip = con->client->src->addr.ipv4.sin_addr.s_addr;
	if (!online && g_hash_table_contains(config->lvs_table, &client_ip)) {
		network_mysqld_con_send_error_full(con->client, C("Proxy Warning - Offline Now"), ER_UNKNOWN_ERROR, "07000");
		return NETWORK_SOCKET_SUCCESS;
	} else if (g_hash_table_size(config->ip_table[config->iptable_index]) != 0) {
                for (i = 0; i < 3; ++i) {
                        if (g_hash_table_contains(config->ip_table[config->iptable_index], &client_ip)) break;
                        client_ip <<= 8;
                }
		if (i == 3 && !g_hash_table_contains(config->lvs_table, &(con->client->src->addr.ipv4.sin_addr.s_addr))) {
			network_mysqld_con_send_error_full(con->client, C("Proxy Warning - IP Forbidden"), ER_UNKNOWN_ERROR, "07000");
			return NETWORK_SOCKET_SUCCESS;
		}    
	}

	network_mysqld_auth_challenge *challenge = network_mysqld_auth_challenge_new();

	challenge->protocol_version = 0;
	challenge->server_version_str = g_strdup("5.0.81-log");
	challenge->server_version = 50081;
	challenge->thread_id = rand();

	GString *str = con->challenge;
	for (i = 0; i < 20; ++i) g_string_append_c(str, rand()%127+1);
	g_string_assign(challenge->challenge, str->str);

	challenge->capabilities = 41484;
	challenge->charset = 8;
	challenge->server_status = 2;

	GString *auth_packet = g_string_new(NULL);
	network_mysqld_proto_append_auth_challenge(auth_packet, challenge);
	network_mysqld_auth_challenge_free(challenge);
	network_mysqld_queue_append(con->client, con->client->send_queue, S(auth_packet));
	g_string_free(auth_packet, TRUE);
	con->state = CON_STATE_SEND_HANDSHAKE;

	return NETWORK_SOCKET_SUCCESS;
}

NETWORK_MYSQLD_PLUGIN_PROTO(proxy_init) {
	network_mysqld_con_lua_t *st = con->plugin_con_state;

	g_assert(con->plugin_con_state == NULL);

	st = network_mysqld_con_lua_new();

	con->plugin_con_state = st;
	
	con->state = CON_STATE_CONNECT_SERVER;

	return NETWORK_SOCKET_SUCCESS;
}

/**
 * cleanup the proxy specific data on the current connection 
 *
 * move the server connection into the connection pool in case it is a 
 * good client-side close
 *
 * @return NETWORK_SOCKET_SUCCESS
 * @see plugin_call_cleanup
 */
NETWORK_MYSQLD_PLUGIN_PROTO(proxy_disconnect_client) {
	network_mysqld_con_lua_t *st = con->plugin_con_state;
	lua_scope  *sc = con->srv->priv->sc;

	if (st == NULL) return NETWORK_SOCKET_SUCCESS;
	
#ifdef HAVE_LUA_H
	/* remove this cached script from registry */
	if (st->L_ref > 0) {
		luaL_unref(sc->L, LUA_REGISTRYINDEX, st->L_ref);
	}
#endif
        if (st->backend)
                g_atomic_int_dec_and_test(&(st->backend->connected_clients));
	network_mysqld_con_lua_free(st);

	con->plugin_con_state = NULL;

	/**
	 * walk all pools and clean them up
	 */

	return NETWORK_SOCKET_SUCCESS;
}

/**
 * read the load data infile data from the client
 *
 * - decode the result-set to track if we are finished already
 * - gets called once for each packet
 *
 * @FIXME stream the data to the backend
 */
NETWORK_MYSQLD_PLUGIN_PROTO(proxy_read_local_infile_data) {
	int query_result = 0;
	network_packet packet;
	network_socket *recv_sock, *send_sock;
	network_mysqld_com_query_result_t *com_query = con->parse.data;

	NETWORK_MYSQLD_CON_TRACK_TIME(con, "proxy::ready_query_result::enter");
	
	recv_sock = con->client;
	send_sock = con->server;

	/* check if the last packet is valid */
	packet.data = g_queue_peek_tail(recv_sock->recv_queue->chunks);
	packet.offset = 0;

	/* if we get here from another state, src/network-mysqld.c is broken */
	g_assert_cmpint(con->parse.command, ==, COM_QUERY);
	g_assert_cmpint(com_query->state, ==, PARSE_COM_QUERY_LOCAL_INFILE_DATA);

	query_result = network_mysqld_proto_get_query_result(&packet, con);
	if (query_result == -1) return NETWORK_SOCKET_ERROR; /* something happend, let's get out of here */

	if (con->server) {
		network_mysqld_queue_append_raw(send_sock, send_sock->send_queue,
				g_queue_pop_tail(recv_sock->recv_queue->chunks));
	} else {
		GString *s;
		/* we don't have a backend
		 *
		 * - free the received packets early
		 * - send a OK later 
		 */
		while ((s = g_queue_pop_head(recv_sock->recv_queue->chunks))) g_string_free(s, TRUE);
	}

	if (query_result == 1) { /* we have everything, send it to the backend */
		if (con->server) {
			con->state = CON_STATE_SEND_LOCAL_INFILE_DATA;
		} else {
			network_mysqld_con_send_ok(con->client);
			con->state = CON_STATE_SEND_LOCAL_INFILE_RESULT;
		}
		g_assert_cmpint(com_query->state, ==, PARSE_COM_QUERY_LOCAL_INFILE_RESULT);
	}

	return NETWORK_SOCKET_SUCCESS;
}

/**
 * read the load data infile result from the server
 *
 * - decode the result-set to track if we are finished already
 */
NETWORK_MYSQLD_PLUGIN_PROTO(proxy_read_local_infile_result) {
	int query_result = 0;
	network_packet packet;
	network_socket *recv_sock, *send_sock;

	NETWORK_MYSQLD_CON_TRACK_TIME(con, "proxy::ready_local_infile_result::enter");

	recv_sock = con->server;
	send_sock = con->client;

	/* check if the last packet is valid */
	packet.data = g_queue_peek_tail(recv_sock->recv_queue->chunks);
	packet.offset = 0;
	
	query_result = network_mysqld_proto_get_query_result(&packet, con);
	if (query_result == -1) return NETWORK_SOCKET_ERROR; /* something happend, let's get out of here */

	network_mysqld_queue_append_raw(send_sock, send_sock->send_queue,
			g_queue_pop_tail(recv_sock->recv_queue->chunks));

	if (query_result == 1) {
		con->state = CON_STATE_SEND_LOCAL_INFILE_RESULT;
	}

	return NETWORK_SOCKET_SUCCESS;
}

/**
 * cleanup after we sent to result of the LOAD DATA INFILE LOCAL data to the client
 */
NETWORK_MYSQLD_PLUGIN_PROTO(proxy_send_local_infile_result) {
	network_socket *recv_sock, *send_sock;

	NETWORK_MYSQLD_CON_TRACK_TIME(con, "proxy::send_local_infile_result::enter");

	recv_sock = con->server;
	send_sock = con->client;

	/* reset the packet-ids */
	if (send_sock) network_mysqld_queue_reset(send_sock);
	if (recv_sock) network_mysqld_queue_reset(recv_sock);

	con->state = CON_STATE_READ_QUERY;

	return NETWORK_SOCKET_SUCCESS;
}


int network_mysqld_proxy_connection_init(network_mysqld_con *con) {
	con->plugins.con_init                      = proxy_init;
	con->plugins.con_connect_server            = proxy_connect_server;
	con->plugins.con_read_handshake            = proxy_read_handshake;
	con->plugins.con_read_auth                 = proxy_read_auth;
	con->plugins.con_read_auth_result          = proxy_read_auth_result;
	con->plugins.con_read_query                = proxy_read_query;
	con->plugins.con_read_query_result         = proxy_read_query_result;
	con->plugins.con_send_query_result         = proxy_send_query_result;
	con->plugins.con_read_local_infile_data = proxy_read_local_infile_data;
	con->plugins.con_read_local_infile_result = proxy_read_local_infile_result;
	con->plugins.con_send_local_infile_result = proxy_send_local_infile_result;
	con->plugins.con_cleanup                   = proxy_disconnect_client;

	return 0;
}

/**
 * free the global scope which is shared between all connections
 *
 * make sure that is called after all connections are closed
 */
void network_mysqld_proxy_free(network_mysqld_con G_GNUC_UNUSED *con) {
}

chassis_plugin_config * network_mysqld_proxy_plugin_new(void) {
	chassis_plugin_config *config;

	config = g_new0(chassis_plugin_config, 1);
	config->fix_bug_25371   = 0; /** double ERR packet on AUTH failures */
	config->profiling       = 1;
	config->start_proxy     = 1;
	config->pool_change_user = 1; /* issue a COM_CHANGE_USER to cleanup the connection 
					 when we get back the connection from the pool */
	config->ip_table[0] = g_hash_table_new_full(g_int_hash, g_int_equal, g_free, NULL);
	config->ip_table[1]= g_hash_table_new_full(g_int_hash, g_int_equal, g_free, NULL);
	config->lvs_table = g_hash_table_new_full(g_int_hash, g_int_equal, g_free, NULL);
	config->dt_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	config->rule_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, shard_rule_free);
       config->pwd_table[0] = g_hash_table_new(g_str_hash, g_str_equal);
	config->pwd_table[1] = g_hash_table_new(g_str_hash, g_str_equal);
	config->sql_log = NULL;
	config->sql_log_type = NULL;
	config->charset = NULL;
       config->iptable_index = 0;
       config->pwdtable_index = 0;
       config->connect_times = 1;
       config->check_time = 4;
	config->fsql = NULL;
       config->reg_array = g_ptr_array_new();
       config->sql_log_slow_ms = 0;

	return config;
}

void network_mysqld_proxy_plugin_free(chassis_plugin_config *config) {
	gsize i;

	if (config->listen_con) {
		/**
		 * the connection will be free()ed by the network_mysqld_free()
		 */
#if 0
		event_del(&(config->listen_con->server->event));
		network_mysqld_con_free(config->listen_con);
#endif
	}

	if (config->backend_addresses) {
		for (i = 0; config->backend_addresses[i]; i++) {
			g_free(config->backend_addresses[i]);
		}
		g_free(config->backend_addresses);
	}
    
       if (config->master_standby_addresses) {
              g_strfreev(config->master_standby_addresses);
       }
       if (config->pwds) {
              g_strfreev(config->pwds);
       }
	if (config->address) {
		/* free the global scope */
		network_mysqld_proxy_free(NULL);

		g_free(config->address);
	}

	if (config->lua_script) g_free(config->lua_script);

	if (config->client_ips) {
		for (i = 0; config->client_ips[i]; i++) {
			g_free(config->client_ips[i]);
		}
		g_free(config->client_ips);
	}

	g_hash_table_remove_all(config->ip_table[0]);
	g_hash_table_destroy(config->ip_table[0]);
	g_hash_table_remove_all(config->ip_table[1]);
	g_hash_table_destroy(config->ip_table[1]);
       g_hash_table_destroy(config->rule_table);
        
        if (config->lvs_ips) {
		for (i = 0; config->lvs_ips[i]; i++) {
			g_free(config->lvs_ips[i]);
		}
		g_free(config->lvs_ips);
	}

	g_hash_table_remove_all(config->lvs_table);
	g_hash_table_destroy(config->lvs_table);

	if (config->tables) {
		for (i = 0; config->tables[i]; i++) {
			g_free(config->tables[i]);
		}
		g_free(config->tables);
	}

	g_hash_table_remove_all(config->dt_table);
	g_hash_table_destroy(config->dt_table);

	g_hash_table_remove_all(config->pwd_table[0]);
	g_hash_table_destroy(config->pwd_table[0]);
	g_hash_table_remove_all(config->pwd_table[1]);
	g_hash_table_destroy(config->pwd_table[1]);

	if (config->sql_log) fclose(config->sql_log);
	if (config->sql_log_type) g_free(config->sql_log_type);

	if (config->charset) g_free(config->charset);
	if (config->fsql) g_strfreev(config->fsql);
       if (config->reg_array) {
              for (i = 0; i < config->reg_array->len; i++) {
                     regex_t *reg = g_ptr_array_index(config->reg_array, i);
                     regfree(reg);
                     g_free(reg);/*regfree does not free the object reg itself*/
              }
              g_ptr_array_free(config->reg_array, TRUE);
       }

	g_free(config);

	//g_mutex_clear(&mutex);
}

/**
 * plugin options 
 */
static GOptionEntry * network_mysqld_proxy_plugin_get_options(chassis_plugin_config *config) {
	guint i;

	/* make sure it isn't collected */
	static GOptionEntry config_entries[] = 
	{
		{ "proxy-address",            'P', 0, G_OPTION_ARG_STRING, NULL, "listening address:port of the proxy-server (default: :4040)", "<host:port>" },
		{ "proxy-read-only-backend-addresses", 
					      'r', 0, G_OPTION_ARG_STRING_ARRAY, NULL, "address:port of the remote slave-server (default: not set)", "<host:port>" },
		{ "proxy-backend-addresses",  'b', 0, G_OPTION_ARG_STRING_ARRAY, NULL, "address:port of the remote backend-servers (default: 127.0.0.1:3306)", "<host:port>" },
		{ "proxy-master-standby-address",  0, 0, G_OPTION_ARG_STRING_ARRAY, NULL, "address:port of the remote master-standby-servers ", "<host:port>" },
		{ "proxy-skip-profiling",     0, G_OPTION_FLAG_REVERSE, G_OPTION_ARG_NONE, NULL, "disables profiling of queries (default: enabled)", NULL },

		{ "proxy-fix-bug-25371",      0, 0, G_OPTION_ARG_NONE, NULL, "fix bug #25371 (mysqld > 5.1.12) for older libmysql versions", NULL },
		{ "proxy-lua-script",         's', 0, G_OPTION_ARG_FILENAME, NULL, "filename of the lua script (default: not set)", "<file>" },
		
		{ "no-proxy",                 0, G_OPTION_FLAG_REVERSE, G_OPTION_ARG_NONE, NULL, "don't start the proxy-module (default: enabled)", NULL },
		
		{ "proxy-pool-no-change-user", 0, G_OPTION_FLAG_REVERSE, G_OPTION_ARG_NONE, NULL, "don't use CHANGE_USER to reset the connection coming from the pool (default: enabled)", NULL },

		{ "client-ips", 0, 0, G_OPTION_ARG_STRING_ARRAY, NULL, "all permitted client ips", NULL },
	
		{ "lvs-ips", 0, 0, G_OPTION_ARG_STRING_ARRAY, NULL, "all lvs ips", NULL },

		{ "tables", 0, 0, G_OPTION_ARG_STRING_ARRAY, NULL, "sub-table settings", NULL },
	
		{ "pwds", 0, 0, G_OPTION_ARG_STRING_ARRAY, NULL, "password settings", NULL },
		
		{ "charset", 0, 0, G_OPTION_ARG_STRING, NULL, "original charset(default: LATIN1)", NULL },

		{ "sql-log", 0, 0, G_OPTION_ARG_STRING, NULL, "sql log type(default: OFF)", NULL },
              { "sql-log-slow", 0, 0, G_OPTION_ARG_INT, NULL, "only log sql which takes longer than this milliseconds (default: 0)", NULL },
              { "check_time", 0, 0, G_OPTION_ARG_INT, NULL, "the time interval of checking the backends", NULL},
              { "connect_times", 0, 0, G_OPTION_ARG_INT, NULL, "the times of checking the backends", NULL},
		{ "forbidden-sql", 0, 0, G_OPTION_ARG_STRING_ARRAY, NULL, "forbidden sql", NULL },
              { "max-connections", 0, 0, G_OPTION_ARG_INT, NULL, "the max connections of one DB (default:0)", NULL },
              { "keep-connection-time", 0, 0, G_OPTION_ARG_INT, NULL, "the expire time of keeping connection(default:0)", NULL },
              { "wait-timeout", 0, 0, G_OPTION_ARG_INT, NULL, "the number of seconds Atlas waits for activity on a noninteractive connection before closing it.(default:0)", NULL },
		{ NULL,                       0, 0, G_OPTION_ARG_NONE,   NULL, NULL, NULL }
	};

	i = 0;
	config_entries[i++].arg_data = &(config->address);
	config_entries[i++].arg_data = &(config->read_only_backend_addresses);
	config_entries[i++].arg_data = &(config->backend_addresses);
	config_entries[i++].arg_data = &(config->master_standby_addresses);

	config_entries[i++].arg_data = &(config->profiling);

	config_entries[i++].arg_data = &(config->fix_bug_25371);
	config_entries[i++].arg_data = &(config->lua_script);
	config_entries[i++].arg_data = &(config->start_proxy);
	config_entries[i++].arg_data = &(config->pool_change_user);
	config_entries[i++].arg_data = &(config->client_ips);
	config_entries[i++].arg_data = &(config->lvs_ips);
	config_entries[i++].arg_data = &(config->tables);
	config_entries[i++].arg_data = &(config->pwds);
	config_entries[i++].arg_data = &(config->charset);
	config_entries[i++].arg_data = &(config->sql_log_type);
	config_entries[i++].arg_data = &(config->sql_log_slow_ms);
       config_entries[i++].arg_data = &(config->check_time);
       config_entries[i++].arg_data = &(config->connect_times);
       config_entries[i++].arg_data = &(config->fsql);
       config_entries[i++].arg_data = &(config->max_connections);
       config_entries[i++].arg_data = &(config->keep_connection_time);
       config_entries[i++].arg_data = &(config->wait_timeout);
	return config_entries;
}

void handler(int sig) {
	switch (sig) {
	case SIGUSR1:
		online = TRUE;
		break;
	case SIGUSR2:
		online = FALSE;
		break;
	}
}

void* check_state(chassis *chas) {
	MYSQL mysql;
       gint i, tm = 1;
       char *user = NULL, *pwd_decr = NULL, *pwd_encr = NULL, *pwds_str = NULL;
       mysql_init(&mysql);
       chassis_plugin *p = chas->modules->pdata[1]; /*proxy plugin*/
       chassis_plugin_config *config = p->config;
       GPtrArray* backends = chas->priv->backends->backends;
       if(config->pwds && config->pwds[0]) {
              pwds_str = strdup(config->pwds[0]);
              user = strsep(&pwds_str, ":");
              pwd_encr = strsep(&pwds_str, ":");
              pwd_decr = pwds_decrypt(pwd_encr);
       }
	sleep(1);
	while (TRUE) {
		guint len = backends->len;

		for (i = 0; i < len; ++i) {
                     network_backend_t* backend = g_ptr_array_index(backends, i);
                     if (backend == NULL || backend->state == BACKEND_STATE_OFFLINE) continue;
                     gchar* ip = inet_ntoa(backend->addr->addr.ipv4.sin_addr);
                     guint port = ntohs(backend->addr->addr.ipv4.sin_port);
                     mysql_options(&mysql, MYSQL_OPT_CONNECT_TIMEOUT, &tm);
                     mysql_real_connect(&mysql, ip, user, pwd_decr, NULL, port, NULL, 0);

                     if(backend->state == BACKEND_STATE_UP) {
                            if(mysql_errno(&mysql) == 0) { 
                                   backend->connect_times = 0;
                            } else {
                                   if(backend->connect_times < config->connect_times) {
                                          ++(backend->connect_times);
                                   } else { 
                                          backend->state = BACKEND_STATE_DOWN;
                                          backend->connect_times = 0;
                                   }
                            }
                     } else if(backend->state == BACKEND_STATE_DOWN) {
                            if(mysql_errno(&mysql) == 0) { 
                                   if(backend->connect_times < config->connect_times) {
                                          ++(backend->connect_times);
                                   } else {
                                          backend->state = BACKEND_STATE_UP;
                                          backend->connect_times = 0;
                                   }
                            } else {
                                          backend->connect_times = 0;
                            }
                     } else if(backend->state == BACKEND_STATE_UNKNOWN) {
                            if(mysql_errno(&mysql) == 0) 
                                   backend->state = BACKEND_STATE_UP;
                            else
                                   backend->state = BACKEND_STATE_DOWN;
                     }
                     mysql_close(&mysql);
		}

              sleep(config->check_time);
	}
}

void proxy_plugin_insert_clientips(gchar** arg_string_array, chassis_plugin_config *config) {
        int i, j;
        char* token;
        guint* sum = NULL;
        
        if (config->iptable_index == 0) {
                g_hash_table_remove_all(config->ip_table[1]);
        }else if (config->iptable_index == 1) {
                g_hash_table_remove_all(config->ip_table[0]);
        }
        
        GPtrArray *clientip_vec = srv->clientip_vec;
        if(clientip_vec) {
               for(i = 0; i < clientip_vec->len; i++) {
                      guint *item = clientip_vec->pdata[i];
                      g_free(item);
               }   
        }   
        g_ptr_array_remove_range(clientip_vec, 0, clientip_vec->len);

        for (j = 0; arg_string_array && arg_string_array[j]; j++) {
                arg_string_array[j] = g_strstrip(arg_string_array[j]);
                sum = g_new0(guint, 1); 
                while ((token = strsep(&arg_string_array[j], ".")) != NULL) {
                        *sum = (*sum << 8) + atoi(token);
                }   
                *sum = htonl(*sum);
                if (config->iptable_index == 0) {
                        g_hash_table_add(config->ip_table[1], sum);
                }else if (config->iptable_index == 1) {
                        g_hash_table_add(config->ip_table[0], sum);
                } 
                guint* sum_copy = g_new0(guint, 1);
                *sum_copy = *sum;
                g_ptr_array_add(srv->clientip_vec, sum_copy);
        }
        if (config->iptable_index == 0) 
                g_atomic_int_inc(&(config->iptable_index));
        else if (config->iptable_index == 1) 
                g_atomic_int_dec_and_test(&(config->iptable_index));
}

int proxy_plugin_insert_pwds(gchar** arg_string_array, chassis_plugin_config *config) {
        char *user = NULL, *pwd = NULL;
        gboolean is_complete = FALSE;
        user_password *up;
        int i, j;
        for(i = 0; i < srv->user_vec->len; i++) {
               user_password *item = srv->user_vec->pdata[i];
               g_free(item->user);
               g_free(item->pwd);
               g_free(item);
        }
        if(srv->user_vec->len)
               g_ptr_array_remove_range(srv->user_vec, 0, srv->user_vec->len);
        if (config->pwdtable_index == 0) {
                g_hash_table_remove_all(config->pwd_table[1]);
        }else if(config->pwdtable_index == 1) {
                g_hash_table_remove_all(config->pwd_table[0]);
        }
        for (j = 0; arg_string_array && arg_string_array[j]; j++) {
                if ((user = strsep(&arg_string_array[j], ":")) != NULL) {
                        if ((pwd = strsep(&arg_string_array[j], ":")) != NULL) {
                                is_complete = TRUE;
                        }
                }
                if (is_complete) {
                        char* raw_pwd = pwds_decrypt(pwd);
                        if (raw_pwd) {
                                GString* hashed_password = g_string_new(NULL);
                                network_mysqld_proto_password_hash(hashed_password, raw_pwd, strlen(raw_pwd));
                                if (config->pwdtable_index == 0)
                                        g_hash_table_insert(config->pwd_table[1], user, hashed_password);
                                else if(config->pwdtable_index == 1)
                                       g_hash_table_insert(config->pwd_table[0], user, hashed_password)  ;
                                up = g_new0(user_password, 1);
                                up->user = g_strdup(user);
                                up->pwd = g_strdup(raw_pwd);
                                g_ptr_array_add(srv->user_vec, up);
                                g_free(raw_pwd);
                        } else {
                                g_critical("password decrypt failed");
                                return -1;
                        }
                } else {
                        g_critical("incorrect password settings");
                        return -1;
                }
        }
        if (config->pwdtable_index == 0) 
                g_atomic_int_inc(&(config->pwdtable_index));
        else if (config->pwdtable_index == 1) 
                g_atomic_int_dec_and_test(&(config->pwdtable_index));
        
        return 0;
}

int get_forbidden_sql(GPtrArray *reg_array, char **fsql) {
       int i, ret;
       regex_t *reg = NULL; 
       char ebuf[128];
       if(fsql == NULL) return 0;
       for(i = 0; fsql&&fsql[i]; i++) {
              reg = g_new0(regex_t, 1);
              ret = regcomp(reg, fsql[i], REG_EXTENDED|REG_ICASE|REG_NOSUB|REG_NEWLINE);
              if(ret != 0) {
                     g_free(reg);
                     regerror(ret, reg, ebuf, sizeof(ebuf));
                     g_message("%s:regcomp fail,error message:%s", G_STRLOC, ebuf);
                     return -1;
              }
              g_ptr_array_add(reg_array, reg);
       }
       return 0;
}
/**
 * init the plugin with the parsed config
 */
int network_mysqld_proxy_plugin_apply_config(chassis *chas, chassis_plugin_config *config) {
	network_mysqld_con *con;
	network_socket *listen_sock;
	chassis_private *g = chas->priv;
	guint i;

	if (!config->start_proxy) {
		return 0;
	}

	//if (!config->address) config->address = g_strdup(":4040");
    if (!config->address) {
        g_critical("%s: Failed to get bind address, please set by --proxy-address=<host:port>",
                G_STRLOC);
        return -1; 
    }

	if (!config->backend_addresses) {
		config->backend_addresses = g_new0(char *, 2);
		config->backend_addresses[0] = g_strdup("127.0.0.1:3306");
	}

	/** 
	 * create a connection handle for the listen socket 
	 */
	con = network_mysqld_con_new();
	network_mysqld_add_connection(chas, con);
	con->config = config;

	config->listen_con = con;
	
	listen_sock = network_socket_new();
	con->server = listen_sock;

	/* set the plugin hooks as we want to apply them to the new connections too later */
	network_mysqld_proxy_connection_init(con);

	if (0 != network_address_set_address(listen_sock->dst, config->address)) {
		return -1;
	}

	if (0 != network_socket_bind(listen_sock)) {
		return -1;
	}
	g_message("proxy listening on port %s", config->address);

	for (i = 0; config->backend_addresses && config->backend_addresses[i]; i++) {
		if (-1 == network_backends_add(g->backends, config->backend_addresses[i], BACKEND_TYPE_RW)) {		
			return -1;
		}
	}
	
	for (i = 0; config->read_only_backend_addresses && config->read_only_backend_addresses[i]; i++) {
		if (-1 == network_backends_add(g->backends, config->read_only_backend_addresses[i], BACKEND_TYPE_RO)) {
			return -1;
		}
	}
	for (i = 0; config->master_standby_addresses && config->master_standby_addresses[i]; i++) {
		if (-1 == network_backends_add(g->backends, config->master_standby_addresses[i], BACKEND_TYPE_SY)) {
			return -1;
		}
	}

	for (i = 0; config->client_ips && config->client_ips[i]; i++) {
		guint* sum = g_new0(guint, 1);
              guint* sum_copy = g_new0(guint, 1);
		char* token;
		while ((token = strsep(&config->client_ips[i], ".")) != NULL) {
			*sum = (*sum << 8) + atoi(token);
		}
		*sum = htonl(*sum);
		g_hash_table_add(config->ip_table[0], sum);
              *sum_copy = *sum;
              g_ptr_array_add(srv->clientip_vec, sum_copy); 
	}

	for (i = 0; config->lvs_ips && config->lvs_ips[i]; i++) {
		guint* lvs_ip = g_new0(guint, 1);
		*lvs_ip = inet_addr(config->lvs_ips[i]);
		g_hash_table_add(config->lvs_table, lvs_ip);
	}
	signal(SIGUSR1, handler);
	signal(SIGUSR2, handler);

	if (config->sql_log_type) {
		if (strcasecmp(config->sql_log_type, "ON") == 0) {
			sql_log_type = ON;
		} else if (strcasecmp(config->sql_log_type, "REALTIME") == 0) {
			sql_log_type = REALTIME;
		}
	}

	if (sql_log_type != OFF) {
		gchar* sql_log_filename = g_strdup_printf("%s/sql_%s.log", chas->log_path, chas->instance_name);
		config->sql_log = fopen(sql_log_filename, "a");
		if (config->sql_log == NULL) {
			g_critical("Failed to open %s", sql_log_filename);
			g_free(sql_log_filename);
			return -1;
		}
		g_free(sql_log_filename);
	}
	for (i = 0; config->pwds && config->pwds[i]; i++) {
		char *user = NULL, *pwd = NULL;
              gboolean is_complete = FALSE;
              char *pwds_str = strdup(config->pwds[i]);
		if ((user = strsep(&pwds_str, ":")) != NULL) {
			if ((pwd = strsep(&pwds_str, ":")) != NULL) {
				is_complete = TRUE;
			}
		}

		if (is_complete) {
			char* raw_pwd = pwds_decrypt(pwd);
			if (raw_pwd) {
				GString* hashed_password = g_string_new(NULL);
				network_mysqld_proto_password_hash(hashed_password, raw_pwd, strlen(raw_pwd));

				g_hash_table_insert(config->pwd_table[0], user, hashed_password);
                            user_password *up = g_new0(user_password, 1);
                            up->user = g_strdup(user);
                            up->pwd = g_strdup(raw_pwd);
                            g_ptr_array_add(srv->user_vec, up);
                            g_free(raw_pwd);
			} else {
				g_critical("password decrypt failed");
				return -1;
			}
		} else {
			g_critical("incorrect password settings");
			return -1;
		}
	}
       if( 0 != get_forbidden_sql(config->reg_array, config->fsql)) {
              g_message("%s:get_forbidden_sql error", G_STRLOC);
              return -1;
       }

	/* load the script and setup the global tables */
	network_mysqld_lua_setup_global(chas->priv->sc->L, g, chas);

	/**
	 * call network_mysqld_con_accept() with this connection when we are done
	 */

	event_set(&(listen_sock->event), listen_sock->fd, EV_READ|EV_PERSIST, network_mysqld_con_accept, con);
	event_base_set(chas->event_base, &(listen_sock->event));
	event_add(&(listen_sock->event), NULL);

	g_thread_create((GThreadFunc)check_state, chas, FALSE, NULL);

	return 0;
}

/*get the shard rule from GKeyFile, and insert the shard rule into a hashtable*/
int proxy_plugin_get_shard_rules(GKeyFile *keyfile, chassis *chas, chassis_plugin_config *config) {
       GError *gerr = NULL;
       gchar **groups, **gname, *table_name;
       shard_rule *item = NULL;
       gsize length;
       int i, j;

       network_backends_t *bs = chas->priv->backends;
       groups = g_key_file_get_groups(keyfile, &length);
       for(i = 0; i < length; i++) {
              gname = g_strsplit(groups[i], "-", 2);
              if(strcasecmp(gname[0], "mysql") == 0) continue;
              item = shard_rule_new();
              keyfile_to_shard_rule(keyfile, gname[0], item);
              get_shard_backend(bs, item);
              if(strcasecmp(gname[0], "range") == 0) {
                     gint64 step = item->range_end / item->table_sum;
                     for(j = 0; j < item->table_sum; j++) {
                            gint64 boundary = step * (j+1) - 1;
                            g_array_append_val(item->range_value_array, boundary);
                     }
                     item->shard_type = RANGE;
              } else if(strcasecmp(gname[0], "hash") == 0) {
                     item->shard_type = HASH;
              } else if(strcasecmp(gname[0], "year") == 0) {
                     item->shard_type = YEAR;
              } else if(strcasecmp(gname[0], "month") == 0) {
                     item->shard_type = MONTH;
              } else if(strcasecmp(gname[0], "week") == 0) {
                     item->shard_type = WEEK;
              }
              table_name = g_strdup(item->shard_table);
              g_hash_table_insert(config->rule_table, table_name, item);
              g_strfreev(gname);
       }
       g_strfreev(groups);
       return 0;
}

G_MODULE_EXPORT int plugin_init(chassis_plugin *p) {
	p->magic        = CHASSIS_PLUGIN_MAGIC;
	p->name         = g_strdup("proxy");
	p->version		= g_strdup(PACKAGE_VERSION);

	p->init         = network_mysqld_proxy_plugin_new;
	p->get_options  = network_mysqld_proxy_plugin_get_options;
	p->apply_config = network_mysqld_proxy_plugin_apply_config;
	p->destroy      = network_mysqld_proxy_plugin_free;
       p->insert_clientips = proxy_plugin_insert_clientips;
       p->insert_pwds = proxy_plugin_insert_pwds;
       p->get_shard_rules = proxy_plugin_get_shard_rules;
	return 0;
}

