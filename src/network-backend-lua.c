/* $%BEGINLICENSE%$
 Copyright (c) 2008, 2009, Oracle and/or its affiliates. All rights reserved.

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
#include <lua.h>

#include "lua-env.h"
#include "glib-ext.h"

#define C(x) x, sizeof(x) - 1
#define S(x) x->str, x->len

#include "network-backend.h"
#include "network-mysqld.h"
#include "network-conn-pool-lua.h"
#include "network-backend-lua.h"
#include "network-address-lua.h"
#include "network-mysqld-lua.h"
#include "chassis-mainloop.h"
#include "network-mysqld-proto.h"

extern chassis *srv;
/**
 * get the info about a backend
 *
 * proxy.backend[0].
 *   connected_clients => clients using this backend
 *   address           => ip:port or unix-path of to the backend
 *   state             => int(BACKEND_STATE_UP|BACKEND_STATE_DOWN)
 *   type              => int(BACKEND_TYPE_RW|BACKEND_TYPE_RO)
 *
 * @return nil or requested information
 * @see backend_state_t backend_type_t
 */
static int proxy_backend_get(lua_State *L) {
	network_backend_t *backend = *(network_backend_t **)luaL_checkself(L);
	gsize keysize = 0;
	const char *key = luaL_checklstring(L, 2, &keysize);

	if (strleq(key, keysize, C("connected_clients"))) {
		lua_pushinteger(L, backend->connected_clients);
	} else if (strleq(key, keysize, C("dst"))) {
		network_address_lua_push(L, backend->addr);
	} else if (strleq(key, keysize, C("state"))) {
		lua_pushinteger(L, backend->state);
	} else if (strleq(key, keysize, C("type"))) {
		lua_pushinteger(L, backend->type);
	} else if (strleq(key, keysize, C("uuid"))) {
		if (backend->uuid->len) {
			lua_pushlstring(L, S(backend->uuid));
		} else {
			lua_pushnil(L);
		}
	} else if (strleq(key, keysize, C("weight"))) {
		lua_pushinteger(L, backend->weight);
	} else {
		lua_pushnil(L);
	}

	return 1;
}

static int proxy_backend_set(lua_State *L) {
	network_backend_t *backend = *(network_backend_t **)luaL_checkself(L);
	gsize keysize = 0;
	const char *key = luaL_checklstring(L, 2, &keysize);

	if (strleq(key, keysize, C("state"))) {
		backend->state = lua_tointeger(L, -1);
	} else if (strleq(key, keysize, C("uuid"))) {
		if (lua_isstring(L, -1)) {
			size_t s_len = 0;
			const char *s = lua_tolstring(L, -1, &s_len);

			g_string_assign_len(backend->uuid, s, s_len);
		} else if (lua_isnil(L, -1)) {
			g_string_truncate(backend->uuid, 0);
		} else {
			return luaL_error(L, "proxy.global.backends[...].%s has to be a string", key);
		}
	} else {
		return luaL_error(L, "proxy.global.backends[...].%s is not writable", key);
	}
	return 1;
}


int network_backend_lua_getmetatable(lua_State *L) {
	static const struct luaL_reg methods[] = {
		{ "__index", proxy_backend_get },
		{ "__newindex", proxy_backend_set },
		{ NULL, NULL },
	};

	return proxy_getmetatable(L, methods);
}

/**
 * get proxy.global.backends[ndx]
 *
 * get the backend from the array of mysql backends.
 *
 * @return nil or the backend
 * @see proxy_backend_get
 */
static int proxy_backends_get(lua_State *L) {
	network_backend_t *backend;
	network_backend_t **backend_p;

	network_backends_t *bs = *(network_backends_t **)luaL_checkself(L);
	int backend_ndx = luaL_checkinteger(L, 2) - 1; /** lua is indexes from 1, C from 0 */

	/* check that we are in range for a _int_ */
	if (NULL == (backend = network_backends_get(bs, backend_ndx))) {
		lua_pushnil(L);

		return 1;
	}

	backend_p = lua_newuserdata(L, sizeof(backend)); /* the table underneath proxy.global.backends[ndx] */
	*backend_p = backend;

	network_backend_lua_getmetatable(L);
	lua_setmetatable(L, -2);

	return 1;
}
gchar* convert_pwds(const gchar* pwds) {
       gchar **vec, *password, *ret_str;
       GString* user_pwds = g_string_new(NULL);
       vec = g_strsplit(pwds, ":", 2);
       if(vec && vec[0] && vec[1]) {
              password = pwds_decrypt(vec[1]);
              g_string_append(user_pwds, vec[0]);
              g_string_append(user_pwds, ":");
              g_string_append(user_pwds, password);
              ret_str = g_strdup(user_pwds->str);
              g_free(password);
       } else {
              ret_str = g_strdup(pwds);
       }
       g_strfreev(vec);
       g_string_free(user_pwds, TRUE);
       return ret_str;
}
/**
 * set proxy.global.backends.addslave
 *
 * add slave server into mysql backends
 *
 * @return nil or the backend
 */
static int proxy_backends_set(lua_State *L) {
	network_backends_t *bs = *(network_backends_t **)luaL_checkself(L);
	gsize keysize = 0;
	const char *key = luaL_checklstring(L, 2, &keysize);

	if (strleq(key, keysize, C("addslave"))) {
        	network_backends_add(bs, g_strdup(lua_tostring(L, -1)), BACKEND_TYPE_RO);
	} else if (strleq(key, keysize, C("addmaster"))) {
        	network_backends_add(bs, g_strdup(lua_tostring(L, -1)), BACKEND_TYPE_RW);
       } else if (strleq(key, keysize, C("changemaster"))) {
              change_standby_to_master(bs);
	} else if (strleq(key, keysize, C("addstandby"))) {
        	network_backends_add(bs, g_strdup(lua_tostring(L, -1)), BACKEND_TYPE_SY);
	} else if (strleq(key, keysize, C("removebackend"))) {
        	network_backends_remove(bs, lua_tointeger(L, -1));
	} else if (strleq(key, keysize, C("addpwds"))) {
              gchar* pwds = g_strdup(lua_tostring(L, -1));
        	network_backends_add_pwds(srv, pwds);
              g_free(pwds);
	} else if (strleq(key, keysize, C("addenpwds"))) {
                gchar* enpwds = convert_pwds(lua_tostring(L, -1));
                network_backends_add_pwds(srv, enpwds);
                g_free(enpwds);
	} else if (strleq(key, keysize, C("removepwds"))) {
              gchar* users = g_strdup(lua_tostring(L, -1));
        	network_backends_remove_pwds(srv, users);
              g_free(users);
	} else if (strleq(key, keysize, C("saveconfig"))) {
                network_save_config(srv);
       } else {
		return luaL_error(L, "proxy.global.backends.%s is not writable", key);
	}
	return 1;
}
static int proxy_backends_len(lua_State *L) {
	network_backends_t *bs = *(network_backends_t **)luaL_checkself(L);

	lua_pushinteger(L, network_backends_count(bs));

	return 1;
}

guint ipstr_to_value(gchar *ipstr) {
       int i;
       guint sum = 0;
       gchar **ip_seg = g_strsplit(ipstr, ".", 4);
       for(i = 0; ip_seg && ip_seg[i]; i++) {
              sum = (sum << 8) + atoi(ip_seg[i]);
       }
       sum = htonl(sum);
       g_strfreev(ip_seg);

       return sum;
}

int proxy_item_exist(lua_State *L) {
       int exist = 0;
       gsize keysize = 0;
       chassis_plugin *p = srv->modules->pdata[1];/*proxy plugin*/
       chassis_plugin_config *config = p->config;
       GHashTable *pwd_table = config->pwd_table[config->pwdtable_index];
       GHashTable *ip_table = config->pwd_table[config->iptable_index];
	network_backends_t *bs = *(network_backends_t **)luaL_checkself(L);
	gchar *key = luaL_checklstring(L, 2, &keysize);
       if(strchr(key, '.') == NULL) {
              gchar **pwds = g_strsplit(key, ":", 2);
              if(pwds && pwds[0]) {
                     if(NULL == g_hash_table_lookup(pwd_table, pwds[0]))
                            exist = 0;
                     else
                            exist = 1;
              }
              g_strfreev(pwds);
       }else {
              guint sum = ipstr_to_value(key);
              if(g_hash_table_contains(ip_table, &sum) == FALSE)
                     exist = 0;
              else
                     exist = 1;
       }
       lua_pushinteger(L, exist);
       return 1;
}

int network_backends_lua_getmetatable(lua_State *L) {
	static const struct luaL_reg methods[] = {
		{ "__index", proxy_backends_get },
		{ "__newindex", proxy_backends_set },
                {"__call", proxy_item_exist },
		{ "__len", proxy_backends_len },
		{ NULL, NULL },
	};

	return proxy_getmetatable(L, methods);
}

int proxy_user_vec_get(lua_State *L) {
       user_password *user_pwd;
       user_password **user_pwd_p;
	GPtrArray *user_vec = *(GPtrArray **)luaL_checkself(L);
	int user_ndx = luaL_checkinteger(L, 2) - 1; /** lua is indexes from 1, C from 0 */

	if (user_ndx < 0 || user_ndx >= user_vec->len ) {
		lua_pushnil(L);
		return 1;
	} else {
              user_pwd = user_vec->pdata[user_ndx];
       }
	user_pwd_p = lua_newuserdata(L, sizeof(user_password *)); /* the table underneath proxy.global.user_vec[ndx] */
	*user_pwd_p = user_pwd;

	network_user_password_lua_getmetatable(L);
	lua_setmetatable(L, -2);

	return 1;
}

int proxy_user_vec_len(lua_State *L) {
       GPtrArray *user_vec = *(GPtrArray **)luaL_checkself(L);
	lua_pushinteger(L, user_vec->len);

	return 1;
}

int network_user_vec_lua_getmetatable(lua_State *L) {
       static const struct luaL_reg methods[] = {
              {"__index", proxy_user_vec_get },
              {"__len", proxy_user_vec_len },
              {NULL, NULL },
       };

       return proxy_getmetatable(L, methods);
}

int proxy_user_password_get(lua_State *L) {
	user_password *user_pwd = *(user_password **)luaL_checkself(L);
	gsize keysize = 0;
	const char *key = luaL_checklstring(L, 2, &keysize);

	if (strleq(key, keysize, C("user"))) {
              lua_pushlstring(L, user_pwd->user, strlen(user_pwd->user));
	} else if (strleq(key, keysize, C("pwd"))) {
                char* enpwds = pwds_encrypt(user_pwd->pwd);
                lua_pushlstring(L, enpwds, strlen(enpwds));
                g_free(enpwds);
	} else {
		lua_pushnil(L);
	}

	return 1;
}

int network_user_password_lua_getmetatable(lua_State *L) {
       static const struct luaL_reg methods[] = {
              {"__index", proxy_user_password_get },
              {NULL, NULL },
       };

       return proxy_getmetatable(L, methods);
}

int proxy_clientip_get(lua_State *L) {
	GPtrArray *clientip_vec = *(GPtrArray **)luaL_checkself(L);
	int clientip_ndx = luaL_checkinteger(L, 2) - 1; /** lua is indexes from 1, C from 0 */

	if (clientip_ndx < 0 || clientip_ndx >= clientip_vec->len ) {
		lua_pushnil(L);
		return 1;
	} else {
              guint ip = *(guint*)clientip_vec->pdata[clientip_ndx];
              gchar *addr = ip_to_str(ip);
              lua_pushlstring(L, addr, strlen(addr));
              g_free(addr);
       }
	return 1;
}

int proxy_clientip_vec_len(lua_State *L) {
       GPtrArray *clientip_vec = *(GPtrArray **)luaL_checkself(L);
	lua_pushinteger(L, clientip_vec->len);

	return 1;
}

int network_clientip_vec_lua_getmetatable(lua_State *L) {
       static const struct luaL_reg methods[] = {
              {"__index", proxy_clientip_get },
              {"__len", proxy_clientip_vec_len },
              {NULL, NULL },
       };

       return proxy_getmetatable(L, methods);
}
