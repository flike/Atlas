/* $%BEGINLICENSE%$
 Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.

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

#include <stdlib.h> 
#include <string.h>
#include <openssl/evp.h>

#include <glib.h>

#include "network-mysqld-packet.h"
#include "network-backend.h"
#include "chassis-plugin.h"
#include "chassis-mainloop.h"
#include "network-conn-pool-lua.h"
#include "glib-ext.h"

#define C(x) x, sizeof(x) - 1
#define S(x) x->str, x->len

network_backend_t *network_backend_new(guint event_thread_count) {
	network_backend_t *b;

	b = g_new0(network_backend_t, 1);

//	b->pool = network_connection_pool_new();
	b->pools = g_ptr_array_new();
	guint i;
	for (i = 0; i <= event_thread_count; ++i) {
		network_connection_pool* pool = network_connection_pool_new();
		g_ptr_array_add(b->pools, pool);
	}

	b->uuid = g_string_new(NULL);
	b->addr = network_address_new();

	return b;
}

void network_backend_free(network_backend_t *b) {
	if (!b) return;

	guint i;
	for (i = 0; i < b->pools->len; ++i) {
		network_connection_pool* pool = g_ptr_array_index(b->pools, i);
		network_connection_pool_free(pool);
	}
	g_ptr_array_free(b->pools, TRUE);

	if (b->addr)     network_address_free(b->addr);
	if (b->uuid)     g_string_free(b->uuid, TRUE);

	g_free(b);
}

network_backends_t *network_backends_new(guint event_thread_count, gchar* config_path) {
	network_backends_t *bs;

	bs = g_new0(network_backends_t, 1);

	bs->backends = g_ptr_array_new();
	bs->backends_mutex = g_mutex_new();	/*remove lock*/
	bs->global_wrr = g_wrr_poll_new();
	bs->event_thread_count = event_thread_count;
       bs->config_path = g_strdup(config_path);
       bs->recycle_backends = g_ptr_array_new();

	return bs;
}

g_wrr_poll *g_wrr_poll_new() {
    g_wrr_poll *global_wrr;

    global_wrr = g_new0(g_wrr_poll, 1);

    global_wrr->max_weight = 0;
    global_wrr->cur_weight = 0;
    global_wrr->next_ndx = 0;
    
    return global_wrr;
}

void g_wrr_poll_free(g_wrr_poll *global_wrr) {
    g_free(global_wrr);
}

void network_backends_free(network_backends_t *bs) {
	gsize i;

	if (!bs) return;

	g_mutex_lock(bs->backends_mutex);	/*remove lock*/
	for (i = 0; i < bs->backends->len; i++) {
		network_backend_t *backend = bs->backends->pdata[i];
		
		network_backend_free(backend);
	}
	g_mutex_unlock(bs->backends_mutex);	/*remove lock*/

	g_ptr_array_free(bs->backends, TRUE);
        for (i = 0; i < bs->recycle_backends->len; i++) {
                network_backend_t * b = g_ptr_array_index(bs->recycle_backends, i);  
                network_backend_free(b);
        }    
        g_ptr_array_free(bs->recycle_backends, TRUE);  
	
        g_mutex_free(bs->backends_mutex);	/*remove lock*/
        g_free(bs->config_path);
        g_wrr_poll_free(bs->global_wrr);
        g_free(bs);
}

int network_backends_remove(network_backends_t *bs, guint index) {
        int ret;
        g_mutex_lock(bs->backends_mutex);
        ret = network_backends_remove_unlock(bs, index);
        g_mutex_unlock(bs->backends_mutex);
        return ret;
}

int network_backends_remove_unlock(network_backends_t *bs, guint index) {
        int i;
        network_backend_t* item = NULL;
        if (index >= bs->backends->len) {
                g_message("%s:network_backends_remove error,the index is out the length of array", G_STRLOC);
                return -1;
        }
        item = g_ptr_array_index(bs->backends, index);
        if (item != NULL) {
                if (item->connected_clients == 0) {
                        network_backend_free(item);
                        g_ptr_array_remove_index(bs->backends, index);
                } else if (item->connected_clients > 0) {
                        for (i = 0; i < bs->recycle_backends->len; i++) {
                                network_backend_t * b = g_ptr_array_index(bs->recycle_backends, i);
                                if (b->connected_clients == 0) {
                                        network_backend_free(b);
                                        g_ptr_array_remove_index(bs->recycle_backends, i);
                                }
                        }
                        g_ptr_array_add(bs->recycle_backends, item);
                        g_ptr_array_remove_index(bs->backends, index);
                } else {
                        g_message("%s:network_backends_remove error, connected_clients less than 0", G_STRLOC);
                }
        }
        return 0;
}

int network_backends_add(network_backends_t *bs, gchar *address, backend_type_t type) {
        int ret;
        g_mutex_lock(bs->backends_mutex);
        ret = network_backends_add_unlock(bs, address, type);
        g_mutex_unlock(bs->backends_mutex);
        return ret;
}
/*
 * FIXME: 1) remove _set_address, make this function callable with result of same
 *        2) differentiate between reasons for "we didn't add" (now -1 in all cases)
 */
int network_backends_add_unlock(network_backends_t *bs, /* const */ gchar *address, backend_type_t type) {
	network_backend_t *new_backend;
	guint i;

	new_backend = network_backend_new(bs->event_thread_count);
	new_backend->type = type;

	if (type == BACKEND_TYPE_RO) {
		guint weight = 1;
		gchar *p = strrchr(address, '@');
		if (p != NULL) {
			*p = '\0';
			weight = atoi(p+1);
		}
		new_backend->weight = weight;
	}

	if (0 != network_address_set_address(new_backend->addr, address)) {
		network_backend_free(new_backend);
		return -1;
	}

	/* check if this backend is already known */
	//g_mutex_lock(bs->backends_mutex);	/*remove lock*/
	gint first_slave = -1;
	for (i = 0; i < bs->backends->len; i++) {
		network_backend_t *old_backend = bs->backends->pdata[i];
		if (first_slave == -1 && old_backend->type == BACKEND_TYPE_RO) first_slave = i;
		if (old_backend->type == type && strleq(S(old_backend->addr->name), S(new_backend->addr->name))) {
			network_backend_free(new_backend);
			//g_mutex_unlock(bs->backends_mutex);	/*remove lock*/
			g_critical("backend %s is already known!", address);
			return -1;
		}
	}
	g_ptr_array_add(bs->backends, new_backend);
	if (first_slave != -1 && type == BACKEND_TYPE_RW) {
		network_backend_t *temp_backend = bs->backends->pdata[first_slave];
		bs->backends->pdata[first_slave] = bs->backends->pdata[bs->backends->len - 1];
		bs->backends->pdata[bs->backends->len - 1] = temp_backend;
	}
	//g_mutex_unlock(bs->backends_mutex);	/*remove lock*/
        if (type == BACKEND_TYPE_RW)
                g_message("added %s backend: %s","read/write",address);
        else if (type == BACKEND_TYPE_RO)
                g_message("added %s backend: %s","read-only",address);
        else
                g_message("added %s backend: %s","master-standby",address);

	return 0;
}

network_backend_t *network_backends_get(network_backends_t *bs, guint ndx) {
        network_backend_t *item = NULL;
        g_mutex_lock(bs->backends_mutex);       /*remove lock*/         
        if (ndx < bs->backends->len) 
                item = bs->backends->pdata[ndx];
        g_mutex_unlock(bs->backends_mutex);     /*remove lock*/
        return item;
}

guint network_backends_count(network_backends_t *bs) {
	guint len;

	g_mutex_lock(bs->backends_mutex);	/*remove lock*/
	len = bs->backends->len;
	g_mutex_unlock(bs->backends_mutex);	/*remove lock*/

	return len;
}

network_backend_t* network_get_backend_by_type(network_backends_t *bs, backend_type_t type) {
        int i, len;
        network_backend_t *item = NULL;
        g_mutex_lock(bs->backends_mutex);
        len = bs->backends->len;
        for (i = 0; i < len; i++) {
                item = bs->backends->pdata[i];
                if (item->type == type) {
                        g_mutex_unlock(bs->backends_mutex);
                        return item;
                }
        }
        g_mutex_unlock(bs->backends_mutex);
        return NULL;
}

network_backend_t* network_get_backend_by_addr(network_backends_t *bs, char* addr) {
       int i, len;
       char **gname;
       network_backend_t *item = NULL;
       g_mutex_lock(bs->backends_mutex);
       len = bs->backends->len;
       for (i = 0; i < len; i++) {
              item = bs->backends->pdata[i];
              gname = g_strsplit(item->addr->name->str, ":", 2); 
              if (strcmp(gname[0], addr) == 0) {
                     g_mutex_unlock(bs->backends_mutex);
                     g_strfreev(gname);
                     return item;
              }   
              g_strfreev(gname);
       }   
       g_mutex_unlock(bs->backends_mutex);
       return NULL;
}

void copy_key(gchar *key, GString *value, GHashTable *new_table) {
       gchar *new_key = g_strdup(key);
       GString *new_value = g_string_new(value->str);
       g_hash_table_insert(new_table, new_key, new_value);
}

int network_backends_add_pwds(chassis *srv, gchar *pwds) {
       int i, j;
       gchar **pwds_vec, **user_pwd;
       chassis_plugin *p = srv->modules->pdata[1];/*proxy plugin*/
       chassis_plugin_config *config = p->config;
       GHashTable *new_table = config->pwd_table[1 - config->pwdtable_index];
       GHashTable *old_table = config->pwd_table[config->pwdtable_index];
       user_password *up;
       
       g_hash_table_remove_all(new_table);
       g_hash_table_foreach(old_table, copy_key, new_table);
       pwds_vec = g_strsplit(pwds, ",", 50);
       for (j = 0; pwds_vec && pwds_vec[j]; j++) {
              user_pwd = g_strsplit(pwds_vec[j], ":", 2);
              if(!user_pwd[0] || !user_pwd[1]) {
                     g_critical("%s:incorrect password settings", G_STRLOC);
                     g_strfreev(pwds_vec);
                     return -1;
              }
              GString* hashed_password = g_string_new(NULL);
              user_pwd[0] = g_strstrip(user_pwd[0]);
              user_pwd[1] = g_strstrip(user_pwd[1]);
              network_mysqld_proto_password_hash(hashed_password, user_pwd[1], strlen(user_pwd[1]));
              g_hash_table_insert(new_table, user_pwd[0], hashed_password);
              up = g_new0(user_password, 1);
              up->user = g_strdup(user_pwd[0]);
              up->pwd = g_strdup(user_pwd[1]);
              g_ptr_array_add(srv->user_vec, up);
       }
       g_strfreev(pwds_vec);

       if(config->pwdtable_index == 0) 
              g_atomic_int_inc(&(config->pwdtable_index));
       else if(config->pwdtable_index == 1) 
              g_atomic_int_dec_and_test(&(config->pwdtable_index));
       
       return 0;
}

int network_backends_remove_pwds(chassis *srv, gchar *users) {
       int i, j;
       gboolean is_delete = FALSE;
       gchar **users_vec;
       
       chassis_plugin *p = srv->modules->pdata[1];/*proxy plugin*/
       chassis_plugin_config *config = p->config;
       GHashTable *new_table = config->pwd_table[1 - config->pwdtable_index];
       GHashTable *old_table = config->pwd_table[config->pwdtable_index];
       
       g_hash_table_remove_all(new_table);
       g_hash_table_foreach(old_table, copy_key, new_table);
       users_vec = g_strsplit(users, ",", 50);
       for(j = 0; users_vec && users_vec[j]; j++) {
              is_delete = g_hash_table_remove(new_table, users_vec[j]);
              if(is_delete == FALSE) g_message("%s:delete %s from pwd_table failed", G_STRLOC, users_vec[j]);
              for(i = 0; i < srv->user_vec->len; i++) {
                     user_password *up = srv->user_vec->pdata[i];
                     if(strcmp(up->user, users_vec[j]) == 0) {
                            g_free(up->user);
                            g_free(up->pwd);
                            g_free(up);
                            g_ptr_array_remove_index(srv->user_vec, i);
                     }
              }
       }
       g_strfreev(users_vec);
       
       if(config->pwdtable_index == 0) 
              g_atomic_int_inc(&(config->pwdtable_index));
       else if(config->pwdtable_index == 1) 
              g_atomic_int_dec_and_test(&(config->pwdtable_index));

       return 0;
}

int network_pwds_save_config(GKeyFile* keyfile, GPtrArray* user_vec, gchar* config_path) {
       int i;
       char *password;
       user_password *up;
       GString *pwds = g_string_new(NULL);
       
       for(i = 0; i < user_vec->len; i++) {
              up = user_vec->pdata[i];
              g_string_append(pwds, up->user);
              g_string_append(pwds, ":");
              password = pwds_encrypt(up->pwd);
              if(password) {
                     g_string_append(pwds, password);
                     g_free(password);
              }
              g_string_append(pwds, ",");
       }
       
       g_string_erase(pwds, pwds->len - 1, 1); /*erase the last comma*/
       g_key_file_set_string(keyfile, "mysql-proxy", "pwds", pwds->str);
       g_string_free(pwds, TRUE);
       
       return 0;
}

gchar* ip_to_str(guint ip) {
       int i;
       guint ip_seg[4];
       gchar *buf = g_new0(gchar, 64);
       guint value = ntohl(ip);
       for(i = 3; 0 <= i; i--) {
              ip_seg[i] = value % 256;
              value = (value - ip_seg[i]) / 256;
       }   
       sprintf(buf, "%d.%d.%d.%d", ip_seg[0], ip_seg[1], ip_seg[2], ip_seg[3]);
       return buf;
}

int network_clientip_save_config(GKeyFile* keyfile, GPtrArray *clientip_vec, gchar* config_path) {
       int i;
       gchar *addr;
       guint ip_num;
       GString *client_ip_str = g_string_new(NULL);
       
       for(i = 0; i < clientip_vec->len; i++) {
              ip_num = *(guint*)clientip_vec->pdata[i];
              addr = ip_to_str(ip_num);
              g_string_append(client_ip_str, addr);
              g_string_append(client_ip_str, ",");
              g_free(addr);
       }
       
       g_string_erase(client_ip_str, client_ip_str->len - 1, 1); /*erase the last comma*/
       g_key_file_set_string(keyfile, "mysql-proxy", "client-ips", client_ip_str->str);
       g_string_free(client_ip_str, TRUE);
       
       return 0;
}

int network_backends_save_config(GKeyFile* keyfile, network_backends_t *bs, gchar* config_path) {
        int i, len, first_append_master = 1, first_append_slave = 1, first_append_standby = 1;
        network_backend_t *backend;
        GString *master, *slave, *standby;

        master = g_string_new(NULL);
        slave = g_string_new(NULL);
        standby = g_string_new(NULL);
        
        g_mutex_lock(bs->backends_mutex);
        len = bs->backends->len;
        for (i = 0; i < len; i++) {
                backend = g_ptr_array_index(bs->backends, i);
                if (backend->type == BACKEND_TYPE_RW) {
                        if (first_append_master) {
                                g_string_append(master, backend->addr->name->str);
                                first_append_master = 0;
                        } else {
                                g_string_append_c(master, ',');
                                g_string_append(master, backend->addr->name->str);
                        }
                } else if (backend->type == BACKEND_TYPE_RO) {
                        if (first_append_slave) {
                                g_string_append(slave, backend->addr->name->str);
                                first_append_slave = 0;
                        } else {
                                g_string_append_c(slave, ',');
                                g_string_append(slave, backend->addr->name->str);
                        }
                } else if (backend->type == BACKEND_TYPE_SY) {
                        if (first_append_standby) {
                                g_string_append(standby, backend->addr->name->str);
                                first_append_standby = 0;
                        } else {
                                g_string_append_c(standby, ',');
                                g_string_append(standby, backend->addr->name->str);
                        }
                }
        }
        g_mutex_unlock(bs->backends_mutex);

        if (master->len != 0)
                g_key_file_set_string(keyfile, "mysql-proxy", "proxy-backend-addresses", master->str);
        else
                g_key_file_set_string(keyfile, "mysql-proxy", "proxy-backend-addresses", "");

        if (slave->len != 0)
                g_key_file_set_string(keyfile, "mysql-proxy", "proxy-read-only-backend-addresses", slave->str);
        else
                g_key_file_set_string(keyfile, "mysql-proxy", "proxy-read-only-backend-addresses", "");

        if (standby->len != 0)
                g_key_file_set_string(keyfile, "mysql-proxy", "proxy-master-standby-address", standby->str);
        else
                g_key_file_set_string(keyfile, "mysql-proxy", "proxy-master-standby-address", "");
        
        g_string_free(master, TRUE);
        g_string_free(slave, TRUE);
        g_string_free(standby, TRUE);
        
        return 0;
}

int network_save_config(chassis *chas) {
       int file_size = 0;
       GKeyFile* keyfile;
       GError *gerr = NULL;
       gchar* file_buf = NULL;
       gchar* config_path = chas->priv->backends->config_path;

       keyfile = g_key_file_new();
       g_key_file_set_list_separator(keyfile, ',');
       if (FALSE == g_key_file_load_from_file(keyfile, config_path, G_KEY_FILE_NONE, NULL)) {
              g_message("%s:load %s error,load config file failed", G_STRLOC, config_path);
              g_key_file_free(keyfile);
              return -1;
       }
       
       network_backends_save_config(keyfile, chas->priv->backends, config_path);
       network_clientip_save_config(keyfile, chas->clientip_vec, config_path);
       network_pwds_save_config(keyfile, chas->user_vec, config_path);

       file_buf = g_key_file_to_data(keyfile, &file_size, &gerr);
       if (file_buf) {
              if (FALSE == g_file_set_contents(config_path, file_buf, file_size, &gerr)) {
                     g_message("%s:g_file_set_contents, gerr is:%s", G_STRLOC, gerr->message);
                     g_error_free(gerr);
                     gerr = NULL;
                     g_message("%s:save to config failure", G_STRLOC);
              } else {
                     g_message("%s:save to config success", G_STRLOC);
              }
              g_free(file_buf);
       } else {
              g_message("%s:save to config failure", G_STRLOC); 
       }
       g_key_file_free(keyfile);
       
       return 0;
}

char* pwds_decrypt(char* in) {
        //1. Base64解码
       EVP_ENCODE_CTX dctx;
       EVP_DecodeInit(&dctx);

       int inl = strlen(in);
       unsigned char inter[512] = {};
       int interl = 0;

       if (EVP_DecodeUpdate(&dctx, inter, &interl, in, inl) == -1) return NULL;
       int len = interl;
       if (EVP_DecodeFinal(&dctx, inter+len, &interl) != 1) return NULL;
       len += interl;

       //2. DES解码
       EVP_CIPHER_CTX ctx;
       EVP_CIPHER_CTX_init(&ctx);
       const EVP_CIPHER* cipher = EVP_des_ecb();

       unsigned char key[] = "aCtZlHaUs";
       if (EVP_DecryptInit_ex(&ctx, cipher, NULL, key, NULL) != 1) return NULL;

       char* out = g_malloc0(512);
       int outl = 0;

       if (EVP_DecryptUpdate(&ctx, out, &outl, inter, len) != 1) {
              g_free(out);
              return NULL;
       }
       len = outl;
       if (EVP_DecryptFinal_ex(&ctx, out+len, &outl) != 1) {
              g_free(out);
              return NULL;
       }
       len += outl;

       EVP_CIPHER_CTX_cleanup(&ctx);

       out[len] = '\0';
       return out;
}

char* pwds_encrypt(char *in) {
       EVP_CIPHER_CTX ctx;
       const EVP_CIPHER* cipher = EVP_des_ecb();
       unsigned char key[] = "aCtZlHaUs";
       int i, LEN = 1024;
       unsigned char *out;

       out = g_new0(unsigned char, 1024);
       //1. DES加密
       EVP_CIPHER_CTX_init(&ctx);
       if (EVP_EncryptInit_ex(&ctx, cipher, NULL, key, NULL) != 1) {
              g_message("%s:加密初始化错误", G_STRLOC);
              g_free(out);
              return NULL;
       }

       int inl = strlen(in);
       unsigned char inter[LEN];
       bzero(inter, LEN);
       int interl = 0;

       if (EVP_EncryptUpdate(&ctx, inter, &interl, in, inl) != 1) {
              g_message("%s:加密更新错误", G_STRLOC);
              g_free(out);
              return NULL;
       }
       int len = interl;
       if (EVP_EncryptFinal_ex(&ctx, inter+len, &interl) != 1) {
              g_message("%s:加密结束错误", G_STRLOC);
              g_free(out);
              return NULL;
       }
       len += interl;
       EVP_CIPHER_CTX_cleanup(&ctx);

       //2. Base64编码
       EVP_ENCODE_CTX ectx;
       EVP_EncodeInit(&ectx);

       int outl = 0;
       EVP_EncodeUpdate(&ectx, out, &outl, inter, len);
       len = outl;
       EVP_EncodeFinal(&ectx, out+len, &outl);
       len += outl;

       if (out[len-1] == 10) out[len-1] = '\0';
       
       return out;
}
