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

#include <glib.h>

#include "network-mysqld-packet.h"
#include "network-backend.h"
#include "chassis-plugin.h"
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

network_backend_t* network_standby_backend_get(network_backends_t *bs) {
        int i, len;
        network_backend_t *item = NULL;
        g_mutex_lock(bs->backends_mutex);
        len = bs->backends->len;
        for (i = 0; i < len; i++) {
                item = bs->backends->pdata[i];
                if (item->type == BACKEND_TYPE_SY) {
                        g_mutex_unlock(bs->backends_mutex);
                        return item;
                }
        }
        g_mutex_unlock(bs->backends_mutex);
        return NULL;
}

int network_backends_save_to_config(network_backends_t *bs, gchar* config_path) {
        int i, len, file_size = 0, first_append_master = 1, first_append_slave = 1, first_append_standby = 1;
        GKeyFile* keyfile;
        network_backend_t *backend;
        GString *master, *slave, *standby;
        GError *gerr = NULL;
        gchar* file_buf = NULL;

        master = g_string_new(NULL);
        slave = g_string_new(NULL);
        standby = g_string_new(NULL);
        keyfile = g_key_file_new();
        g_key_file_set_list_separator(keyfile, ',');
        if (FALSE == g_key_file_load_from_file(keyfile, config_path, G_KEY_FILE_NONE, NULL)) {
                g_message("%s:load %s error,load config file failed", G_STRLOC, config_path);
                g_string_free(master, TRUE);
                g_string_free(slave, TRUE);
                g_string_free(standby, TRUE);
                g_key_file_free(keyfile);
                return -1;
        }
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
        g_string_free(master, TRUE);
        g_string_free(slave, TRUE);
        g_string_free(standby, TRUE);
        g_key_file_free(keyfile);
        return 0;
}                          
