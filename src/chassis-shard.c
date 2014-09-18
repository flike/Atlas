#include "chassis-shard.h"
#include <time.h>
#include <stdio.h>

static gchar op = COM_QUERY;

shard_rule* shard_rule_new() {
       shard_rule* sr =  g_new0(shard_rule, 1);
       sr->shard_backend = g_ptr_array_new();
       sr->range_value_array = g_array_new(FALSE, FALSE, sizeof(gint64));
       return sr;
}

void shard_rule_free(shard_rule* sr) {
       if(sr->shard_backend) {
              g_ptr_array_free(sr->shard_backend, TRUE);
              sr->shard_backend = NULL;
       }
       if(sr->range_value_array) {
              g_array_free(sr->range_value_array, TRUE);
              sr->range_value_array = NULL;
       }
       if(sr->shard_nodes) {
              g_strfreev(sr->shard_nodes);
              sr->shard_nodes = NULL;
       }
       if(sr->shard_table) {
              g_free(sr->shard_table);
              sr->shard_table = NULL;
       }
       if(sr->shard_key) {
              g_free(sr->shard_key);
              sr->shard_key = NULL;
       }
       g_free(sr);
       sr = NULL;
}

/*read the GKeyFile, and set shard_rule*/
int keyfile_to_shard_rule(GKeyFile* keyfile, gchar* group_name, shard_rule* sr) {
       int i = 0;
       GOptionEntry config_entries[] = {
              {"shard-nodes", 0, 0, G_OPTION_ARG_STRING_ARRAY, NULL, "the nodes for data shard", NULL},
              {"shard-table", 0, 0, G_OPTION_ARG_STRING, NULL, "shard table name", NULL},
              {"shard-key", 0, 0, G_OPTION_ARG_STRING, NULL, "shard key", NULL},
              {"range-begin", 0, 0, G_OPTION_ARG_INT64, NULL, "range begin", NULL},
              {"range-end", 0, 0, G_OPTION_ARG_INT64, NULL, "range end", NULL},
              {"year-begin", 0, 0, G_OPTION_ARG_INT, NULL, "year begin", NULL},
              {"year-end", 0, 0, G_OPTION_ARG_INT, NULL, "year end", NULL},
              {NULL, 0, 0, G_OPTION_ARG_NONE, NULL, NULL, NULL}
       };
       config_entries[i++].arg_data = &(sr->shard_nodes);
       config_entries[i++].arg_data = &(sr->shard_table);
       config_entries[i++].arg_data = &(sr->shard_key);
       config_entries[i++].arg_data = &(sr->range_begin);
       config_entries[i++].arg_data = &(sr->range_end);
       config_entries[i++].arg_data = &(sr->year_begin);
       config_entries[i++].arg_data = &(sr->year_end);
       if(-1 == chassis_keyfile_to_options(keyfile, group_name, config_entries)) {
              g_message("%s:chassis_keyfile_to_options error", G_STRLOC);
              return -1;
       }
       return 0;
}

/*from the shard_nodes parse the pointer of backend*/
int get_shard_backend(network_backends_t *bs, shard_rule *sr) {
       int i, j, count = 0;
       gchar **node;
       network_backend_t *backend;
       for(i = 0; sr->shard_nodes[i]; i++) {
              node = g_strsplit(sr->shard_nodes[i], "#", 2);
              count = atoi(node[1]);
              backend = network_get_backend_by_addr(bs, node[0]);
              if(backend != NULL) {
                     sr->table_sum += count;
                     for(j = 0; j < count; j++)
                            g_ptr_array_add(sr->shard_backend, backend);
              }
              g_strfreev(node);
       }
       return 0;
}

/*sunday:0,...saturday:6*/
gint day_to_week(gint year, gint month, gint day) {
       struct tm t, *bt;
       memset(&t,0,sizeof(t));

       t.tm_year = year - 1900; 
       t.tm_mon = month - 1; 
       t.tm_mday = day;

       time_t ct = mktime(&t);
       if(-1 == ct) {   
              return -1; 
       } else {   
              bt = localtime(&ct);
              return bt->tm_wday;
       } 
}

guint get_table_index(GPtrArray* tokens, gint* d, gint* t) { 
       *d = *t = -1;
       sql_token** ts = (sql_token**)(tokens->pdata);
       guint len = tokens->len;

       guint i = 1, j;
       while (ts[i]->token_id == TK_COMMENT && ++i < len);
       sql_token_id token_id = ts[i]->token_id;

       if (token_id == TK_SQL_SELECT || token_id == TK_SQL_DELETE) {
              for (; i < len; ++i) {
                     if (ts[i]->token_id == TK_SQL_FROM) {
                            for (j = i+1; j < len; ++j) {
                                   if (ts[j]->token_id == TK_SQL_WHERE) break;

                                   if (ts[j]->token_id == TK_LITERAL) {
                                          if (j + 2 < len && ts[j+1]->token_id == TK_DOT) {
                                                 *d = j; 
                                                 *t = j + 2; 
                                          } else {
                                                 *t = j; 
                                          }    
                                          break;
                                   }    
                            }    
                            break;
                     }    
              }    
              return 1;
       } else if (token_id == TK_SQL_UPDATE) {
              for (; i < len; ++i) {
                     if (ts[i]->token_id == TK_SQL_SET) break;
                     if (ts[i]->token_id == TK_LITERAL) {
                            if (i + 2 < len && ts[i+1]->token_id == TK_DOT) {
                                   *d = i; 
                                   *t = i + 2; 
                            } else {
                                   *t = i; 
                            }    
                            break;
                     }    
              }    
              return 2;
       } else if (token_id == TK_SQL_INSERT || token_id == TK_SQL_REPLACE) {
              for (; i < len; ++i) {
                     gchar* str = ts[i]->text->str;
                     if (strcasecmp(str, "VALUES") == 0 || strcasecmp(str, "VALUE") == 0) break;

                     sql_token_id token_id = ts[i]->token_id;
                     if (token_id == TK_LITERAL && i + 2 < len && ts[i+1]->token_id == TK_DOT) {
                            *d = i; 
                            *t = i + 2; 
                            break;
                     } else if (token_id == TK_LITERAL || token_id == TK_FUNCTION) {
                            if (i == len - 1) { 
                                   *t = i; 
                                   break;
                            } else {
                                   str = ts[i+1]->text->str;
                                   token_id = ts[i+1]->token_id;
                                   if (strcasecmp(str, "VALUES") == 0 || strcasecmp(str, "VALUE") == 0 || token_id == TK_OBRACE || token_id == TK_SQL_SET) {
                                          *t = i;
                                          break;
                                   }
                            }
                     }
              }
              return 3;
       }
       return 0;
}

gint64 get_id_value(gchar* str, SHARD_TYPE type) {
       gint64 id_value = 0;
       gint year = 0, month = 0, day = 0;
       gchar ** str_vec =  NULL;
       switch(type) {
              case RANGE:
              case HASH:
                     id_value = atol(str);
                     break;
              case YEAR:
                     str_vec = g_strsplit(str, "-", 3);
                     if(str_vec[0])
                            id_value = atoi(str_vec[0]);
                     g_strfreev(str_vec);
                     break;
              case MONTH:
                     str_vec = g_strsplit(str, "-", 3);
                     if(str_vec[1])
                            id_value = atoi(str_vec[1]);
                     g_strfreev(str_vec);
                     break;
              case WEEK:
                     str_vec = g_strsplit(str, "-", 3);
                     if(str_vec[0])
                            year = atoi(str_vec[0]);//year
                     if(str_vec[1])
                            month = atoi(str_vec[1]);//month
                     if(str_vec[2])
                            day = atoi(str_vec[2]);//day
                     id_value = day_to_week(year, month, day);
                     g_strfreev(str_vec);
                     break;
       }
       return id_value;
}

/*get the value for shard id, and the sql type is select or delete*/
GArray* get_shard_value_select(GPtrArray* tokens, shard_rule* rule, gint start) {
       GArray* columns = g_array_new(FALSE, FALSE, sizeof(guint));
       sql_token** ts = (sql_token**)(tokens->pdata);
       guint len = tokens->len;
       guint i, j, k;
       gint64 id_value;

       for (i = start; i < len; ++i) {
              if (ts[i]->token_id == TK_SQL_WHERE) {
                     for (j = i+1; j < len-2; ++j) {
                            if (ts[j]->token_id == TK_LITERAL && strcasecmp(ts[j]->text->str, rule->shard_key) == 0) {
                                   if (ts[j+1]->token_id == TK_EQ || ts[j+1]->token_id == TK_LT || ts[j+1]->token_id == TK_GT || ts[j+1]->token_id == TK_LE || ts[j+1]->token_id == TK_GE ) {
                                          if (ts[j-1]->token_id != TK_DOT || strcasecmp(ts[j-2]->text->str, rule->shard_table) == 0) {
                                                 id_value = get_id_value(ts[j+2]->text->str, rule->shard_type);
                                                 g_array_append_val(columns, id_value);
                                                 rule->opt = ts[j+1]->token_id;
                                                 break;
                                          }
                                   } else if (j + 3 < len && strcasecmp(ts[j+1]->text->str, "IN") == 0 && ts[j+2]->token_id == TK_OBRACE) {
                                          k = j + 3;
                                          id_value = get_id_value(ts[j+3]->text->str, rule->shard_type);
                                          g_array_append_val(columns, id_value);
                                          while ((k += 2) < len && ts[k-1]->token_id != TK_CBRACE) {
                                                 id_value = get_id_value(ts[k]->text->str, rule->shard_type);	
                                                 g_array_append_val(columns, id_value);
                                          }
                                          rule->opt = TK_SQL_IN;
                                          break;
                                   } else if (j + 4 <= len && ts[j+1]->token_id == TK_SQL_BETWEEN ) {
                                          id_value = get_id_value(ts[j+2]->text->str, rule->shard_type);
                                          g_array_append_val(columns, id_value);//begin
                                          id_value = get_id_value(ts[j+4]->text->str, rule->shard_type);
                                          g_array_append_val(columns, id_value);//end
                                          rule->opt = ts[j+1]->token_id;
                                          break;
                                   }
                            }
                     }
                     break;
              }
       }
       return columns;
}

/*get the value for shard id, and the sql type is update*/
GArray* get_shard_value_update(GPtrArray* tokens, shard_rule* rule, gint start) {
       GArray* columns = g_array_new(FALSE, FALSE, sizeof(guint));
       sql_token** ts = (sql_token**)(tokens->pdata);
       guint len = tokens->len;
       guint i, j, k;
       gint64 id_value;

       for (i = start; i < len; ++i) {
              if (ts[i]->token_id == TK_SQL_WHERE) {
                     for (j = i+1; j < len-2; ++j) {
                            if (ts[j]->token_id == TK_LITERAL && strcasecmp(ts[j]->text->str, rule->shard_key) == 0) {
                                   if (ts[j+1]->token_id == TK_EQ || ts[j+1]->token_id == TK_LT || ts[j+1]->token_id == TK_GT || ts[j+1]->token_id == TK_LE || ts[j+1]->token_id == TK_GE) {
                                          if (ts[j-1]->token_id != TK_DOT || strcasecmp(ts[j-2]->text->str, rule->shard_table) == 0) {
                                                 id_value = get_id_value(ts[j+2]->text->str, rule->shard_type);
                                                 g_array_append_val(columns, id_value);
                                                 rule->opt = ts[j+1]->token_id;
                                                 break;
                                          }
                                   } else if (j + 3 < len && strcasecmp(ts[j+1]->text->str, "IN") == 0 && ts[j+2]->token_id == TK_OBRACE) {
                                          k = j + 3;
                                          id_value = get_id_value(ts[k]->text->str, rule->shard_type);
                                          g_array_append_val(columns, id_value);
                                          while ((k += 2) < len && ts[k-1]->token_id != TK_CBRACE) {
                                                 id_value = get_id_value(ts[k]->text->str, rule->shard_type);
                                                 g_array_append_val(columns, id_value);
                                          }
                                          rule->opt = TK_SQL_IN;
                                          break;
                                   } else if (j + 4 <= len && ts[j+1]->token_id == TK_SQL_BETWEEN) {
                                          id_value = get_id_value(ts[j+2]->text->str, rule->shard_type);
                                          g_array_append_val(columns, id_value);//begin
                                          id_value = get_id_value(ts[j+4]->text->str, rule->shard_type);
                                          g_array_append_val(columns, id_value);//end
                                          rule->opt = ts[j+1]->token_id;
                                          break;
                                   }
                            }
                     }
                     break;
              }
       }
       return columns;
}

/*get the value for shard id, and the sql type is insert*/
GArray* get_shard_value_insert(GPtrArray* tokens, shard_rule* rule, gint start) {
       GArray* columns = g_array_new(FALSE, FALSE, sizeof(guint));
       sql_token** ts = (sql_token**)(tokens->pdata);
       guint len = tokens->len;
       guint i, j, k;
       gint64 id_value;

       sql_token_id token_id = ts[start]->token_id;
       if (token_id == TK_SQL_SET) {
              for (i = start+1; i < len-2; ++i) {
                     if (ts[i]->token_id == TK_LITERAL && strcasecmp(ts[i]->text->str, rule->shard_key) == 0) {
                            id_value = get_id_value(ts[i+2]->text->str, rule->shard_type);
                            g_array_append_val(columns, id_value);
                            break;
                     }
              }
       } else {
              k = 2;
              if (token_id == TK_OBRACE && start + 1 < len && ts[start + 1]->token_id != TK_CBRACE) {
                     gint found = -1;
                     for (j = start+1; j < len; ++j) {
                            token_id = ts[j]->token_id;
                            if (token_id == TK_CBRACE) break;
                            if (token_id == TK_LITERAL && strcasecmp(ts[j]->text->str, rule->shard_key) == 0) {
                                   if (ts[j-1]->token_id != TK_DOT || strcasecmp(ts[j-2]->text->str, rule->shard_table) == 0) {
                                          found = j;
                                          break;
                                   }
                            }
                     }
                     k = found - start + 1;
              }

              for (i = start; i < len-1; ++i) {
                     gchar* str = ts[i]->text->str;
                     if ((strcasecmp(str, "VALUES") == 0 || strcasecmp(str, "VALUE") == 0) && ts[i+1]->token_id == TK_OBRACE) {
                            k += i;
                            if (k < len) {
                                   id_value = get_id_value(ts[k]->text->str, rule->shard_type);
                                   g_array_append_val(columns, id_value);
                            }
                            break;
                     }
              }
       }
       rule->opt = TK_EQ;
       return columns;
}

gint calculate_table_index_date(gint* table_index_array, GArray* columns, shard_rule* rule) {
       gint begin_id, end_id, i, t, k, j = 0;
       guint id;
       if(columns->len == 0) {
              if(rule->shard_type == YEAR) {
                     for(i = rule->year_begin; i <= rule->year_end; i++)
                            table_index_array[j++] = i;
              } else if(rule->shard_type == MONTH) {
                     for(i = 1; i <= 12; i++)
                            table_index_array[j++] = i;
              } else if(rule->shard_type == WEEK) {
                     for(i = 0; i <= 6; i++)
                            table_index_array[j++] = i;
              }
              return j;
       }

       id = g_array_index(columns, guint, 0);
       switch(rule->opt) {
              case TK_LT: /* < */
              case TK_LE: /* <= */
                     if(rule->shard_type == YEAR) {
                            end_id = (id > rule->year_end) ? (rule->year_end) : id;
                            for(i = rule->year_begin; i <= end_id; i++)
                                   table_index_array[j++] = i;
                     } else {
                            begin_id = (rule->shard_type == MONTH) ? 1 : 0;
                            end_id = (rule->shard_type == MONTH) ? 12 : 6;
                            for(i = begin_id; i <= end_id; i++)
                                   table_index_array[j++] = i;
                     }
                     break;
              case TK_GT: /* > */
              case TK_GE: /* >= */
                     if(rule->shard_type == YEAR) {
                            for(i = id; i <= rule->year_end; i++)
                                   table_index_array[j++] = i;
                     } else {
                            begin_id = (rule->shard_type == MONTH) ? 1 : 0;
                            end_id = (rule->shard_type == MONTH) ? 12 : 6;
                            for(i = begin_id; i <= end_id; i++)
                                   table_index_array[j++] = i;
                     }
                     break;
              case TK_EQ: /* = */
                     table_index_array[j++] = id;
                     break;
              case TK_SQL_BETWEEN:/*between*/
                     if(rule->shard_type == MONTH || rule->shard_type == WEEK) {
                            begin_id = (rule->shard_type == MONTH) ? 1 : 0;
                            end_id = (rule->shard_type == MONTH) ? 12 : 6;
                            for(i = begin_id; i <= end_id; i++)
                                   table_index_array[j++] = i;
                     } else {
                            begin_id = g_array_index(columns, guint, 0);
                            end_id = g_array_index(columns, guint, 1);
                            for(i = begin_id; i <= end_id; i++)
                                   table_index_array[j++] = i;
                     }
                     break;
              case TK_SQL_IN: /* in */
                     for(i = 0; i < columns->len; i++) {
                            t = g_array_index(columns, guint, i);
                            for(k = 0; k < j; k++) /* j is the length of table_index_array */
                                   if (t == table_index_array[k]) break;
                            if(k == j) table_index_array[j++] = t;
                     }
                     break;
              default:
                     table_index_array[j++] = id;
       }
       return j;
}

gint calculate_table_index_hash(gint* table_index_array, GArray* columns, shard_rule* rule) {
       gint i, k, t, id, j = 0;
       if(columns->len == 0) {
              for(i = 0; i < rule->table_sum; i++)
                     table_index_array[j++] = i;
              return j;
       }
       if(rule->opt == TK_EQ) {
              for(i = 0; i < columns->len; i++) {
                     id = g_array_index(columns, guint, i);
                     table_index_array[j++] = id % rule->table_sum;
              }
       } else if(rule->opt == TK_SQL_IN) {
              for(i = 0; i < columns->len; i++) {
                     id = g_array_index(columns, guint, i);
                     k = id % rule->table_sum;
                     for(t = 0; t < j; t++) 
                            if(table_index_array[t] == k) break;
                     if(t == j) table_index_array[j++] = k;
              }
       } else {
              for(i = 0; i < rule->table_sum; i++)
                     table_index_array[j++] = i;
       }

       return j;
}

/*return the len of table_index_array*/
gint calculate_table_index_range(gint* table_index_array, GArray* columns, shard_rule* rule) {
       gint start, end, id_end, i, k, t, j = 0;
       guint id ;
       if(columns->len == 0) {
              for(i = 0; i < rule->table_sum; i++)
                     table_index_array[j++] = i;
              return j;
       }

       id = g_array_index(columns, guint, 0);
       switch(rule->opt) {
              case TK_LT:/* < */
              case TK_LE:/* <= */
                     for(i = 0; i < rule->table_sum; i++ ) {
                            if (id <= g_array_index(rule->range_value_array, gint64, i)) {
                                   table_index_array[j++] = i;
                                   break;
                            } else {
                                   table_index_array[j++] = i;
                            }
                     }
                     break;
              case TK_GT:/* > */
              case TK_GE:/* >= */
                     id_end = (rule->opt == TK_GE) ? id : (id - 1);
                     for(i = 0; i < rule->table_sum; i++) {
                            if (id_end <= g_array_index(rule->range_value_array, gint64, i)) {
                                   for(k = i; k < rule->table_sum; k++) {
                                          table_index_array[j++] = k;
                                   }
                                   break;
                            }
                     }
                     break;
              case TK_EQ:/* = */
                     for(i = 0; i < rule->table_sum; i++) {
                            if (id <= g_array_index(rule->range_value_array, gint64, i)) {
                                   table_index_array[j++] = i;
                                   break;
                            }
                     }
                     break;
              case TK_SQL_BETWEEN:/*between*/
                     end = rule->table_sum - 1;
                     start = rule->table_sum;
                     id_end = g_array_index(columns, guint, 1);
                     for(i = 0; i < rule->table_sum; i++) {
                            if(id <= g_array_index(rule->range_value_array, gint64, i)) {
                                   start = i;
                                   break;
                            }
                     }
                     for(i = 0; i < rule->table_sum; i++) {
                            if(id_end <= g_array_index(rule->range_value_array, gint64, i)) {
                                   end =  i;
                                   break;
                            }
                     }
                     for(i = start; i <= end; i++)
                            table_index_array[j++] = i;
                     break;
              case TK_SQL_IN:
                     for(i = 0; i < columns->len; i++) {
                            id = g_array_index(columns, guint, i);
                            for(k = 0; k < rule->table_sum; k++) {
                                   if(id <= g_array_index(rule->range_value_array, gint64, k)) { /*if two number in the same range,we only record one table*/
                                          for(t = 0; t < j; t++) 
                                                 if(table_index_array[t] == k) break;
                                          if(t == j) table_index_array[j++] = k;
                                          break;
                                   }
                            }
                     }
                     break;
              default:/*insert*/
                     for(k = 0; k < rule->table_sum; k++) {
                            if(id <= g_array_index(rule->range_value_array, gint64, k)) {
                                   table_index_array[j++] = k;
                                   break;
                            }
                     }
       }
       return j;
}

GString* generate_sql(GString* sql_format, int table_num) {
       int len;
       char *s = NULL, *start, buf[16];
       GString* sql_instance = g_string_new(NULL);
       start = sql_format->str;
       s = strstr(start, "%d");
       sprintf(buf, "%d", table_num);
       while(s != NULL) {
              len = s - start;
              g_string_append_len(sql_instance, start, len);
              g_string_append(sql_instance, buf);
              start = s + 2;
              s = strstr(start, "%d");
       }
       g_string_append(sql_instance, start);
       return sql_instance;
}

GPtrArray* combine_sql(GPtrArray* tokens, gint table_index, GArray* columns, shard_rule* rule) {
       guint i, len, shard_id, table_sum;
       GPtrArray* sqls = g_ptr_array_new();
       guint *table_index_array;
       gint table_index_array_len;

       sql_token** ts = (sql_token**)(tokens->pdata);
       len = tokens->len;
       table_sum = rule->table_sum;

       GString* sql_format = g_string_new(&op);
       if (ts[1]->token_id == TK_COMMENT) {
              g_string_append_printf(sql_format, "/*%s*/", ts[1]->text->str);
       } else {
              g_string_append(sql_format, ts[1]->text->str);
       }	
       for (i = 2; i < len; ++i) {
              sql_token_id token_id = ts[i]->token_id;

              if (token_id != TK_OBRACE) g_string_append_c(sql_format, ' ');
              if (i == table_index) {
                     g_string_append_printf(sql_format, "%s_%s", ts[i]->text->str, "%d");
              } else if (token_id == TK_STRING) {
                     g_string_append_printf(sql_format, "'%s'", ts[i]->text->str);
              } else if (token_id == TK_COMMENT) {
                     g_string_append_printf(sql_format, "/*%s*/", ts[i]->text->str);
              } else if (ts[i]->token_id == TK_LITERAL && strcasecmp(rule->shard_table, ts[i]->text->str)==0 && i+1 < len && ts[i+1]->token_id == TK_DOT){
                     g_string_append_printf(sql_format, "%s_%s",rule->shard_table, "%d");
              }else{
                     g_string_append(sql_format, ts[i]->text->str);
              }
       }

       table_index_array = g_new0(guint, rule->table_sum);
       if(rule->shard_type == RANGE) {
              table_index_array_len = calculate_table_index_range(table_index_array, columns, rule);
       } else if(rule->shard_type == YEAR || rule->shard_type == MONTH || rule->shard_type == WEEK) {
              table_index_array_len = calculate_table_index_date(table_index_array, columns, rule);
       } else if(rule->shard_type == HASH) {
              table_index_array_len = calculate_table_index_hash(table_index_array, columns, rule);
       }

       if(0 < table_index_array_len) {
              for(i = 0; i < table_index_array_len; i++) {
                     //GString* sql_instance = g_string_new(NULL);
                     //g_string_printf(sql_instance, sql_format->str, table_index_array[i]);
                     GString* sql_instance = generate_sql(sql_format, table_index_array[i]);
                     g_ptr_array_add(sqls, sql_instance);
              }
       } else {
              GString* sql_instance;
              if(rule->shard_type == YEAR) {
                     //g_string_printf(sql_instance, sql_format->str, (rand() % rule->table_sum + rule->year_begin));
                     sql_instance = generate_sql(sql_format, (rand() % rule->table_sum + rule->year_begin));
              } else {
                     //g_string_printf(sql_instance, sql_format->str, rand() % rule->table_sum);
                     sql_instance = generate_sql(sql_format, rand() % rule->table_sum);
              }
              g_ptr_array_add(sqls, sql_instance);
       }
       g_string_free(sql_format, TRUE);
       g_free(table_index_array);
       return sqls;
}

GPtrArray* sql_parse(network_mysqld_con* con, GPtrArray* tokens, GHashTable *rule_table) {
       gint db, table;
       GArray* columns = NULL; 
       guint sql_type = get_table_index(tokens, &db, &table);
       if (table == -1) return NULL;
       gchar* table_name = NULL;

       /*if (db == -1) {
              table_name = g_strdup_printf("%s.%s", con->client->default_db->str, ((sql_token*)tokens->pdata[table])->text->str);
       } else {
              table_name = g_strdup_printf("%s.%s", ((sql_token*)tokens->pdata[db])->text->str, ((sql_token*)tokens->pdata[table])->text->str);
       }*/
       table_name = g_strdup_printf("%s", ((sql_token*)tokens->pdata[table])->text->str);

       shard_rule* rule = g_hash_table_lookup(rule_table, table_name);
       if (rule == NULL) {
              g_free(table_name);
              return NULL;
       }

       if(sql_type ==  1) { /*select and delete*/
              columns = get_shard_value_select(tokens, rule, table+1);
       } else if(sql_type == 2) { /*update*/
              columns = get_shard_value_update(tokens, rule, table+1);
       } else if(sql_type == 3) { /*insert*/
              columns = get_shard_value_insert(tokens, rule, table+1);
       }
       g_free(table_name);
       GPtrArray* sqls = combine_sql(tokens, table, columns, rule);
       g_array_free(columns, TRUE);
       return sqls;
}

