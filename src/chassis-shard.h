#ifndef __CHASSIS_SHARD__
#define __CHASSIS_SHARD__

#include <glib.h>
#include "network-backend.h"
#include "lib/sql-tokenizer.h"
#include "network-mysqld.h"

typedef enum {
       RANGE,
       WEEK,
       MONTH,
       YEAR,
       HASH
} SHARD_TYPE;

typedef struct {
       gchar** shard_nodes;//the nodes for shard
       GPtrArray* shard_backend;
       gchar* shard_table;//the table for shard
       SHARD_TYPE shard_type;
       gchar* shard_key;
       gint64 range_begin;//when shard type is range, need the start index for shard
       gint64 range_end;//when shard type is range, need the end index for shard
       gint table_sum;//the sum of shard table
       GArray *range_value_array;//when shard type is range,we calculate the bound value of the range in advance
       gint year_begin;//when shard type is year, need the begin year for shard
       gint year_end;//when shard type is year, need the end year for shard
       sql_token_id opt;//conditional operator for the shard 
} shard_rule;

gint day_to_week(gint year, gint month, gint day);
gint64 get_id_value(gchar* str, SHARD_TYPE type);
GArray* get_shard_value_select(GPtrArray* tokens, shard_rule* rule, gint start);
GArray* get_shard_value_update(GPtrArray* tokens, shard_rule* rule, gint start);
GArray* get_shard_value_insert(GPtrArray* tokens, shard_rule* rule, gint start);
gint calculate_table_index_range(gint* table_index_array, GArray* columns, shard_rule* rule);
GPtrArray* combine_sql(GPtrArray* tokens, gint table_index, GArray* columns, shard_rule* rule);
guint get_table_index(GPtrArray* tokens, gint* d, gint* t);
GPtrArray* sql_parse(network_mysqld_con* con, GPtrArray* tokens, GHashTable *rule_table);
shard_rule* shard_rule_new();
void shard_rule_free(shard_rule* sr);
int keyfile_to_shard_rule(GKeyFile* keyfile, gchar* group_name, shard_rule* sr);
int get_shard_backend(network_backends_t *bs, shard_rule *sr);
#endif 
