#ifndef _DAP_CONFIG_H_
#define _DAP_CONFIG_H_

#include <stdbool.h>
#include <stdint.h>


#ifdef __cplusplus
extern "C" {
#endif

typedef struct dap_config{
    void * _internal;
} dap_config_t;

int dap_config_init(const char * a_configs_path);
void dap_config_deinit();
dap_config_t * dap_config_open(const char * a_name);
void dap_config_close(dap_config_t * a_config);

int32_t dap_config_get_item_int32(dap_config_t * a_config, const char * a_section_path, const char * a_item_name);
int32_t dap_config_get_item_int32_default(dap_config_t * a_config, const char * a_section_path, const char * a_item_name, int32_t a_default);
const char * dap_config_get_item_str(dap_config_t * a_config, const char * a_section_path, const char * a_item_name);
const char * dap_config_get_item_str_default(dap_config_t * a_config, const char * a_section_path, const char * a_item_name, const char * a_value_default);
char** dap_config_get_array_str(dap_config_t * a_config, const char * a_section_path,
                                      const char * a_item_name, uint16_t * array_length);

bool dap_config_get_item_bool(dap_config_t * a_config, const char * a_section_path, const char * a_item_name);
bool dap_config_get_item_bool_default(dap_config_t * a_config, const char * a_section_path, const char * a_item_name, bool a_default);

double dap_config_get_item_double(dap_config_t * a_config, const char * a_section_path, const char * a_item_name);

#ifdef __cplusplus
}
#endif


#endif
