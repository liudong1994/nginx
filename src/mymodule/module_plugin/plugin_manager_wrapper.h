#ifndef __PLUGIN_MANAGER_WRAPPER_H__
#define __PLUGIN_MANAGER_WRAPPER_H__

#if __cplusplus
extern "C" {
#endif

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>



int plugin_create_manager(void *conf);
int plugin_init_master();
int plugin_init_process();
void plugin_exit_process();
void plugin_exit_master();
void* plugin_getbyname(const char *name, size_t len);


#if __cplusplus
}
#endif

#endif

