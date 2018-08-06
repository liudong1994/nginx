#ifndef NGX_HTTP_PLUGIN_MODULE_H_
#define NGX_HTTP_PLUGIN_MODULE_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_str_t   plugin_name;
    ngx_str_t   plugin_path;
    ngx_str_t   plugin_conf;
} plugin_info_t;

typedef struct {
    ngx_array_t plugin_info;        // plugin_info_t
} ngx_http_plugin_main_conf_t;


#endif

