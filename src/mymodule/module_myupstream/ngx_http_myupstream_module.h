#ifndef _NGX_HTTP_MYSTREAM_MODULE_H__
#define _NGX_HTTP_MYSTREAM_MODULE_H__


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_http_upstream_conf_t     upstream;
} ngx_http_myupstream_loc_conf_t;


#endif

