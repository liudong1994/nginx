#ifndef __NGX_HTTP_MYSUBREQUEST_MODULE_H__
#define __NGX_HTTP_MYSUBREQUEST_MODULE_H__

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <sys/time.h>


typedef enum {
    MODULE_STATE_INIT,
    MODULE_STATE_RECEIVE_AGAIN,
    MODULE_STATE_PROCESS,
    MODULE_STATE_WAIT_SUBREQUEST,
    MODULE_STATE_POST_SUBREQUEST,
    MODULE_STATE_FINAL,
    MODULE_STATE_DONE,
    MODULE_STATE_ERROR
} mysubrequest_state_t;


typedef struct {
    ngx_str_t           uri;
    ngx_str_t           args;
    ngx_http_request_t  *subr;   
} subrequest_t;

typedef struct {
    mysubrequest_state_t    state;

    struct timeval          time_start;
    struct timeval          time_end;
    ngx_str_t               user_key;

    void                    *plugin;
    void                    *request;

    ngx_array_t             *subrequests;
    ngx_int_t               subr_count;
} ngx_http_mysubrequest_ctx_t;


// ngx_subrequest_interface use
extern ngx_module_t  ngx_http_mysubrequest_module;

#endif

