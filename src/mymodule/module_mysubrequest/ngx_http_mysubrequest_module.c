#include "ngx_http_mysubrequest_module.h"
#include "ngx_subrequest_interface.h"


// TODO mysubrequest -> myplugin handler

/*
static ngx_http_variable_t ngx_http_mysubrequest_variables[] = {
{ ngx_string("user_key"), NULL, ngx_http_user_key,
0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

{ ngx_null_string, NULL, NULL, 0, 0, 0 }
};
*/

static ngx_int_t ngx_http_mysubrequest_preconfiguration(ngx_conf_t *cf);

static char *ngx_http_mysubrequest_cb(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_mysubrequest_handler(ngx_http_request_t *r);

static void ngx_http_mysubrequest_post_body(ngx_http_request_t *r);


static ngx_command_t  ngx_http_mysubrequest_commands[] = {

    { ngx_string("ngx_mysubrequest"),
      NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
      ngx_http_mysubrequest_cb,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    ngx_null_command
};

static ngx_http_module_t ngx_http_mysubrequest_module_ctx = {
    ngx_http_mysubrequest_preconfiguration,     /* preconfiguration */
    NULL,                                       /* postconfiguration */

    NULL,                                       /* create main configuration */
    NULL,                                       /* init main configuration */

    NULL,                                       /* create server configuration */
    NULL,                                       /* merge server configuration */

    NULL,                                       /* create location configuration */
    NULL                                        /* merge location configuration */
};

ngx_module_t  ngx_http_mysubrequest_module = {
    NGX_MODULE_V1,
    &ngx_http_mysubrequest_module_ctx,      /* module context */
    ngx_http_mysubrequest_commands,         /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t ngx_http_mysubrequest_preconfiguration(ngx_conf_t *cf) {
    // TODO

    return NGX_OK;
}

static char *ngx_http_mysubrequest_cb(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_core_loc_conf_t *clcf = (ngx_http_core_loc_conf_t *)ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);   // TODO ngx_http_core_module
    clcf->handler = ngx_http_mysubrequest_handler;

    return NGX_OK;
}

static ngx_int_t ngx_http_mysubrequest_handler(ngx_http_request_t *r) {
    ngx_http_mysubrequest_ctx_t *ctx = (ngx_http_mysubrequest_ctx_t *)ngx_http_get_module_ctx(r, ngx_http_mysubrequest_module);
    
    if (ctx == NULL) {
        ctx = (ngx_http_mysubrequest_ctx_t *)ngx_pcalloc(r->pool, sizeof(ngx_http_mysubrequest_ctx_t));
        if (ctx == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[mysubrequest] ngx_http_mysubrequest_handler new ctx failed");
            return NGX_ERROR;
        }

        ngx_http_set_ctx(r, ctx, ngx_http_mysubrequest_module);

        // init mysubrequest module ctx
        ctx->state = MODULE_STATE_INIT;
        gettimeofday(&ctx->time_start, NULL);
        ngx_str_null(&ctx->user_key);

        /*set by ngx_pcalloc():
        ctx->plugin = NULL;
        ctx->request = NULL;
        ctx->subrequests = NULL;*/
    }


    // 状态机转换
    ngx_int_t rc = NGX_OK;
    if (ctx->state == MODULE_STATE_INIT) {
        // 初始化plugin  GET获取成功 POST获取body完毕 此状态结束
        rc = plugin_init_request(r, ngx_http_mysubrequest_post_body);

        if (rc == NGX_OK) {
            // GET or POST body  read completely
            ctx->state = MODULE_STATE_PROCESS;
        } else if (rc == NGX_AGAIN) {
            /* 
            *   POST body read incompletely
            *   Don't need r->main->count++ because ngx_http_read_client_body has already increased main request count.
            */
            ctx->state = MODULE_STATE_RECEIVE_AGAIN;
            return NGX_AGAIN;
        } else {
            ctx->state = MODULE_STATE_ERROR;
        }
    }

    if (ctx->state == MODULE_STATE_PROCESS) {
        /*
            处理  GET 或者 获取成功的POST body请求
            如果plugin需要访问其他服务 同时会创建子请求
        */
        rc = plugin_process_request(r);

        if (rc == NGX_OK) {
            ctx->state = MODULE_STATE_FINAL;
        } else if (rc == NGX_AGAIN) {
            // 需要subrequest请求 进行subrequest请求结束响应等待
            ctx->state = MODULE_STATE_WAIT_SUBREQUEST;
            r->main->count++;

            return NGX_DONE;
        } else {
            ctx->state = MODULE_STATE_ERROR;
        }
    }

    if (ctx->state == MODULE_STATE_WAIT_SUBREQUEST) {
        // 等待所有subrequest请求处理完毕
        rc = plugin_check_subrequest(r);

        if (rc == NGX_OK) {
            ctx->state = MODULE_STATE_POST_SUBREQUEST;
        } else if (rc == NGX_AGAIN) {
            ctx->state = MODULE_STATE_WAIT_SUBREQUEST;
            r->main->count++;
            return NGX_AGAIN;
        } else {
            ctx->state = MODULE_STATE_ERROR;
        }
    }

    if (ctx->state == MODULE_STATE_POST_SUBREQUEST) {
        // 将subrequest的结果交给plugin进行处理
        rc = plugin_post_subrequest(r);

        if (rc == NGX_OK) {
            ctx->state = MODULE_STATE_FINAL;
        } else if (rc == NGX_AGAIN) {
            ctx->state = MODULE_STATE_WAIT_SUBREQUEST;
            r->main->count++;
            return NGX_AGAIN;
        } else {
            ctx->state = MODULE_STATE_ERROR;
        }
    }

    if (ctx->state == MODULE_STATE_FINAL) {
        ctx->state = MODULE_STATE_DONE;

        gettimeofday(&ctx->time_end, NULL);
        int use_s = ctx->time_end.tv_sec- ctx->time_start.tv_sec;
        int use_ms = (ctx->time_end.tv_usec - ctx->time_start.tv_usec) / 1000;
        if(use_ms < 0) {
            use_s--;
            use_ms += 1000;
        }

        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[mysubrequest] final request, time consume: %ds.%dms", use_s, use_ms);
        return plugin_final_request(r);
    }

    if (ctx->state == MODULE_STATE_ERROR) {     // TODO 测试一下
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[mysubrequest] plugin process error, destory request context");

        /* destroy request context exactly once */
        plugin_destroy_request(r);
        return NGX_ERROR;
    }

    return NGX_OK;
}

static void ngx_http_mysubrequest_post_body(ngx_http_request_t *r) {
    ngx_http_mysubrequest_ctx_t *ctx = (ngx_http_mysubrequest_ctx_t *)ngx_http_get_module_ctx(r, ngx_http_mysubrequest_module);

    // read whole request body at first time
    if (ctx->state == MODULE_STATE_INIT) {
        // ctx->state auto modify
        ngx_http_finalize_request(r, NGX_DONE);
        return;
    }

    // read whole request body in multiple times
    ctx->state = MODULE_STATE_PROCESS;
    ngx_http_finalize_request(r, r->content_handler(r));    // TODO ngx_http_finalize_request
}

