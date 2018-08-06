#include "ngx_http_plugin_module.h"
#include "plugin_manager_wrapper.h"


// conf function
static void* ngx_http_plugin_create_main_conf(ngx_conf_t *cf);
static char* ngx_http_plugin_init_main_conf(ngx_conf_t *cf, void *conf);

// command funciton
static char *ngx_http_plugin_set_info(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

// module function
static ngx_int_t ngx_http_plugin_init_module(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_plugin_init_process(ngx_cycle_t *cycle);
static void ngx_http_plugin_exit_process(ngx_cycle_t *cycle);
static void ngx_http_plugin_exit_master(ngx_cycle_t *cycle);



// ngx_http_module_t接口
static ngx_http_module_t ngx_http_plugin_module_ctx = {
    NULL,                                       /* preconfiguration */
    NULL,                                       /* postconfiguration */

    ngx_http_plugin_create_main_conf,           /* create main configuration */
    ngx_http_plugin_init_main_conf,             /* init main configuration */

    NULL,                                       /* create server configuration */
    NULL,                                       /* merge server configuration */

    NULL,                                       /* create location configuration */
    NULL                                        /* merge location configuration */
};

// ngx_http_command_t接口
static ngx_command_t ngx_http_plugin_commands[] = {
    {
        ngx_string("plugin_info"),      //name
        NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE3,   //type
        ngx_http_plugin_set_info,       //set handler
        NGX_HTTP_MAIN_CONF_OFFSET,       //conf
        0,                              //offset
        NULL                            //post
    },

    ngx_null_command
};

ngx_module_t ngx_http_plugin_module = {
    NGX_MODULE_V1,
    &ngx_http_plugin_module_ctx,            /* module context */
    ngx_http_plugin_commands,               /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    ngx_http_plugin_init_module,            /* init module */
    ngx_http_plugin_init_process,           /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    ngx_http_plugin_exit_process,           /* exit process */
    ngx_http_plugin_exit_master,            /* exit master */
    NGX_MODULE_V1_PADDING
};



// Function implementation
static void* ngx_http_plugin_create_main_conf(ngx_conf_t *cf) {
    ngx_http_plugin_main_conf_t *main_conf = (ngx_http_plugin_main_conf_t *)ngx_palloc(cf->pool, sizeof(ngx_http_plugin_main_conf_t));
    if (NULL == main_conf) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "[plugin] ngx_http_plugin_create_main_conf failed");
        return NGX_CONF_ERROR;
    }


    return main_conf;
}

static char* ngx_http_plugin_init_main_conf(ngx_conf_t *cf, void *conf) {

    return NGX_CONF_OK;
}

static char *ngx_http_plugin_set_info(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_array_t *plugin_info_array = &(((ngx_http_plugin_main_conf_t *)conf)->plugin_info);

    if (NULL == plugin_info_array->elts) {
        if (NGX_OK != ngx_array_init(plugin_info_array, cf->pool, 1, sizeof(plugin_info_t))) {
            return NGX_CONF_ERROR;
        }
    }

    if (4 != cf->args->nelts) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "[plugin] ngx_http_plugin_set_info cf->args->nelts error");
        return NGX_CONF_ERROR;
    }

    plugin_info_t *plugin_info = (plugin_info_t *)ngx_array_push(plugin_info_array);
    ngx_str_t *value = (ngx_str_t *)cf->args->elts;

    // 0.plugin_info

    // 1.plugin_name=***
    if (value[1].len >= 12 && 0 == ngx_strncmp(value[1].data, "plugin_name=", 12)) {
        plugin_info->plugin_name.data = value[1].data + 12;
        plugin_info->plugin_name.len = value[1].len - 12;
    } else {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "[plugin] invalid plugin_name %V", value + 1);
        return NGX_CONF_ERROR;
    }


    // 2.plugin_path=***
    if (value[2].len >= 12 && 0 == ngx_strncmp(value[2].data, "plugin_path=", 12)) {
        plugin_info->plugin_path.data = value[2].data + 12;
        plugin_info->plugin_path.len = value[2].len - 12;
    } else {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "[plugin] invalid plugin_path %V", value + 2);
        return NGX_CONF_ERROR;
    }


    // 3.plugin_conf=***
    if (value[3].len >= 12 && 0 == ngx_strncmp(value[3].data, "plugin_conf=", 12)) {
        plugin_info->plugin_conf.data = value[3].data + 12;
        plugin_info->plugin_conf.len = value[3].len - 12;
    } else {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "[plugin] invalid plugin_conf %V", value + 3);
        return NGX_CONF_ERROR;
    }

    ngx_log_error(NGX_LOG_DEBUG, cf->log, 0, "[plugin] ngx_http_plugin_module info: plugin_name:%V plugin_path:%V plugin_conf:%V",
                                    &(plugin_info->plugin_name), &(plugin_info->plugin_path), &(plugin_info->plugin_conf));
    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_plugin_init_module(ngx_cycle_t *cycle) {
    ngx_http_plugin_main_conf_t *main_conf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_plugin_module);
    ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "[plugin] plugin manager create start");

    if (plugin_create_manager(main_conf) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "[plugin] create plugin manager fail");
        return NGX_ERROR;
    }

    if (plugin_init_master() != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "[plugin] plugin init module fail");
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "[plugin] create plugin manager success");
    return NGX_OK;
}

static ngx_int_t ngx_http_plugin_init_process(ngx_cycle_t *cycle) {
    if (plugin_init_process() != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "[plugin] plugin init process failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}

static void ngx_http_plugin_exit_process(ngx_cycle_t *cycle) {
    ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "[plugin] exit process");
    plugin_exit_process();
}

static void ngx_http_plugin_exit_master(ngx_cycle_t *cycle) {
    ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "[plugin] exit master");
    plugin_exit_master();
}

