#include "plugin_manager_wrapper.h"
#include "ngx_http_plugin_module.h"
#include "plugin_manager.h"

static plugin::CPluginManager *g_plugin_manager = NULL;


int plugin_create_manager(void *conf) {
    if (NULL != g_plugin_manager)
        return NGX_ERROR;

    g_plugin_manager = new plugin::CPluginManager();
    ngx_http_plugin_main_conf_t *main_conf = (ngx_http_plugin_main_conf_t *)conf;
    plugin_info_t *plugininfo = (plugin_info_t *)main_conf->plugin_info.elts;

    for (size_t i = 0; i < main_conf->plugin_info.nelts; ++i) {
        std::string name((char *)plugininfo[i].plugin_name.data, plugininfo[i].plugin_name.len);
        std::string path((char *)plugininfo[i].plugin_path.data, plugininfo[i].plugin_path.len);
        std::string conf((char *)plugininfo[i].plugin_conf.data, plugininfo[i].plugin_conf.len);

        int rc = g_plugin_manager->LoadPlugin(name, path, conf);
        if (rc != 0) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

int plugin_init_master() {
    return g_plugin_manager->PluginInitMaster();
}

int plugin_init_process() {
    return g_plugin_manager->PluginInitProcess();
}

void plugin_exit_process() {
    g_plugin_manager->PluginExitProcess();
}

void plugin_exit_master() {
    g_plugin_manager->PluginInitMaster();
    delete g_plugin_manager;
    g_plugin_manager = NULL;
}

void* plugin_getbyname(const char *name, size_t len) {
    return g_plugin_manager->GetPlugin(std::string(name, len));
}

