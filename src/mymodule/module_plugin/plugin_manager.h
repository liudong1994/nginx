#ifndef __PLUGIN_MANAGER_H__
#define __PLUGIN_MANAGER_H__

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <map>
#include <string>
#include <memory>           // c++11 shared_ptr
#include "plugin.h"


namespace PLUGIN {

struct CPluginContext {
    std::string plugin_name;
    std::string plugin_path;
    std::string plugin_conf;

    CPlugin*    plugin_ptr;
    void*       plugin_so_handler;

    CPluginContext();
    ~CPluginContext();
};


class CPluginManager {
public:
    CPluginManager() {}
    virtual ~CPluginManager() {}


    int LoadPlugin(const std::string& plugin_name, const std::string& plugin_path, const std::string& plugin_conf);
    int PluginInitMaster();
    int PluginInitProcess();
    void PluginExitProcess();
    void PluginExitMaster();

    CPlugin* GetPlugin(const std::string& plugin_name);

private:
    std::map<std::string, std::shared_ptr<CPluginContext>> m_map_plugins_context;
};

}

#endif

