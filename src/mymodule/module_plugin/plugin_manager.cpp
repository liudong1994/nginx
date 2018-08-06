#include <dlfcn.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <utility>

#include "plugin_manager.h"


using namespace std;
using namespace PLUGIN;


typedef CPlugin *(*create_plugin_func)();
const static string g_create_plugin_func_name = "create_instance";


CPluginContext::CPluginContext() : plugin_ptr(NULL), plugin_so_handler(NULL) {
}

CPluginContext::~CPluginContext() {
    if (plugin_ptr != NULL) {
        delete plugin_ptr;
        plugin_ptr = NULL;
    }

    if (plugin_so_handler != NULL) {
        dlclose(plugin_so_handler);
        plugin_so_handler = NULL;
    }
}

// plugin manager implementation
int CPluginManager::LoadPlugin(const std::string& plugin_name, const std::string& plugin_path, const std::string& plugin_conf) {
    cerr << "LoadPlugin: " << plugin_name << " " << plugin_path << " " << plugin_conf << endl;

    void *so_handler = dlopen(plugin_path.c_str(), RTLD_LAZY);
    if (so_handler == NULL) {
        cerr << "plugin_manager dlopen path=" << plugin_path << ", error=" << dlerror() << endl;
        return -1;
    }

    create_plugin_func handler = (create_plugin_func)dlsym(so_handler, g_create_plugin_func_name.c_str());
    if (handler == NULL) {
        dlclose(so_handler);
        cerr << "plugin_manager dlsym path=" << plugin_path << ", error=" << dlerror() << endl;
        return -1;
    }

    CPlugin* plugin = (*handler)();
    if (plugin == NULL) {
        dlclose(so_handler);
        cerr << "plugin_manager create_instance path=" << plugin_path << endl;
        return -1;
    }

    std::shared_ptr<CPluginContext> plugin_context = make_shared<CPluginContext>();
    plugin_context->plugin_name = plugin_name;
    plugin_context->plugin_path = plugin_path;
    plugin_context->plugin_conf  = plugin_conf;
    plugin_context->plugin_ptr = plugin;
    plugin_context->plugin_so_handler = so_handler;

    m_map_plugins_context.insert(make_pair(plugin_name, plugin_context));
    return 0;
}

int CPluginManager::PluginInitMaster() {
    for (auto itr = m_map_plugins_context.begin(); itr != m_map_plugins_context.end(); ++itr) {
        std::shared_ptr<CPluginContext> plugin_context = itr->second;
        int rc = plugin_context->plugin_ptr->InitMaster(plugin_context->plugin_conf);
        if (NGX_OK != rc) {
            cerr << plugin_context->plugin_path << " init module error, so_conf=" << plugin_context->plugin_conf << endl;
            return NGX_ERROR;
        }
    }
    return NGX_OK;
}

int CPluginManager::PluginInitProcess() {
    for (auto itr = m_map_plugins_context.begin(); itr != m_map_plugins_context.end(); ++itr) {
        std::shared_ptr<CPluginContext> plugin_context = itr->second;
        int rc = plugin_context->plugin_ptr->InitProcess(plugin_context->plugin_conf);
        if (NGX_OK != rc) {
            cerr << plugin_context->plugin_path << " init process error, so_conf=" << plugin_context->plugin_conf << endl;
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

void CPluginManager::PluginExitProcess() {
    for (auto itr = m_map_plugins_context.begin(); itr != m_map_plugins_context.end(); ++itr) {
        std::shared_ptr<CPluginContext> plugin_context = itr->second;
        plugin_context->plugin_ptr->ExitProcess();
    }
}

void CPluginManager::PluginExitMaster() {
    for (auto itr = m_map_plugins_context.begin(); itr != m_map_plugins_context.end(); ++itr) {
        std::shared_ptr<CPluginContext> plugin_context = itr->second;
        plugin_context->plugin_ptr->ExitMaster();
    }
}

CPlugin* CPluginManager::GetPlugin(const std::string& plugin_name) {
    auto itr = m_map_plugins_context.find(plugin_name);
    if (itr == m_map_plugins_context.end()) {
        return NULL;
    }

    return itr->second->plugin_ptr;
}

