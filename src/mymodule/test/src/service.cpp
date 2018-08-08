#include <iostream>
#include <utility>

#include "errcode.h"
#include "str_util.h"
#include "service.h"
#include "handler_process.h"

using std::string;
using std::vector;

const uint64_t DEFAULT_TIMEOUT_MS = 100;
const string SERVER_URI = "/server/";


CService::CService()
: m_pAsync(nullptr) {

}

CService::~CService() {
    if (m_pAsync) {
        delete m_pAsync;
        m_pAsync = nullptr;
    }
}

int CService::InitAsync() {
    m_pAsync = new CAsyncTask<Context *>(AsyncHandler, 2048, 1);
    if (!m_pAsync) {
        return RET_ERR;
    }

    return RET_OK;
}

int CService::InitHandler() {
    CBlackHandler *pBlackHandler = CBlackHandler::getInstance();
    if (RET_OK != pBlackHandler->Init()) {
        return RET_ERR;
    }

    return RET_OK;
}

int CService::InitProcess(const string &filepath) {
    int rc = InitAsync();
    if (rc != RET_OK) {
        std::cerr << "[FATAL] init async failed!" << std::endl; 
        return CPlugin::PLUGIN_ERROR;
    }

    rc = InitHandler();
    if (rc != RET_OK) {
        std::cerr << "[FATAL] init handler failed!" << std::endl; 
        return CPlugin::PLUGIN_ERROR;
    }

    return CPlugin::PLUGIN_OK;
}

void CService::ExitProcess() {
}

int CService::Handle(plugin::CRequest &r) {
    Context *ctx = nullptr;
    if (string::npos != r.uri.find(SERVER_URI)) {
        ctx = CBlackHandler::getInstance()->GetHandlerContext();
    } else {
        std::cerr << "Handle uri: " << r.uri << " not implement!" << std::endl;
        return CPlugin::PLUGIN_ERROR;
    }

    ctx->r = &r;
    ctx->timer.start();
    ctx->StartRequest();
    r.ctx = (void *)ctx;

    return ProcessBody(r);
}

int CService::ProcessBody(plugin::CRequest &r) {
    Context *ctx = (Context *)r.ctx;
    if (!ctx) {
        fprintf(stderr, "ProcessBody unexpected error occur!");
        return CPlugin::PLUGIN_ERROR;
    }

    for (;;) {
        int rc = ctx->Handler();

        switch (rc) {
        case RET_OK:
        case RET_IGNORE:
            break;

        case RET_REMOTE:
            return CPlugin::PLUGIN_AGAIN;

        case RET_DONE:
            Ending(ctx);
            AsyncTask(ctx);
            return CPlugin::PLUGIN_OK;

        /* ToDo
        case RET_ERR:
            ctx->status = HANDLE_ERROR;
            return CPlugin::PUUGIN_ERROR;
            break;
        */

        default:
            return CPlugin::PLUGIN_OK;
        }
    }
    
    return CPlugin::PLUGIN_OK;
}

void CService::Ending(Context *ctx) {
    if (ctx) {
        ctx->EndRequest();
    }

    ctx->timer.stop();
    uint64_t use_time = ctx->timer.get_time() / 1000; // ns to ms
    ctx->is_timeout = use_time > DEFAULT_TIMEOUT_MS ? true : false;

    return;
}

void CService::AsyncTask(Context *ctx) {
    if (m_pAsync && m_pAsync->add_task(ctx) != 0) {
        fprintf(stderr, "async add task failed! execute immediately");
        AsyncHandler(ctx);
    }
}

void CService::AsyncHandler(Context *ctx) {
    if (!ctx) {
        fprintf(stderr, "AsyncHandler unexpected error occur!");
        return;
    }

    //ctx->timer stopped before
    if (ctx->is_timeout) {
        fprintf(stderr, "adx_config timeout! use time: %luus", ctx->timer.get_time());
    }
    ctx->AsyncHook();

    //destroy
    delete ctx;
    ctx = nullptr;

    return;
}

extern "C" {               
    plugin::CPlugin * create_instance() {
        return new CService();
    }
}

