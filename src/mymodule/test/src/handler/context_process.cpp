#include <iostream>
#include "context_process.h"
#include "handler_process.h"

const string SERVER_UPDATE = "/server/update";
const string RET_HANDLE_OK = "Process Handler OK";


enum ADX_BLACK_STATUS{
    // pre
    UNINITIALIZE = -1,

    // update
    INITIALIZE_UPDATE_OK,

    // done
    HANDLE_OK,
    HANDLE_ERROR
};


CBlackContext::CBlackContext() {

}

CBlackContext::~CBlackContext() {

}

void CBlackContext::StartRequest() {
    if (SERVER_UPDATE == r->uri) {
        status = INITIALIZE_UPDATE_OK;
    } else {
        status = UNINITIALIZE;
    }
}

void CBlackContext::EndRequest() {
}

int CBlackContext::Handler() {
    int rc = RET_OK;

    switch (status) {
    case INITIALIZE_UPDATE_OK:
        rc = ProcessHandler();
        break;

    case HANDLE_OK:
    case HANDLE_ERROR:
        rc = RET_DONE;
        break;

    default:
        r->response_body = "uri not support";
        rc = RET_ERR;
    }

    // 内部状态处理
    if (rc == RET_ERR) {
        status = HANDLE_ERROR;
        rc = RET_IGNORE;
    }

    return rc;
}

int CBlackContext::ProcessHandler() {
    int rc = CBlackHandler::getInstance()->Process();
    if (rc == RET_ERR) {
        std::cerr << "Process failed!" << std::endl;
        r->response_body = ErrMsg(INITIALIZE_UPDATE_OK, "Process error!");
        return RET_ERR;
    } else if (rc == RET_REMOTE) {
        std::cerr << "Process return remote!" << std::endl;
        r->response_body = ErrMsg(INITIALIZE_UPDATE_OK, "Process return error!");
        return RET_ERR;
    }

    r->response_body = RET_HANDLE_OK;
    status = HANDLE_OK;
    std::cerr << "Process success: response: " << r->response_body << std::endl;
    return RET_OK;
}

void CBlackContext::AsyncHook() {
    WriteLog();
}

void CBlackContext::WriteLog() {
    return;
}

string CBlackContext::ErrMsg(const int errcode, const string &msg) {
    stringstream ss;
    ss << "{\"errno\":" << errcode<< "," << "\"msg\":\"" << msg << "\"}";
    return ss.str();
}

