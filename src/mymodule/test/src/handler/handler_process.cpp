#include <utility>
#include <sstream>

#include "errcode.h"
#include "handler_process.h"
#include "context_process.h"


CBlackHandler* CBlackHandler::m_pInstance = new CBlackHandler();
CBlackHandler* CBlackHandler::getInstance(){ return m_pInstance; }

CBlackHandler::CBlackHandler() {

}

CBlackHandler::~CBlackHandler() {

}

Context *CBlackHandler::GetHandlerContext() {
    return new CBlackContext();
}

int CBlackHandler::Init() {

    return RET_OK;
}

int CBlackHandler::Process() {

    return RET_OK;
}

