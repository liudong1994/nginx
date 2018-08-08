#ifndef _BLACK_HANDLER_H_
#define _BLACK_HANDLER_H_

#include "context.h"

using std::string;



class CBlackHandler {
public:
    CBlackHandler();
    virtual ~CBlackHandler();

    virtual int Init();
    virtual Context *GetHandlerContext();

public:
    // �����ṩ�ķ���
    int Process();


    // instance
private:
    static CBlackHandler* m_pInstance;
public:
    static CBlackHandler* getInstance();
};

#endif /* _BLACK_HANDLER_H_ */

