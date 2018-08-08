#ifndef _BLACK_CONTEXT_H_
#define _BLACK_CONTEXT_H_
#include <string>
#include <sstream>

#include "time_util.h"
#include "errcode.h"
#include "handler_process.h"
#include "context.h"

using std::string;
using std::stringstream;


class CBlackContext : public Context {
public:
    CBlackContext();
    virtual ~CBlackContext();

public:
    virtual void StartRequest() final;
    virtual void EndRequest() final;

    virtual int Handler() final;
    virtual void AsyncHook() final;


private:
    int ProcessHandler();

    string ErrMsg(const int errcode, const string &msg);
    void WriteLog();
};

#endif /* _BLACK_CONTEXT_H_ */

