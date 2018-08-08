#ifndef _CONTEXT_H_
#define _CONTEXT_H_

#include <string>
#include <vector>
#include <my_nginx/plugin.h>
#include "time_util.h"


struct REMOTE_PAIR_T {
    std::string        args;
    void              *ctx;

    const std::string *response;
    uint32_t           status;
    uint32_t           time;

    REMOTE_PAIR_T():
        ctx(nullptr),
        response(nullptr),
        status(0),
        time(0)
    {}
};

struct REMOTE_T {
    std::vector<REMOTE_PAIR_T> pairs;

    REMOTE_PAIR_T *add_pair() {
        pairs.push_back(REMOTE_PAIR_T());
        return &pairs.back();
    }
};

class Context {
public:
    Context(): status(-1), r(nullptr), is_timeout(false) {
    }

    virtual ~Context() {}

public:
    virtual int Handler() = 0;
    virtual void StartRequest() = 0;
    virtual void EndRequest() = 0;

    virtual void AsyncHook() = 0;


public:
    int         status;     // µ±Ç°ÇëÇó×´Ì¬
    plugin::CRequest *r;
    CClockTime  timer;
    bool        is_timeout;

    REMOTE_T    remote;
};

#endif /* _CONTEXT_H_ */

