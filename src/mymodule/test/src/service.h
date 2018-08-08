#ifndef _BLACK_SERVICE_H_
#define _BLACK_SERVICE_H_

#include <string>

#include <my_nginx/plugin.h>
#include "context.h"
#include "async_task.h"


class CService : public plugin::CPlugin {
public:
    CService();
    virtual ~CService();

public:
    virtual int InitProcess(const std::string &filepath) override;
    virtual int Handle(plugin::CRequest &r) override;
    virtual int ProcessBody(plugin::CRequest &r) override;
    virtual void ExitProcess() override;

protected:
    void Ending(Context *ctx);
    void AsyncTask(Context *ctx);

    /* init  function */
    int InitAsync();
    int InitHandler();

    /* async function */
    static void AsyncHandler(Context *ctx);

private:
    CAsyncTask<Context *> *m_pAsync;
};

#endif /* _BLACK_SERVICE_H_ */

