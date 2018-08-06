#ifndef __PLUGIN_H__
#define __PLUGIN_H__

#include <string>
#include <vector>
#include <list>
#include <map>
#include <memory>
#include <stdint.h>
#include <sys/time.h>


namespace PLUGIN {

struct CSubrequest {
    std::string uri;
    std::string args;

    uint32_t status;
    uint32_t sec;
    uint32_t msec;
    std::string response;


    CSubrequest(const std::string& u, const std::string& param)
        :uri(u), args(param), status(0), sec(0), msec(0) {}
};

struct CHeadersIn {
    /* contain all header fields, include standard and non-standard fields */
    std::list<std::pair<std::string, std::string> > headers;        // TODO unordered_map

    std::string                     host;
    std::string                     user_agent;
    std::string                     referer;

    std::vector<std::string>        x_forwarded_for;
    std::string                     x_real_ip;

    std::map<std::string, std::string>  cookies;
};

struct CHeadersOut {
    /** 
     * additional header fields, push them with format below. 
     * "Set-Cookie" "a=1; b=2; c=3"
     * "User-Defined-Field" "Hello World"
     */
    std::list<std::pair<std::string, std::string> >  headers;       // TODO unordered_map

    uint32_t                status;
    std::string             status_line;

    std::string             location;           

    std::string             content_encoding;

    std::string             content_type;
    std::string             charset;
	
    CHeadersOut(uint32_t status=200):status(status){};
};


/** 
 * CRequest represents a http request in C++ domain, just like ngx_http_request in nginx domain. 
 * CRequest contains all run-time infomation in a http request's life cycle.
 */
struct CRequest {
    struct timeval  start_time;

    std::string     request_body;
    std::string	    uri;
    std::map<std::string, std::string>  param;
    CHeadersIn      headers_in;


    CHeadersOut     headers_out;
    std::string     response_body;
	

    std::string     user_key;                   /* used by upstream hash $USER_KEY */
    std::vector<CSubrequest> subrequests;       /* used by subrequest module */

    void *ctx;      /* plugin defined context, used by upstream and subrequest */
};


class CPlugin {
public:
    CPlugin() {}
    virtual ~CPlugin() {}
    
    enum {PLUGIN_OK = 0, PLUGIN_AGAIN = 1, PLUGIN_ERROR = -1};

public:
    // init plugin in nginx master process
    virtual int InitMaster(const std::string& plugin_conf) {
        (void)plugin_conf;
        return 0;
    }

    // init plugin in nginx worker process
    virtual int InitProcess(const std::string& plugin_conf) {
        (void)plugin_conf;
        return 0;
    }

    virtual int Handle(CRequest& request) { 
        (void)request;
        return 0; 
    }

    /* callback of upstream or subrequest. */
    virtual int ProcessBody(CRequest& request) {
        (void)request;

        return 0;
    }

    virtual void Destroy(CRequest & request) {
        (void)request;
    }

    virtual void ExitProcess() {}
    virtual void ExitMaster() {}

};


/**
 * In each plugin_so, provide a create_instance function.
 * extern "C" {
 *      CPlugin *create_instance() {
 *          return new CPlugin(); 
 *      }
 * }
 */


}

#endif 

