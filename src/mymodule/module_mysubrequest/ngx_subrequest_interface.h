#ifndef __NGX_MYSUBREQUEST_INTERFACE_H__
#define __NGX_MYSUBREQUEST_INTERFACE_H__

#if __cplusplus
extern "C" {
#endif

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/* request api */


/*
* @return
*      NGX_OK      GET request;
*                  POST request with body read completely. 
*      NGX_AGAIN   POST request and body read incompletely.
*      NGX_ERROR   POST request read client request body error.
*/
ngx_int_t plugin_init_request(ngx_http_request_t *r, ngx_http_client_body_handler_pt post_handler);


/*
* @return 
*      NGX_OK      plugin process request sucess   
*      NGX_AGAIN   plugin has subrequest to be processed
*      NGX_ERROR   plugin process reuquest fail
*/
ngx_int_t plugin_process_request(ngx_http_request_t *r);


/*
 * @return 
 *      NGX_OK          all subrequests have been done
 *      NGX_AGAIN       some subrequests haven't been done
 */
ngx_int_t plugin_check_subrequest(ngx_http_request_t *r);


/*
 * @return 
 *      NGX_OK      plugin process request sucess   
 *      NGX_AGAIN   plugin has subrequest to be processed
 *      NGX_ERROR   plugin process reuquest fail
 */
ngx_int_t plugin_post_subrequest(ngx_http_request_t *r);


/*
 * @return 
 *      NGX_OK          output filter body complete
 *      NGX_AGAIN       output filter body incomplete
 *      NGX_ERROR       plugin finalize request fail
 */
ngx_int_t plugin_final_request(ngx_http_request_t *r);


/*
 * @return 
 *      NGX_OK          output filter body complete
 *      NGX_AGAIN       output filter body incomplete
 *      NGX_ERROR       plugin finalize request fail
 */
ngx_int_t plugin_done_request(ngx_http_request_t *r);


/* destroy plugin */
void plugin_destroy_request(ngx_http_request_t *r);


#if __cplusplus
}
#endif

#endif 

