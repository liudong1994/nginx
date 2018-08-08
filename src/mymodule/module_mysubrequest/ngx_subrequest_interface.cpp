#include <string>
#include <algorithm>
#include <iostream>
#include <map>

#include "utils.h"
#include "plugin.h"
#include "plugin_manager_wrapper.h"
#include "ngx_subrequest_interface.h"
#include "ngx_http_mysubrequest_module.h"

using namespace std;        // important std::replace
using namespace plugin;


#define safeAssert(_e) if(!(_e)) {                                  \
    r->headers_out.content_length_n = 0;                            \
    r->headers_out.status = NGX_HTTP_INTERNAL_SERVER_ERROR;         \
    return NGX_ERROR;                                               \
}


// get plugin by name && init CRequest
static ngx_int_t plugin_prepare(ngx_http_request_t *r);

// add request userkey to ngx_http_subrequest_t
static void plugin_add_variable(ngx_http_request_t *r);

// plugin need start subrequest
static ngx_int_t start_subrequest(ngx_http_request_t *r);
// plugin subrequest post handler
static ngx_int_t subrequest_post_handler(ngx_http_request_t *r, void *data, ngx_int_t rc);

// Convert ngx_http_request_t  To  CRequest
static int ngxr_to_crequest(ngx_http_request_t *r, CRequest *request);
// Convert CRequest  TO  ngx_http_request_t, send_header and output_filter
static int crequest_to_ngxr(CRequest *request, ngx_http_request_t *r, int nosend = 0);
// Convert ngx_http_request_t post body  TO  CRequest request_body
static int ngxrbody_to_crequestbody(ngx_http_request_t *r, string &post_body);



// function implement
ngx_int_t plugin_init_request(ngx_http_request_t *r, ngx_http_client_body_handler_pt post_handler) {
    if (r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD)) {
        return NGX_OK;
    }

    if (r->method & NGX_HTTP_POST) {
        return ngx_http_read_client_request_body(r, post_handler);
    }

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[mysubrequest] only GET/HEAD/POST request accepted");
    return NGX_ERROR;
}

ngx_int_t plugin_process_request(ngx_http_request_t *r) {
    ngx_int_t rc = plugin_prepare(r);
    if(rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[mysubrequest] plugin create CRequest error");
        return NGX_ERROR;
    }

    ngx_http_mysubrequest_ctx_t *ctx = (ngx_http_mysubrequest_ctx_t *)ngx_http_get_module_ctx(r, ngx_http_mysubrequest_module);
    CPlugin *plugin = (CPlugin *)ctx->plugin;
    CRequest *request = (CRequest*)ctx->request;

    rc = plugin->Handle(*request);
    if (rc == CPlugin::PLUGIN_AGAIN) {
        // plugin need subrequest
        plugin_add_variable(r);
        rc = start_subrequest(r);
        if(rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[mysubrequest] plugin_process_request plugin start subrequest error");
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    return NGX_OK;
}

ngx_int_t plugin_check_subrequest(ngx_http_request_t *r) {
    ngx_http_mysubrequest_ctx_t  *ctx = (ngx_http_mysubrequest_ctx_t *)ngx_http_get_module_ctx(r, ngx_http_mysubrequest_module);

    // check nginx subrequest process status
    subrequest_t *ngx_sub = (subrequest_t *)ctx->subrequests->elts;
    size_t subr_count = ctx->subrequests->nelts;
    for (size_t i=0; i<subr_count; ++i) {
        if (ngx_sub->subr->done != 1) {
            return NGX_AGAIN;
        }
        ngx_sub++;
    }
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,  "[mysubrequest] all subrequest done, subrequest_size: %d", subr_count);

    
    // copy ngixn ctx subrequests  to  CRequest subrequest
    CRequest *request = (CRequest *)ctx->request;
    ngx_sub = (subrequest_t *)ctx->subrequests->elts;

    for(size_t i=0; i<subr_count; ++i) {
        ngx_http_upstream_t *upstream = ngx_sub->subr->upstream;
        if(upstream == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[subrequest] plugin subrequest upstream null, location: \"%V\", args: \"%V\"", &ngx_sub->uri, &ngx_sub->args);
            return NGX_ERROR;
        }

        CSubrequest &c_sub = request->subrequests[i];
        c_sub.status = upstream->state->status;
        c_sub.sec = upstream->state->response_sec;
        c_sub.msec = upstream->state->response_msec;
        c_sub.response = string((char *)upstream->buffer.pos, upstream->buffer.last - upstream->buffer.pos);

        ngx_sub++;
    }

    return NGX_OK;
}

ngx_int_t plugin_post_subrequest(ngx_http_request_t *r) {
    ngx_http_mysubrequest_ctx_t *ctx = (ngx_http_mysubrequest_ctx_t *)ngx_http_get_module_ctx(r, ngx_http_mysubrequest_module);
    CRequest *request = (CRequest *)ctx->request;
    CPlugin *plugin = (CPlugin *)ctx->plugin;


    ngx_int_t rc = plugin->ProcessBody(*request);
    if (rc == CPlugin::PLUGIN_AGAIN) {
        plugin_add_variable(r);
        rc = start_subrequest(r);
        if(rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[mysubrequest] plugin_post_subrequest plugin start subrequest error");
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    return NGX_OK;
}

ngx_int_t plugin_final_request(ngx_http_request_t *r) {
    ngx_http_mysubrequest_ctx_t  *ctx = (ngx_http_mysubrequest_ctx_t *)ngx_http_get_module_ctx(r, ngx_http_mysubrequest_module);
    CRequest *request = (CRequest *)ctx->request;
    CPlugin *plugin = (CPlugin *)ctx->plugin;

    ngx_int_t rc = crequest_to_ngxr(request, r);    // TODO ngx_http_output_filter

    if (request) {
        plugin->Destroy(*request);
        delete request;
        ctx->request = NULL;
    }

    return rc;
}

ngx_int_t plugin_done_request(ngx_http_request_t *r) {
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[mysubrequest] done request, count = %d", r->main->count);

    return ngx_http_output_filter(r, NULL);
}

void plugin_destroy_request(ngx_http_request_t *r) {
    ngx_http_mysubrequest_ctx_t *ctx = (ngx_http_mysubrequest_ctx_t *)ngx_http_get_module_ctx(r, ngx_http_mysubrequest_module);
    CRequest *request = (CRequest *)ctx->request;
    CPlugin *plugin = (CPlugin *)ctx->plugin;

    if(request) {
        plugin->Destroy(*request);
        delete request;
        request = NULL;
    }

    return ;
}


// assist function
static ngx_int_t plugin_prepare(ngx_http_request_t *r) {
    // get request plugin name
    ngx_str_t plugin_name;
    plugin_name.data = (u_char *)"plugin_name";
    plugin_name.len = sizeof("plugin_name") - 1;

    ngx_uint_t hash_key = ngx_hash_key(plugin_name.data, plugin_name.len);
    ngx_http_variable_value_t *value_plugin_name = ngx_http_get_variable(r, &plugin_name, hash_key);        // TODO request set $plugin_name
    if (value_plugin_name == NULL || value_plugin_name->not_found || 0 == value_plugin_name->len) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[mysubrequest] plugin_name variable is not found!");
        return NGX_ERROR;
    }

    // get plugin by name
    CPlugin *plugin = (CPlugin *)plugin_getbyname((char *)value_plugin_name->data, value_plugin_name->len);
    if (plugin == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[mysubrequest] plugin handler init failed!");
        return NGX_ERROR;
    }

    // convert ngx_http_request_t to CRequest
    CRequest *request = new CRequest();
    if (request == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[mysubrequest] new CRequest failed!");
        return NGX_ERROR;
    }
    
    gettimeofday(&request->start_time, NULL);
    if (ngxr_to_crequest(r, request) != NGX_OK) {
        delete request;     // TODO shared_ptr
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[mysubrequest] convert ngx_http_request_t failed!");
        return NGX_ERROR;
    }

    // assignment ngx_http_mysubrequest_ctx variable
    ngx_http_mysubrequest_ctx_t *ctx = (ngx_http_mysubrequest_ctx_t *)ngx_http_get_module_ctx(r, ngx_http_mysubrequest_module);
    ctx->plugin = plugin;
    ctx->request = request;

    return NGX_OK;
}

static void plugin_add_variable(ngx_http_request_t *r) {        // TODO
    ngx_http_mysubrequest_ctx_t *ctx = (ngx_http_mysubrequest_ctx_t *)ngx_http_get_module_ctx(r, ngx_http_mysubrequest_module);
    CRequest *request = (CRequest *)ctx->request;

    ctx->user_key.data = (u_char *)request->user_key.c_str();
    ctx->user_key.len = request->user_key.size();

    return;
}

static ngx_int_t start_subrequest(ngx_http_request_t *r) {
    ngx_http_mysubrequest_ctx_t *ctx = (ngx_http_mysubrequest_ctx_t *)ngx_http_get_module_ctx(r, ngx_http_mysubrequest_module);
    CRequest *request = (CRequest *)ctx->request;

    // 1.create or init subrequests array
    ngx_int_t rc = NGX_OK;
    size_t subr_count = request->subrequests.size();
    if (ctx->subrequests) {
        rc = ngx_array_init(ctx->subrequests, r->pool, subr_count, sizeof(subrequest_t));
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[mysubrequest] ngx_array_init failed!");
            return NGX_ERROR;
        }
    } else {
        ctx->subrequests = ngx_array_create(r->pool, subr_count, sizeof(subrequest_t)); 
    }


    // 2.copy CRequest subrequest  to  ngixn ctx subrequests
    for(size_t i=0; i<subr_count; ++i) {
        // copy subrequest param
        subrequest_t *ngx_sub = (subrequest_t *)ngx_array_push(ctx->subrequests);
        if (ngx_sub == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[mysubrequest] ngx_array_push failed!");
            return NGX_ERROR;
        }

        CSubrequest &c_sub = request->subrequests[i];

        ngx_sub->uri.data = (u_char *)c_sub.uri.c_str();
        ngx_sub->uri.len = c_sub.uri.length();

        ngx_sub->args.data = (u_char *)c_sub.args.c_str();
        ngx_sub->args.len = c_sub.args.length();


        // start nginx subrequest
        ngx_http_post_subrequest_t *psr = (ngx_http_post_subrequest_t *)ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
        if(psr == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[mysubrequest] ngx_palloc ngx_http_post_subrequest_t failed!");
            return NGX_ERROR;
        }

        psr->handler = subrequest_post_handler;
        psr->data = ctx;

        rc = ngx_http_subrequest(r, &ngx_sub->uri, &ngx_sub->args, &ngx_sub->subr, psr, NGX_HTTP_SUBREQUEST_IN_MEMORY | NGX_HTTP_SUBREQUEST_WAITED);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[mysubrequest] ngx_http_subrequest failed!");
            return NGX_ERROR;
        }
    }

    ctx->subr_count = subr_count;
    return NGX_OK;
}

static ngx_int_t subrequest_post_handler(ngx_http_request_t *r, void *data, ngx_int_t rc) {     // TODO
    ngx_http_mysubrequest_ctx_t * ctx = (ngx_http_mysubrequest_ctx_t *)data;

    r->post_subrequest = NULL;
    ctx->subr_count--;

    if (ctx->subr_count > 0) {
        r->parent->write_event_handler = ngx_http_request_empty_handler;
        return NGX_OK;
    } else if (ctx->subr_count < 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[mysubrequest] subrequest_post_handler subr_count < 0, count: %d!", ctx->subr_count);
    }

    // start process
    r->parent->write_event_handler = ngx_http_core_run_phases;
    return NGX_OK;
}

static int ngxr_to_crequest(ngx_http_request_t *r, CRequest *request) {
    // get start_time
    gettimeofday(&request->start_time, NULL);

    // get uri
    request->uri.append((char *)r->uri.data, r->uri.len);

    // get param
    if (r->args.len > 0) {
        //string uri_dec = uri_decode(string((char *)r->args.data, r->args.len));
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[mysubrequest] ngxr_to_crequest uri: %V", &r->args);
        replace((char *)r->args.data, (char *)r->args.data + r->args.len, '\t', ' ');
        split_string(request->param, (char *)r->args.data, r->args.len, '&');
    }

    //get headers
    ngx_list_part_t *part = &r->headers_in.headers.part;
    ngx_table_elt_t *elts = (ngx_table_elt_t *)part->elts;
    for (size_t i = 0; ; ++i) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            elts = (ngx_table_elt_t *)part->elts;
            i = 0;
        }

        string key = string((char *)elts[i].key.data, elts[i].key.len);
        string val = string((char *)elts[i].value.data, elts[i].value.len);     // TODO срж╣
        request->headers_in.headers.push_back(make_pair(key, val));
    }

    //get host
    ngx_table_elt_t *host = r->headers_in.host;
    if (host && host->value.len) {
        request->headers_in.host = string((char *)host->value.data, host->value.len);;
    }

    //get user_agent
    ngx_table_elt_t *user_agent = r->headers_in.user_agent;
    if (user_agent && user_agent->value.len) {
        request->headers_in.user_agent = string((char *)user_agent->value.data, user_agent->value.len);
        replace(request->headers_in.user_agent.begin(), request->headers_in.user_agent.end(), '\t', ' ');
    }

    //get referer
    ngx_table_elt_t *referer = r->headers_in.referer;
    if (referer && referer->value.len) {
        request->headers_in.referer = string((char *)referer->value.data, referer->value.len);
    }

#ifdef NGX_HTTP_X_FORWARDED_FOR
    //get x_forwarded_for (need nginx http_realip_module)
    ngx_table_elt_t **forward = (ngx_table_elt_t **)r->headers_in.x_forwarded_for.elts;
    for (size_t i = 0; i < r->headers_in.x_forwarded_for.nelts; ++i) {
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "x_forwarded_for line %d: %V", i, &forward[i]->value);
        request->headers_in.x_forwarded_for.push_back(string((char *)forward[i]->value.data, forward[i]->value.len));
    }
#endif 

    //get x_real_ip
    ngx_table_elt_t *x_real_ip = r->headers_in.x_real_ip;
    if (x_real_ip && x_real_ip->value.len) {
        request->headers_in.x_real_ip = string((char *)x_real_ip->value.data, x_real_ip->value.len);
    }
    else {
        request->headers_in.x_real_ip = string((char *)r->connection->addr_text.data, r->connection->addr_text.len);
    }

    //get cookie
    ngx_table_elt_t **cookies = (ngx_table_elt_t**)r->headers_in.cookies.elts;
    for (size_t i = 0; i < r->headers_in.cookies.nelts; ++i) {
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Cookie line %d: %V", i, &cookies[i]->value);

        string cookie_str = string((char *)cookies[i]->value.data, cookies[i]->value.len);
        split_string(request->headers_in.cookies, (char *)cookies[i]->value.data, cookies[i]->value.len, ';');
    }

    //get http post request_body
    if (r->method & NGX_HTTP_POST) {
        int rc = ngxrbody_to_crequestbody(r, request->request_body);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngxr_to_crequest get post body error");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

static int crequest_to_ngxr(CRequest *request, ngx_http_request_t *r, int nosend) {     // TODO some filed have no value, don't add to r
    //set headers
    list<pair<string, string> >::iterator beg = request->headers_out.headers.begin();
    list<pair<string, string> >::iterator end = request->headers_out.headers.end();
    for (; beg != end; ++beg) {
        ngx_table_elt_t *field = (ngx_table_elt_t*)ngx_list_push(&r->headers_out.headers);
        safeAssert(field);

        field->hash = 1;

        field->key.len = beg->first.size();
        field->key.data = (u_char *)ngx_palloc(r->pool, field->key.len);
        safeAssert(field->key.data);
        ngx_memcpy(field->key.data, beg->first.c_str(), field->key.len);

        field->value.len = beg->second.size();
        field->value.data = (u_char *)ngx_palloc(r->pool, field->value.len);
        safeAssert(field->value.data);
        ngx_memcpy(field->value.data, beg->second.c_str(), field->value.len);
    }

    //set status_line
    ngx_str_t str;
    str.len = request->headers_out.status_line.size();
    str.data = (u_char *)ngx_palloc(r->pool, str.len);
    safeAssert(str.data);
    ngx_memcpy(str.data, request->headers_out.status_line.c_str(), str.len);
    r->headers_out.status_line = str;

    //set location
    ngx_table_elt_t *field = (ngx_table_elt_t*)ngx_list_push(&r->headers_out.headers);
    safeAssert(field);

    field->hash = 1;

    field->key.len = sizeof("Location") - 1;
    field->key.data = (u_char *)ngx_palloc(r->pool, field->key.len);
    safeAssert(field->key.data);
    ngx_memcpy(field->key.data, "Location", field->key.len);


    field->value.len = request->headers_out.location.size();
    field->value.data = (u_char *)ngx_palloc(r->pool, field->value.len);
    safeAssert(field->value.data);
    ngx_memcpy(field->value.data, request->headers_out.location.c_str(), request->headers_out.location.size());

    //set content_type
    str.len = request->headers_out.content_type.size();
    str.data = (u_char *)ngx_palloc(r->pool, str.len);
    safeAssert(str.data);
    ngx_memcpy(str.data, request->headers_out.content_type.c_str(), str.len);
    r->headers_out.content_type = str;
    r->headers_out.content_type_len = str.len;

    //set charset
    str.len = request->headers_out.charset.size();
    str.data = (u_char *)ngx_palloc(r->pool, str.len);
    safeAssert(str.data);
    ngx_memcpy(str.data, request->headers_out.charset.c_str(), str.len);
    r->headers_out.charset = str;

    //set content_length_n
    uint32_t body_size = request->response_body.size();
    r->headers_out.content_length_n = body_size;

    //set status
    uint32_t status = 0;
    uint32_t set_status = request->headers_out.status;
    if (set_status == 0) {
        if (body_size == 0) {
            status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        } else {
            status = NGX_HTTP_OK;
        }
    } else {
        status = set_status;
    }
    r->headers_out.status = status;

    if (nosend) {
        return NGX_OK;
    }

    ngx_int_t rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    ngx_buf_t *b;
    ngx_chain_t out;

    if (body_size == 0) {
        b = (ngx_buf_t *)ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
        safeAssert(b);
    } else {
        b = ngx_create_temp_buf(r->pool, request->response_body.size());
        safeAssert(b);

        ngx_memcpy(b->pos, request->response_body.c_str(), request->response_body.size());
        b->last = b->pos + request->response_body.size();
    }

    b->last_buf = 1;
    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "crequest_to_ngxr r->main->count: %d", r->main->count);
    return ngx_http_output_filter(r, &out);     // TODO
}

static int ngxrbody_to_crequestbody(ngx_http_request_t *r, string &post_body) {
    if (r->request_body == NULL || r->request_body->bufs == NULL) {
        return NGX_OK;
    }

    char *buf_temp = NULL;
    int buf_size = 0;

    for (ngx_chain_t *cl = r->request_body->bufs; cl; cl = cl->next) {
        if (ngx_buf_in_memory(cl->buf)) {
            post_body.append((char *)cl->buf->pos, cl->buf->last - cl->buf->pos);
            continue;
        }

        /* buf in file */
        int nbytes = cl->buf->file_last - cl->buf->file_pos;
        if (nbytes <= 0) {
            continue;
        }

        /* allocate lager temp buf */
        if (nbytes > buf_size) {
            if (buf_size > 0) delete[] buf_temp;

            buf_temp = new char[nbytes];
            buf_size = nbytes;
        }

        int buf_pos = 0;
        while (nbytes > 0) {
            int nread = ngx_read_file(cl->buf->file, (u_char *)buf_temp + buf_pos, cl->buf->file_last - cl->buf->file_pos, cl->buf->file_pos);

            if (nread < 0) { /* read temp file error */
                if (buf_size > 0) {
                    delete[] buf_temp;
                }
                return NGX_ERROR;
            }

            buf_pos += nread;
            nbytes -= nread;
        }

        post_body.append(buf_temp, buf_size);
    }

    if (buf_size > 0) {
        delete[] buf_temp;
    }
    return NGX_OK;
}

