#include "ngx_http_myupstream_module.h"


// 与上游服务器进行TCP通信的前缀标志
#define NGX_MYPROTOCOL_FLAG		        0xe8
#define NGX_MYPROTOCOL_OK               0
#define NGX_MYPROTOCOL_ERROR            -1
#define NGX_MYPROTOCOL_MOREDATA         -2
#define NGX_MYPROTOCOL_HEADER_LENGTH    sizeof(ngx_http_myprotocol_head_t)

typedef struct {
    int flag;
    int length;
    char body[];
} ngx_http_myprotocol_head_t;


// conf function
static void* ngx_http_myupstream_create_loc_conf(ngx_conf_t *cf);
static char* ngx_http_myupstream_merge_loc_conf(ngx_conf_t *cf, void *prev, void *conf);

// command funciton
static char *ngx_http_myupstream_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


// internal function
static ngx_int_t ngx_http_myupstream_handler(ngx_http_request_t *r);

static ngx_int_t ngx_http_myupstream_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_myupstream_reinit_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_myupstream_process_header(ngx_http_request_t *r);
static void ngx_http_myupstream_finalize_request(ngx_http_request_t *r, ngx_int_t rc);
static ngx_int_t ngx_http_myupstream_filter_init(void *data);
static ngx_int_t ngx_http_myupstream_filter(void *data, ssize_t bytes);


static ngx_int_t ngx_http_myprotocol_encode(ngx_str_t * data, ngx_pool_t * pool, ngx_buf_t ** buf);
static ngx_int_t ngx_http_myprotocol_decode(ngx_buf_t * buf);



// ngx_http_module_t接口
static ngx_http_module_t ngx_http_myupstream_module_ctx = {
    NULL,                                       /* preconfiguration */
    NULL,                                       /* postconfiguration */

    NULL,                                       /* create main configuration */
    NULL,                                       /* init main configuration */

    NULL,                                       /* create server configuration */
    NULL,                                       /* merge server configuration */

    ngx_http_myupstream_create_loc_conf,        /* create location configuration */
    ngx_http_myupstream_merge_loc_conf          /* merge location configuration */
};


static ngx_conf_bitmask_t  ngx_http_myupstream_next_upstream_masks[] = {        // TODO
    { ngx_string("error"), NGX_HTTP_UPSTREAM_FT_ERROR },
    { ngx_string("timeout"), NGX_HTTP_UPSTREAM_FT_TIMEOUT },
    { ngx_string("invalid_response"), NGX_HTTP_UPSTREAM_FT_INVALID_HEADER },
    { ngx_string("not_found"), NGX_HTTP_UPSTREAM_FT_HTTP_404 },
    { ngx_string("off"), NGX_HTTP_UPSTREAM_FT_OFF },
    { ngx_null_string, 0 }
};

// ngx_http_command_t接口
static ngx_command_t ngx_http_myupstream_commands[] = {
    { ngx_string("myupstream_pass"),
    NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
    ngx_http_myupstream_pass,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL },

    { ngx_string("myupstream_timeout"),
    NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_msec_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_myupstream_loc_conf_t, upstream.connect_timeout),
    NULL },

    { ngx_string("myupstream_buffer_size"),
    NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_size_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_myupstream_loc_conf_t, upstream.buffer_size),
    NULL },

    { ngx_string("next_myupstream"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
    ngx_conf_set_bitmask_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_myupstream_loc_conf_t, upstream.next_upstream),
    &ngx_http_myupstream_next_upstream_masks },

    ngx_null_command
};

ngx_module_t ngx_http_myupstream_module = {
    NGX_MODULE_V1,
    &ngx_http_myupstream_module_ctx,        /* module context */
    ngx_http_myupstream_commands,           /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};



// Function implementation
static void* ngx_http_myupstream_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_myupstream_loc_conf_t *conf = (ngx_http_myupstream_loc_conf_t *)ngx_palloc(cf->pool, sizeof(ngx_http_myupstream_loc_conf_t));
    if (NULL == conf) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "[plugin] ngx_http_myupstream_create_loc_conf failed");
        return NGX_CONF_ERROR;
    }

    conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;

    conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;

    conf->upstream.hide_headers = NGX_CONF_UNSET_PTR;
    conf->upstream.pass_headers = NGX_CONF_UNSET_PTR;

    /* the hardcoded values */
    conf->upstream.store_access = 0600;
    conf->upstream.buffering = 0;
    conf->upstream.bufs.num = 8;
    conf->upstream.bufs.size = ngx_pagesize;
    conf->upstream.busy_buffers_size = 2 * ngx_pagesize;
    conf->upstream.temp_file_write_size = 2 * ngx_pagesize;
    conf->upstream.max_temp_file_size = 1024 * 1024 * 1024;

    return conf;
}

static char* ngx_http_myupstream_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_myupstream_loc_conf_t *prev = parent;
    ngx_http_myupstream_loc_conf_t *conf = child;

    ngx_conf_merge_ptr_value(conf->upstream.local, prev->upstream.local, NULL);
    ngx_conf_merge_msec_value(conf->upstream.connect_timeout, prev->upstream.connect_timeout, 60000);

    conf->upstream.send_timeout = conf->upstream.connect_timeout;
    conf->upstream.read_timeout = conf->upstream.connect_timeout;

    ngx_conf_merge_size_value(conf->upstream.buffer_size, prev->upstream.buffer_size, 8096);
    ngx_conf_merge_bitmask_value(conf->upstream.next_upstream, prev->upstream.next_upstream,
        (NGX_CONF_BITMASK_SET
        |NGX_HTTP_UPSTREAM_FT_ERROR
        |NGX_HTTP_UPSTREAM_FT_TIMEOUT));

    if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) {
        conf->upstream.next_upstream = NGX_CONF_BITMASK_SET | NGX_HTTP_UPSTREAM_FT_OFF;
    }

    if (conf->upstream.upstream == NULL) {
        conf->upstream.upstream = prev->upstream.upstream;
    }

    return NGX_CONF_OK;
}

static char *ngx_http_myupstream_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    // TODO
    ngx_http_myupstream_loc_conf_t *mlcf = conf;
    if (mlcf->upstream.upstream) {
        return "is duplicate";
    }

    ngx_str_t *value = cf->args->elts;
    ngx_url_t url;
    ngx_memzero(&url, sizeof(ngx_url_t));
    url.url = value[1];
    url.no_resolve = 1;

    /* parse upstream server configuration, it may be server address or server group */
    mlcf->upstream.upstream = ngx_http_upstream_add(cf, &url, 0);
    if (mlcf->upstream.upstream == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_http_core_loc_conf_t *clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_myupstream_handler;

    if (clcf->name.data[clcf->name.len - 1] == '/') {
        clcf->auto_redirect = 1;
    }

    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_myupstream_handler(ngx_http_request_t *r) {
    if (!(r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    // 创建upstream
    if (ngx_http_upstream_create(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_myupstream_loc_conf_t *mlcf = ngx_http_get_module_loc_conf(r, ngx_http_myupstream_module);
    ngx_http_upstream_t *upstream = r->upstream;
    upstream->conf = &mlcf->upstream;

    // TODO
    ngx_str_set(&upstream->schema, "myupstream://");
    upstream->output.tag = (ngx_buf_tag_t) &ngx_http_myupstream_module;
    
    // 设置回调函数
    upstream->create_request = ngx_http_myupstream_create_request;
    upstream->reinit_request = ngx_http_myupstream_reinit_request;
    upstream->process_header = ngx_http_myupstream_process_header;
    upstream->finalize_request = ngx_http_myupstream_finalize_request;
    upstream->input_filter_init = ngx_http_myupstream_filter_init;
    upstream->input_filter = ngx_http_myupstream_filter;
    upstream->input_filter_ctx = r;

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[myupstream] start a upstream request");
    r->main->count++;
    ngx_http_upstream_init(r);

    return NGX_DONE;
}

static ngx_int_t ngx_http_myupstream_create_request(ngx_http_request_t *r) {
    // 构造发往上游服务器的请求
    ngx_buf_t                *b = NULL;
    ngx_chain_t              *cl = NULL;

    cl = ngx_alloc_chain_link(r->pool);

    if (cl == NULL) {
        return NGX_ERROR;
    }

    ngx_int_t rc = ngx_http_myprotocol_encode(&r->args, r->pool, &b);
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[myupstream] args encode ready,rc: %d, will send to backend \"%V\", ori_size: %d, new_size: %d",
        rc, &r->connection->addr_text, r->args.len, b->last - b->pos);

    cl->buf = b;
    cl->next = NULL;
    r->upstream->request_bufs = cl;

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[ahstream] plugin request has been ready, will send to backend \"%V\".", &r->connection->addr_text);

    return NGX_OK;
}

static ngx_int_t ngx_http_myupstream_reinit_request(ngx_http_request_t *r) {
    // ToDo
    // 出现错误后重新初始化HTTP请求 暂不实现

    return NGX_OK;
}

static ngx_int_t ngx_http_myupstream_process_header(ngx_http_request_t *r) {
    // 上游服务器包头处理函数 只需要解析出包头中长度参数即可（包体长度）
    ngx_http_upstream_t *u = r->upstream;
    int length = ngx_http_myprotocol_decode(&(u->buffer));

    if (length < 0) {
        if (length == NGX_MYPROTOCOL_ERROR) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "head flag error.");
        }
        else if (length == NGX_MYPROTOCOL_MOREDATA) {
            ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[myupstream] recieve response NOT complete, recieve again. length now: %d", u->buffer.last - u->buffer.pos);
            return NGX_AGAIN;
        }
        return NGX_ERROR;
    }

    u->headers_in.content_length_n = length;

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[myupstream] process header succes, body length: %d", length, &r->connection->addr_text);
    return NGX_OK;
}

static void ngx_http_myupstream_finalize_request(ngx_http_request_t *r, ngx_int_t rc) {
    ngx_http_upstream_t *u = r->upstream;

    if (rc == 0) {
        u->state->status = NGX_HTTP_OK;
    }

    return ;
}

static ngx_int_t ngx_http_myupstream_filter_init(void *data) {
    ngx_http_request_t  *r = data;
    ngx_http_upstream_t *u = r->upstream;

    u->length = u->headers_in.content_length_n;

    return NGX_OK;
}

static ngx_int_t ngx_http_myupstream_filter(void *data, ssize_t bytes) {
    // 上游服务返回的包体 处理函数
    ngx_http_request_t   *r = data;
    ngx_chain_t          *cl, **ll;

    ngx_http_upstream_t  *u = r->upstream;

    for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
        ll = &cl->next;
    }

    cl = ngx_chain_get_free_buf(r->pool, &u->free_bufs);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    *ll = cl;

    cl->buf->flush = 1;
    cl->buf->memory = 1;

    ngx_buf_t *b = &u->buffer;

    cl->buf->pos = b->last;
    b->last += bytes;
    cl->buf->last = b->last;
    cl->buf->tag = u->output.tag;

    u->length -= bytes;

    if (u->length == 0) {
        u->keepalive = 1;
        return NGX_OK;
    }

    return NGX_OK;
}

static ngx_int_t ngx_http_myprotocol_encode(ngx_str_t * data, ngx_pool_t * pool, ngx_buf_t ** buf)
{
    if (data == NULL || pool == NULL || buf == NULL) {
        return NGX_ERROR;
    }

    ngx_int_t len = NGX_MYPROTOCOL_HEADER_LENGTH + data->len;
    *buf = ngx_create_temp_buf(pool, len);

    if (*buf == NULL) {
        return NGX_ERROR;
    }

    /* encode request header */
    ngx_http_myprotocol_head_t head;
    head.flag = NGX_MYPROTOCOL_FLAG;
    head.length = htonl(data->len);
    (*buf)->last = ngx_copy((*buf)->last, (u_char*)&head, NGX_MYPROTOCOL_HEADER_LENGTH);
    /* encode request body */
    (*buf)->last = ngx_copy((*buf)->last, data->data, data->len);

    return NGX_MYPROTOCOL_OK;
}

static ngx_int_t ngx_http_myprotocol_decode(ngx_buf_t * buf)
{
    if (buf == NULL) {
        return NGX_ERROR;
    }

    size_t dataLen = buf->last - buf->pos;

    if (dataLen < NGX_MYPROTOCOL_HEADER_LENGTH) {
        return NGX_MYPROTOCOL_MOREDATA;
    }

    ngx_http_myprotocol_head_t * pstHead = (ngx_http_myprotocol_head_t*)buf->pos;

    if ((int)NGX_MYPROTOCOL_FLAG != pstHead->flag) {
        return NGX_MYPROTOCOL_ERROR;
    }

    size_t bodyLen = ntohl(pstHead->length);
    if (bodyLen > dataLen - NGX_MYPROTOCOL_HEADER_LENGTH) {
        return NGX_MYPROTOCOL_MOREDATA;
    }

    buf->pos += NGX_MYPROTOCOL_HEADER_LENGTH;
    return bodyLen;
}

