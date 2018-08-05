
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static void ngx_http_read_client_request_body_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_do_read_client_request_body(ngx_http_request_t *r);
static ngx_int_t ngx_http_write_request_body(ngx_http_request_t *r,
    ngx_chain_t *body);
static ngx_int_t ngx_http_read_discarded_request_body(ngx_http_request_t *r);
static ngx_int_t ngx_http_test_expect(ngx_http_request_t *r);


/*
 * on completion ngx_http_read_client_request_body() adds to
 * r->request_body->bufs one or two bufs:
 *    *) one memory buf that was preread in r->header_in;
 *    *) one memory or file buf that contains the rest of the body
 */

// 对于HTTP模块而言 调用一次本函数即可接收HTTP请求完整包体
ngx_int_t
ngx_http_read_client_request_body(ngx_http_request_t *r,
    ngx_http_client_body_handler_pt post_handler)
{
    size_t                     preread;
    ssize_t                    size;
    ngx_buf_t                 *b;
    ngx_chain_t               *cl, **next;
    ngx_temp_file_t           *tf;
    ngx_http_request_body_t   *rb;
    ngx_http_core_loc_conf_t  *clcf;

    // 将请求的原始请求计数加1
    r->main->count++;

    // 检查本请求是否接收过数据 或者 丢弃包体状态   上述状态都不满足在进行包体的读取
    if (r->request_body || r->discard_body) {
        post_handler(r);
        return NGX_OK;
    }

    if (ngx_http_test_expect(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    // 分配接收包体的结构体ngx_http_request_body_t
    rb = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
    if (rb == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->request_body = rb;

    // 如果content_length长度小于等于0 不用接收包体 直接调用客户端的post_handler方法 表示接收包体已经处理完毕
    if (r->headers_in.content_length_n < 0) {
        post_handler(r);
        return NGX_OK;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (r->headers_in.content_length_n == 0) {

        if (r->request_body_in_file_only) {
            tf = ngx_pcalloc(r->pool, sizeof(ngx_temp_file_t));
            if (tf == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            tf->file.fd = NGX_INVALID_FILE;
            tf->file.log = r->connection->log;
            tf->path = clcf->client_body_temp_path;
            tf->pool = r->pool;
            tf->warn = "a client request body is buffered to a temporary file";
            tf->log_level = r->request_body_file_log_level;
            tf->persistent = r->request_body_in_persistent_file;
            tf->clean = r->request_body_in_clean_file;

            if (r->request_body_file_group_access) {
                tf->access = 0660;
            }

            rb->temp_file = tf;

            if (ngx_create_temp_file(&tf->file, tf->path, tf->pool,
                                     tf->persistent, tf->clean, tf->access)
                != NGX_OK)
            {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }

        post_handler(r);

        return NGX_OK;
    }

    /*
        将客户端传入post_handler存入ngx_http_request_body_t结构体的成员变量内
        因为接收包体不知道那次事件触发才能完成 完成后才能调用post_handler方法
    */
    rb->post_handler = post_handler;

    /*
     * set by ngx_pcalloc():
     *
     *     rb->bufs = NULL;
     *     rb->buf = NULL;
     *     rb->rest = 0;
     */

    preread = r->header_in->last - r->header_in->pos;

    if (preread) {
        
        // 之前接收HTTP头部的时候 接收到了部分HTTP包体数据
        /* there is the pre-read part of the request body */

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http client request body preread %uz", preread);

        b = ngx_calloc_buf(r->pool);
        if (b == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        b->temporary = 1;
        b->start = r->header_in->pos;
        b->pos = r->header_in->pos;
        b->last = r->header_in->last;
        b->end = r->header_in->end;

        rb->bufs = ngx_alloc_chain_link(r->pool);
        if (rb->bufs == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        rb->bufs->buf = b;
        rb->bufs->next = NULL;

        rb->buf = b;

        if ((off_t) preread >= r->headers_in.content_length_n) {

            // 之前多接收的数据已经完整的接收了HTTP包体数据了 直接回调HTTP模块传入的post_handler方法
            /* the whole request body was pre-read */

            r->header_in->pos += (size_t) r->headers_in.content_length_n;
            r->request_length += r->headers_in.content_length_n;
            b->last = r->header_in->pos;

            if (r->request_body_in_file_only) {
                if (ngx_http_write_request_body(r, rb->bufs) != NGX_OK) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
            }

            post_handler(r);

            return NGX_OK;
        }

        /*
         * to not consider the body as pipelined request in
         * ngx_http_set_keepalive()
         */
        r->header_in->pos = r->header_in->last;

        r->request_length += preread;

        // HTTP包体还需要接收的数据量
        rb->rest = r->headers_in.content_length_n - preread;

        if (rb->rest <= (off_t) (b->end - b->last)) {

            // HTTP请求的headers_in缓冲区剩余空间可以存放HTTP包体 不用在申请新的空间了
            /* the whole request body may be placed in r->header_in */

            rb->to_write = rb->bufs;

            // 设置可读事件执行方法 后面再触发读事件调用指定的读取包体函数
            r->read_event_handler = ngx_http_read_client_request_body_handler;

            return ngx_http_do_read_client_request_body(r);
        }

        next = &rb->bufs->next;

    } else {
        b = NULL;
        rb->rest = r->headers_in.content_length_n;
        next = &rb->bufs;
    }

    // 根据配置文件申请存放包体缓冲区
    size = clcf->client_body_buffer_size;
    size += size >> 2;

    if (rb->rest < size) {
        size = (ssize_t) rb->rest;

        // 要求HTTP包体在一个buf里面 就需要加上 之前在接收HTTP头部时可能多接收的HTTP包体
        if (r->request_body_in_single_buf) {
            size += preread;
        }

    } else {
        size = clcf->client_body_buffer_size;

        /* disable copying buffer for r->request_body_in_single_buf */
        b = NULL;
    }

    rb->buf = ngx_create_temp_buf(r->pool, size);
    if (rb->buf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    cl->buf = rb->buf;
    cl->next = NULL;

    if (b && r->request_body_in_single_buf) {
        // HTTP包体需要放在一个缓冲区中 拷贝之前接收HTTP头部时多接收的包体数据
        size = b->last - b->pos;
        ngx_memcpy(rb->buf->pos, b->pos, size);
        rb->buf->last += size;

        next = &rb->bufs;
    }

    *next = cl;

    if (r->request_body_in_file_only || r->request_body_in_single_buf) {
        rb->to_write = rb->bufs;

    } else {
        rb->to_write = rb->bufs->next ? rb->bufs->next : rb->bufs;
    }

    // 设置可读事件执行方法(可读或者读事件定时器超时)
    r->read_event_handler = ngx_http_read_client_request_body_handler;

    return ngx_http_do_read_client_request_body(r);
}


// HTTP包体 读事件触发调用方法
static void
ngx_http_read_client_request_body_handler(ngx_http_request_t *r)
{
    ngx_int_t  rc;

	// 判断连接是否超时
    if (r->connection->read->timedout) {
        r->connection->timedout = 1;
        ngx_http_finalize_request(r, NGX_HTTP_REQUEST_TIME_OUT);
        return;
    }

	// 调用真正接收TCP数据的函数
    rc = ngx_http_do_read_client_request_body(r);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        ngx_http_finalize_request(r, rc);
    }
}


// 读取TCP连接上得缓冲区字节流
static ngx_int_t
ngx_http_do_read_client_request_body(ngx_http_request_t *r)
{
    size_t                     size;
    ssize_t                    n;
    ngx_buf_t                 *b;
    ngx_connection_t          *c;
    ngx_http_request_body_t   *rb;
    ngx_http_core_loc_conf_t  *clcf;

    c = r->connection;
    rb = r->request_body;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http read client request body");

    for ( ;; ) {
        for ( ;; ) {
            if (rb->buf->last == rb->buf->end) {

				// buf缓冲区没有空闲空间了 将数据写入到文件中
                if (ngx_http_write_request_body(r, rb->to_write) != NGX_OK) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                rb->to_write = rb->bufs->next ? rb->bufs->next : rb->bufs;
				// 缓冲区复用 将last指针指向start起始点
                rb->buf->last = rb->buf->start;
            }

            size = rb->buf->end - rb->buf->last;

            if ((off_t) size > rb->rest) {
                size = (size_t) rb->rest;
            }

			// 调用recv获取数据
            n = c->recv(c, rb->buf->last, size);

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "http client request body recv %z", n);

            if (n == NGX_AGAIN) {
                break;
            }

            if (n == 0) {
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "client closed prematurely connection");
            }

			// recv出错 返回400错误
            if (n == 0 || n == NGX_ERROR) {
                c->error = 1;
                return NGX_HTTP_BAD_REQUEST;
            }

			// 接收到正常HTTP包体数据 更新相关数据
            rb->buf->last += n;
            rb->rest -= n;
            r->request_length += n;

            if (rb->rest == 0) {
                break;
            }

            if (rb->buf->last < rb->buf->end) {
                break;
            }
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http client request body rest %O", rb->rest);

		// 数据接收完毕
        if (rb->rest == 0) {
            break;
        }

		// 数据没有接收完毕 并且 当前套接字没有可读字符流
        if (!c->read->ready) {
			// 添加定时器
            clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
            ngx_add_timer(c->read, clcf->client_body_timeout);

			// 添加读事件到epoll中 等待HTTP包体数据的到来
            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            return NGX_AGAIN;
        }
    }

	// 到这里说明已经接收完毕HTTP包体数据了

	// 如果当前连接添加着定时器 这里需要删除 防止不必要的定时器触发
    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (rb->temp_file || r->request_body_in_file_only) {

        /* save the last part */

		// 将缓冲区中剩余的数据写入文件
        if (ngx_http_write_request_body(r, rb->to_write) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        b = ngx_calloc_buf(r->pool);
        if (b == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        b->in_file = 1;
        b->file_pos = 0;
        b->file_last = rb->temp_file->file.offset;
        b->file = &rb->temp_file->file;

        if (rb->bufs->next) {
            rb->bufs->next->buf = b;

        } else {
            rb->bufs->buf = b;
        }
    }

    if (rb->bufs->next
        && (r->request_body_in_file_only || r->request_body_in_single_buf))
    {
        rb->bufs = rb->bufs->next;
    }

	// HTTP包体已经接收完毕 读事件不需要在进行处理 设置为ngx_http_block_reading
    r->read_event_handler = ngx_http_block_reading;

	// 执行HTTP模块提供的post_handler方法
    rb->post_handler(r);

    return NGX_OK;
}


static ngx_int_t
ngx_http_write_request_body(ngx_http_request_t *r, ngx_chain_t *body)
{
    ssize_t                    n;
    ngx_temp_file_t           *tf;
    ngx_http_request_body_t   *rb;
    ngx_http_core_loc_conf_t  *clcf;

    rb = r->request_body;

    if (rb->temp_file == NULL) {
        tf = ngx_pcalloc(r->pool, sizeof(ngx_temp_file_t));
        if (tf == NULL) {
            return NGX_ERROR;
        }

        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        tf->file.fd = NGX_INVALID_FILE;
        tf->file.log = r->connection->log;
        tf->path = clcf->client_body_temp_path;
        tf->pool = r->pool;
        tf->warn = "a client request body is buffered to a temporary file";
        tf->log_level = r->request_body_file_log_level;
        tf->persistent = r->request_body_in_persistent_file;
        tf->clean = r->request_body_in_clean_file;

        if (r->request_body_file_group_access) {
            tf->access = 0660;
        }

        rb->temp_file = tf;
    }

    n = ngx_write_chain_to_temp_file(rb->temp_file, body);

    /* TODO: n == 0 or not complete and level event */

    if (n == NGX_ERROR) {
        return NGX_ERROR;
    }

    rb->temp_file->offset += n;

    return NGX_OK;
}


ngx_int_t
ngx_http_discard_request_body(ngx_http_request_t *r)
{
    ssize_t       size;
    ngx_event_t  *rev;

	// 检查是否最原始请求(非原始请求 不存在处理HTTP包体的概念) 或者 已经处理过丢弃包体操作了
    if (r != r->main || r->discard_body) {
        return NGX_OK;
    }

    if (ngx_http_test_expect(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rev = r->connection->read;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0, "http set discard body");

	// 丢弃包体不需要考虑超时问题
    if (rev->timer_set) {
        ngx_del_timer(rev);
    }

    if (r->headers_in.content_length_n <= 0 || r->request_body) {
		/*
			如果HTTP包体长度小于等于0 或者 request_body不为NULL 即已经接收过包体了
			这个时候就可以直接返回NGX_OK了
		*/
        return NGX_OK;
    }

    size = r->header_in->last - r->header_in->pos;

    if (size) {
        if (r->headers_in.content_length_n > size) {
			// 在接收HTTP头部的时候 接收了部分HTTP包体数据
            r->header_in->pos += size;
            r->headers_in.content_length_n -= size;

        } else {
			// 在接收HTTP头部的时候 已经将HTTP包体的数据接收完毕了 直接返回NGX_OK即可
            r->header_in->pos += (size_t) r->headers_in.content_length_n;
            r->headers_in.content_length_n = 0;
            return NGX_OK;
        }
    }

	// 设置读事件方法 为下次继续接收HTTP包体数据做准备
    r->read_event_handler = ngx_http_discarded_request_body_handler;

	// 添加读事件到epoll
    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

	// 调用ngx_http_read_discarded_request_body接收包体 (本方法和ngx_http_discarded_request_body_handler方法提取的公共方法)
    if (ngx_http_read_discarded_request_body(r) == NGX_OK) {
		// 已经接收完完整的包体了 将请求的lingering_close延时关闭标志位设为0 表示不需要为了包体的接收而延时关闭了
        r->lingering_close = 0;

    } else {
		/*
			先把引用计数加1 防止这边还在丢弃包体 而其他事件却已让请求意外销毁 引发严重错误
			同时把ngx_http_request_t结构体的discard_body标志位置为1 表示正在丢弃包体 并返回NGX_OK
			当然 这时的NGX_OK绝不表示已经成功地接收完包体 只是说明ngx_http_discard_request_body执行完毕而已
		*/
        r->count++;
        r->discard_body = 1;
    }

    return NGX_OK;
}


void
ngx_http_discarded_request_body_handler(ngx_http_request_t *r)
{
    ngx_int_t                  rc;
    ngx_msec_t                 timer;
    ngx_event_t               *rev;
    ngx_connection_t          *c;
    ngx_http_core_loc_conf_t  *clcf;

    c = r->connection;
    rev = c->read;

    // 首先检查连接是否超时
    if (rev->timedout) {
        c->timedout = 1;
        c->error = 1;
        ngx_http_finalize_request(r, NGX_ERROR);
        return;
    }

    if (r->lingering_time) {
        timer = (ngx_msec_t) (r->lingering_time - ngx_time());

        if (timer <= 0) {
            r->discard_body = 0;
            r->lingering_close = 0;
            ngx_http_finalize_request(r, NGX_ERROR);
            return;
        }

    } else {
        timer = 0;
    }

    // 调用丢弃数据的函数
    rc = ngx_http_read_discarded_request_body(r);

    if (rc == NGX_OK) {
        r->discard_body = 0;
        r->lingering_close = 0;
        ngx_http_finalize_request(r, NGX_DONE);
        return;
    }

    /* rc == NGX_AGAIN */

    // 仍然需要接收数据 继续添加epoll读事件感兴趣
    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        c->error = 1;
        ngx_http_finalize_request(r, NGX_ERROR);
        return;
    }

    if (timer) {

        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        timer *= 1000;

        if (timer > clcf->lingering_timeout) {
            timer = clcf->lingering_timeout;
        }

        ngx_add_timer(rev, timer);
    }
}


static ngx_int_t
ngx_http_read_discarded_request_body(ngx_http_request_t *r)
{
    size_t   size;
    ssize_t  n;
    u_char   buffer[NGX_HTTP_DISCARD_BUFFER_SIZE];

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http read discarded body");

    for ( ;; ) {
        if (r->headers_in.content_length_n == 0) {
            /*
                丢弃包体时request_body其实是NULL指针 content_length_n表示还需要丢弃(接收)的包体长度
                并设置读方法为ngx_http_block_reading 表示对读事件不再感兴趣
            */
            r->read_event_handler = ngx_http_block_reading;
            return NGX_OK;
        }

        // 没有可读内容
        if (!r->connection->read->ready) {
            return NGX_AGAIN;
        }

        // 确定本次接收数据的长度 如果大于NGX_HTTP_DISCARD_BUFFER_SIZE 则使用NGX_HTTP_DISCARD_BUFFER_SIZE字段值
        size = (r->headers_in.content_length_n > NGX_HTTP_DISCARD_BUFFER_SIZE) ?
                   NGX_HTTP_DISCARD_BUFFER_SIZE:
                   (size_t) r->headers_in.content_length_n;

        n = r->connection->recv(r->connection, buffer, size);

        if (n == NGX_ERROR) {
            r->connection->error = 1;
            return NGX_OK;
        }

        if (n == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        if (n == 0) {
            return NGX_OK;
        }

        // 接收到有效数据 剩余准备接收的数据减去刚才接收的数据
        r->headers_in.content_length_n -= n;
    }
}


static ngx_int_t
ngx_http_test_expect(ngx_http_request_t *r)
{
    ngx_int_t   n;
    ngx_str_t  *expect;

    if (r->expect_tested
        || r->headers_in.expect == NULL
        || r->http_version < NGX_HTTP_VERSION_11)
    {
        return NGX_OK;
    }

    r->expect_tested = 1;

    expect = &r->headers_in.expect->value;

    if (expect->len != sizeof("100-continue") - 1
        || ngx_strncasecmp(expect->data, (u_char *) "100-continue",
                           sizeof("100-continue") - 1)
           != 0)
    {
        return NGX_OK;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "send 100 Continue");

    n = r->connection->send(r->connection,
                            (u_char *) "HTTP/1.1 100 Continue" CRLF CRLF,
                            sizeof("HTTP/1.1 100 Continue" CRLF CRLF) - 1);

    if (n == sizeof("HTTP/1.1 100 Continue" CRLF CRLF) - 1) {
        return NGX_OK;
    }

    /* we assume that such small packet should be send successfully */

    return NGX_ERROR;
}
