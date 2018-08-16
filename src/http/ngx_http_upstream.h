
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_UPSTREAM_H_INCLUDED_
#define _NGX_HTTP_UPSTREAM_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_event_pipe.h>
#include <ngx_http.h>


#define NGX_HTTP_UPSTREAM_FT_ERROR           0x00000002
#define NGX_HTTP_UPSTREAM_FT_TIMEOUT         0x00000004
#define NGX_HTTP_UPSTREAM_FT_INVALID_HEADER  0x00000008
#define NGX_HTTP_UPSTREAM_FT_HTTP_500        0x00000010
#define NGX_HTTP_UPSTREAM_FT_HTTP_502        0x00000020
#define NGX_HTTP_UPSTREAM_FT_HTTP_503        0x00000040
#define NGX_HTTP_UPSTREAM_FT_HTTP_504        0x00000080
#define NGX_HTTP_UPSTREAM_FT_HTTP_404        0x00000100
#define NGX_HTTP_UPSTREAM_FT_UPDATING        0x00000200
#define NGX_HTTP_UPSTREAM_FT_BUSY_LOCK       0x00000400
#define NGX_HTTP_UPSTREAM_FT_MAX_WAITING     0x00000800
#define NGX_HTTP_UPSTREAM_FT_NOLIVE          0x40000000
#define NGX_HTTP_UPSTREAM_FT_OFF             0x80000000

#define NGX_HTTP_UPSTREAM_FT_STATUS          (NGX_HTTP_UPSTREAM_FT_HTTP_500  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_502  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_503  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_504  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_404)

#define NGX_HTTP_UPSTREAM_INVALID_HEADER     40


#define NGX_HTTP_UPSTREAM_IGN_XA_REDIRECT    0x00000002
#define NGX_HTTP_UPSTREAM_IGN_XA_EXPIRES     0x00000004
#define NGX_HTTP_UPSTREAM_IGN_EXPIRES        0x00000008
#define NGX_HTTP_UPSTREAM_IGN_CACHE_CONTROL  0x00000010
#define NGX_HTTP_UPSTREAM_IGN_SET_COOKIE     0x00000020
#define NGX_HTTP_UPSTREAM_IGN_XA_LIMIT_RATE  0x00000040
#define NGX_HTTP_UPSTREAM_IGN_XA_BUFFERING   0x00000080
#define NGX_HTTP_UPSTREAM_IGN_XA_CHARSET     0x00000100


typedef struct {
    ngx_msec_t                       bl_time;
    ngx_uint_t                       bl_state;

    ngx_uint_t                       status;
    time_t                           response_sec;
    ngx_uint_t                       response_msec;
    off_t                            response_length;

    ngx_str_t                       *peer;
} ngx_http_upstream_state_t;


typedef struct {
    ngx_hash_t                       headers_in_hash;
    ngx_array_t                      upstreams;
                                             /* ngx_http_upstream_srv_conf_t */
} ngx_http_upstream_main_conf_t;

typedef struct ngx_http_upstream_srv_conf_s  ngx_http_upstream_srv_conf_t;

typedef ngx_int_t (*ngx_http_upstream_init_pt)(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us);
typedef ngx_int_t (*ngx_http_upstream_init_peer_pt)(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);


typedef struct {
    ngx_http_upstream_init_pt        init_upstream;
    ngx_http_upstream_init_peer_pt   init;
    void                            *data;
} ngx_http_upstream_peer_t;


typedef struct {
    ngx_addr_t                      *addrs;
    ngx_uint_t                       naddrs;
    ngx_uint_t                       weight;
    ngx_uint_t                       max_fails;
    time_t                           fail_timeout;

    unsigned                         down:1;
    unsigned                         backup:1;
} ngx_http_upstream_server_t;


#define NGX_HTTP_UPSTREAM_CREATE        0x0001
#define NGX_HTTP_UPSTREAM_WEIGHT        0x0002
#define NGX_HTTP_UPSTREAM_MAX_FAILS     0x0004
#define NGX_HTTP_UPSTREAM_FAIL_TIMEOUT  0x0008
#define NGX_HTTP_UPSTREAM_DOWN          0x0010
#define NGX_HTTP_UPSTREAM_BACKUP        0x0020


struct ngx_http_upstream_srv_conf_s {
    ngx_http_upstream_peer_t         peer;
    void                           **srv_conf;

    ngx_array_t                     *servers;  /* ngx_http_upstream_server_t */

    ngx_uint_t                       flags;
    ngx_str_t                        host;
    u_char                          *file_name;
    ngx_uint_t                       line;
    in_port_t                        port;
    in_port_t                        default_port;
};


typedef struct {
    // 当在ngx_http_upstream_t结构体中没有实现resolved 成员时  upstream这个结构体才会生效 它会定义上游服务器的配置
    ngx_http_upstream_srv_conf_t    *upstream;

    // 建立TCP 连接的超时时间，实际上就是写事件添加到定时器中时设置的超时时间
    ngx_msec_t                       connect_timeout;
    // 发送请求的超时时间。通常就是写事件添加到定时器中设置的超时时间
    ngx_msec_t                       send_timeout;
    // 接收响应的超时时间。通常就是读事件添加到定时器中设置的超时时间
    ngx_msec_t                       read_timeout;
    // 目前无意义
    ngx_msec_t                       timeout;

    // TCP的SO_SNOLOWAT选项 表示发送缓冲区的下限
    size_t                           send_lowat;
    /* 
        定义了接收头部的缓冲区分配的内存大小（ngx_http_upstream_t 中的buffer 缓冲区）
        当不转发响应给下游或者在buffering 标志位为0的情况下转发响应时 它同样表示接收包体的缓冲区大小
    */
    size_t                           buffer_size;

    /*
        仅当buffering标志位为1  并且向下游转发响应时生效
        它会设置到ngx_event_pipe_t结构体的busy_size成员中
    */
    size_t                           busy_buffers_size;
    /* 
        在buffering标志位为1时 如果上游速度快于下游速度 将有可能把来自上游的响应存储到临时文件中
        而max_temp_file_size 指定了临时文件的最大长度 
        实际上 它将限制ngx_event_pipe_t结构体中的temp_file
    */
    size_t                           max_temp_file_size;
    // 表示将缓冲区中的响应写入临时文件时一次写入字符流的最大长度
    size_t                           temp_file_write_size;

    // 以下3个成员目前都没有任何意义
    size_t                           busy_buffers_size_conf;
    size_t                           max_temp_file_size_conf;
    size_t                           temp_file_write_size_conf;

    // 以缓存响应的方式转发上游服务器的包体时所使用的内存大小
    ngx_bufs_t                       bufs;

    /* 
        针对ngx_http_upstream_t结构体中保存解析完的包头的headers_in成员 ignore_headers可以按照二进制位使得upstream在转发包头时跳过对某些头部的处理
        作为32 位整型 理论上ignore_headers最多可以表示32个需要跳过不予处理的头部 然而目前upstream 机制仅提供8个位用于忽略
        8个HTTP头部的处理 包括：
            #define NGX_HTTP_UPSTREAM_IGN_XA_REDIRECT       0x00000002
            #define NGX_HTTP_UPSTREAM_IGN_XA_EXPIRES        0x00000004
            #define NGX_HTTP_UPSTREAM_IGN_EXPIRES           0x00000008
            #define NGX_HTTP_UPSTREAM_IGN_CACHE_CONTROL     0x00000010
            #define NGX_HTTP_UPSTREAM_IGN_SET_COOKIE        0x00000020
            #define NGX_HTTP_UPSTREAM_IGN_XA_LIMIT_RATE     0x00000040
            #define NGX_HTTP_UPSTREAM_IGN_XA_BUFFERING      0x00000080
            #define NGX_HTTP_UPSTREAM_IGN_XA_CHARSET        0x00000100
    */
    ngx_uint_t                       ignore_headers;
    // 以二进制位来表示一些错误码 如果处理上游响应时发现这些错误码 那么在没有将响应转发给下游客户端时 将会选择下一个上游服务器来重发请求
    ngx_uint_t                       next_upstream;
    /* 
        在buffering标志位为1的情况下转发响应时 将有可能把响应存放到临时文件中
        在ngx_http_upstream_t中的store标志位为1时 store_access表示所创建的目录、文件的权限
    */
    ngx_uint_t                       store_access;

    /* 
        决定转发响应方式的标志位 
        buffering为1时表示打开缓存 这时认为上游的网速快于下游的网速 会尽量地在内存或者磁盘中缓存来自上游的响应\
        如果buffering为0 仅会开辟一块固定大小的内存块作为缓存来转发响应
    */
    ngx_flag_t                       buffering;
    // 以下两项暂无意义
    ngx_flag_t                       pass_request_headers;
    ngx_flag_t                       pass_request_body;

    /* 
        表示标志位 当它为1时 表示与上游服务器交互时将不检查Nginx与下游客户端间的连接是否断开
        也就是说 即使下游客户端主动关闭了连接 也不会中断与上游服务器间的交互
    */
    ngx_flag_t                       ignore_client_abort;
    /* 
        当解析上游响应的包头时 如果解析后设置到headers_in结构体中的status_n错误码大于400 
        则会试图把它与error_page中指定的错误码相匹配 如果匹配上 则发送error_page中指定的响应
        否则继续返回上游服务器的错误码 详见ngx_http_upstream_intercept_errors方法
    */
    ngx_flag_t                       intercept_errors;
    /*
        buffering 标志位为1的情况下转发响应时才有意义
        这时 如果cyclic_temp_file为1 则会试图复用临时文件中已经使用过的空间 
        不建议将cyclic_temp_file设为1
    */
    ngx_flag_t                       cyclic_temp_file;

    // 在buffering标志位为1的情况下转发响应时 存放临时文件的路径
    ngx_path_t                      *temp_path;

    /* 
        不转发的头部 实际上是通过ngx_http_upstream_hide_headers_hash方法 
        根据hide_headers和pass_headers动态数组构造出的需要隐藏的HTTP头部散列表
    */
    ngx_hash_t                       hide_headers_hash;
    /* 
        当转发上游响应头部（ngx_http_upstream_t中headers_in结构体中的头部）给下游客户端时
        如果不希望某些头部转发给下游 就设置到hide_headers动态数组中
    */
    ngx_array_t                     *hide_headers;

    /*
        当转发上游响应头部（ngx_http_upstream_t中headers_in结构体中的头部）给下游客户端时 upstream机制默认不会转发如"Date"、"Server"之类的头部
        如果确实希望直接转发它们到下游 就设置到pass_headers动态数组中
    */
    ngx_array_t                     *pass_headers;

    // 连接上游服务器时使用的本机地址
    ngx_addr_t                      *local;

#if (NGX_HTTP_CACHE)
    ngx_shm_zone_t                  *cache;

    ngx_uint_t                       cache_min_uses;
    ngx_uint_t                       cache_use_stale;
    ngx_uint_t                       cache_methods;

    ngx_array_t                     *cache_valid;
    ngx_array_t                     *cache_bypass;
    ngx_array_t                     *no_cache;
#endif

    /* 
        当ngx_http_upstream_t中的store标志位为1时 如果需要将上游的响应存放到文件中
        store_lengths将表示存放路径的长度 而store_values表示存放路径
    */
    ngx_array_t                     *store_lengths;
    ngx_array_t                     *store_values;

    // 到目前为止 store标志位的意义与ngx_http_upstream_t中的store相同 仍只有0和1被使用到
    signed                           store:2;
    /* 
        上面的intercept_errors标志位定义了400以上的错误码将会与error_page比较后再行处理
        实际上这个规则是可以有一个例外情况的 如果将intercept_404标志位设为1  
        当上游返回404时会直接转发这个错误码给下游 而不会去与error_page进行比较
    */
    unsigned                         intercept_404:1;
    /* 
        当该标志位为1时 将会根据ngx_http_upstream_t中headers_in结构体里的X-Accel-Buffering头部（它的值会是yes和no）来改变buffering标志位 当其值为yes时 buffering标志位为1 
        因此 change_buffering为1时将有可能根据上游服务器返回的响应头部 动态地决定是以上游网速优先还是以下游网速优先
    */
    unsigned                         change_buffering:1;

#if (NGX_HTTP_SSL)
    ngx_ssl_t                       *ssl;
    ngx_flag_t                       ssl_session_reuse;
#endif

    // 使用upstream的模块名称 仅用于记录日志
    ngx_str_t                        module;
} ngx_http_upstream_conf_t;


typedef struct {
    ngx_str_t                        name;
    ngx_http_header_handler_pt       handler;
    ngx_uint_t                       offset;
    ngx_http_header_handler_pt       copy_handler;
    ngx_uint_t                       conf;
    ngx_uint_t                       redirect;  /* unsigned   redirect:1; */
} ngx_http_upstream_header_t;


typedef struct {
    ngx_list_t                       headers;

    ngx_uint_t                       status_n;
    ngx_str_t                        status_line;

    ngx_table_elt_t                 *status;
    ngx_table_elt_t                 *date;
    ngx_table_elt_t                 *server;
    ngx_table_elt_t                 *connection;

    ngx_table_elt_t                 *expires;
    ngx_table_elt_t                 *etag;
    ngx_table_elt_t                 *x_accel_expires;
    ngx_table_elt_t                 *x_accel_redirect;
    ngx_table_elt_t                 *x_accel_limit_rate;

    ngx_table_elt_t                 *content_type;
    ngx_table_elt_t                 *content_length;

    ngx_table_elt_t                 *last_modified;
    ngx_table_elt_t                 *location;
    ngx_table_elt_t                 *accept_ranges;
    ngx_table_elt_t                 *www_authenticate;

#if (NGX_HTTP_GZIP)
    ngx_table_elt_t                 *content_encoding;
#endif

    off_t                            content_length_n;

    ngx_array_t                      cache_control;
} ngx_http_upstream_headers_in_t;


typedef struct {
    ngx_str_t                        host;
    in_port_t                        port;
    ngx_uint_t                       no_port; /* unsigned no_port:1 */

    ngx_uint_t                       naddrs;
    in_addr_t                       *addrs;

    struct sockaddr                 *sockaddr;
    socklen_t                        socklen;

    ngx_resolver_ctx_t              *ctx;
} ngx_http_upstream_resolved_t;


typedef void (*ngx_http_upstream_handler_pt)(ngx_http_request_t *r,
    ngx_http_upstream_t *u);


struct ngx_http_upstream_s {
    // 处理读事件的回调方法，每一个阶段都有不同的read_event_handler
    ngx_http_upstream_handler_pt     read_event_handler;
    // 处理写事件的回调方法，每一个阶段都有不同的write_event_handler
    ngx_http_upstream_handler_pt     write_event_handler;

    // 表示主动向上游服务器发起的连接
    ngx_peer_connection_t            peer;

    /*
        当向下游客户端转发响应时（ngx_http_request_t结构体中的subrequest_in_memory标志位为0）
        如果打开了缓存且认为上游网速更快（conf配置中的buffering标志位为1），这时会使用pipe成员来转发响应
        在使用这种方式转发响应时，必须由HTTP模块在使用upstream机制前构造pipe结构体，否则会出现严重的coredump错误
    */
    ngx_event_pipe_t                *pipe;

    /*
        request_bufs以链表的方式把ngx_buf_t缓冲区链接起来，它表示所有需要发送到上游服务器的请求内容
        所以，HTTP模块实现的create_request回调方法就在于构造request_bufs链表
    */
    ngx_chain_t                     *request_bufs;

    // 定义了向下游发送响应的方式
    ngx_output_chain_ctx_t           output;
    ngx_chain_writer_ctx_t           writer;

	// upstream访问时的所有限制参数
    ngx_http_upstream_conf_t        *conf;

    /*
        HTTP模块在实现process_header方法时，如果希望upstream直接转发响应，就需要把解析出的响应头部适配为HTTP的响应头部同时需要把包头中的信息设置到headers_in结构体中
        这样，会把headers_in中设置的头部添加到要发送到下游客户端的响应头部headers_out中
    */
    ngx_http_upstream_headers_in_t   headers_in;

	// 通过resolved可以直接指定上游服务器的地址
    ngx_http_upstream_resolved_t    *resolved;

	/*
		buffer成员存储接收自上游服务器发来的响应内容，由于它会被复用，所以具有以下多种意义：
		1.在使用 process_header方法解析上游服务器响应的包头时，buffer中将会保存完整的响应包头；
		2.当下面的 buffering成员变量为1的时候，而且此时 upstream是向下游转发上游的包体时，buffer没有意义；
		3.当 buffering标志位为0时，buffer缓冲区会被用于反复的接收上游的包体，进而向下游转发；
		4.当 upstream并不用于转发上游包体时，buffer会被用于反复接收上游的包体，HTTP模块实现的 input_filter方法需要关注它
	*/
    /*
        接收上游服务器响应包头的缓冲区，在不需要把响应直接转发给客户端，或者buffering标志位为0的情况下转发包体时，接收包体的缓冲区仍然使用buffer
        注意，如果没有自定义input_filter方法处理包体，将会使用buffer存储全部的包体，这时buffer必须足够大！它的大小由ngx_http_upstream_conf_t配置结构体中的buffer_size成员决定
    */
    ngx_buf_t                        buffer;
    // 表示来自上游服务器的响应包体的长度
    size_t                           length;

    /* 
        out_bufs在两种场景下有不同的意义：
        ①当不需要转发包体，且使用默认的input_filter方法（也就是ngx_http_upstream_non_buffered_filter方法）处理包体时，out_bufs将会指向响应包体
        事实上，out_bufs链表中会产生多个ngx_buf_t缓冲区，每个缓冲区都指向buffer缓存中的一部分，而这里的一部分就是每次调用recv方法接收到的一段TCP流。
        ②当需要转发响应包体到下游时（buffering标志位为0，即以下游网速优先），这个链表指向上一次向下游转发响应到现在这段时间内接收自上游的缓存响应
    */
    ngx_chain_t                     *out_bufs;

    //当需要转发响应包体到下游时（buffering标志位为0，即以下游网速优先），它表示上一次向下游转发响应时没有发送完的内容
    ngx_chain_t                     *busy_bufs;

    // 这个链表将用于回收out_bufs中已经发送给下游的ngx_buf_t结构体，这同样应用在buffering标志位为0即以下游网速优先的场景
    ngx_chain_t                     *free_bufs;

    // 处理包体前的初始化方法，其中data参数用于传递用户数据结构，它实际上就是下面的input_filter_ctx指针
    ngx_int_t                      (*input_filter_init)(void *data);

    /*
        处理包体的方法，其中data参数用于传递用户数据结构，它实际上就是下面的input_filter_ctx指针，而bytes表示本次接收到的包体长度。
        返回NGX_ERROR时表示处理包体错误，请求需要结束，否则都将继续upstream流程
    */
    ngx_int_t                      (*input_filter)(void *data, ssize_t bytes);

    // 用于传递HTTP模块自定义的数据结构，在input_filter_init和input_filter方法被回调时会作为参数传递过去
    void                            *input_filter_ctx;

#if (NGX_HTTP_CACHE)
    ngx_int_t                      (*create_key)(ngx_http_request_t *r);
#endif

    // HTTP模块实现的create_request方法用于构造发往上游服务器的请求
    ngx_int_t                      (*create_request)(ngx_http_request_t *r);
    
    // 与上游服务器的通信失败后，如果按照重试规则还需要再次向上游服务器发起连接，则会调用reinit_request方法
    ngx_int_t                      (*reinit_request)(ngx_http_request_t *r);

	/*
		收到上游服务器的响应后就会回调 process_header方法。如果 process_header返回 NGX_AGAIN，
		那么是在告诉 upstream还没有收到完整的响应包头，此时，对于本次 upstream来说，再次接收到
		上游服务器发来的 TCP流时，还会调用 process_header方法处理，直到 process_header函数返回
		非 NGX_AGAIN值这一阶段才会停止
	*/
    /*
        解析上游服务器返回响应的包头，返回NGX_AGAIN表示包头还没有接收完整，返回NGX_HTTP_UPSTREAM_INVALID_HEADER表示包头不合法，返回NGX_ERROR表示出现错误，返回NGX_OK表示解析到完整的包头
    */
    ngx_int_t                      (*process_header)(ngx_http_request_t *r);

    // 当前版本下abort_request回调方法没有任意意义
    void                           (*abort_request)(ngx_http_request_t *r);

    // 请求结束时会调用
    void                           (*finalize_request)(ngx_http_request_t *r,
                                         ngx_int_t rc);

    // 在上游返回的响应出现Location或者Refresh头部表示重定向时，会通过ngx_http_upstream_process_headers方法调用到可由HTTP模块实现的rewrite_redirect方法
    ngx_int_t                      (*rewrite_redirect)(ngx_http_request_t *r,
                                         ngx_table_elt_t *h, size_t prefix);

    // 暂无意义
    ngx_msec_t                       timeout;

    // 用于表示上游响应的错误码、包体长度等信息
    ngx_http_upstream_state_t       *state;

    // 不使用文件缓存时没有意义
    ngx_str_t                        method;

    // schema和uri成员仅在记录日志时会用到，除此以外没有意义
    ngx_str_t                        schema;
    ngx_str_t                        uri;

    // 目前它仅用于表示是否需要清理资源，相当于一个标志位，实际不会调用到它所指向的方法
    ngx_http_cleanup_pt             *cleanup;

    // 是否指定文件缓存路径的标志位
    unsigned                         store:1;
    // 是否启用文件缓存
    unsigned                         cacheable:1;
    unsigned                         accel:1;

	//是否基于 ssl协议访问上游服务器
    unsigned                         ssl:1;
#if (NGX_HTTP_CACHE)
    unsigned                         cache_status:3;
#endif

	/*
		在向上客户端转发上游服务器的包体时才有用。当 buffering为1时，表示使用多个缓冲区以及磁盘文件
		来转发上游的响应包体。当 Nginx与上游的网速远大于 Nginx与下游的网速的时候，让 Nginx开辟更多的
		内存甚至使用磁盘文件来缓存上游的响应包体，这是有意义的，它可以减轻上游服务器的并发压力。当
		buffering为0时，表示只使用上面的这一个 buffer缓冲区来向下游转发响应包体
	*/
    unsigned                         buffering:1;


    /*
        request_sent表示是否已经向上游服务器发送了请求，当request_sent为1时，表示upstream机制已经向上游服务器发送了全部或者部分的请求
        事实上，这个标志位更多的是为了使用ngx_output_chain方法发送请求，因为该方法发送请求时会自动把未发送完的request_bufs链表记录下来，为了防止反复发送重复请求，必须有request_sent标志位记录是否调用过ngx_output_chain方法
    */
    unsigned                         request_sent:1;

    /*
        将上游服务器的响应划分为包头和包尾，如果把响应直接转发给客户端，header_sent标志位表示包头是否发送，header_sent为1时表示已经把包头转发给客户端了
        如果不转发响应到客户端，则header_sent没有意义
    */
    unsigned                         header_sent:1;
};


typedef struct {
    ngx_uint_t                      status;
    ngx_uint_t                      mask;
} ngx_http_upstream_next_t;


ngx_int_t ngx_http_upstream_header_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

ngx_int_t ngx_http_upstream_create(ngx_http_request_t *r);
void ngx_http_upstream_init(ngx_http_request_t *r);
ngx_http_upstream_srv_conf_t *ngx_http_upstream_add(ngx_conf_t *cf,
    ngx_url_t *u, ngx_uint_t flags);
char *ngx_http_upstream_bind_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
ngx_int_t ngx_http_upstream_hide_headers_hash(ngx_conf_t *cf,
    ngx_http_upstream_conf_t *conf, ngx_http_upstream_conf_t *prev,
    ngx_str_t *default_hide_headers, ngx_hash_init_t *hash);


#define ngx_http_conf_upstream_srv_conf(uscf, module)                         \
    uscf->srv_conf[module.ctx_index]


extern ngx_module_t        ngx_http_upstream_module;
extern ngx_conf_bitmask_t  ngx_http_upstream_cache_method_mask[];
extern ngx_conf_bitmask_t  ngx_http_upstream_ignore_headers_masks[];


#endif /* _NGX_HTTP_UPSTREAM_H_INCLUDED_ */
