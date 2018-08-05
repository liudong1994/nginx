
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_CORE_H_INCLUDED_
#define _NGX_HTTP_CORE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_GZIP_PROXIED_OFF       0x0002
#define NGX_HTTP_GZIP_PROXIED_EXPIRED   0x0004
#define NGX_HTTP_GZIP_PROXIED_NO_CACHE  0x0008
#define NGX_HTTP_GZIP_PROXIED_NO_STORE  0x0010
#define NGX_HTTP_GZIP_PROXIED_PRIVATE   0x0020
#define NGX_HTTP_GZIP_PROXIED_NO_LM     0x0040
#define NGX_HTTP_GZIP_PROXIED_NO_ETAG   0x0080
#define NGX_HTTP_GZIP_PROXIED_AUTH      0x0100
#define NGX_HTTP_GZIP_PROXIED_ANY       0x0200


#define NGX_HTTP_AIO_OFF                0
#define NGX_HTTP_AIO_ON                 1
#define NGX_HTTP_AIO_SENDFILE           2


#define NGX_HTTP_SATISFY_ALL            0
#define NGX_HTTP_SATISFY_ANY            1


#define NGX_HTTP_LINGERING_OFF          0
#define NGX_HTTP_LINGERING_ON           1
#define NGX_HTTP_LINGERING_ALWAYS       2


#define NGX_HTTP_IMS_OFF                0
#define NGX_HTTP_IMS_EXACT              1
#define NGX_HTTP_IMS_BEFORE             2


#define NGX_HTTP_KEEPALIVE_DISABLE_NONE    0x0002
#define NGX_HTTP_KEEPALIVE_DISABLE_MSIE6   0x0004
#define NGX_HTTP_KEEPALIVE_DISABLE_SAFARI  0x0008


typedef struct ngx_http_location_tree_node_s  ngx_http_location_tree_node_t;
typedef struct ngx_http_core_loc_conf_s  ngx_http_core_loc_conf_t;


typedef struct {
    union {
        struct sockaddr        sockaddr;
        struct sockaddr_in     sockaddr_in;
#if (NGX_HAVE_INET6)
        struct sockaddr_in6    sockaddr_in6;
#endif
#if (NGX_HAVE_UNIX_DOMAIN)
        struct sockaddr_un     sockaddr_un;
#endif
        u_char                 sockaddr_data[NGX_SOCKADDRLEN];
    } u;

    socklen_t                  socklen;

    unsigned                   set:1;
    unsigned                   default_server:1;
    unsigned                   bind:1;
    unsigned                   wildcard:1;
#if (NGX_HTTP_SSL)
    unsigned                   ssl:1;
#endif
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    unsigned                   ipv6only:2;
#endif

    int                        backlog;
    int                        rcvbuf;
    int                        sndbuf;
#if (NGX_HAVE_SETFIB)
    int                        setfib;
#endif

#if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
    char                      *accept_filter;
#endif
#if (NGX_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
    ngx_uint_t                 deferred_accept;
#endif

    u_char                     addr[NGX_SOCKADDR_STRLEN + 1];
} ngx_http_listen_opt_t;


typedef enum {
	//在接收到完整的HTTP头部后处理的HTTP阶段
    NGX_HTTP_POST_READ_PHASE = 0,

	//在将请求的URI与location表达式匹配前 修改请求的URI(所谓的重定向)是一个独立的HTTP阶段
    NGX_HTTP_SERVER_REWRITE_PHASE,

	/*
		根据请求的URI寻找匹配的location表达式 这个阶段只能由ngx_http_core_module模块实现
		不建议其他HTTP模块重新定义这一阶段的行为
	*/
    NGX_HTTP_FIND_CONFIG_PHASE,
	//在NGX_HTTP_FIND_CONFIG_PHASE阶段寻找到匹配的location之后再修改请求的URI
    NGX_HTTP_REWRITE_PHASE,
	/*
		这一阶段是用于在rewrite重写URL后 防止错误的nginx.conf配置导致死循环(递归地修改URI) 因此 这一阶段仅由ngx_http_core_module模块处理
		目前 控制死循环的方式很简单 首先检查rewrite的次数 如果一个请求超过10次重定向
		就认为进入了rewrite死循环 这时在NGX_HTTP_POST_REWRITE_PHASE阶段就会向用户返回500 表示服务器内部错误
	*/
    NGX_HTTP_POST_REWRITE_PHASE,

	//表示在处理NGX_HTTP_ACCESS_PHASE阶段决定请求的访问权限前 HTTP模块可以介入的处理阶段
    NGX_HTTP_PREACCESS_PHASE,

	//这个阶段用于让HTTP模块判断是否允许这个请求访问Nginx服务器
    NGX_HTTP_ACCESS_PHASE,
	/*
		在NGX_HTTP_ACCESS_PHASE阶段中 当HTTP模块的handler处理函数返回不允许访问的错误码时(实际就是NGX_HTTP_FORBIDDEN或者NGX_HTTP_UNAUTHORIZED)
		这里将负责向用户发送拒绝服务的错误响应 因此 这个阶段实际上用于给NGX_HTTP_ACCESS_PHASE阶段收尾
	*/
    NGX_HTTP_POST_ACCESS_PHASE,

	/*
		这个阶段完全是为try_files配置项而设立的 HTTP请求访问静态文件资源时 try_files配置项可以使这个请求顺序地访问多个静态文件资源 
		如果某一次访问失败 则继续访问try_files中指定的下一个静态资源 这个功能完全是在NGX_HTTP_TRY_FILES_PHASE阶段中实现的
	*/
    NGX_HTTP_TRY_FILES_PHASE,
	//用于处理HTTP请求内容的阶段 这是大部分HTTP模块最愿意介入的阶段
    NGX_HTTP_CONTENT_PHASE,

	/*
		处理完请求后记录日志的阶段 例如 ngx_http_log_module模块就在这个阶段中加入了一个handler处理方法
		使得每个HTTP请求处理完毕后会记录access_log访问日志
	*/
    NGX_HTTP_LOG_PHASE
} ngx_http_phases;

typedef struct ngx_http_phase_handler_s  ngx_http_phase_handler_t;


//一个HTTP处理阶段中的checker检查方法 仅可以由HTTP框架实现 以此控制HTTP请求的处理流程
typedef ngx_int_t (*ngx_http_phase_handler_pt)(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);

/*
由HTTP模块实现的handler处理方法
typedef ngx_int_t(*ngx_http_handler_pt)(ngx_http_request_t *r);
*/

//ngx_http_phase_handler_t结构体仅表示处理阶段中的一个处理方法
struct ngx_http_phase_handler_s {
	/*
		在处理到某一个HTTP阶段时 HTTP框架将会在checker方法已实现的前提下首先调用checker方法来处理请求 
		而不会直接调用任何阶段中的handler方法 只有在checker方法中才会去调用handler方法
		因此 事实上所有的checker方法都是由框架中的ngx_http_core_module模块实现的 且普通的HTTP模块无法重定义checker方法
	*/
    ngx_http_phase_handler_pt  checker;
	//除ngx_http_core_module模块以外的HTTP模块 只能通过定义handler方法才能介入某一个HTTP处理阶段以处理请求
    ngx_http_handler_pt        handler;
	//将要执行的下一个HTTP处理阶段的序号
	/* 
		next的设计使得处理阶段不必按顺序依次执行 
		既可以向后跳跃数个阶段继续执行 也可以跳跃到之前曾经执行过的某个阶段重新执行
		通常 next表示下一个处理阶段中的第1个ngx_http_phase_handler_t处理方法
	*/
    ngx_uint_t                 next;
};


typedef struct {
	//handlers是由ngx_http_phase_handler_t构成的数组首地址 它表示一个请求可能经历的所有ngx_http_handler_pt处理方法
    ngx_http_phase_handler_t  *handlers;
	/*
		表示NGX_HTTP_SERVER_REWRITE_PHASE阶段第1个ngx_http_phase_handler_t处理方法在handlers数组中的序号 
		用于在执行HTTP请求的任何阶段中快速跳转到NGX_HTTP_SERVER_REWRITE_PHASE阶段处理请求
	*/
    ngx_uint_t                 server_rewrite_index;
	/*
		表示NGX_HTTP_REWRITE_PHASE阶段第1个ngx_http_phase_handler_t处理方法在handlers数组中的序号
		用于在执行HTTP请求的任何阶段中快速跳转到NGX_HTTP_REWRITE_PHASE阶段处理请求
	*/
    ngx_uint_t                 location_rewrite_index;
} ngx_http_phase_engine_t;


typedef struct {
	//handlers动态数组保存着每一个HTTP模块初始化时添加到当前阶段的处理方法
    ngx_array_t                handlers;
} ngx_http_phase_t;


typedef struct {
    /*
        存储指针的动态数组 每个指针指向ngx_http_core_srv_conf_t结构体的地址
        也就是其成员类型为ngx_http_core_srv_conf_t** 
    */
    ngx_array_t                servers;         /* ngx_http_core_srv_conf_t */

	//由下面各阶段处理方法构成的phases数组构建的阶段引擎才是流水式处理HTTP请求的实际数据结构
    ngx_http_phase_engine_t    phase_engine;

    ngx_hash_t                 headers_in_hash;

    ngx_hash_t                 variables_hash;

    ngx_array_t                variables;       /* ngx_http_variable_t */
    ngx_uint_t                 ncaptures;

    ngx_uint_t                 server_names_hash_max_size;
    ngx_uint_t                 server_names_hash_bucket_size;

    ngx_uint_t                 variables_hash_max_size;
    ngx_uint_t                 variables_hash_bucket_size;

    ngx_hash_keys_arrays_t    *variables_keys;

	//存放着该http{}配置块下监听的所有ngx_http_conf_port_t端口
    ngx_array_t               *ports;

    ngx_uint_t                 try_files;       /* unsigned  try_files:1 */

	/*
		用于在HTTP框架初始化时帮助各个HTTP模块在任意阶段中添加HTTP处理方法
		它是一个有11个成员的ngx_http_phase_t数组 其中每一个ngx_http_phase_t结构体对应一个HTTP阶段
		在HTTP框架初始化完毕后运行过程中的phases数组是无用的
	*/
    ngx_http_phase_t           phases[NGX_HTTP_LOG_PHASE + 1];
} ngx_http_core_main_conf_t;


typedef struct {
    /* array of the ngx_http_server_name_t, "server_name" directive */
    ngx_array_t                 server_names;

    /* server ctx */
    //指向当前server块所属的ngx_http_conf_ctx_t结构体
    ngx_http_conf_ctx_t        *ctx;

    /*
        当前server块的虚拟主机名 如果存在的话 则会与HTTP请求中的Host头部做匹配
        匹配上后再由当前ngx_http_core_srv_conf_t处理请求
    */
    ngx_str_t                   server_name;

    size_t                      connection_pool_size;
    size_t                      request_pool_size;
    size_t                      client_header_buffer_size;

    ngx_bufs_t                  large_client_header_buffers;

    ngx_msec_t                  client_header_timeout;

    ngx_flag_t                  ignore_invalid_headers;
    ngx_flag_t                  merge_slashes;
    ngx_flag_t                  underscores_in_headers;

    unsigned                    listen:1;
#if (NGX_PCRE)
    unsigned                    captures:1;
#endif

    ngx_http_core_loc_conf_t  **named_locations;
} ngx_http_core_srv_conf_t;


/* list of structures to find core_srv_conf quickly at run time */


typedef struct {
    /* the default server configuration for this address:port */
    ngx_http_core_srv_conf_t  *default_server;

    ngx_http_virtual_names_t  *virtual_names;

#if (NGX_HTTP_SSL)
    ngx_uint_t                 ssl;   /* unsigned  ssl:1; */
#endif
} ngx_http_addr_conf_t;


typedef struct {
    in_addr_t                  addr;
    ngx_http_addr_conf_t       conf;
} ngx_http_in_addr_t;


#if (NGX_HAVE_INET6)

typedef struct {
    struct in6_addr            addr6;
    ngx_http_addr_conf_t       conf;
} ngx_http_in6_addr_t;

#endif


typedef struct {
    /* ngx_http_in_addr_t or ngx_http_in6_addr_t */
    void                      *addrs;
    ngx_uint_t                 naddrs;
} ngx_http_port_t;


typedef struct {
	//socket地址家族
    ngx_int_t                  family;
	//监听端口
    in_port_t                  port;
	//监听的端口下对应着的所有ngx_http_conf_addr_t地址 (可能会有很多地址监听相同端口)
    ngx_array_t                addrs;     /* array of ngx_http_conf_addr_t */
} ngx_http_conf_port_t;


typedef struct {
	//监听套接字的各种属性
    ngx_http_listen_opt_t      opt;

	/*
		以下3个散列表用于加速寻找到对应监听端口上的新连接 确定到底使用哪个server{}虚拟主机下的配置来处理它
		所以 散列表的值就是ngx_http_core_srv_conf_t结构体的地址
	*/
	//完全匹配server name的散列表
    ngx_hash_t                 hash;
	//通配符前置的散列表
    ngx_hash_wildcard_t       *wc_head;
	// 通配符后置的散列表
    ngx_hash_wildcard_t       *wc_tail;

#if (NGX_PCRE)
	//下面的regex数组中元素的个数
    ngx_uint_t                 nregex;
	/*
		regex指向静态数组 其数组成员就是ngx_http_server_name_t结构体
		表示正则表达式及其匹配的server{}虚拟主机
	*/
    ngx_http_server_name_t    *regex;
#endif

    /* the default server configuration for this address:port */
	//该监听端口下对应的默认server{}虚拟主机
    ngx_http_core_srv_conf_t  *default_server;
	//servers动态数组中的成员将指向ngx_http_core_srv_conf_t结构体
    ngx_array_t                servers;  /* array of ngx_http_core_srv_conf_t */
} ngx_http_conf_addr_t;


struct ngx_http_server_name_s {
#if (NGX_PCRE)
    ngx_http_regex_t          *regex;
#endif
    ngx_http_core_srv_conf_t  *server;   /* virtual name server conf */
    ngx_str_t                  name;
};


typedef struct {
    ngx_int_t                  status;
    ngx_int_t                  overwrite;
    ngx_http_complex_value_t   value;
    ngx_str_t                  args;
} ngx_http_err_page_t;


typedef struct {
    ngx_array_t               *lengths;
    ngx_array_t               *values;
    ngx_str_t                  name;

    unsigned                   code:10;
    unsigned                   test_dir:1;
} ngx_http_try_file_t;


struct ngx_http_core_loc_conf_s {
    //location的名称 即nginx.conf中location后的表达式
    ngx_str_t     name;          /* location name */

#if (NGX_PCRE)
    ngx_http_regex_t  *regex;
#endif

    unsigned      noname:1;   /* "if () {}" block or limit_except */
    unsigned      lmt_excpt:1;
    unsigned      named:1;

    unsigned      exact_match:1;
    unsigned      noregex:1;

    unsigned      auto_redirect:1;
#if (NGX_HTTP_GZIP)
    unsigned      gzip_disable_msie6:2;
#if (NGX_HTTP_DEGRADATION)
    unsigned      gzip_disable_degradation:2;
#endif
#endif

    ngx_http_location_tree_node_t   *static_locations;
#if (NGX_PCRE)
    ngx_http_core_loc_conf_t       **regex_locations;
#endif

    /* pointer to the modules' loc_conf */
    /*
        指向所属location块内ngx_http_conf_ctx_t结构体中的loc_conf指针数组
        它保存着当前location块内所有HTTP模块create_loc_conf方法产生的结构体指针
    */
    void        **loc_conf;

    uint32_t      limit_except;
    void        **limit_except_loc_conf;

    ngx_http_handler_pt  handler;

    /* location name length for inclusive location with inherited alias */
    size_t        alias;
    ngx_str_t     root;                    /* root, alias */
    ngx_str_t     post_action;

    ngx_array_t  *root_lengths;
    ngx_array_t  *root_values;

    ngx_array_t  *types;
    ngx_hash_t    types_hash;
    ngx_str_t     default_type;

    off_t         client_max_body_size;    /* client_max_body_size */
    off_t         directio;                /* directio */
    off_t         directio_alignment;      /* directio_alignment */

    size_t        client_body_buffer_size; /* client_body_buffer_size */
    size_t        send_lowat;              /* send_lowat */
    size_t        postpone_output;         /* postpone_output */
    size_t        limit_rate;              /* limit_rate */
    size_t        limit_rate_after;        /* limit_rate_after */
    size_t        sendfile_max_chunk;      /* sendfile_max_chunk */
    size_t        read_ahead;              /* read_ahead */

    ngx_msec_t    client_body_timeout;     /* client_body_timeout */
    ngx_msec_t    send_timeout;            /* send_timeout */
    ngx_msec_t    keepalive_timeout;       /* keepalive_timeout */
    ngx_msec_t    lingering_time;          /* lingering_time */
    ngx_msec_t    lingering_timeout;       /* lingering_timeout */
    ngx_msec_t    resolver_timeout;        /* resolver_timeout */

    ngx_resolver_t  *resolver;             /* resolver */

    time_t        keepalive_header;        /* keepalive_timeout */

    ngx_uint_t    keepalive_requests;      /* keepalive_requests */
    ngx_uint_t    keepalive_disable;       /* keepalive_disable */
    ngx_uint_t    satisfy;                 /* satisfy */
    ngx_uint_t    lingering_close;         /* lingering_close */
    ngx_uint_t    if_modified_since;       /* if_modified_since */
    ngx_uint_t    max_ranges;              /* max_ranges */
    ngx_uint_t    client_body_in_file_only; /* client_body_in_file_only */

    ngx_flag_t    client_body_in_single_buffer;
                                           /* client_body_in_singe_buffer */
    ngx_flag_t    internal;                /* internal */
    ngx_flag_t    sendfile;                /* sendfile */
#if (NGX_HAVE_FILE_AIO)
    ngx_flag_t    aio;                     /* aio */
#endif
    ngx_flag_t    tcp_nopush;              /* tcp_nopush */
    ngx_flag_t    tcp_nodelay;             /* tcp_nodelay */
    ngx_flag_t    reset_timedout_connection; /* reset_timedout_connection */
    ngx_flag_t    server_name_in_redirect; /* server_name_in_redirect */
    ngx_flag_t    port_in_redirect;        /* port_in_redirect */
    ngx_flag_t    msie_padding;            /* msie_padding */
    ngx_flag_t    msie_refresh;            /* msie_refresh */
    ngx_flag_t    log_not_found;           /* log_not_found */
    ngx_flag_t    log_subrequest;          /* log_subrequest */
    ngx_flag_t    recursive_error_pages;   /* recursive_error_pages */
    ngx_flag_t    server_tokens;           /* server_tokens */
    ngx_flag_t    chunked_transfer_encoding; /* chunked_transfer_encoding */

#if (NGX_HTTP_GZIP)
    ngx_flag_t    gzip_vary;               /* gzip_vary */

    ngx_uint_t    gzip_http_version;       /* gzip_http_version */
    ngx_uint_t    gzip_proxied;            /* gzip_proxied */

#if (NGX_PCRE)
    ngx_array_t  *gzip_disable;            /* gzip_disable */
#endif
#endif

    ngx_array_t  *error_pages;             /* error_page */
    ngx_http_try_file_t    *try_files;     /* try_files */

    ngx_path_t   *client_body_temp_path;   /* client_body_temp_path */

    ngx_open_file_cache_t  *open_file_cache;
    time_t        open_file_cache_valid;
    ngx_uint_t    open_file_cache_min_uses;
    ngx_flag_t    open_file_cache_errors;
    ngx_flag_t    open_file_cache_events;

    ngx_log_t    *error_log;

    ngx_uint_t    types_hash_max_size;
    ngx_uint_t    types_hash_bucket_size;

    /*
        将同一个server块内多个表达location块的ngx_http_core_loc_conf_t结构体以双向链表方式组织起来
        该locations指针将指向ngx_http_location_queue_t结构体
    */
    ngx_queue_t  *locations;

#if 0
    ngx_http_core_loc_conf_t  *prev_location;
#endif
};

//每一个配置文件中的location都有下面一个结构体 由上面的locations进行关联
typedef struct {
    //queue将作为ngx_queue_t双向链表容器 从而将ngx_http_location_queue_t结构体连接起来
    ngx_queue_t                      queue;
    /*
        如果location中的字符串可以精确匹配(包括正则表达式) 
        exact将指向对应的ngx_http_core_loc_conf_t结构体 否则值为NULL
    */
    ngx_http_core_loc_conf_t        *exact;
    /*
        如果location中的字符串无法精确匹配(包括了自定义的通配符)
        inclusive将指向对应的ngx_http_core_loc_conf_t结构体，否则值为NULL
    */
    ngx_http_core_loc_conf_t        *inclusive;
    //指向location的名称
    ngx_str_t                       *name;
    u_char                          *file_name;
    ngx_uint_t                       line;
    ngx_queue_t                      list;
} ngx_http_location_queue_t;


struct ngx_http_location_tree_node_s {
    ngx_http_location_tree_node_t   *left;
    ngx_http_location_tree_node_t   *right;
    ngx_http_location_tree_node_t   *tree;

    ngx_http_core_loc_conf_t        *exact;
    ngx_http_core_loc_conf_t        *inclusive;

    u_char                           auto_redirect;
    u_char                           len;
    u_char                           name[1];
};


void ngx_http_core_run_phases(ngx_http_request_t *r);
ngx_int_t ngx_http_core_generic_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_rewrite_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_find_config_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_post_rewrite_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_access_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_post_access_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_try_files_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_content_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);


void *ngx_http_test_content_type(ngx_http_request_t *r, ngx_hash_t *types_hash);
ngx_int_t ngx_http_set_content_type(ngx_http_request_t *r);
void ngx_http_set_exten(ngx_http_request_t *r);
ngx_int_t ngx_http_send_response(ngx_http_request_t *r, ngx_uint_t status,
    ngx_str_t *ct, ngx_http_complex_value_t *cv);
u_char *ngx_http_map_uri_to_path(ngx_http_request_t *r, ngx_str_t *name,
    size_t *root_length, size_t reserved);
ngx_int_t ngx_http_auth_basic_user(ngx_http_request_t *r);
#if (NGX_HTTP_GZIP)
ngx_int_t ngx_http_gzip_ok(ngx_http_request_t *r);
#endif


/*
	r:		当前的请求,是父请求(调用这个函数会产生子请求)
	uri:	子请求的 uri,它会去 nginx.conf中进行匹配,根据匹配结构决定调用哪个模块来处理子请求
	args:	是子请求的 uri参数,如果没有参数,传入 NULL即可
	sr:		输出参数,它将 ngx_http_subrequest生成的子请求传出来.我们可以提前建立一个 NULL的子请求指针 sr,
			然后作为参数传入,如果 ngx_http_subrequest返回成功,那么 sr就指向建立好的子请求
	psr:	要传入的子请求结束时的回调处理方法
	flags:	取值范围(flag按比特位操作,可以同时包含下面的多个值):
			0:	没有特殊需求
			NGX_HTTP_SUBREQUEST_IN_MEMORY:	这个宏将 subrequest_in_memory标志位置为1,这意味着如果子请求使用 upstream访问上游服务器,
											那么上游服务器的响应都会在内存中处理
			NGX_HTTP_SUBREQUEST_WAITED:		这个宏将子请求的 waited标志位置为1,当子请求提前结束,有个 done标志位会置为1,但目前 HTTP
											框架并没有针对这两个标志位做任何实质性的处理。

	返回值:	NGX_OK表示成功建立子请求,NGX_ERROR代表失败.
*/
ngx_int_t ngx_http_subrequest(ngx_http_request_t *r,
    ngx_str_t *uri, ngx_str_t *args, ngx_http_request_t **sr,
    ngx_http_post_subrequest_t *psr, ngx_uint_t flags);

ngx_int_t ngx_http_internal_redirect(ngx_http_request_t *r,
    ngx_str_t *uri, ngx_str_t *args);
ngx_int_t ngx_http_named_location(ngx_http_request_t *r, ngx_str_t *name);


ngx_http_cleanup_t *ngx_http_cleanup_add(ngx_http_request_t *r, size_t size);


typedef ngx_int_t (*ngx_http_output_header_filter_pt)(ngx_http_request_t *r);
typedef ngx_int_t (*ngx_http_output_body_filter_pt)
    (ngx_http_request_t *r, ngx_chain_t *chain);


ngx_int_t ngx_http_output_filter(ngx_http_request_t *r, ngx_chain_t *chain);
ngx_int_t ngx_http_write_filter(ngx_http_request_t *r, ngx_chain_t *chain);


extern ngx_module_t  ngx_http_core_module;

extern ngx_uint_t ngx_http_max_module;

extern ngx_str_t  ngx_http_core_get_method;


#define ngx_http_clear_content_length(r)                                      \
                                                                              \
    r->headers_out.content_length_n = -1;                                     \
    if (r->headers_out.content_length) {                                      \
        r->headers_out.content_length->hash = 0;                              \
        r->headers_out.content_length = NULL;                                 \
    }
                                                                              \
#define ngx_http_clear_accept_ranges(r)                                       \
                                                                              \
    r->allow_ranges = 0;                                                      \
    if (r->headers_out.accept_ranges) {                                       \
        r->headers_out.accept_ranges->hash = 0;                               \
        r->headers_out.accept_ranges = NULL;                                  \
    }

#define ngx_http_clear_last_modified(r)                                       \
                                                                              \
    r->headers_out.last_modified_time = -1;                                   \
    if (r->headers_out.last_modified) {                                       \
        r->headers_out.last_modified->hash = 0;                               \
        r->headers_out.last_modified = NULL;                                  \
    }

#define ngx_http_clear_location(r)                                            \
                                                                              \
    if (r->headers_out.location) {                                            \
        r->headers_out.location->hash = 0;                                    \
        r->headers_out.location = NULL;                                       \
    }


#endif /* _NGX_HTTP_CORE_H_INCLUDED_ */
