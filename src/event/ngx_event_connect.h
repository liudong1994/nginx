
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_CONNECT_H_INCLUDED_
#define _NGX_EVENT_CONNECT_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#define NGX_PEER_KEEPALIVE           1
#define NGX_PEER_NEXT                2
#define NGX_PEER_FAILED              4


typedef struct ngx_peer_connection_s  ngx_peer_connection_t;

typedef ngx_int_t (*ngx_event_get_peer_pt)(ngx_peer_connection_t *pc,
    void *data);
typedef void (*ngx_event_free_peer_pt)(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state);
#if (NGX_SSL)

typedef ngx_int_t (*ngx_event_set_peer_session_pt)(ngx_peer_connection_t *pc,
    void *data);
typedef void (*ngx_event_save_peer_session_pt)(ngx_peer_connection_t *pc,
    void *data);
#endif


struct ngx_peer_connection_s { 
    //一个主动连接也需要ngx_connection_t中大部分成员 出于重用的考虑定义了connection成员
    ngx_connection_t                *connection;

    //远端服务器的socket地址
    struct sockaddr                 *sockaddr;
    //sockaddr地址的长度
    socklen_t                        socklen;
    // 远端服务器的名称
    ngx_str_t                       *name;

    //表示在连接一个远端服务器时 当前连接出现异常失败后可以重试的次数 就是允许的最多失败次数
    ngx_uint_t                       tries;

    //获取连接的方法 如果使用长连接构成的连接池 那么必须要实现get方法
    ngx_event_get_peer_pt            get;
    //与get方法对应的释放连接的方法
    ngx_event_free_peer_pt           free;
    /* 
        这个data指针仅用于和上面的get、free方法配合传递参数 它的具体含义与实现get方法、free方法的模块相关
        可参照ngx_event_get_peer_pt和ngx_event_free_peer_pt方法原型中的data参数
    */
    void                            *data;

#if (NGX_SSL)
    ngx_event_set_peer_session_pt    set_session;
    ngx_event_save_peer_session_pt   save_session;
#endif

#if (NGX_THREADS)
    ngx_atomic_t                    *lock;
#endif

    //本机地址信息
    ngx_addr_t                      *local;

    //套接字的接收缓冲区大小
    int                              rcvbuf;

    //记录日志的对象
    ngx_log_t                       *log;

    //标志位 为1时表示上面的connection连接已经缓存
    unsigned                         cached:1;

                                     /* ngx_connection_log_error_e */
    /*
        与ngx_connection_t里的log_error意义是相同的 区别在于这里的log_error只有两位 
        只能表达4 种错误 NGX_ERROR_IGNORE_EINVAL错误无法表达
    */
    unsigned                         log_error:2;
};


ngx_int_t ngx_event_connect_peer(ngx_peer_connection_t *pc);
ngx_int_t ngx_event_get_peer(ngx_peer_connection_t *pc, void *data);


#endif /* _NGX_EVENT_CONNECT_H_INCLUDED_ */
