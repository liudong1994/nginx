
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
    //һ����������Ҳ��Ҫngx_connection_t�д󲿷ֳ�Ա �������õĿ��Ƕ�����connection��Ա
    ngx_connection_t                *connection;

    //Զ�˷�������socket��ַ
    struct sockaddr                 *sockaddr;
    //sockaddr��ַ�ĳ���
    socklen_t                        socklen;
    // Զ�˷�����������
    ngx_str_t                       *name;

    //��ʾ������һ��Զ�˷�����ʱ ��ǰ���ӳ����쳣ʧ�ܺ�������ԵĴ��� ������������ʧ�ܴ���
    ngx_uint_t                       tries;

    //��ȡ���ӵķ��� ���ʹ�ó����ӹ��ɵ����ӳ� ��ô����Ҫʵ��get����
    ngx_event_get_peer_pt            get;
    //��get������Ӧ���ͷ����ӵķ���
    ngx_event_free_peer_pt           free;
    /* 
        ���dataָ������ں������get��free������ϴ��ݲ��� ���ľ��庬����ʵ��get������free������ģ�����
        �ɲ���ngx_event_get_peer_pt��ngx_event_free_peer_pt����ԭ���е�data����
    */
    void                            *data;

#if (NGX_SSL)
    ngx_event_set_peer_session_pt    set_session;
    ngx_event_save_peer_session_pt   save_session;
#endif

#if (NGX_THREADS)
    ngx_atomic_t                    *lock;
#endif

    //������ַ��Ϣ
    ngx_addr_t                      *local;

    //�׽��ֵĽ��ջ�������С
    int                              rcvbuf;

    //��¼��־�Ķ���
    ngx_log_t                       *log;

    //��־λ Ϊ1ʱ��ʾ�����connection�����Ѿ�����
    unsigned                         cached:1;

                                     /* ngx_connection_log_error_e */
    /*
        ��ngx_connection_t���log_error��������ͬ�� �������������log_errorֻ����λ 
        ֻ�ܱ��4 �ִ��� NGX_ERROR_IGNORE_EINVAL�����޷����
    */
    unsigned                         log_error:2;
};


ngx_int_t ngx_event_connect_peer(ngx_peer_connection_t *pc);
ngx_int_t ngx_event_get_peer(ngx_peer_connection_t *pc, void *data);


#endif /* _NGX_EVENT_CONNECT_H_INCLUDED_ */
