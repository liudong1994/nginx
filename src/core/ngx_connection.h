
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CONNECTION_H_INCLUDED_
#define _NGX_CONNECTION_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_listening_s  ngx_listening_t;

struct ngx_listening_s {
	//socket�׽��־��
    ngx_socket_t        fd;
	
	//����sockaddr��ַ
    struct sockaddr    *sockaddr;
	//sockaddr�ĵ�ַ
    socklen_t           socklen;    /* size of sockaddr */
	//�洢IP��ַ���ַ���addr_text��󳤶� ��ָ����addr_text��������ڴ��С
    size_t              addr_text_max_len;
	//���ַ�����ʽ�洢IP��ַ
    ngx_str_t           addr_text;

	//�׽������� �磺��type��SOCK_STREAMʱ ��ʾTCP
    int                 type;

	//TCPʵ�ּ���ʱ��backlog���� ����ʾ��������ͨ���������ֽ���TCP���ӵ���û��������̿�ʼ���������������
    int                 backlog;
	//�ں��ж�������׽��ֵĽ��ջ�������С
    int                 rcvbuf;
	//�ں��ж�������׽��ֵķ��ͻ�������С
    int                 sndbuf;

    /* handler of accepted connection */
    ngx_connection_handler_pt   handler;	//���µ�TCP���ӽ����ɹ���Ĵ����� �ǳ���Ҫ

	/*
		ʵ���Ͽ�ܴ��벻ʹ��serversָ�� ��������һ������ָ�� Ŀǰ��Ҫ���ڴ���HTTP����mail��ģ�� ���ڱ��浱ǰ�����˿ڶ�Ӧ�ŵ�����������
	*/
    void               *servers;  /* array of ngx_http_in_addr_t, for example */

	//log��logp���ǿ��õ���־�����ָ��
    ngx_log_t           log;
    ngx_log_t          *logp;

	//���Ϊ�µ�TCP���Ӵ����ڴ�� ���ڴ�صĳ�ʼ����СӦ����pool_size
    size_t              pool_size;

    /* should be here because of the AcceptEx() preread */
	size_t              post_accept_buffer_size;
    /* 
		should be here because of the deferred accept
		TCP_DEFER_ACCEPTѡ��ڽ���TCP���ӳɹ����ҽ��յ��û�������������ݺ� ����Լ����׽��ָ���Ȥ�Ľ��з����¼�֪ͨ 
		�����ӽ����ɹ��� ���post_accept_timeout�����Ȼû���յ��û������� ���ں�ֱ�Ӷ�������
	*/
    ngx_msec_t          post_accept_timeout;

	//ǰ��һ��ngx_listening_t�ṹ ���ngx_listening_t�ṹ��֮����previousָ����ɵ�����
    ngx_listening_t    *previous;
	//��ǰ���������Ӧ�ŵ�ngx_connect_t�ṹ��
    ngx_connection_t   *connection;

	/*
		��־λ��Ϊ1��ʾ�ڵ�ǰ���������Ч ��ִ��ngx_init_cycleʱ���رռ����˿� Ϊ0ʱ�������ر� �ñ�־λ��ܴ�����Զ�����
	*/
    unsigned            open:1;
	/*
		��־λ��Ϊ1��ʾʹ�����е�ngx_cycle_t����ʼ���µ�ngx_cycle_t�ṹ��ʱ ���ر�ԭ���򿪵ļ����˿� ����������������������
		remainΪ0ʱ ��ʾ�����ر������򿪵ļ����˿�
		�ñ�־λ��ܴ�����Զ�����
	*/
    unsigned            remain:1;
	/*
		��־λ��Ϊ1ʱ��ʾ�������õ�ǰngx_listening_t�ṹ���е��׽��� Ϊ0ʱ������ʼ���׽��� �ñ�־λ��ܴ����Զ�����
	*/
    unsigned            ignore:1;

	//��ʾ�Ƿ��Ѿ��� ʵ����Ŀǰ�ñ�־λû��ʹ��
    unsigned            bound:1;       /* already bound */
	/*
		��ʾ��ǰ��������Ƿ�����ǰһ������(������Nginx����) ���Ϊ1 ��ʾ����ǰһ������ һ��ᱣ��֮ǰ�Ѿ����úõ��׽��� �����ı�
	*/
    unsigned            inherited:1;   /* inherited from previous process */
	//Ŀǰδʹ��
    unsigned            nonblocking_accept:1;
	//Ϊ1ʱ��ʾ��ǰ�ṹ���е��׽����Ѿ���ʼ����
    unsigned            listen:1;
	//��ʾ�׽����Ƿ����� Ŀǰ�ñ�־λû������
    unsigned            nonblocking:1;
	//Ŀǰ�ñ�־λû������
    unsigned            shared:1;    /* shared between threads or processes */
	//Ϊ1ʱ��ʾNginx�Ὣ�����ַת��Ϊ�ַ�����ʽ�ĵ�ַ
    unsigned            addr_ntop:1;

#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    unsigned            ipv6only:2;
#endif

#if (NGX_HAVE_DEFERRED_ACCEPT)
    unsigned            deferred_accept:1;
    unsigned            delete_deferred:1;
    unsigned            add_deferred:1;
#ifdef SO_ACCEPTFILTER
    char               *accept_filter;
#endif
#endif
#if (NGX_HAVE_SETFIB)
    int                 setfib;
#endif

};


typedef enum {
     NGX_ERROR_ALERT = 0,
     NGX_ERROR_ERR,
     NGX_ERROR_INFO,
     NGX_ERROR_IGNORE_ECONNRESET,
     NGX_ERROR_IGNORE_EINVAL
} ngx_connection_log_error_e;


typedef enum {
     NGX_TCP_NODELAY_UNSET = 0,
     NGX_TCP_NODELAY_SET,
     NGX_TCP_NODELAY_DISABLED
} ngx_connection_tcp_nodelay_e;


typedef enum {
     NGX_TCP_NOPUSH_UNSET = 0,
     NGX_TCP_NOPUSH_SET,
     NGX_TCP_NOPUSH_DISABLED
} ngx_connection_tcp_nopush_e;


#define NGX_LOWLEVEL_BUFFERED  0x0f
#define NGX_SSL_BUFFERED       0x01


struct ngx_connection_s {
    /*
        ����δʹ��ʱ data��Ա���ڳ䵱���ӳ��п������������е�nextָ��
        �����ӱ�ʹ��ʱ data��������ʹ������Nginxģ����� 
        ����HTTP����� dataָ��ngx_http_request_t����
    */
    void               *data;
    //���Ӷ�Ӧ�Ķ��¼�
    ngx_event_t        *read;
    //���Ӷ�Ӧ��д�¼�
    ngx_event_t        *write;

    //�׽��־��
    ngx_socket_t        fd;

    //ֱ�ӽ��������ַ����ķ���
    ngx_recv_pt         recv;
    //ֱ�ӷ��������ַ����ķ���
    ngx_send_pt         send;
    //��ngx_chain_t����Ϊ���� �����������ַ����ķ���
    ngx_recv_chain_pt   recv_chain;
    //��ngx_chain_t����Ϊ���� �����������ַ����ķ���
    ngx_send_chain_pt   send_chain;

    //������Ӷ�Ӧ��ngx_listening_t�������� ��������listening�����˿ڵ��¼�����
    ngx_listening_t    *listening;

    //����������Ѿ����ͳ�ȥ���ֽ���
    off_t               sent;

    //��־����
    ngx_log_t          *log;

    /*
        �ڴ�� һ����acceptһ��������ʱ �ᴴ��һ���ڴ�� ����������ӽ���ʱ�������ڴ��
        ע�� ������˵��������ָ�ɹ�������TCP���� ���е�ngx_connection_t�ṹ�嶼��Ԥ����� 
        ����ڴ�صĴ�С���������listening���������е�pool_size��Ա����
    */
    ngx_pool_t         *pool;

    //���ӿͻ��˵�sockaddr�ṹ��
    struct sockaddr    *sockaddr;
    //sockaddr�ṹ��ĳ���
    socklen_t           socklen;
    //���ӿͻ����ַ�����ʽ��IP��ַ
    ngx_str_t           addr_text;

#if (NGX_SSL)
    ngx_ssl_connection_t  *ssl;
#endif

    //�����ļ����˿ڶ�Ӧ��sockaddr�ṹ�� Ҳ����listening���������е�sockaddr��Ա
    struct sockaddr    *local_sockaddr;

    /*
        ���ڽ��ա�����ͻ��˷������ַ��� ÿ���¼�����ģ������ɾ��������ӳ��з�����Ŀռ��buffer������ջ����ֶ�
        ���� ��HTTPģ���� ���Ĵ�С������client_header_buffer_size������
    */
    ngx_buf_t          *buffer;

    /*
        ���ֶ���������ǰ������˫������Ԫ�ص���ʽ��ӵ�ngx_cycle_t���Ľṹ���
        reusable_connections_queue˫�������� ��ʾ�������õ�����
    */
    ngx_queue_t         queue;

    /*
        ����ʹ�ô��� ngx_connection_t�ṹ��ÿ�ν���һ�����Կͻ��˵����� 
        ���������������˷�������������ʱ(ngx_peer_connection_tҲʹ����) number�����1
    */
    ngx_atomic_uint_t   number;

    //������������
    ngx_uint_t          requests;

    /*
        �����е�ҵ������ �κ��¼�����ģ�鶼�����Զ�����Ҫ�ı�־λ ���buffered�ֶ���8λ ������ͬʱ��ʾ8����ͬ��ҵ��
        ������ģ�����Զ���buffered��־λʱע�ⲻҪ�����ʹ�õ�ģ�鶨��ı�־λ��ͻ Ŀǰopensslģ�鶨����һ����־λ��
            #define NGX_SSL_BUFFERED 0x01
        HTTP�ٷ�ģ�鶨�������±�־λ��
            #define NGX_HTTP_LOWLEVEL_BUFFERED 0xf0
            #define NGX_HTTP_WRITE_BUFFERED 0x10
            #define NGX_HTTP_GZIP_BUFFERED 0x20
            #define NGX_HTTP_SSI_BUFFERED 0x01
            #define NGX_HTTP_SUB_BUFFERED 0x02
            #define NGX_HTTP_COPY_BUFFERED 0x04
            #define NGX_HTTP_IMAGE_BUFFERED 0x08
        ����HTTPģ����� buffered�ĵ�4λҪ���� ��ʵ�ʷ�����Ӧ��ngx_http_write_filter_module����ģ���� 
    ��4λ��־λΪ1����ζ��Nginx��һֱ��Ϊ��HTTPģ�黹��Ҫ����������� ����ȴ�HTTPģ�齫��4λȫ��Ϊ0�Ż�������������
        ����4λ�ĺ����£�
            #define NGX_LOWLEVEL_BUFFERED 0x0f
    */
    unsigned            buffered:8;
    
    /*
        �����Ӽ�¼��־ʱ�ļ��� ��ռ����3λ ȡֵ��Χ��0~7 ��ʵ����Ŀǰֻ������5��ֵ 
        ��ngx_connection_log_error_eö�ٱ�ʾ ���£�
        typedef enum {
            NGX_ERROR_ALERT = 0,
            NGX_ERROR_ERR,
            NGX_ERROR_INFO,
            NGX_ERROR_IGNORE_ECONNRESET,
            NGX_ERROR_IGNORE_EINVAL
        } ngx_connection_log_error_e;
    */
    unsigned            log_error:3;     /* ngx_connection_log_error_e */

    /*
        ��־λ Ϊ1ʱ��ʾ���������� ��ӿͻ��˷�������� 
        Ϊ0ʱ��ʾ�����������ӵ���Ϊ�����������ķǶ������� ��ʹ��upstream�������˷�������������������
    */
    unsigned            single_connection:1;
    //��־λ Ϊ1ʱ��ʾ���ڴ��ַ������� Ŀǰ������
    unsigned            unexpected_eof:1;
    //��־λ Ϊ1ʱ��ʾ�����Ѿ���ʱ
    unsigned            timedout:1;
    //��־λ Ϊ1ʱ��ʾ���Ӵ�������г��ִ���
    unsigned            error:1;
    /*
        ��־λ Ϊ1ʱ��ʾ�����Ѿ����� ���������ָ�ǵ�TCP���� ������ngx_connection_t�ṹ��
        ��destroyedΪ1ʱ ngx_connection_t�ṹ����Ȼ���� �����Ӧ���׽��֡��ڴ�ص��Ѿ�������
    */
    unsigned            destroyed:1;

    //��־λ Ϊ1ʱ��ʾ���Ӵ��ڿ���״̬ ��keepalive��������������֮���״̬
    unsigned            idle:1;
    //��־λ Ϊ1ʱ��ʾ���ӿ����� ���������queue�ֶ��Ƕ�Ӧʹ�õ�
    unsigned            reusable:1;
    //��־λ Ϊ1ʱ��ʾ���ӹر�
    unsigned            close:1;

    //��־λ Ϊ1ʱ��ʾ���ڽ��ļ��е����ݷ������ӵ���һ��
    unsigned            sendfile:1;
    /*
        ��־λ ���Ϊ1 ���ʾֻ���������׽��ֶ�Ӧ�ķ��ͻ�������������������õĴ�С��ֵʱ �¼�����ģ��Ż�ַ����¼� 
        �������Ľ��ܹ���ngx_handle_write_event�����е�lowat�����Ƕ�Ӧ��
    */
    unsigned            sndlowat:1;
    /*
        ��־λ ��ʾ���ʹ��TCP��nodelay���� 
        ����ȡֵ��Χ���������ö������ngx_connection_tcp_nodelay_e��
        typedef enum {
            NGX_TCP_NODELAY_UNSET = 0,
            NGX_TCP_NODELAY_SET,
            NGX_TCP_NODELAY_DISABLED
        } ngx_connection_tcp_nodelay_e;
    */
    unsigned            tcp_nodelay:2;   /* ngx_connection_tcp_nodelay_e */
    /*
        ��־λ ��ʾ���ʹ��TCP��nopush���� 
        ����ȡֵ��Χ���������ö������ngx_connection_tcp_nopush_e��
        typedef enum {
            NGX_TCP_NOPUSH_UNSET = 0,
            NGX_TCP_NOPUSH_SET,
            NGX_TCP_NOPUSH_DISABLED
        } ngx_connection_tcp_nopush_e;
    */
    unsigned            tcp_nopush:2;    /* ngx_connection_tcp_nopush_e */

#if (NGX_HAVE_IOCP)
    unsigned            accept_context_updated:1;
#endif

#if (NGX_HAVE_AIO_SENDFILE)
    //��־λ Ϊ1ʱ��ʾʹ���첽I/O�ķ�ʽ���������ļ����͸��������ӵ���һ��
    unsigned            aio_sendfile:1;
    //ʹ���첽I/O��ʽ���͵��ļ� busy_sendfile����������������ļ�����Ϣ
    ngx_buf_t          *busy_sendfile;
#endif

#if (NGX_THREADS)
    ngx_atomic_t        lock;
#endif
};


ngx_listening_t *ngx_create_listening(ngx_conf_t *cf, void *sockaddr,
    socklen_t socklen);
ngx_int_t ngx_set_inherited_sockets(ngx_cycle_t *cycle);
ngx_int_t ngx_open_listening_sockets(ngx_cycle_t *cycle);
void ngx_configure_listening_sockets(ngx_cycle_t *cycle);
void ngx_close_listening_sockets(ngx_cycle_t *cycle);
void ngx_close_connection(ngx_connection_t *c);
ngx_int_t ngx_connection_local_sockaddr(ngx_connection_t *c, ngx_str_t *s,
    ngx_uint_t port);
ngx_int_t ngx_connection_error(ngx_connection_t *c, ngx_err_t err, char *text);

ngx_connection_t *ngx_get_connection(ngx_socket_t s, ngx_log_t *log);
void ngx_free_connection(ngx_connection_t *c);

void ngx_reusable_connection(ngx_connection_t *c, ngx_uint_t reusable);

#endif /* _NGX_CONNECTION_H_INCLUDED_ */
