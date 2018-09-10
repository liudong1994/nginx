
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_PIPE_H_INCLUDED_
#define _NGX_EVENT_PIPE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


typedef struct ngx_event_pipe_s  ngx_event_pipe_t;

// ������������εİ���Ļص�����ԭ��
typedef ngx_int_t (*ngx_event_pipe_input_filter_pt)(ngx_event_pipe_t *p,
                                                    ngx_buf_t *buf);

// �����η�����Ӧ�Ļص�����ԭ��
typedef ngx_int_t (*ngx_event_pipe_output_filter_pt)(void *data,
                                                     ngx_chain_t *chain);

// ע�� ngx_event_pipe_t�ṹ�������ת����Ӧ
struct ngx_event_pipe_s {
    // Nginx�����η������������
    ngx_connection_t  *upstream;
    // Nginx�����οͻ��˵�����
    ngx_connection_t  *downstream;

    /*
        ֱ�ӽ��������η������Ļ��������� 
        ��������е�˳��������� Ҳ����˵����ǰ�˵�ngx_buf_t������ָ����Ǻ���յ�����Ӧ 
        ����˵�ngx_buf_t������ָ������Ƚ��յ�����Ӧ
        ��� free_raw_bufs������ڽ�����Ӧʱʹ��
    */
    ngx_chain_t       *free_raw_bufs;

    /*
        ��ʾ���յ���������Ӧ������
        ͨ�� in��������input_filter���������õ� 
        �ɲο�ngx_event_pipe_copy_input_filter���� ���Ὣ���յ��Ļ��������õ�in������
    */
    ngx_chain_t       *in;
    // ָ��ոս��յ���һ��������
    ngx_chain_t      **last_in;

    /*
        �����Ž�Ҫ���͸��ͻ��˵Ļ���������
        ��д����ʱ�ļ��ɹ�ʱ ���in������д���ļ��Ļ�������ӵ�out������
    */
    ngx_chain_t       *out;
    // ָ��ռ���out����Ļ����� ����ʵ������
    ngx_chain_t      **last_out;

    // �ȴ��ͷŵĻ�����
    ngx_chain_t       *free;

    /*
        ��ʾ�ϴε���ngx_http_output_filter����������Ӧʱû�з�����Ļ���������
        ��������еĻ������Ѿ����浽�����out������busy�����ڼ�¼���ж�����Ӧ���ȴ�����
    */
    ngx_chain_t       *busy;

    /*
     * the input filter i.e. that moves HTTP/1.1 chunks
     * from the raw bufs to an incoming chain
     */

    /*
        ������յ����������η������Ļ�����
        һ��ʹ��upstream����Ĭ���ṩ��ngx_event_pipe_copy_input_filter������Ϊinput_filter
    */
    ngx_event_pipe_input_filter_pt    input_filter;
    // ����input_filter�����ĳ�Ա һ�㽫������Ϊngx_http_request_t�ṹ��ĵ�ַ
    void                             *input_ctx;

    // ��ʾ�����η�����Ӧ�ķ��� Ĭ��ʹ��ngx_http_output_filter������Ϊoutput_filter
    ngx_event_pipe_output_filter_pt   output_filter;
    // ָ��ngx_http_request_t�ṹ��
    void                             *output_ctx;

    // ��־λ readΪ1ʱ��ʾ��ǰ�Ѿ���ȡ�����ε���Ӧ
    unsigned           read:1;
    // ��־λ Ϊ1ʱ��ʾ�����ļ�����
    unsigned           cacheable:1;
    // ��־λ Ϊ1ʱ��ʾ����������Ӧʱһ��ֻ�ܽ���һ��ngx_buf_t������
    unsigned           single_buf:1;
    /*
        ��־λ Ϊ1ʱһ�����ٽ���������Ӧ���� �������ܵ������ͷŻ�����
        ��ν��������ָ һ�����������û�б����� ��û������д����ʱ�ļ��������������οͻ����ͷ� �Ͱѻ�����ָ����ڴ��ͷŸ�pool�ڴ��
    */
    unsigned           free_bufs:1;
    /* 
        �ṩ��HTTPģ����input_filter������ʹ�õı�־λ 
        ��ʾNginx�����μ�Ľ����ѽ���
        ���HTTPģ���ڽ�������ʱ ��Ϊ��ҵ������Ҫ���������μ������ ��ô���԰�upstream_done��־λ��Ϊ1
    */
    unsigned           upstream_done:1;
    /*
        Nginx�����η�����֮������ӳ��ִ���ʱ upstream_error��־λΪ1
        һ�㵱����������Ӧ��ʱ ���ߵ���recv���ճ��ִ���ʱ �ͻ�Ѹñ�־λ��Ϊ1
    */
    unsigned           upstream_error:1;
    // ��ʾ�����ε�����״̬ ��Nginx�����ε������Ѿ��ر�ʱ upstream_eof��־λΪ1
    unsigned           upstream_eof:1;
    /*
        ��ʾ��ʱ����ס��ȡ������Ӧ������ �ڴ�ͨ�������η�����Ӧ����������еĻ����� ���ÿճ��Ļ�����������Ӧ
        Ҳ����˵ upstream_blocked��־λΪ1ʱ����ngx_event_pipe������ѭ�����ȵ���ngx_event_pipe_write_to_downstream����������Ӧ
        Ȼ���ٴε���ngx_event_pipe_read_upstream������ȡ������Ӧ
    */
    unsigned           upstream_blocked:1;
    // downstream_done��־λΪ1ʱ��ʾ�����μ�Ľ����Ѿ����� Ŀǰ������
    unsigned           downstream_done:1;
    /*
        Nginx�����οͻ��˼�����ӳ��ִ���ʱ downstream_error��־λΪ1 
        �ڴ����� һ���������η�����Ӧ��ʱ ����ʹ��ngx_http_output_filter����������Ӧȴ����NGX_ERRORʱ ��downstream_error��־λ��Ϊ1
    */
    unsigned           downstream_error:1;
    /* 
        cyclic_temp_file��־λΪ1ʱ����ͼ������ʱ�ļ�������ʹ�ù��Ŀռ� 
        �����齫cyclic_temp_file��Ϊ1 ������ngx_http_upstream_conf_t���ýṹ���е�ͬ����Ա��ֵ��
    */
    unsigned           cyclic_temp_file:1;

    // ��ʾ�Ѿ�����Ļ�������Ŀ allocated�ܵ�bufs.num��Ա������
    ngx_int_t          allocated;
    // bufs��¼�˽���������Ӧ���ڴ滺������С ����bufs.size��ʾÿ���ڴ滺�����Ĵ�С ��bufs.num��ʾ��������num�����ջ�����
    ngx_bufs_t         bufs;
    // ��������/�Ƚϻ�����������ngx_buf_t�ṹ���tag��־λ
    ngx_buf_tag_t      tag;

    /*
        ����busy�������д����͵���Ӧ���ȴ���ֵ
        ���ﵽbusy_size����ʱ ����ȴ�busy�������������㹻������ ���ܼ�������out��in�������е�����
    */
    ssize_t            busy_size;

    // �Ѿ����յ���������Ӧ���峤��
    off_t              read_length;

    // ��ngx_http_upstream_conf_t���ýṹ���е�max_temp_file_size������ͬ ͬʱ���ǵ�ֵҲ����ȵ� ��ʾ��ʱ�ļ�����󳤶�
    off_t              max_temp_file_size;
    // ��ngx_http_upstream_conf_t���ýṹ���е�temp_file_write_size������ͬ ͬʱ���ǵ�ֵҲ����ȵ� ��ʾһ��д���ļ�ʱ����󳤶�
    ssize_t            temp_file_write_size;

    // ��ȡ������Ӧ�ĳ�ʱʱ��
    ngx_msec_t         read_timeout;
    // �����η�����Ӧ�ĳ�ʱʱ��
    ngx_msec_t         send_timeout;
    // �����η�����Ӧʱ TCP���������õ�send_lowat ˮλ
    ssize_t            send_lowat;

    // ���ڷ����ڴ滺���������ӳض���
    ngx_pool_t        *pool;
    // ���ڼ�¼��־��ngx_log_t����
    ngx_log_t         *log;

    // ��ʾ�ڽ������η�������Ӧͷ���׶� �Ѿ���ȡ������Ӧ����
    ngx_chain_t       *preread_bufs;
    // ��ʾ�ڽ������η�������Ӧͷ���׶� �Ѿ���ȡ������Ӧ���峤��
    size_t             preread_size;
    // �����ڻ����ļ��ĳ���
    ngx_buf_t         *buf_to_file;

    // ���������Ӧ����ʱ�ļ� ��󳤶���max_temp_file_size��Ա����
    ngx_temp_file_t   *temp_file;

    // ��ʹ�õ�ngx_buf_t��������Ŀ
    /* STUB */ int     num;
};


ngx_int_t ngx_event_pipe(ngx_event_pipe_t *p, ngx_int_t do_write);
ngx_int_t ngx_event_pipe_copy_input_filter(ngx_event_pipe_t *p, ngx_buf_t *buf);
ngx_int_t ngx_event_pipe_add_free_buf(ngx_event_pipe_t *p, ngx_buf_t *b);


#endif /* _NGX_EVENT_PIPE_H_INCLUDED_ */
