
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_SHMEM_H_INCLUDED_
#define _NGX_SHMEM_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {
    u_char      *addr;	//�����ڴ���ʼ��ַ
    size_t       size;	//�����ڴ��С
    ngx_str_t    name;	//�����ڴ�����
    ngx_log_t   *log;	//��־ģ��
	ngx_uint_t   exists;   /* unsigned  exists:1;  ��ʾ�����ڴ��Ƿ��Ѿ�������ı�־λ Ϊ1ʱ��ʾ�Ѿ����� */ 
} ngx_shm_t;


ngx_int_t ngx_shm_alloc(ngx_shm_t *shm);
void ngx_shm_free(ngx_shm_t *shm);


#endif /* _NGX_SHMEM_H_INCLUDED_ */
