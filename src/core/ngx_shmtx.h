
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_SHMTX_H_INCLUDED_
#define _NGX_SHMTX_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

/*
    ����������� ��Ӧ��nginx������������ʵ�ַ�ʽ
    1.��֧��ԭ�ӱ��� ʹ���ļ���
    2.֧��ԭ�ӱ�����֧���ź���
    3.֧��ԭ�ӱ���Ҳ֧���ź���
*/
typedef struct {
#if (NGX_HAVE_ATOMIC_OPS)
    //ԭ�ӱ�����
    ngx_atomic_t  *lock;
#if (NGX_HAVE_POSIX_SEM)
    //semaphoreΪ1ʱ��ʾ��ȡ��������ʹ�õ����ź���
    ngx_uint_t     semaphore;
    //sem�����ź�����
    sem_t          sem;
#endif
#else
    //ʹ���ļ���ʱfd��ʾʹ�õ��ļ����
    ngx_fd_t       fd;
    //name��ʾ�ļ���
    u_char        *name;
#endif
    /*
        �������� ��ʾ������״̬�µȴ�����������ִ�н�����ͷ�����ʱ��
        ���ļ���ʵ��ʱ spinû���κ�����
    */
    ngx_uint_t     spin;
} ngx_shmtx_t;


ngx_int_t ngx_shmtx_create(ngx_shmtx_t *mtx, void *addr, u_char *name);
void ngx_shmtx_destory(ngx_shmtx_t *mtx);
ngx_uint_t ngx_shmtx_trylock(ngx_shmtx_t *mtx);
void ngx_shmtx_lock(ngx_shmtx_t *mtx);
void ngx_shmtx_unlock(ngx_shmtx_t *mtx);


#endif /* _NGX_SHMTX_H_INCLUDED_ */
