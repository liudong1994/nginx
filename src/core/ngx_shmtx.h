
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_SHMTX_H_INCLUDED_
#define _NGX_SHMTX_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

/*
    下面的两个宏 对应着nginx互斥锁的三种实现方式
    1.不支持原子变量 使用文件锁
    2.支持原子变量不支持信号量
    3.支持原子变量也支持信号量
*/
typedef struct {
#if (NGX_HAVE_ATOMIC_OPS)
    //原子变量锁
    ngx_atomic_t  *lock;
#if (NGX_HAVE_POSIX_SEM)
    //semaphore为1时表示获取锁将可能使用到的信号量
    ngx_uint_t     semaphore;
    //sem就是信号量锁
    sem_t          sem;
#endif
#else
    //使用文件锁时fd表示使用的文件句柄
    ngx_fd_t       fd;
    //name表示文件名
    u_char        *name;
#endif
    /*
        自旋次数 表示在自旋状态下等待其他处理器执行结果中释放锁的时间
        由文件锁实现时 spin没有任何意义
    */
    ngx_uint_t     spin;
} ngx_shmtx_t;


ngx_int_t ngx_shmtx_create(ngx_shmtx_t *mtx, void *addr, u_char *name);
void ngx_shmtx_destory(ngx_shmtx_t *mtx);
ngx_uint_t ngx_shmtx_trylock(ngx_shmtx_t *mtx);
void ngx_shmtx_lock(ngx_shmtx_t *mtx);
void ngx_shmtx_unlock(ngx_shmtx_t *mtx);


#endif /* _NGX_SHMTX_H_INCLUDED_ */
