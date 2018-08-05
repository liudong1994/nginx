
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


#if (NGX_HAVE_ATOMIC_OPS)

/*
    ԭ�ӱ��� + �ź��� ������ʵ�ַ�ʽ
*/

ngx_int_t
ngx_shmtx_create(ngx_shmtx_t *mtx, void *addr, u_char *name)
{
    mtx->lock = addr;

    //��spinֵΪ-1ʱ ��ʾ����ʹ���ź��� ֱ�ӷ��سɹ�
    if (mtx->spin == (ngx_uint_t) -1) {
        return NGX_OK;
    }

    //spinֵĬ��Ϊ2048
    mtx->spin = 2048;

    //ϵͳ֧���ź���
#if (NGX_HAVE_POSIX_SEM)

    //�Զ����ʹ�õķ�ʽ��ʼ��sem�ź��� sem��ʼֵΪ0
    if (sem_init(&mtx->sem, 1, 0) == -1) {
        //��ʼ��ʧ����
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno,
                      "sem_init() failed");
    } else {
        //���ź�����ʼ���ɹ��� ����semaphore��־λΪ1
        mtx->semaphore = 1;
    }

#endif

    return NGX_OK;
}


void
ngx_shmtx_destory(ngx_shmtx_t *mtx)
{
#if (NGX_HAVE_POSIX_SEM)

    //���������spinֵ��Ϊ(ngx_uint_t) -1ʱ �ҳ�ʼ���ź����ɹ� semaphore��־λ��Ϊ1
    if (mtx->semaphore) {
        //�����ź���
        if (sem_destroy(&mtx->sem) == -1) {
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno,
                          "sem_destroy() failed");
        }
    }

#endif
}


ngx_uint_t
ngx_shmtx_trylock(ngx_shmtx_t *mtx)
{
    ngx_atomic_uint_t  val;

    //ȡ��lock����ֵ ͨ���ж����Ƿ�Ϊ�Ǹ�����ȷ����״̬
    val = *mtx->lock;

    /*
        ���valΪ0�������� ��˵��û�н��̳�����
        ��ʱ����ngx_atomic_cmp_set������lock����Ϊ���� ��ʾ��ǰ���̳����˻�����
    */
    return ((val & 0x80000000) == 0
            && ngx_atomic_cmp_set(mtx->lock, val, val | 0x80000000));
}


void
ngx_shmtx_lock(ngx_shmtx_t *mtx)
{
    ngx_uint_t         i, n;
    ngx_atomic_uint_t  val;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0, "shmtx lock");

    //û���õ���֮ǰ�ǲ�������ѭ����
    for ( ;; ) {

        /*
            lockֵ�ǵ�ǰ����״̬ ע�� lockһ�����ڹ����ڴ��е� �����ܻ�ʱ�̱仯 
            ��val�ǵ�ǰ���̵�ջ�б�������������ִ������������lockֵ��һ��
        */
        val = *mtx->lock;

        //���valΪ�Ǹ��� ��˵����δ������ ������ͼͨ���޸�lockֵΪ������������
        if ((val & 0x80000000) == 0
            && ngx_atomic_cmp_set(mtx->lock, val, val | 0x80000000))
        {
            /*
                �ڳɹ��ؽ�lockֵ��ԭ�ȵ�val��Ϊ�Ǹ�����
                ��ʾ�ɹ��س������� ngx_shmtx_lock��������
            */
            return;
        }

        //���ڶദ����״̬��spinֵ�������� ����PAUSEָ���ǲ���ִ�е�
        if (ngx_ncpu > 1) {

            //ѭ��ִ��PAUSE ������Ƿ��Ѿ��ͷ�
            for (n = 1; n < mtx->spin; n <<= 1) {

                //���ų�ʱ��û�л�õ��� ����ִ�и����PAUSE�Ż�����
                for (i = 0; i < n; i++) {
                    //���ڶദ����ϵͳ ִ��ngx_cpu_pause���Խ��͹���
                    ngx_cpu_pause();
                }

                //�ٴ��ɹ����ڴ��л��lockԭ�ӱ�����ֵ
                val = *mtx->lock;

                /*
                    ���lock�Ƿ��Ѿ�Ϊ�Ǹ��� �����Ƿ��Ѿ����ͷ� 
                    ������Ѿ��ͷ� ��ô��ͨ����lockԭ�ӱ���ֵ����Ϊ��������ʾ��ǰ���̳�������
                */
                if ((val & 0x80000000) == 0
                    && ngx_atomic_cmp_set(mtx->lock, val, val | 0x80000000))
                {
                    //�������ɹ������̷���
                    return;
                }
            }
        }

#if (NGX_HAVE_POSIX_SEM)
        /*
            �о�����ʹ���ź�������;�����ý��̽���˯��״̬ ������Ƶ������ngx_sched_yield
            ֱ���н����ͷ��ź���ʱ ���ѽ��̼��������¼�(��Ȼ���ַ�ʽӦ����ҪӦ��˯���¼��ϳ��ĳ���)
        */

        //semaphore��־λΪ1��ʹ���ź���
        if (mtx->semaphore) {
            //���»�ȡһ�ο����ڹ����ڴ��е�lockԭ�ӱ���
            val = *mtx->lock;

            //���lockֵΪ���� ��lockֵ����1
            if ((val & 0x80000000)
                && ngx_atomic_cmp_set(mtx->lock, val, val + 1))
            {
                ngx_log_debug1(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                               "shmtx wait %XA", val);

                /*
                    ����ź���sem��ֵ ���semֵΪ���� ��semֵ��1 ��ʾ�õ����ź��������� 
                    ͬʱsem_wait��������0 ���semֵΪ0���߸��� ��ǰ���̽���˯��״̬ 
                    �ȴ���������ʹ��ngx_shmtx_unlock�����ͷ������ȴ�sem�ź�����Ϊ������ 
                    ��ʱLinux�ں˻����µ��ȵ�ǰ���� �������semֵ�Ƿ�Ϊ�� �ظ���������
                */
                while (sem_wait(&mtx->sem) == -1) {
                    ngx_err_t  err;

                    err = ngx_errno;

                    //��EINTR�źų���ʱ ��ʾsem_waitֻ�Ǳ���� �����ǳ���
                    if (err != NGX_EINTR) {
                        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, err,
                                   "sem_wait() failed while waiting on shmtx");
                        break;
                    }
                }

                ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                               "shmtx awoke");
            }

            //ѭ�����lock����ֵ ע�� ��ʹ���ź����󲻻����sched_yield
            continue;
        }

#endif

        //�ڲ�ʹ���ź���ʱ ����sched_yield����ʹ��ǰ������ʱ���ó���������
        ngx_sched_yield();
    }
}


void
ngx_shmtx_unlock(ngx_shmtx_t *mtx)
{
    ngx_atomic_uint_t  val, old, wait;

    if (mtx->spin != (ngx_uint_t) -1) {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0, "shmtx unlock");
    }

    //��ͼѭ������lockֵΪ���� ��ʱ��ؽ��������ͷ�
    for ( ;; ) {

        //�ɹ����ڴ��е�lockԭ�ӱ���ȡ����״̬
        old = *mtx->lock;
        //ͨ�������λ��Ϊ0 ��lock��Ϊ����
        wait = old & 0x7fffffff;
        //�����Ϊ������lock����0 ���ȥ1
        val = wait ? wait - 1 : 0;

        //��lock����ֵ��Ϊ�Ǹ���val
        if (ngx_atomic_cmp_set(mtx->lock, old, val)) {
            //�������ɹ����������ѭ�� ���򽫳�������ͼ�޸�lockֵΪ�Ǹ���
            break;
        }
    }

#if (NGX_HAVE_POSIX_SEM)

    /*
        ���lock��ԭ�ȵ�ֵΪ0 Ҳ����˵ ��û����ĳ�����̳����� ��ʱֱ�ӷ���
        ���� semaphore��־λΪ0 ��ʾ����Ҫʹ���ź��� Ҳ��������
    */
    if (wait == 0 || !mtx->semaphore) {
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "shmtx wake %XA", old);

    /*
        ͨ��sem_post���ź���sem��1 ��ʾ��ǰ�����ͷ����ź���������
        ֪ͨ�������̵�sem_wait����ִ��
    */
    if (sem_post(&mtx->sem) == -1) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno,
                      "sem_post() failed while wake shmtx");
    }

#endif
}


#else


/*
    �ļ���ʵ�ַ�ʽ
*/

ngx_int_t
ngx_shmtx_create(ngx_shmtx_t *mtx, void *addr, u_char *name)
{
    //�����ڵ���ngx_shmtx_create����ǰ���и�ֵ��ngx_shmtx_t�ṹ���еĳ�Ա
    if (mtx->name) {

        /*
            ���ngx_shmtx_t�е�name��Ա��ֵ ��ô�����name������ͬ��ζ��mtx�������Ѿ���ʼ������
            ���� ��Ҫ������mtx�еĻ����������·���mtx
        */
        if (ngx_strcmp(name, mtx->name) == 0) {
            mtx->name = name;
            return NGX_OK;
        }

        ngx_shmtx_destory(mtx);
    }

    //����nameָ����·��������������ļ�
    mtx->fd = ngx_open_file(name, NGX_FILE_RDWR, NGX_FILE_CREATE_OR_OPEN,
                            NGX_FILE_DEFAULT_ACCESS);

    if (mtx->fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, ngx_errno,
                      ngx_open_file_n " \"%s\" failed", name);
        return NGX_ERROR;
    }

    //����ֻ��Ҫ����ļ����ں��е�INODE��Ϣ ���Կ��԰��ļ�ɾ�� ֻҪfd���þ���
    if (ngx_delete_file(name) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno,
                      ngx_delete_file_n " \"%s\" failed", name);
    }

    mtx->name = name;

    return NGX_OK;
}


void
ngx_shmtx_destory(ngx_shmtx_t *mtx)
{
    //�ر�ngx_shmtx_t�ṹ���е�fd���
    if (ngx_close_file(mtx->fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", mtx->name);
    }
}


ngx_uint_t
ngx_shmtx_trylock(ngx_shmtx_t *mtx)
{
    ngx_err_t  err;

    err = ngx_trylock_fd(mtx->fd);

    if (err == 0) {
        return 1;
    }

    if (err == NGX_EAGAIN) {
        return 0;
    }

#if __osf__ /* Tru64 UNIX */

    if (err == NGX_EACCESS) {
        return 0;
    }

#endif

    ngx_log_abort(err, ngx_trylock_fd_n " %s failed", mtx->name);

    return 0;
}


void
ngx_shmtx_lock(ngx_shmtx_t *mtx)
{
    ngx_err_t  err;

    err = ngx_lock_fd(mtx->fd);

    if (err == 0) {
        return;
    }

    ngx_log_abort(err, ngx_lock_fd_n " %s failed", mtx->name);
}


void
ngx_shmtx_unlock(ngx_shmtx_t *mtx)
{
    ngx_err_t  err;

    err = ngx_unlock_fd(mtx->fd);

    if (err == 0) {
        return;
    }

    ngx_log_abort(err, ngx_unlock_fd_n " %s failed", mtx->name);
}

#endif
