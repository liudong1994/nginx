
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CYCLE_H_INCLUDED_
#define _NGX_CYCLE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#ifndef NGX_CYCLE_POOL_SIZE
#define NGX_CYCLE_POOL_SIZE     16384
#endif


#define NGX_DEBUG_POINTS_STOP   1
#define NGX_DEBUG_POINTS_ABORT  2


typedef struct ngx_shm_zone_s  ngx_shm_zone_t;

typedef ngx_int_t (*ngx_shm_zone_init_pt) (ngx_shm_zone_t *zone, void *data);

struct ngx_shm_zone_s {
    void                     *data;
    ngx_shm_t                 shm;
    ngx_shm_zone_init_pt      init;
    void                     *tag;
};


struct ngx_cycle_s {
	/*
		����������ģ��洢������Ľṹ���ָ��
		��������һ������(*) ÿ������ĳ�Ա����һ��ָ��(**) ���ָ����ָ����һ���洢��ָ�������(**) ��Ϊ�ῴ��void****
	*/
    void                  ****conf_ctx;
	//�ڴ��
    ngx_pool_t               *pool;

	/*
		��־ģ�����ṩ�����ɻ���ngx_log_t��־����Ĺ��� �����logʵ�������ڻ�û��ִ��ngx_init_cycle����ǰ Ҳ���ǻ�û�н�������ǰ
	�������Ϣ��Ҫ�������־ �ͻ���ʱʹ��log���� �����������Ļ ��ngx_init_cycle����ִ�к� �������nginx,conf�����ļ��е�������
	�������ȷ����־�ļ� ��ʱ���log���¸�ֵ
	*/
    ngx_log_t                *log;
	/*
		��nginx.conf�����ļ���ȡ����־�ļ�·���� ����ʼ��ʼ��error_log��־�ļ� ����log���������������־����Ļ 
	��ʱ����new_log������ʱ�Ե����log��־ ����ʼ����ɺ� ����new_log�ĵ�ַ���������logָ��
	*/
    ngx_log_t                 new_log;

	/*
		����poll��rtsig�������¼�ģ�� ������Ч�ļ������Ԥ�Ƚ�����Щngx_connection_t�ṹ�� �Լ����¼����ռ����ַ� 
	��ʱfiles�ͻᱣ������ngx_connection_t��ָ����ɵ����� files_n(����)����ָ������� ���ļ������ֵ��������files�����Ա
	*/
    ngx_connection_t        **files;
	//�������ӳ� ��free_connection_n���ʹ��
    ngx_connection_t         *free_connections;
	//�������ӳ��е���������
    ngx_uint_t                free_connection_n;

	//˫���������� Ԫ������ʱngx_connection_t�ṹ�� ��ʾ���ظ�ʹ�����Ӷ���
    ngx_queue_t               reusable_connections_queue;

	//����Ԫ�ض���ngx_listening_t�ṹ�� ÿ������Ԫ���ִ���Nginx������������һ���˿�
    ngx_array_t               listening;
	/*
		��̬�������� ��������Nginx��Ҫ������Ŀ¼ �����Ŀ¼������ �����ͼ���� ������Ŀ¼ʧ�ܵĻ��ᵼ��Nginx����ʧ��
	*/
    ngx_array_t               pathes;
	/*
		���������� Ԫ��������ngx_open_file_t�ṹ�� ����ʾNginx�Ѿ��򿪵����е��ļ� ��ʵ�� Nginx��ܲ�����open_files������
	����ļ� �����ɶԴ˸���Ȥ��ģ������������ļ�·������ Nginx��ܻ���ngx_init_cycle�����д���Щ�ļ�
	*/
    ngx_list_t                open_files;
	//���������� Ԫ�ص�������ngx_shm_zone_t�ṹ�� ÿ��Ԫ�ر�ʾһ�鹲���ڴ�
    ngx_list_t                shared_memory;

	//��ǰ�������������Ӷ�������� �������connections���ʹ��
    ngx_uint_t                connection_n;
	//�������files���ʹ��
    ngx_uint_t                files_n;

	//��ǰ���̵��������Ӷ��� �������connection_n���ʹ��
    ngx_connection_t         *connections;
	//��ǰ�������ж��¼����� connection_nͬʱ��ʾ���ж��¼�������
    ngx_event_t              *read_events;
	//��ǰ��������д�¼����� connection_nͬʱ��ʾ����д�¼�������
    ngx_event_t              *write_events;

	/*
		�ɵ�ngx_cycle_t��������������һ��ngx_cycle_t�����еĳ�Ա
		���磺
		ngx_init_cycle���� ���������� ��Ҫ����һ����ʱ��ngx_cycle_t���󱣴�һЩ���� �ٵ���ngx_init_cycle����ʱ���԰Ѿɵ�ngx_cycle_t����
	����ȥ ����ʱold_cycle����ͻᱣ�����ǰ�ڵ�ngx_cycle_t����
	*/
    ngx_cycle_t              *old_cycle;

	//�����ļ�����ڰ�װĿ¼��·������
    ngx_str_t                 conf_file;
	//Nginx���������ļ�ʱ��Ҫ���⴦�����������Я���Ĳ��� һ����-gѡ��Я���Ĳ���
	ngx_str_t                 conf_param;
	//Nginx�����ļ�����Ŀ¼��·��
    ngx_str_t                 conf_prefix;
	//Nginx��װĿ¼��·��
    ngx_str_t                 prefix;
	//���ڽ��̼�ͬ�����ļ�������
    ngx_str_t                 lock_file;
	//ʹ��gethostnameϵͳ���û�ȡ��������
    ngx_str_t                 hostname;
};


typedef struct {
     ngx_flag_t               daemon;
     ngx_flag_t               master;

     ngx_msec_t               timer_resolution;

     ngx_int_t                worker_processes;
     ngx_int_t                debug_points;

     ngx_int_t                rlimit_nofile;
     ngx_int_t                rlimit_sigpending;
     off_t                    rlimit_core;

     int                      priority;

     ngx_uint_t               cpu_affinity_n;
     u_long                  *cpu_affinity;

     char                    *username;
     ngx_uid_t                user;
     ngx_gid_t                group;

     ngx_str_t                working_directory;
     ngx_str_t                lock_file;

     ngx_str_t                pid;
     ngx_str_t                oldpid;

     ngx_array_t              env;
     char                   **environment;

#if (NGX_THREADS)
     ngx_int_t                worker_threads;
     size_t                   thread_stack_size;
#endif

} ngx_core_conf_t;


typedef struct {
     ngx_pool_t              *pool;   /* pcre's malloc() pool */
} ngx_core_tls_t;


#define ngx_is_init_cycle(cycle)  (cycle->conf_ctx == NULL)


ngx_cycle_t *ngx_init_cycle(ngx_cycle_t *old_cycle);
ngx_int_t ngx_create_pidfile(ngx_str_t *name, ngx_log_t *log);
void ngx_delete_pidfile(ngx_cycle_t *cycle);
ngx_int_t ngx_signal_process(ngx_cycle_t *cycle, char *sig);
void ngx_reopen_files(ngx_cycle_t *cycle, ngx_uid_t user);
char **ngx_set_environment(ngx_cycle_t *cycle, ngx_uint_t *last);
ngx_pid_t ngx_exec_new_binary(ngx_cycle_t *cycle, char *const *argv);
u_long ngx_get_cpu_affinity(ngx_uint_t n);
ngx_shm_zone_t *ngx_shared_memory_add(ngx_conf_t *cf, ngx_str_t *name,
    size_t size, void *tag);


extern volatile ngx_cycle_t  *ngx_cycle;
extern ngx_array_t            ngx_old_cycles;
extern ngx_module_t           ngx_core_module;
extern ngx_uint_t             ngx_test_config;
extern ngx_uint_t             ngx_quiet_mode;
#if (NGX_THREADS)
extern ngx_tls_key_t          ngx_core_tls_key;
#endif


#endif /* _NGX_CYCLE_H_INCLUDED_ */
