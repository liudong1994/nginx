#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_conf_file.h>


/*
    配置文件中出现
    location /ldFtp{
        ldFtp;
    }

    在 NGX_HTTP_CONTENT_PHARE阶段将有可能调用我们的 ngx_http_ldFtp_handler方法

    在配置文件出现 ldFtp配置项时，ngx_http_ldFtp_handler方法将会被调用，这时将 ngx_http_core_loc_conf_t结构体的 handler成员指定为 ngx_http_ldFtp_handler方法，
    另外，Http框架在接收完 Http请求的头部之后，会调用 handler指向的方法。
*/

static char *ngx_http_ldFtp(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_ldFtp_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_ldFtp_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static char *ngx_http_ldFtp(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_ldFtp_handler(ngx_http_request_t *r);
static void ngx_http_client_body_read_complete(ngx_http_request_t *r);


//自定义存储配置文件结构体
typedef struct{
    ngx_str_t       file_path;
    ngx_int_t       version;

}ngx_http_ldFtp_loc_conf_t;

//模块 上下文结构体
typedef struct 
{
    ngx_str_t	    file_name;
}ngx_http_ldFtp_ctx_t;


static ngx_command_t ngx_http_ldFtp_commands[] = {
    {
        ngx_string("ldFtp"),                //name
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_NOARGS,   //type
        ngx_http_ldFtp,                     //set handler
        NGX_HTTP_LOC_CONF_OFFSET,           //conf
        0,                                  //offset
        NULL                                //post
    },

    //添加我们要解析的字段 函数及名称
    {
        ngx_string("file_path"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_ldFtp_loc_conf_t, file_path),
        NULL
    },

    {
        ngx_string("version"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_ldFtp_loc_conf_t, version),
        NULL
    },

    ngx_null_command
};

//ngx_http_module_t接口
static ngx_http_module_t ngx_http_ldFtp_module_ctx = {
    NULL,                                       /* preconfiguration */
    NULL,                                       /* postconfiguration */

    NULL,                                       /* create main configuration */
    NULL,                                       /* init main configuration */

    NULL,                                       /* create server configuration */
    NULL,                                       /* merge server configuration */

    ngx_http_ldFtp_create_loc_conf,             /* create location configuration */
    NULL                                        /* merge location configuration */
};


/*
    定义ldFtp模块 在ngx_modules.c文件中的数组中会有 ngx_http_ldFtp_module的 extern(被注册)
    ngx_http_ldFtp_module里面会有 
        1.ngx_http_ldFtp_module_ctx     指出 针对配置文件的读取存储方式(HTTP模块指定)
        2.ngx_http_ldFtp_commands       指出 配置文件中出现的 URL匹配后相应操作(nginx总模块指定)
*/
ngx_module_t ngx_http_ldFtp_module = {
    NGX_MODULE_V1,
    &ngx_http_ldFtp_module_ctx,            /* module context */
    ngx_http_ldFtp_commands,               /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};

static void *ngx_http_ldFtp_create_loc_conf(ngx_conf_t *cf)
{
    printf("ngx_http_ldFtp_create_loc_conf\n");
    ngx_http_ldFtp_loc_conf_t *myLocConf = NULL;

    myLocConf = (ngx_http_ldFtp_loc_conf_t *)ngx_palloc(cf->pool, sizeof(ngx_http_ldFtp_loc_conf_t));
    if(NULL == myLocConf)
    {
        printf("ngx_http_ldFtp_create_loc_conf ngx_palloc ngx_http_ldFtp_loc_conf_t failed\n");
        return NULL;
    }

    //给配置文件中参数默认值
    myLocConf->version = NGX_CONF_UNSET;
    myLocConf->file_path.len = 0;
    myLocConf->file_path.data = NULL;

    return myLocConf;
}

/*
static char *ngx_http_ldFtp_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_ldFtp_loc_conf_t *pPrev = (ngx_http_ldFtp_loc_conf_t *)parent;
    ngx_http_ldFtp_loc_conf_t *pConf = (ngx_http_ldFtp_loc_conf_t *)child;

    //将server配置文件的file_path变量赋值给loc配置文件的file_path变量
    ngx_conf_merge_str_value(pConf->file_path, pPrev->file_path, "defaultstr");

    return NGX_CONF_OK;
}
*/


static char *ngx_http_ldFtp(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    //在前面字段值已经全部解析成功
    ngx_http_ldFtp_loc_conf_t *pMyLocConf = (ngx_http_ldFtp_loc_conf_t *)conf;
    printf("ngx_http_ldFtp: file_path:%.*s version:%d\n", pMyLocConf->file_path.len, pMyLocConf->file_path.data, pMyLocConf->version);

    //首先找到 mytest配置项所属的配置块
    ngx_http_core_loc_conf_t *clcf;
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    /*
    HTTP框架在处理用户请求进行到 NGX_HTTP_CONTENT_PHARE阶段时，如果请求的主机域名、URI与 mytest配置项所在的 配置块
    相匹配，就调用我们实现的 ngx_http_mytest_handler方法处理和这个请求
    */

    //发送本地文件数据
    clcf->handler = ngx_http_ldFtp_handler;

    return NGX_CONF_OK;
}


/*
	响应回调函数实现
*/
//接收HTTP包体数据 进行数据保存
static ngx_int_t ngx_http_ldFtp_handler(ngx_http_request_t *r)
{
	//上下文结构体start
	ngx_http_ldFtp_ctx_t *myctx = ngx_http_get_module_ctx(r, ngx_http_ldFtp_module);

	if (NULL == myctx)
	{
		printf("ldFtp Module Set Ctx Pointer\n");
		myctx = ngx_palloc(r->pool, sizeof(ngx_http_ldFtp_ctx_t));
		if (!myctx)
			return NGX_ERROR;

		//存储在 ngx_http_request_t的 ctx这个成员变量中
        ngx_http_set_ctx(r, myctx, ngx_http_ldFtp_module);

		//之后就可以任意使用myctx这个上下文结构体
	}
	//上下文结构体end


	//必须是 GET或者 POST方法，其他返回 405 Not Allow
	if (!(r->method & (NGX_HTTP_GET | NGX_HTTP_POST)))
	{
		return NGX_HTTP_NOT_ALLOWED;
	}

    // ToDo 从请求url中获取文件名保存到上下文环境中去  gdb查一下
    // myctx->file_name = r->headers_in.x_real_ip;


    // 接收完整的HTTP包体数据
    ngx_int_t rc = ngx_http_read_client_request_body(r, ngx_http_client_body_read_complete);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;

    /*
	//忽略Http请求中的包体
	ngx_int_t rc = ngx_http_discard_request_body(r);
	if (rc != NGX_OK)
	{
		return rc;
	}
    */
}

void ngx_http_client_body_read_complete(ngx_http_request_t *r)
{
    /*
        ToDo 获取客户端请求的包体进行数据保存
        从上下文中获取客户端请求url中的目录结构
    */




    //下面设置返回的 Content-type
    ngx_str_t content_type = ngx_string("text/plain");

    //设置返回的 Response(将配置文件中获取的数据进行返回)
    u_char *pBuf = ngx_palloc(r->pool, 256);
    ngx_http_ldFtp_loc_conf_t *pLocConf = (ngx_http_ldFtp_loc_conf_t *)ngx_http_get_module_loc_conf(r, ngx_http_ldFtp_module);
    if (NULL == pBuf || NULL == pLocConf)
        return ;
    ngx_snprintf(pBuf, 256, "Hello Nginx version:%d", pLocConf->version);
    printf("TEST: MyLocation Conf:%s\n", pBuf);

    ngx_str_t response;
    response.len = strlen(pBuf);
    response.data = pBuf;

    //设置返回状态码 Content-Length Content-Type
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_type_len = response.len;
    r->headers_out.content_type = content_type;

    //发送 HTTP的头部
    ngx_int_t rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only)
    {
        return ;
    }

    //准备发送 HTTP包体
    ngx_buf_t *stOutBuf = ngx_create_temp_buf(r->pool, response.len);
    if (NULL == stOutBuf)
    {
        printf("ngx_http_mytest_handler ngx_create_temp_buf Failed, Len:%d\n", response.len);
        return ;
    }

    //将 “Hello World”复制到 buf中
    ngx_memcpy(stOutBuf->pos, response.data, response.len);

    //设置 ngx_buf_t的 last指针
    stOutBuf->last = stOutBuf->pos + response.len;
    stOutBuf->last_buf = 1;

    //构造发送的 ngx_chain_t结构体
    ngx_chain_t stOutChain;
    stOutChain.buf = stOutBuf;
    stOutChain.next = NULL;

    ngx_http_output_filter(r, &stOutChain);

    return;
}

