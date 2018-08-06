#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_conf_file.h>
#include <ngx_http_upstream.h>

/*
    配置文件中出现
    location /test{
        mytest;
    }

    在 NGX_HTTP_CONTENT_PHARE阶段将有可能调用我们的 ngx_http_mytest_handler方法

    在配置文件出现 mytest配置项时，ngx_http_mytest方法将会被调用，这时将 ngx_http_core_loc_conf_t结构体的 handler成员指定为 ngx_http_mytest_handler方法，
    另外，Http框架在接收完 Http请求的头部之后，会调用 handler指向的方法。
*/

static char *ngx_http_mytest(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static void *ngx_http_mytest_create_loc_conf(ngx_conf_t *cf);
static char *ngx_conf_set_mytest(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char *ngx_http_mytest_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

//upstream回调方法实现(/test)
static ngx_int_t ngx_http_mytest_handler_upstream(ngx_http_request_t *r);
static ngx_int_t ngx_http_mytest_handler_memory(ngx_http_request_t *r);
static ngx_int_t ngx_http_mytest_handler_file(ngx_http_request_t *r);


static ngx_int_t mytest_upstream_create_request(ngx_http_request_t *r);
static ngx_int_t mytest_process_status_line(ngx_http_request_t *r);
static ngx_int_t mytest_upstream_process_header(ngx_http_request_t *r);
static void mytest_upstream_finalize_request(ngx_http_request_t *r, ngx_int_t rc);


//upstream相关
//子请求结束时回调
static ngx_int_t mytest_subrequest_post_handler(ngx_http_request_t *r, void *data, ngx_int_t rc);
//激活父请求的方法
static void mytest_post_handler(ngx_http_request_t * r);



static ngx_str_t  ngx_http_proxy_hide_headers[] =
{
	ngx_string("Date"),
	ngx_string("Server"),
	ngx_string("X-Pad"),
	ngx_string("X-Accel-Expires"),
	ngx_string("X-Accel-Redirect"),
	ngx_string("X-Accel-Limit-Rate"),
	ngx_string("X-Accel-Buffering"),
	ngx_string("X-Accel-Charset"),
	ngx_null_string
};

//自定义存储配置文件结构体
typedef struct{
    ngx_str_t       my_str;
    ngx_int_t       my_num;
    ngx_flag_t      my_flag;
    ngx_path_t      *my_path;

    //用于自定义解析
    ngx_str_t		my_config_str;
    ngx_int_t		my_config_num;

	//upstream
	ngx_http_upstream_conf_t	upstreamConf;
}ngx_http_mytest_loc_conf_t;

//模块 上下文结构体
typedef struct 
{
    ngx_http_status_t           status;
    ngx_str_t					backendServer;

	ngx_str_t					stock[6];
}ngx_http_mytest_ctx_t;


static ngx_command_t ngx_http_mytest_commands[] = {
    {
        ngx_string("mytest"),       //name
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_NOARGS,   //type
        ngx_http_mytest,    //set handler
        NGX_HTTP_LOC_CONF_OFFSET,   //conf
        0,                  //offset
        NULL                //post
    },

    //添加我们要解析的字段 函数及名称
    {
        ngx_string("test_flag"),
        NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_loc_conf_t, my_flag),
        NULL
    },

    {
        ngx_string("test_num"),
        NGX_HTTP_LOC_CONF | NGX_CONF_FLAG | NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_loc_conf_t, my_num),
        NULL
    },

    {
        ngx_string("test_str"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_loc_conf_t, my_str),
        NULL
    },

//     {
//         ngx_string("test_path"),
//         NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
//         ngx_conf_set_path_slot,
//         NGX_HTTP_LOC_CONF_OFFSET,
//         offsetof(ngx_http_mytest_loc_conf_t, my_path),
//         NULL
//     },

    //ToDo 添加对upstreamConf中时间字段值的读取

    {
        ngx_string("test_myconf"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE12,
        ngx_conf_set_mytest,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },

    ngx_null_command
};

//ngx_http_module_t接口
static ngx_http_module_t ngx_http_mytest_module_ctx = {
    NULL,           /* preconfiguration */
    NULL,           /* postconfiguration */

    NULL,           /* create main configuration */
    NULL,           /* init main configuration */

    NULL,           /* create server configuration */
    NULL,           /* merge server configuration */

    ngx_http_mytest_create_loc_conf,           /* create location configuration */
	ngx_http_mytest_merge_loc_conf            /* merge location configuration */
};


/*
    定义mytst模块 在ngx_modules.c文件中的数组中会有 ngx_http_mytest_module的 extern(被注册)
    ngx_http_mytest_module里面会有 
        1.ngx_http_mytest_module_ctx    指出 针对配置文件的读取存储方式
        2.ngx_http_mytest_commands      指出 配置文件中出现的 URL匹配后相应操作
*/
ngx_module_t ngx_http_mytest_module = {
    NGX_MODULE_V1,
    &ngx_http_mytest_module_ctx,            /* module context */
    ngx_http_mytest_commands,               /* module directives */
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






static char *ngx_http_mytest(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    //在前面字段值已经全部解析成功
    ngx_http_mytest_loc_conf_t *pMyLocConf = (ngx_http_mytest_loc_conf_t *)conf;
    printf("ngx_http_mytest:\nmy_flag:%d my_str:%*s\nngx_conf_set_mytest my_conf_str:%*s my_conf_num:%d\n", pMyLocConf->my_flag, pMyLocConf->my_str.len, pMyLocConf->my_str.data,
        pMyLocConf->my_config_str.len, pMyLocConf->my_config_str.data, pMyLocConf->my_config_num);

    ngx_http_core_loc_conf_t *clcf;

    //首先找到 mytest配置项所属的配置块
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    /*
        HTTP框架在处理用户请求进行到 NGX_HTTP_CONTENT_PHARE阶段时，如果请求的主机域名、URI与 mytest配置项所在的 配置块
    相匹配，就调用我们实现的 ngx_http_mytest_handler方法处理和这个请求
    */

    //upstream测试
	clcf->handler = ngx_http_mytest_handler_upstream;

    //发送本地文件数据
    //clcf->handler =  ngx_http_mytest_handler_file

    return NGX_CONF_OK;    
}

static void *ngx_http_mytest_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_mytest_loc_conf_t *myLocConf = NULL;

    myLocConf = (ngx_http_mytest_loc_conf_t *)ngx_palloc(cf->pool, sizeof(ngx_http_mytest_loc_conf_t));
    if(NULL == myLocConf)
    {
        printf("ngx_http_mytest_create_loc_conf ngx_palloc ngx_http_mytest_loc_conf_t failed\n");
        return NULL;
    }

    //给配置文件中参数默认值
    myLocConf->my_flag = NGX_CONF_UNSET;
    myLocConf->my_num = NGX_CONF_UNSET;

	//upstream结构体默认值设置(下面的值最好从配置文件中读出  这里前使用硬编码设置默认值)
	myLocConf->upstreamConf.connect_timeout = 60000;
	myLocConf->upstreamConf.send_timeout = 60000;
	myLocConf->upstreamConf.read_timeout = 60000;
	myLocConf->upstreamConf.store_access = 0600;

	/*
		这里的 buffering决定了将以固定大小的内存作为缓冲区来转发上游服务器的响应包体，这块固定的缓冲区的大小就是 buffer_size。
		如果 buffering为1，就会使用更多的内存缓冲区缓存来不及发往下游的响应。例如：最多使用 bufs.num个缓冲区且每个缓冲区大小
		为 bufs.size，另外还会使用临时文件，临时文件的最大长度为 max_temp_file_size
	*/
	myLocConf->upstreamConf.buffering = 0;
	myLocConf->upstreamConf.bufs.num = 8;
	myLocConf->upstreamConf.bufs.size = ngx_pagesize;
	myLocConf->upstreamConf.buffer_size = ngx_pagesize;
	myLocConf->upstreamConf.busy_buffers_size = 2 * ngx_pagesize;
	myLocConf->upstreamConf.temp_file_write_size = 2 * ngx_pagesize;
	myLocConf->upstreamConf.max_temp_file_size = 1024 * 1024 * 1024;

	/*
		upstream模块要求 hide_headers成员必须要初始化(upstream在解析完上游服务器返回的包头时，会调用 ngx_http_upstream_process_headers
		方法按照 hide_headers成员将本应该转发给下游的一些 HTTP头部隐藏)，这里初始化为 NGX_CONF_UNSET_PTR，这里为了在 merge合并配置项方法
		中使用 upstream模块提供的 ngx_http_upstream_hide_headers_hash方法初始化 hide_headers成员
	*/
	myLocConf->upstreamConf.hide_headers = NGX_CONF_UNSET_PTR;
	myLocConf->upstreamConf.pass_headers = NGX_CONF_UNSET_PTR;

    return myLocConf;
}

//自定义的配置解析函数
static char *ngx_conf_set_mytest(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    //conf就是我们的申请的 ngx_http_mytest_loc_conf_t文件
    ngx_http_mytest_loc_conf_t *pMyLocConf = (ngx_http_mytest_loc_conf_t *)conf;
    if(NULL == pMyLocConf)
        return NGX_CONF_ERROR;

    //准备解析我们指定的配置文件格式
    ngx_str_t *pValue = cf->args->elts;

    if(cf->args->nelts > 1)
    {
        //直接赋值即可 ngx_str_t结构只是指针的传递
        pMyLocConf->my_config_str = pValue[1];
    }

    if(cf->args->nelts > 2)
    {
        //根据字符串形式的第2个参数转为整型
        pMyLocConf->my_config_num = ngx_atoi(pValue[2].data, pValue[2].len);

        if(NGX_ERROR == pMyLocConf->my_config_num)
        {
            printf("Invalid Number\n");
        }
    }

    return NGX_CONF_OK;    
}

static char *ngx_http_mytest_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_mytest_loc_conf_t *prev = (ngx_http_mytest_loc_conf_t *)parent;
    ngx_http_mytest_loc_conf_t *conf = (ngx_http_mytest_loc_conf_t *)child;

    ngx_hash_init_t             hash;
    hash.max_size = 100;
    hash.bucket_size = 1024;
    hash.name = "proxy_headers_hash";
    if (ngx_http_upstream_hide_headers_hash(cf, &conf->upstreamConf,
        &prev->upstreamConf, ngx_http_proxy_hide_headers, &hash)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/*
	响应回调函数实现
*/


//从内存中发送数据
static ngx_int_t ngx_http_mytest_handler_memory(ngx_http_request_t *r)
{
	//上下文结构体add
	ngx_http_mytest_ctx_t *myctx = ngx_http_get_module_ctx(r, ngx_http_mytest_module);

	if (NULL == myctx)
	{
		printf("mytest Module Set Ctx Pointer\n");
		myctx = ngx_palloc(r->pool, sizeof(ngx_http_mytest_ctx_t));
		if (!myctx)
			return NGX_ERROR;

		//存储在 ngx_http_request_t的 ctx这个成员变量中
		ngx_http_set_ctx(r, myctx, ngx_http_mytest_module);

		//之后就可以任意使用myctx这个上下文结构体
	}

	//上下文结构体end


	//必须是 GET或者 HEAD方法，其他返回 405 Not Allow
	if (!(r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD)))
	{
		return NGX_HTTP_NOT_ALLOWED;
	}

	//忽略Http请求中的包体
	ngx_int_t rc = ngx_http_discard_request_body(r);
	if (rc != NGX_OK)
	{
		return rc;
	}

	//下面设置返回的 Content-type
	ngx_str_t content_type = ngx_string("text/plain");

	//设置返回的 Response(将配置文件中获取的数据进行返回)
	u_char *pBuf = ngx_palloc(r->pool, 256);
	//ngx_http_mytest_loc_conf_t *pLocConf = (ngx_http_mytest_loc_conf_t *)ngx_http_get_module_loc_conf(r, ngx_http_mytest_module);
	ngx_http_mytest_loc_conf_t *pLocConf = r->loc_conf[ngx_http_mytest_module.ctx_index];
	if (NULL == pBuf || NULL == pLocConf)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;

	//upstream start
	r->upstream->conf = &pLocConf->upstreamConf;
	//upstream end

	ngx_snprintf(pBuf, 256, "Hello Nginx flag:%d num:%d str:%*s mystr:%*s", pLocConf->my_flag, pLocConf->my_num, pLocConf->my_str.len, pLocConf->my_str.data,
		pLocConf->my_config_str.len, pLocConf->my_config_str.data);
	printf("MyLocation Conf:%s\n", pBuf);
	ngx_str_t response;
	response.len = strlen(pBuf);
	response.data = pBuf;

	//设置返回状态码 Content-Length Content-Type
	r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.content_type_len = response.len;
	r->headers_out.content_type = content_type;

	//发送 HTTP的头部
	rc = ngx_http_send_header(r);
	if (rc == NGX_ERROR || rc > NGX_OK || r->header_only)
	{
		return rc;
	}

	//准备发送 HTTP包体
	ngx_buf_t *stOutBuf = ngx_create_temp_buf(r->pool, response.len);
	if (NULL == stOutBuf)
	{
		printf("ngx_http_mytest_handler ngx_create_temp_buf Failed, Len:%d\n", response.len);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
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

	return ngx_http_output_filter(r, &stOutChain);
}

//从硬盘中发送数据
static ngx_int_t ngx_http_mytest_handler_file(ngx_http_request_t *r)
{
	//必须是 GET或者 HEAD方法，其他返回 405 Not Allow
	if (!(r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD)))
	{
		return NGX_HTTP_NOT_ALLOWED;
	}

	//忽略Http请求中的包体
	ngx_int_t rc = ngx_http_discard_request_body(r);
	if (rc != NGX_OK)
	{
		return rc;
	}

	//准备发送 HTTP包体
	ngx_buf_t *stOutBuf = ngx_palloc(r->pool, sizeof(ngx_buf_t));
	if (NULL == stOutBuf)
	{
		printf("ngx_http_mytest_handler ngx_palloc1 Failed, Len:%d\n", sizeof(ngx_buf_t));
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	stOutBuf->in_file = 1;

	stOutBuf->file = ngx_palloc(r->pool, sizeof(ngx_file_t));
	if (NULL == stOutBuf->file)
	{
		printf("ngx_http_mytest_handler ngx_palloc2 Failed, Len:%d\n", sizeof(ngx_file_t));
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	//设置文件描述符 名称等信息
	u_char *fileName = (u_char *)"/tmp/test.txt";
	stOutBuf->file->fd = ngx_open_file(fileName, NGX_FILE_RDONLY | NGX_FILE_NONBLOCK, NGX_FILE_OPEN, 0);
	stOutBuf->file->name.data = fileName;
	stOutBuf->file->name.len = strlen(fileName);
	stOutBuf->file->log = r->connection->log;
	if (stOutBuf->file->fd < 0)
	{
		return NGX_HTTP_NOT_FOUND;
	}

	//支持断点续传
	r->allow_ranges = 1;

	//设置文件stat状态信息
	if (ngx_file_info(fileName, &stOutBuf->file->info) == NGX_FILE_ERROR)
	{
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	stOutBuf->file_pos = 0;
	stOutBuf->file_last = stOutBuf->file->info.st_size;



	//设置文件句柄清理函数(在发送完本地文件后 HTTP框架进行调用)
	ngx_pool_cleanup_t* cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_pool_cleanup_file_t));
	if (cln == NULL)
	{
		return NGX_ERROR;
	}

	cln->handler = ngx_pool_cleanup_file;
	ngx_pool_cleanup_file_t  *clnf = cln->data;
	clnf->fd = stOutBuf->file->fd;
	clnf->name = stOutBuf->file->name.data;
	clnf->log = r->pool->log;



	//下面设置返回的 Content-type
	ngx_str_t content_type = ngx_string("text/plain");

	//设置返回状态码 Content-Length Content-Type
	r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.content_type = content_type;
	r->headers_out.content_length_n = stOutBuf->file->info.st_size;


	//发送 HTTP的头部
	rc = ngx_http_send_header(r);
	if (rc == NGX_ERROR || rc > NGX_OK || r->header_only)
	{
		return rc;
	}


	//构造发送的 ngx_chain_t结构体
	ngx_chain_t stOutChain;
	stOutChain.buf = stOutBuf;
	stOutChain.next = NULL;

	return ngx_http_output_filter(r, &stOutChain);
}

/*
    upstream在 http的 request中
    我们的 location配置文件中存放的是 upstream的配置文件 conf,这个配置文件是在 create_loc_conf函数中进行初始化的
*/
static ngx_int_t ngx_http_mytest_handler_upstream(ngx_http_request_t *r)
{
    //上下文结构体add
    ngx_http_mytest_ctx_t *myctx = ngx_http_get_module_ctx(r, ngx_http_mytest_module);

    if (NULL == myctx)
    {
        printf("mytest Module Set Ctx Pointer\n");
        myctx = ngx_palloc(r->pool, sizeof(ngx_http_mytest_ctx_t));
        if (!myctx)
            return NGX_ERROR;

        //存储在 ngx_http_request_t的 ctx这个成员变量中
        ngx_http_set_ctx(r, myctx, ngx_http_mytest_module);

        //之后就可以任意使用myctx这个上下文结构体
    }
    //上下文结构体end

    //对每1个要使用upstream的请求，必须调用且只能调用1次
    //ngx_http_upstream_create方法，它会初始化r->upstream成员
    if (ngx_http_upstream_create(r) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_upstream_create() failed");
        return NGX_ERROR;
    }

    //获取location配置结构体
    ngx_http_mytest_loc_conf_t *pLocConf = (ngx_http_mytest_loc_conf_t *)ngx_http_get_module_loc_conf(r, ngx_http_mytest_module);
    ngx_http_upstream_t *pUpStream = r->upstream;
    //使用配置文件中的结构体给 r->upstream->conf成员
    pUpStream->conf = &pLocConf->upstreamConf;
    //使用配置文件中的 缓冲区使用方式
    pUpStream->buffering = pLocConf->upstreamConf.buffering;

    //设置请求upstream的地址
    pUpStream->resolved = (ngx_http_upstream_resolved_t*) ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_resolved_t));
    if (pUpStream->resolved == NULL)
    {
        printf("ngx_pcalloc resolved error. %s.", strerror(errno));
        return NGX_ERROR;
    }

    //这里的上游服务器就是www.google.com
    static struct sockaddr_in backendSockAddr;
    struct hostent *pHost = gethostbyname((char*) "www.baidu.com");
    if (pHost == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "gethostbyname fail. %s", strerror(errno));
        return NGX_ERROR;
    }

    //访问上游服务器的80端口
    backendSockAddr.sin_family = AF_INET;
    backendSockAddr.sin_port = htons((in_port_t) 80);
    char* pDmsIP = inet_ntoa(*(struct in_addr*) (pHost->h_addr_list[0]));
    backendSockAddr.sin_addr.s_addr = inet_addr(pDmsIP);
    myctx->backendServer.data = (u_char*)pDmsIP;
    myctx->backendServer.len = strlen(pDmsIP);

    //将地址设置到resolved成员中
    pUpStream->resolved->sockaddr = (struct sockaddr *)&backendSockAddr;
    pUpStream->resolved->socklen = sizeof(struct sockaddr_in);
    pUpStream->resolved->naddrs = 1;


    //设置三个必须实现的回调方法
    pUpStream->create_request = mytest_upstream_create_request;
    pUpStream->process_header = mytest_process_status_line;
    pUpStream->finalize_request = mytest_upstream_finalize_request;

    //这里必须将count成员加1 告知HTTP框架还需使用 不要销毁
    r->main->count++;
    //启动upstream
    ngx_http_upstream_init(r);

    //告知HTTP框架 后续需要继续处理
    return NGX_DONE;
}

//创建发往upstream的请求
static ngx_int_t mytest_upstream_create_request(ngx_http_request_t *r)
{
    //给 ngx_http_request_t里面的 upstream中的 request_bufs进行赋值操作

    //要查询的请求
    //ngx_str_t backendQueryLine = ngx_string("GET /search?q=%V HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: close\r\n\r\n");
    //ngx_int_t queryLineLen = backendQueryLine.len + r->args.len - 2;    //ToDo -2 ???

	//test
	ngx_str_t backendQueryLine = ngx_string("GET /s?wd=111&rsv_spt=1&rsv_iqid=0xf1d8bc990004b2be&issp=1&f=8&rsv_bp=0&rsv_idx=2&ie=utf-8&tn=baiduhome_pg&rsv_enter=1&rsv_sug3=3&rsv_sug1=3&rsv_sug7=100&rsv_sug2=0&inputT=1082&rsv_sug4=1082 HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: close\r\n\r\n");
    ngx_int_t queryLineLen = backendQueryLine.len;
	//test

    //设置buf为请求字符串
    ngx_buf_t *buf = (ngx_buf_t *)ngx_create_temp_buf(r->pool, queryLineLen);
    if(NULL == buf)
        return NGX_ERROR;
    
    //last指向请求的结尾处
    buf->last = buf->pos + queryLineLen;
    ngx_snprintf(buf->pos, queryLineLen, backendQueryLine.data, &r->args);
	printf("Nginx request URL:%.*s\n", queryLineLen, buf->pos);

    // r->upstream->request_bufs是一个ngx_chain_t结构，它包含着要发送给上游服务器的请求
    r->upstream->request_bufs = ngx_alloc_chain_link(r->pool);
    if(NULL == r->upstream->request_bufs)
        return NGX_ERROR;

    r->upstream->request_bufs->buf = buf;
    r->upstream->request_bufs->next = NULL;

    //在与后台服务器建立TCP连接成功后 upstream模块会将request_send标志位置为1
    r->upstream->request_sent = 0;
    r->upstream->header_sent = 0;
    // header_hash不可以为0
    r->header_hash = 1;

    return NGX_OK;
}

/*
    用于上游服务器返回的状态行解析
    状态行解析成功后替换 header_process函数，用于解析头部行字段
*/
static ngx_int_t mytest_process_status_line(ngx_http_request_t *r)
{
    //获取上下文结构体
    ngx_http_mytest_ctx_t *pCtx = ngx_http_get_module_ctx(r, ngx_http_mytest_module);
    if(NULL == pCtx)
        return NGX_ERROR;

    ngx_http_upstream_t *pUpStream = r->upstream;

    //解析http的响应行 输入就是收到的字符流(upstream中的buffer)和上下文中的 ngx_http_status_t结构体
    ngx_int_t rc = ngx_http_parse_status_line(r, &pUpStream->buffer, &pCtx->status);
    if(NGX_AGAIN == rc)
        return rc;
    //返回NGX_ERROR表示没有接收到合法的 http 响应行
    if(NGX_ERROR == rc)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "upstream sent no valid HTTP/1.0 header");

        r->http_version = NGX_HTTP_VERSION_9;
        pUpStream->state->status = NGX_HTTP_OK;

        return NGX_OK;
    }

    /*
        以下表示解析到完整的http响应行，这时会做一些简单的赋值操作，将解析出的信息设置到r->upstream->headers_in结构体中，upstream解析完所有的包头时
        就会把headers_in中的成员设置到将要向下游发送的r->headers_out结构体中，也就是说，现在我们向headers_in中设置的信息，最终都会发往下游客户端。
        为什么不是直接设置r->headers_out而要这样多此一举呢？
        这是因为upstream希望能够按照ngx_http_upstream_conf_t配置结构体中的hide_headers等成员对发往下游的响应头部做统一处理
    */
    if(pUpStream->state)
    {
        pUpStream->state->status = pCtx->status.code;
    }

    //获取状态行长度
    size_t uLen = pCtx->status.end - pCtx->status.start;

    //上游服务器 状态码/状态行赋值
    pUpStream->headers_in.status_n = pCtx->status.code;

    pUpStream->headers_in.status_line.len = uLen;
    pUpStream->headers_in.status_line.data = ngx_palloc(r->pool, uLen);
    if(NULL == pUpStream->headers_in.status_line.data)
        return NGX_ERROR;
    ngx_memcpy(pUpStream->headers_in.status_line.data, pCtx->status.start, uLen);
    

    //上面是在 解析HTTP返回状态行 下面开始解析HTTP头部信息 并重置process_header函数
    pUpStream->process_header = mytest_upstream_process_header;

    return mytest_upstream_process_header(r);
}

static ngx_int_t mytest_upstream_process_header(ngx_http_request_t *r)
{
    //未解析完头部文件之前 需要返回NGX_AGAIN

    
    /*
        这里将upstream模块配置项ngx_http_upstream_main_conf_t取了出来，目的只有1个，
        对将要转发给下游客户端的http响应头部作统一处理。该结构体中存储了需要做统一处理的http头部名称和回调方法
    */
    ngx_http_upstream_main_conf_t  *umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

    //对 HTTP头部字段进行解析
	printf("mytest_upstream_process_header:\n%.*s\n", r->upstream->buffer.end - r->upstream->buffer.start, r->upstream->buffer.start);
    for( ; ;)
    {
        ngx_int_t rc = ngx_http_parse_header_line(r, &r->upstream->buffer, 1);

        //成功解析出一行 http头
        if(NGX_OK == rc)
        {
			printf("Parse NGX_OK Header\n");
            //向headers_in.headers这个ngx_list_t链表中添加http头部
            ngx_table_elt_t *h = ngx_list_push(&r->upstream->headers_in.headers);
            if (h == NULL)
            {
                return NGX_ERROR;
            }
            //以下开始构造刚刚添加到headers链表中的http头部
            h->hash = r->header_hash;

            h->key.len = r->header_name_end - r->header_name_start;
            h->value.len = r->header_end - r->header_start;
            //必须由内存池中分配存放http头部的内存
            h->key.data = ngx_pnalloc(r->pool,
                h->key.len + 1 + h->value.len + 1 + h->key.len);
            if (h->key.data == NULL)
            {
                return NGX_ERROR;
            }

            h->value.data = h->key.data + h->key.len + 1;
            h->lowcase_key = h->key.data + h->key.len + 1 + h->value.len + 1;

            ngx_memcpy(h->key.data, r->header_name_start, h->key.len);
            h->key.data[h->key.len] = '\0';
            ngx_memcpy(h->value.data, r->header_start, h->value.len);
            h->value.data[h->value.len] = '\0';

            if (h->key.len == r->lowcase_index)
            {
                ngx_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);
            }
            else
            {
                ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
            }

            //upstream模块会对一些http头部做特殊处理
            ngx_http_upstream_header_t *hh = ngx_hash_find(&umcf->headers_in_hash, h->hash,
                h->lowcase_key, h->key.len);

            if (hh && hh->handler(r, h, hh->offset) != NGX_OK)
            {
                return NGX_ERROR;
            }

            continue;
        }

        //表示响应中的 http头部全部解析完毕，接下来需要解析http包体
        if(NGX_HTTP_PARSE_HEADER_DONE == rc)
        {
			printf("Parse NGX_HTTP_PARSE_HEADER_DONE Header\n");
            //如果之前解析http头部时没有发现server和date头部，以下会
            //根据http协议添加这两个头部
            if (r->upstream->headers_in.server == NULL)
            {
                ngx_table_elt_t *h = ngx_list_push(&r->upstream->headers_in.headers);
                if (h == NULL)
                {
                    return NGX_ERROR;
                }

                h->hash = ngx_hash(ngx_hash(ngx_hash(ngx_hash(
                    ngx_hash('s', 'e'), 'r'), 'v'), 'e'), 'r');

                ngx_str_set(&h->key, "Server");
                ngx_str_null(&h->value);
                h->lowcase_key = (u_char *) "server";
            }

            if (r->upstream->headers_in.date == NULL)
            {
                ngx_table_elt_t *h = ngx_list_push(&r->upstream->headers_in.headers);
                if (h == NULL)
                {
                    return NGX_ERROR;
                }

                h->hash = ngx_hash(ngx_hash(ngx_hash('d', 'a'), 't'), 'e');

                ngx_str_set(&h->key, "Date");
                ngx_str_null(&h->value);
                h->lowcase_key = (u_char *) "date";
            }

            return NGX_OK;
        }

        //表示状态机没有解析到完整的 http头部，要求 upstream模块继续接收新的字符流在进行解析
        if(NGX_AGAIN == rc)
        {
			printf("Parse NGX_AGAIN Header\n");
            return NGX_AGAIN;
        }

        //其他返回值都是错误的
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "upstream sent invalid header");

        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }

    return NGX_AGAIN;
}

static void mytest_upstream_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "mytest_upstream_finalize_request");
}


//subrequest请求处理
static ngx_int_t ngx_http_mytest_handler_subrequest(ngx_http_request_t *r)
{
	//上下文结构体add
	ngx_http_mytest_ctx_t *myctx = ngx_http_get_module_ctx(r, ngx_http_mytest_module);

	if (NULL == myctx)
	{
		printf("mytest Module Set Ctx Pointer\n");
		myctx = ngx_palloc(r->pool, sizeof(ngx_http_mytest_ctx_t));
		if (!myctx)
			return NGX_ERROR;

		//存储在 ngx_http_request_t的 ctx这个成员变量中
		ngx_http_set_ctx(r, myctx, ngx_http_mytest_module);

		//之后就可以任意使用myctx这个上下文结构体
	}
	//上下文结构体end


	ngx_http_post_subrequest_t  *pSubRequest = ngx_pnalloc(r->pool, sizeof(ngx_http_post_subrequest_t));
	if (NULL == pSubRequest)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;

	//设置子请求结束时的回调方法 及 Data参数值
	pSubRequest->handler = mytest_subrequest_post_handler;
	pSubRequest->data = myctx;

	//设定开启 子请求的一些参数值
	ngx_str_t sub_prefix = ngx_string("/list=");
	ngx_str_t sub_location;
	sub_location.len = sub_prefix.len + r->args.len;
	sub_location.data = ngx_pnalloc(r->pool, sub_location.len);
	if (NULL == sub_location.data)
	{
		printf("ngx_http_mytest_handler_subrequest ngx_pnalloc sub_location.data Failed\n");
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	ngx_snprintf(sub_location.data, sub_location.len, "%V%V", &sub_prefix, &r->args);

	/*
	调用ngx_http_subrequest创建子请求，它只会返回NGX_OK或者NGX_ERROR返回NGX_OK时，sr就已经是合法的子请求

	这里的NGX_HTTP_SUBREQUEST_IN_MEMORY参数将告诉upstream模块把上游服务器的响应全部保存在子请求的sr->upstream->buffer内存缓冲区中
	*/
	ngx_http_request_t *pSr;
	ngx_int_t rc = ngx_http_subrequest(r, &sub_location, NULL, &pSr, pSubRequest, NGX_HTTP_SUBREQUEST_IN_MEMORY);
	if (NGX_OK != rc)
	{
		printf("ngx_http_subrequest Failed\n");
		return NGX_ERROR;
	}

	return NGX_DONE;
}

static ngx_int_t mytest_subrequest_post_handler(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
	//当前子请求结束时会调用
	ngx_http_request_t *pParentRequest = r->parent;

	//注意，上下文是保存在父请求中的所以要由pr中取上下文。其实参数data就是上下文，初始化subrequest时,我们就对其进行设置的
	ngx_http_mytest_ctx_t *pMyCtx = ngx_http_get_module_ctx(pParentRequest, ngx_http_mytest_module);

	pParentRequest->headers_out.status = r->headers_out.status;
	//如果返回NGX_HTTP_OK（也就是200）意味着访问新浪服务器成功，接着开始解析http包体
	if (r->headers_out.status == NGX_HTTP_OK)
	{
		int flag = 0;

		/*
		在不转发响应时，buffer中会保存着上游服务器的响应。特别是在使用反向代理模块访问上游服务器时，如果它使用upstream机制时没有重定义
		input_filter方法，upstream机制默认的input_filter方法会试图把所有的上游响应全部保存到buffer缓冲区中
		*/
		ngx_buf_t* pRecvBuf = &r->upstream->buffer;

		//以下开始解析上游服务器的响应，并将解析出的值赋到上下文结构体
		//myctx->stock数组中
		for (; pRecvBuf->pos != pRecvBuf->last; pRecvBuf->pos++)
		{
			if (*pRecvBuf->pos == ',' || *pRecvBuf->pos == '\"')
			{
				if (flag > 0)
				{
					pMyCtx->stock[flag - 1].len = pRecvBuf->pos - pMyCtx->stock[flag - 1].data;
				}
				flag++;
				pMyCtx->stock[flag - 1].data = pRecvBuf->pos + 1;
			}

			if (flag > 6)
				break;
		}
	}

	//这一步很重要，设置接下来父请求的回调方法(激活父请求)
	pParentRequest->write_event_handler = mytest_post_handler;

	return NGX_OK;
}

static void mytest_post_handler(ngx_http_request_t * r)
{
	//如果没有返回200则直接把错误码发回用户
	if (r->headers_out.status != NGX_HTTP_OK)
	{
		ngx_http_finalize_request(r, r->headers_out.status);
		return;
	}

	//当前请求是父请求，直接取其上下文
	ngx_http_mytest_ctx_t* myctx = ngx_http_get_module_ctx(r, ngx_http_mytest_module);

	//定义发给用户的http包体内容，格式为：
	//stock[…],Today current price: …, volumn: …
	ngx_str_t output_format = ngx_string("stock[%V],Today current price: %V, volumn: %V");

	//计算待发送包体的长度
	int bodylen = output_format.len + myctx->stock[0].len + myctx->stock[1].len + myctx->stock[4].len - 6;
	r->headers_out.content_length_n = bodylen;

	//在内存池上分配内存保存将要发送的包体
	ngx_buf_t* b = ngx_create_temp_buf(r->pool, bodylen);
	ngx_snprintf(b->pos, bodylen, (char*)output_format.data, &myctx->stock[0], &myctx->stock[1], &myctx->stock[4]);
	b->last = b->pos + bodylen;
	b->last_buf = 1;

	ngx_chain_t out;
	out.buf = b;
	out.next = NULL;
	//设置Content-Type，注意汉字编码新浪服务器使用了GBK
	static ngx_str_t type = ngx_string("text/plain; charset=GBK");
	r->headers_out.content_type = type;
	r->headers_out.status = NGX_HTTP_OK;

	r->connection->buffered |= NGX_HTTP_WRITE_BUFFERED;
	ngx_int_t ret = ngx_http_send_header(r);
	ret = ngx_http_output_filter(r, &out);

	//注意，这里发送完响应后必须手动调用ngx_http_finalize_request结束请求，因为这时http框架不会再帮忙调用它
	ngx_http_finalize_request(r, ret);
}

