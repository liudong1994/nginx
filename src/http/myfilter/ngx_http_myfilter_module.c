#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_conf_file.h>


//过滤模块的配置文件
typedef struct 
{
	ngx_flag_t	enable;
}ngx_http_myfilter_conf_t;

//过滤模块的上下文结构体
typedef struct  
{
	/*
		为0时表示 不需要添加前缀
		为1时表示 需要添加前缀
		为2时表示 需要添加而且已经添加完成了
	*/
	ngx_int_t	add_prefix;
}ngx_http_myfilter_ctx_t;


//将在包体中添加这个前缀
static ngx_str_t filter_prefix = ngx_string("[my filter prefix]");

//用于初始化过滤链表
static ngx_http_output_header_filter_pt		ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt		ngx_http_next_body_filter;


//myfilter使用函数
//本过滤模块初始化使用
static ngx_int_t ngx_http_myfilter_init(ngx_conf_t *cf);

//用于配置文件的创建和合并
static void* ngx_http_myfilter_create_loc_conf(ngx_conf_t *cf);
static char* ngx_http_myfilter_merge_loc_conf(ngx_conf_t *cf, void *prev, void *conf);

//本过滤模块针对HTTP头部和包体的处理方法
static ngx_int_t ngx_http_myfilter_output_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_myfilter_output_body_filter(ngx_http_request_t *r, ngx_chain_t *chain);


static ngx_command_t ngx_http_module_myfilter_command[] = {
	{
		ngx_string("add_prefix"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_FLAG,
		ngx_conf_set_flag_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_myfilter_conf_t, enable),
		NULL
	},

	ngx_null_command
};

static ngx_http_module_t ngx_http_module_myfilter_ctx = {
	NULL,           /* preconfiguration */
	ngx_http_myfilter_init,	           /* postconfiguration */

	NULL,           /* create main configuration */
	NULL,           /* init main configuration */

	NULL,           /* create server configuration */
	NULL,           /* merge server configuration */

	ngx_http_myfilter_create_loc_conf,           /* create location configuration */
	ngx_http_myfilter_merge_loc_conf             /* merge location configuration */
};

/*
    严重注意:
    因为别的c文件需要extern ngx_http_myfilter_module
    所以这里不能是 static,否则编译出错...
*/
/*static*/ ngx_module_t ngx_http_myfilter_module = {
	NGX_MODULE_V1,
	&ngx_http_module_myfilter_ctx,          /* module context */
	ngx_http_module_myfilter_command,       /* module directives */
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

ngx_int_t ngx_http_myfilter_init(ngx_conf_t *cf)
{
	//将本过滤模块加入到总的过滤链表中去
	ngx_http_next_header_filter = ngx_http_top_header_filter;
	ngx_http_next_body_filter = ngx_http_top_body_filter;

	ngx_http_top_header_filter = ngx_http_myfilter_output_header_filter;
	ngx_http_top_body_filter = ngx_http_myfilter_output_body_filter;

	return NGX_OK;
}

void* ngx_http_myfilter_create_loc_conf(ngx_conf_t *cf)
{
	ngx_http_myfilter_conf_t *pMyfilterConf = NULL;
	pMyfilterConf = (ngx_http_myfilter_conf_t *)ngx_pcalloc(cf->pool, sizeof(ngx_http_myfilter_conf_t));

	if (NULL == pMyfilterConf)
		return NULL;

	//ngx_flat_t类型的变量 如果使用预设函数ngx_conf_set_flag_slot解析配置项参数 必须初始化为NGX_CONF_UNSET
	pMyfilterConf->enable = NGX_CONF_UNSET;
	return pMyfilterConf;
}

char* ngx_http_myfilter_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_myfilter_conf_t *prev = (ngx_http_myfilter_conf_t *)parent;
	ngx_http_myfilter_conf_t *conf = (ngx_http_myfilter_conf_t *)child;

	//合并ngx_flat_t类型的配置项enable
	ngx_conf_merge_value(conf->enable, prev->enable, 0);

    printf("ngx_http_myfilter_merge_loc_conf:\nadd_prefix:%d\n", conf->enable);

	return NGX_CONF_OK;
}

ngx_int_t ngx_http_myfilter_output_header_filter(ngx_http_request_t *r)
{
	//处理HTTP头部数据

	//如果HTTP返回的值不是200OK 我们没有必要再前面加上前缀
	if (r->headers_out.status != NGX_HTTP_OK)
		return ngx_http_next_header_filter(r);

	ngx_http_myfilter_ctx_t *pMyfilterCtx = ngx_http_get_module_ctx(r, ngx_http_myfilter_module);
	if (NULL != pMyfilterCtx)
	{
		//该请求的上下文已经存在，这说明 ngx_http_myfilter_header_filter已经被调用过了 直接交由下一个过滤模块处理
		return ngx_http_next_header_filter(r);
	}

	ngx_http_myfilter_conf_t *pMyfilterConf = ngx_http_get_module_loc_conf(r, ngx_http_myfilter_module);

	//配置文件中没有开启add_prefix 不用添加前缀
	if (0 == pMyfilterConf->enable)
	{
		return ngx_http_next_header_filter(r);
	}

	pMyfilterCtx = ngx_pnalloc(r->pool, sizeof(ngx_http_myfilter_ctx_t));
	if (NULL == pMyfilterCtx)
		return NGX_ERROR;

	//前设置添加前缀为0 下面根据HTTP头部信息进行本字段的处理
	pMyfilterCtx->add_prefix = 0;

	ngx_http_set_ctx(r, pMyfilterCtx, ngx_http_myfilter_module);

	//myfilter模块只处理Content-Type是 "text/plain"类型的 HTTP响应(有的时候这里 Content-Type类型不匹配会导致 不添加头部字段)
	if (r->headers_out.content_type.len >= (sizeof("text/plain") - 1)
		&& 0 == ngx_strncasecmp(r->headers_out.content_type.data, (u_char *)"text/plain", sizeof("text/plain")) - 1)
	{
		//针对HTTP的包体需要添加前缀
		pMyfilterCtx->add_prefix = 1;

		/*
			如果处理模块已经在Content-Length写入了http包体的长度
			由于我们加入了前缀字符串，所以需要把这个字符串的长度也加入到Content-Length中
		*/
		if (r->headers_out.content_length_n > 0)
		{
			r->headers_out.content_length_n += filter_prefix.len;
		}
	}

    printf("ngx_http_myfilter_output_header_filter, ContentType:%.*s\n", r->headers_out.content_type.len, r->headers_out.content_type.data);
	return ngx_http_next_header_filter(r);
}

ngx_int_t ngx_http_myfilter_output_body_filter(ngx_http_request_t *r, ngx_chain_t *chain)
{
	//处理HTTP包体数据
	ngx_http_myfilter_ctx_t *pMyfilterCtx = ngx_http_get_module_ctx(r, ngx_http_myfilter_module);
	if (NULL == pMyfilterCtx || 1 != pMyfilterCtx->add_prefix)
	{
		return ngx_http_next_body_filter(r, chain);
	}

	//将 add_prefix值设置为 2，即使再次调用本函数时，也不会添加多次前缀
	pMyfilterCtx->add_prefix = 2;

	//申请内存 用于存放要添加的 前缀字符串
	ngx_buf_t *pBuf = ngx_create_temp_buf(r->pool, filter_prefix.len);
	pBuf->start = pBuf->pos = filter_prefix.data;
	pBuf->last = pBuf->start + filter_prefix.len;

	//将前缀字符串放在 chain最前面,后面是本应该要发送的字符串
	ngx_chain_t *pChain = ngx_alloc_chain_link(r->pool);
	pChain->buf = pBuf;
	pChain->next = chain;

	return ngx_http_next_body_filter(r, pChain);
}

