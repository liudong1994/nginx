#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_conf_file.h>


//����ģ��������ļ�
typedef struct 
{
	ngx_flag_t	enable;
}ngx_http_myfilter_conf_t;

//����ģ��������Ľṹ��
typedef struct  
{
	/*
		Ϊ0ʱ��ʾ ����Ҫ���ǰ׺
		Ϊ1ʱ��ʾ ��Ҫ���ǰ׺
		Ϊ2ʱ��ʾ ��Ҫ��Ӷ����Ѿ���������
	*/
	ngx_int_t	add_prefix;
}ngx_http_myfilter_ctx_t;


//���ڰ�����������ǰ׺
static ngx_str_t filter_prefix = ngx_string("[my filter prefix]");

//���ڳ�ʼ����������
static ngx_http_output_header_filter_pt		ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt		ngx_http_next_body_filter;


//myfilterʹ�ú���
//������ģ���ʼ��ʹ��
static ngx_int_t ngx_http_myfilter_init(ngx_conf_t *cf);

//���������ļ��Ĵ����ͺϲ�
static void* ngx_http_myfilter_create_loc_conf(ngx_conf_t *cf);
static char* ngx_http_myfilter_merge_loc_conf(ngx_conf_t *cf, void *prev, void *conf);

//������ģ�����HTTPͷ���Ͱ���Ĵ�����
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
    ����ע��:
    ��Ϊ���c�ļ���Ҫextern ngx_http_myfilter_module
    �������ﲻ���� static,����������...
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
	//��������ģ����뵽�ܵĹ���������ȥ
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

	//ngx_flat_t���͵ı��� ���ʹ��Ԥ�躯��ngx_conf_set_flag_slot������������� �����ʼ��ΪNGX_CONF_UNSET
	pMyfilterConf->enable = NGX_CONF_UNSET;
	return pMyfilterConf;
}

char* ngx_http_myfilter_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_myfilter_conf_t *prev = (ngx_http_myfilter_conf_t *)parent;
	ngx_http_myfilter_conf_t *conf = (ngx_http_myfilter_conf_t *)child;

	//�ϲ�ngx_flat_t���͵�������enable
	ngx_conf_merge_value(conf->enable, prev->enable, 0);

    printf("ngx_http_myfilter_merge_loc_conf:\nadd_prefix:%d\n", conf->enable);

	return NGX_CONF_OK;
}

ngx_int_t ngx_http_myfilter_output_header_filter(ngx_http_request_t *r)
{
	//����HTTPͷ������

	//���HTTP���ص�ֵ����200OK ����û�б�Ҫ��ǰ�����ǰ׺
	if (r->headers_out.status != NGX_HTTP_OK)
		return ngx_http_next_header_filter(r);

	ngx_http_myfilter_ctx_t *pMyfilterCtx = ngx_http_get_module_ctx(r, ngx_http_myfilter_module);
	if (NULL != pMyfilterCtx)
	{
		//��������������Ѿ����ڣ���˵�� ngx_http_myfilter_header_filter�Ѿ������ù��� ֱ�ӽ�����һ������ģ�鴦��
		return ngx_http_next_header_filter(r);
	}

	ngx_http_myfilter_conf_t *pMyfilterConf = ngx_http_get_module_loc_conf(r, ngx_http_myfilter_module);

	//�����ļ���û�п���add_prefix �������ǰ׺
	if (0 == pMyfilterConf->enable)
	{
		return ngx_http_next_header_filter(r);
	}

	pMyfilterCtx = ngx_pnalloc(r->pool, sizeof(ngx_http_myfilter_ctx_t));
	if (NULL == pMyfilterCtx)
		return NGX_ERROR;

	//ǰ�������ǰ׺Ϊ0 �������HTTPͷ����Ϣ���б��ֶεĴ���
	pMyfilterCtx->add_prefix = 0;

	ngx_http_set_ctx(r, pMyfilterCtx, ngx_http_myfilter_module);

	//myfilterģ��ֻ����Content-Type�� "text/plain"���͵� HTTP��Ӧ(�е�ʱ������ Content-Type���Ͳ�ƥ��ᵼ�� �����ͷ���ֶ�)
	if (r->headers_out.content_type.len >= (sizeof("text/plain") - 1)
		&& 0 == ngx_strncasecmp(r->headers_out.content_type.data, (u_char *)"text/plain", sizeof("text/plain")) - 1)
	{
		//���HTTP�İ�����Ҫ���ǰ׺
		pMyfilterCtx->add_prefix = 1;

		/*
			�������ģ���Ѿ���Content-Lengthд����http����ĳ���
			�������Ǽ�����ǰ׺�ַ�����������Ҫ������ַ����ĳ���Ҳ���뵽Content-Length��
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
	//����HTTP��������
	ngx_http_myfilter_ctx_t *pMyfilterCtx = ngx_http_get_module_ctx(r, ngx_http_myfilter_module);
	if (NULL == pMyfilterCtx || 1 != pMyfilterCtx->add_prefix)
	{
		return ngx_http_next_body_filter(r, chain);
	}

	//�� add_prefixֵ����Ϊ 2����ʹ�ٴε��ñ�����ʱ��Ҳ������Ӷ��ǰ׺
	pMyfilterCtx->add_prefix = 2;

	//�����ڴ� ���ڴ��Ҫ��ӵ� ǰ׺�ַ���
	ngx_buf_t *pBuf = ngx_create_temp_buf(r->pool, filter_prefix.len);
	pBuf->start = pBuf->pos = filter_prefix.data;
	pBuf->last = pBuf->start + filter_prefix.len;

	//��ǰ׺�ַ������� chain��ǰ��,�����Ǳ�Ӧ��Ҫ���͵��ַ���
	ngx_chain_t *pChain = ngx_alloc_chain_link(r->pool);
	pChain->buf = pBuf;
	pChain->next = chain;

	return ngx_http_next_body_filter(r, pChain);
}

