#include <ngx_config.h>
#include <ngx_core.h>

#include <ngx_array_test.h>


typedef struct TestNode_s TestNode;

struct TestNode_s{
	int nNum;
	char *pName;
};

int ngx_array_test_func()
{
	//创建动态数组需要的内存池
	ngx_pool_t *pPool = ngx_create_pool(1024, NULL);
	if (NULL == pPool)
		return -1;

	//创建数组
	ngx_array_t *pArray = ngx_array_create(pPool, 3, sizeof(TestNode));
	if (NULL == pArray)
		return -1;

	TestNode *pNode = ngx_array_push(pArray);
	if (pNode)
	{
		pNode->nNum = 1;
		pNode->pName = "1";
	}

	pNode = ngx_array_push_n(pArray, 3);
	pNode->nNum = 2;
	(pNode + 1)->nNum = 3;
	(pNode + 2)->nNum = 4;

	//循环遍历数组 打印数组内部基本信息
	pNode = pArray->elts;
	ngx_uint_t nArrayPos = 0;

	printf("ngx_array:\n");
	//nelts有效元素个数
	for (; nArrayPos < pArray->nelts; ++nArrayPos)
	{
		TestNode *pNodeTmp = pNode + nArrayPos;
		printf("%d ", pNodeTmp->nNum);
	}
	printf("\n");


	ngx_array_destroy(pArray);

	return 0;
}

