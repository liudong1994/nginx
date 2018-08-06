#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_queue.h>
#include "ngx_queue_test.h"

typedef struct QueueTest_s  QueueTest;

struct QueueTest_s
{
	u_char *pStr;

	//ngx_queue_t�ṹ�����������λ��
	ngx_queue_t stNginxQueue;

	int		nNum;
};


//��ϰ ����queue����
int ngx_queue_test_func()
{
	//�����ڱ�(����)
	ngx_queue_t queContainer;
	ngx_queue_init(&queContainer);

	QueueTest arrQueTest[5];
	int i = 0;
	for (i = 0; i < 5; ++i)
	{
		arrQueTest[i].nNum = i;
	}

	//�������5���ڵ���뵽������ȥ(3 2 0 1 4)
	ngx_queue_insert_head(&queContainer, &arrQueTest[0].stNginxQueue);
	ngx_queue_insert_tail(&queContainer, &arrQueTest[1].stNginxQueue);
	ngx_queue_insert_after(&queContainer, &arrQueTest[2].stNginxQueue);
	ngx_queue_insert_head(&queContainer, &arrQueTest[3].stNginxQueue);
	ngx_queue_insert_tail(&queContainer, &arrQueTest[4].stNginxQueue);

	//����Queue��ӡԪ��ֵ
	ngx_queue_t *pQue = NULL;
	printf("Sort Before:\n");
	for (pQue = ngx_queue_head(&queContainer); pQue != ngx_queue_sentinel(&queContainer); pQue = ngx_queue_next(pQue))
	{
		QueueTest *pQueueElement = ngx_queue_data(pQue, QueueTest, stNginxQueue);
		printf(" %d", pQueueElement->nNum);
	}
	printf("\n");

	//����������
	ngx_queue_sort(&queContainer, compQueueTest);

	printf("Sort After:\n");
	for (pQue = ngx_queue_head(&queContainer); pQue != ngx_queue_sentinel(&queContainer); pQue = ngx_queue_next(pQue))
	{
		QueueTest *pQueueElement = ngx_queue_data(pQue, QueueTest, stNginxQueue);
		printf(" %d", pQueueElement->nNum);
	}
	printf("\n");

	return 0;
}

ngx_int_t compQueueTest(const ngx_queue_t *left, const ngx_queue_t *right)
{
	QueueTest *pQueLeft = ngx_queue_data(left, QueueTest, stNginxQueue);
	QueueTest *pQueRight = ngx_queue_data(right, QueueTest, stNginxQueue);

	return pQueLeft->nNum > pQueRight->nNum;
}

