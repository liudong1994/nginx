#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_rbtree.h>
#include "ngx_rbtree.h"


typedef struct 
{
    ngx_rbtree_node_t   rbTreeNode;     //��Ϊ��һ����Ա���� ����ǿ��ת��
    ngx_uint_t          num;            //�Զ����Ա����
}TestRbtreeNode;

int ngx_rbtree_test_func()
{
    ngx_rbtree_t stNgxRbTree;           //�����
    ngx_rbtree_node_t stNgxSentinel;    //������ڵ�
    
    ngx_rbtree_init(&stNgxRbTree, &stNgxSentinel, ngx_rbtree_insert_value);

    TestRbtreeNode arrTestRbtreeNode[10];
    arrTestRbtreeNode[0].num = 1;
    arrTestRbtreeNode[1].num  = 3;
    arrTestRbtreeNode[2].num  = 5;
    arrTestRbtreeNode[3].num  = 7;
    arrTestRbtreeNode[4].num  = 8;
    arrTestRbtreeNode[5].num  = 12;
    arrTestRbtreeNode[6].num  = 15;
    arrTestRbtreeNode[7].num  = 16;
    arrTestRbtreeNode[8].num  = 18;
    arrTestRbtreeNode[9].num  = 22;

    int i=0;
    for( ; i<10; ++i)
    {
        arrTestRbtreeNode[i].rbTreeNode.key = arrTestRbtreeNode[i].num;
        ngx_rbtree_insert(&stNgxRbTree, &arrTestRbtreeNode[i].rbTreeNode);
    }

    // ��ȡ��С�ڵ�
    ngx_rbtree_node_t *pMinRbtreeNode = ngx_rbtree_min(stNgxRbTree.root, &stNgxSentinel);
    printf("RbTree MinNode:%d\n", pMinRbtreeNode->key);

    // ���������
    printf("TraversalRbtree:\n");
    TraversalRbtree(stNgxRbTree.root, &stNgxSentinel);
    printf("\n");

    // ʹ��ָ����������
    printf("TraversalRbtree(pointer):\n");
    ngx_rbtree_node_t *node = pMinRbtreeNode;
    for( ; node != NULL; node = ngx_rbtree_next(node, stNgxRbTree.sentinel))
    {
        printf("%u ", node->key);
    }
    printf("\n");

    // ����ָ���ڵ�
    ngx_rbtree_node_t *pFindRbtreeNode = ngx_rbtree_lookup(&stNgxRbTree, 15, &stNgxSentinel);
    if(pFindRbtreeNode)
    {
        TestRbtreeNode *pTestFindRbtreeNode = (TestRbtreeNode *)pFindRbtreeNode;
        printf("Rbtree Find 15 Node Num:%u\n", pTestFindRbtreeNode->num);
    }
    else
    {
        printf("Rbtree Not Find 15 Node\n");
    }

    // ɾ���ڵ�
    printf("ngx_rbtree delete 15 node\n");
    ngx_rbtree_delete(&stNgxRbTree, pFindRbtreeNode);

    // ���������
    printf("TraversalRbtree:\n");
    TraversalRbtree(stNgxRbTree.root, &stNgxSentinel);
    printf("\n");

    // ʹ��ָ����������
    printf("TraversalRbtree(pointer):\n");
    node = pMinRbtreeNode;
    for( ; node != NULL; node = ngx_rbtree_next(node, stNgxRbTree.sentinel))
    {
        printf("%u ", node->key);
    }
    printf("\n");

    return 0;
}

