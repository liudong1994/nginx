
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_RBTREE_H_INCLUDED_
#define _NGX_RBTREE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef ngx_uint_t  ngx_rbtree_key_t;
typedef ngx_int_t   ngx_rbtree_key_int_t;


typedef struct ngx_rbtree_node_s  ngx_rbtree_node_t;

struct ngx_rbtree_node_s {
    ngx_rbtree_key_t       key;         //关键字key
    ngx_rbtree_node_t     *left;        //左子节点
    ngx_rbtree_node_t     *right;       //右子节点
    ngx_rbtree_node_t     *parent;      //父节点
    u_char                 color;       //节点颜色  0黑 1红
    u_char                 data;        //节点数据(1个字节 空间很小 使用频率不多)
};


typedef struct ngx_rbtree_s  ngx_rbtree_t;

typedef void (*ngx_rbtree_insert_pt) (ngx_rbtree_node_t *root,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);

struct ngx_rbtree_s {
    ngx_rbtree_node_t     *root;        //根节点
    ngx_rbtree_node_t     *sentinel;    //sentinel哨兵节点

    /*
		表示红黑树添加元素的函数指针 它决定在添加元素时的行为是替换还是新增
        为了解决不同节点含有相同关键字的元素冲突问题 红黑树设置了这个指针 可以灵活的添加冲突元素
    */
    ngx_rbtree_insert_pt   insert;
};


/*
    tree    红黑树容器指针
    s       哨兵节点指针(哨兵永远是黑色的)
    i       ngx_rbtree_insert_pt节点添加方法
*/
#define ngx_rbtree_init(tree, s, i)                                           \
    ngx_rbtree_sentinel_init(s);                                              \
    (tree)->root = s;                                                         \
    (tree)->sentinel = s;                                                     \
    (tree)->insert = i


void ngx_rbtree_insert(ngx_thread_volatile ngx_rbtree_t *tree,
    ngx_rbtree_node_t *node);
void ngx_rbtree_delete(ngx_thread_volatile ngx_rbtree_t *tree,
    ngx_rbtree_node_t *node);
void ngx_rbtree_insert_value(ngx_rbtree_node_t *root, ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel);
void ngx_rbtree_insert_timer_value(ngx_rbtree_node_t *root,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
/*
    下面字符串作为第二索引关键字的代码 在 ngx_string文件中声明和实现
void ngx_str_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
ngx_str_node_t *ngx_str_rbtree_lookup(ngx_rbtree_t *rbtree, ngx_str_t *name,
    uint32_t hash);
*/

// 自定义的检索函数
ngx_rbtree_node_t *ngx_rbtree_lookup(ngx_thread_volatile ngx_rbtree_t *tree, ngx_uint_t key, ngx_rbtree_node_t *sentinel);

// 遍历红黑树进行节点key显示
void TraversalRbtree(ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);

// 获取红黑树的下一个节点
ngx_rbtree_node_t *ngx_rbtree_next(ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);

// 获取红黑树的上一个节点
ngx_rbtree_node_t *ngx_rbtree_prev(ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);


#define ngx_rbt_red(node)               ((node)->color = 1)
#define ngx_rbt_black(node)             ((node)->color = 0)
#define ngx_rbt_is_red(node)            ((node)->color)
#define ngx_rbt_is_black(node)          (!ngx_rbt_is_red(node))
#define ngx_rbt_copy_color(n1, n2)      (n1->color = n2->color)


/* a sentinel must be black */

#define ngx_rbtree_sentinel_init(node)  ngx_rbt_black(node)


/*
    找到当前节点及其子树中最小的节点(按照key关键字查找)
*/
static ngx_inline ngx_rbtree_node_t *
ngx_rbtree_min(ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    while (node->left != sentinel) {
        node = node->left;
    }

    return node;
}


#endif /* _NGX_RBTREE_H_INCLUDED_ */
