
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


/*
 * The red-black tree code is based on the algorithm described in
 * the "Introduction to Algorithms" by Cormen, Leiserson and Rivest.
 */


//左旋
static ngx_inline void ngx_rbtree_left_rotate(ngx_rbtree_node_t **root,
    ngx_rbtree_node_t *sentinel, ngx_rbtree_node_t *node);

//右旋
static ngx_inline void ngx_rbtree_right_rotate(ngx_rbtree_node_t **root,
    ngx_rbtree_node_t *sentinel, ngx_rbtree_node_t *node);


void
ngx_rbtree_insert(ngx_thread_volatile ngx_rbtree_t *tree,
    ngx_rbtree_node_t *node)
{
	//移动原则是将红色节点不断上移 移动到root节点的时候 将root节点设置为黑色即可

    ngx_rbtree_node_t  **root, *temp, *sentinel;

    /* a binary tree insert */

    root = (ngx_rbtree_node_t **) &tree->root;
    sentinel = tree->sentinel;

    //还没有数据 将插入的节点作为根节点
    if (*root == sentinel) {
        node->parent = NULL;
        node->left = sentinel;
        node->right = sentinel;
        ngx_rbt_black(node);
        *root = node;

        return;
    }

	//根据规则插入节点
    tree->insert(*root, node, sentinel);

    /* re-balance tree */

    //根据红黑树的性质 进行调整 使之继续满足红黑树的所有性质
    while (node != *root && ngx_rbt_is_red(node->parent)) {
		//当节点的父节点是红色的时候 说明需要调整红黑树了

        if (node->parent == node->parent->parent->left) {
			//父节点是 祖父节点的 左节点
            temp = node->parent->parent->right;

			/*
                temp是叔叔节点 叔叔节点是红色
                case1情况：
                
                操作方法：
                直接将父节点与叔叔节点设置为黑色 祖父节点设置为红色 保证不增加黑色节点的数目
                执行完成之后 继续按照
            */
            if (ngx_rbt_is_red(temp)) {
                ngx_rbt_black(node->parent);
                ngx_rbt_black(temp);
                ngx_rbt_red(node->parent->parent);
                node = node->parent->parent;

            } else {
                /*
                    叔叔节点是黑色节点 不能使用上面的方法
                    case2情况：当前节点是 红色父节点的右节点 需要旋转 移动到一侧 方便处理

                    操作方法：
                    直接以 父节点进行左旋 就可以出现下面的情况case3
                */
                if (node == node->parent->right) {
                    node = node->parent;
                    ngx_rbtree_left_rotate(root, sentinel, node);
                }

                /*
                    case3情况：当前节点是 红色父节点的左节点 在一侧 直接操作

                    操作方法：
                    将父节点设置为黑色 将祖父节点设置为红色 将祖父节点进行右旋
                    经过上面的操作 父节点代替了祖父节点(依然是黑色 不会造成少黑色节点) 祖父节点向下走
                */
                ngx_rbt_black(node->parent);
                ngx_rbt_red(node->parent->parent);
                ngx_rbtree_right_rotate(root, sentinel, node->parent->parent);
            }

        } else {
            //下面操作与上面只是 左右的区别 镜像一下就好 操作相同


			//父节点是 祖父节点的 右节点
            temp = node->parent->parent->left;

			//temp是叔叔节点 叔叔节点是红色的话 直接将父节点与叔叔节点设置为黑色 祖父节点设置为红色 然后继续执行
            if (ngx_rbt_is_red(temp)) {
                ngx_rbt_black(node->parent);
                ngx_rbt_black(temp);
                ngx_rbt_red(node->parent->parent);
                node = node->parent->parent;

            } else {
                if (node == node->parent->left) {
                    node = node->parent;
                    ngx_rbtree_right_rotate(root, sentinel, node);
                }

                ngx_rbt_black(node->parent);
                ngx_rbt_red(node->parent->parent);
                ngx_rbtree_left_rotate(root, sentinel, node->parent->parent);
            }
        }
    }

    //设置根节点为黑色
    ngx_rbt_black(*root);
}


void
ngx_rbtree_insert_value(ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t  **p;

    for ( ;; ) {

        p = (node->key < temp->key) ? &temp->left : &temp->right;

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);          //临时全部设置为红色节点
}


void
ngx_rbtree_insert_timer_value(ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t  **p;

    for ( ;; ) {

        /*
         * Timer values
         * 1) are spread in small range, usually several minutes,
         * 2) and overflow each 49 days, if milliseconds are stored in 32 bits.
         * The comparison takes into account that overflow.
         */

        /*  node->key < temp->key */

        p = ((ngx_rbtree_key_int_t) node->key - (ngx_rbtree_key_int_t) temp->key
              < 0)
            ? &temp->left : &temp->right;

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


void
ngx_rbtree_delete(ngx_thread_volatile ngx_rbtree_t *tree,
    ngx_rbtree_node_t *node)
{
    // 删除操作没有提供删除的操作指针 所以这里进行了二步 第一步进行了节点的删除 第二步进行了红黑树的变幻

    ngx_uint_t           red;
    ngx_rbtree_node_t  **root, *sentinel, *subst, *temp, *w;

    /* a binary tree delete */

    root = (ngx_rbtree_node_t **) &tree->root;
    sentinel = tree->sentinel;

    // 替代节点temp 删除节点subst
    if (node->left == sentinel) {
        // 寻找删除节点1
        temp = node->right;
        subst = node;

    } else if (node->right == sentinel) {
        // 寻找删除节点2
        temp = node->left;
        subst = node;

    } else {
        // 寻找删除节点3
        /*
            这里和上面有点不一样  这里替代节点需要寻找一下 因为左右子树都有节点
            这里实际上删除的节点是 即将找到的最下节点subst 由subst的左子或右子节点替代它
        */
        
        subst = ngx_rbtree_min(node->right, sentinel);

        if (subst->left != sentinel) {
            temp = subst->left;
        } else {
            temp = subst->right;
        }
    }

    // 要删除的节点是根节点 直接删除 将代替接待设置为根节点即可
    if (subst == *root) {
        *root = temp;
        ngx_rbt_black(temp);

        /* DEBUG stuff */
        node->left = NULL;
        node->right = NULL;
        node->parent = NULL;
        node->key = 0;

        return;
    }

    red = ngx_rbt_is_red(subst);

    // 替换操作  (将代替节点 设置为当前要删除的节点)

    // 1.设置被删除节点的 父节点指向子节点的指针
    if (subst == subst->parent->left) {
        subst->parent->left = temp;

    } else {
        subst->parent->right = temp;
    }

    // 2.设置被删除节点 指向父节点的指针
    if (subst == node) {
        // 被删除节点的 左子或者右子 其中一个节点是哨兵节点
        temp->parent = subst->parent;

    } else {
        /*
            出现了上面 寻找删除节点3 的情况  这种情况是找到了替代被删除节点的节点
            我们需要处理的有2个点
            1.替代点的子节点代替 替代点
            2.替代点 代替 被删除节点

            替代点subst  替代点的子节点temp  删除节点node
        */

        // subst为替代节点  temp为替代节点subst的子节点(真正要删除的节点其实是node节点  这里只是要到替换node节点的subst 转换为了删除subst节点)
        if (subst->parent == node) {
            temp->parent = subst;

        } else {
            temp->parent = subst->parent;
        }

        // 下面进行subst替换node节点的操作 都是指针之间的操作(都是 双向的 所以一个节点需要操作两个指针)
        subst->left = node->left;
        subst->right = node->right;
        subst->parent = node->parent;
        ngx_rbt_copy_color(subst, node);

        if (node == *root) {
            *root = subst;

        } else {
            if (node == node->parent->left) {
                node->parent->left = subst;
            } else {
                node->parent->right = subst;
            }
        }

        if (subst->left != sentinel) {
            subst->left->parent = subst;
        }

        if (subst->right != sentinel) {
            subst->right->parent = subst;
        }
    }

    /* DEBUG stuff */
    node->left = NULL;
    node->right = NULL;
    node->parent = NULL;
    node->key = 0;

    // 如果被删除节点是红色节点 直接返回 不用进行红黑树的调整
    if (red) {
        return;
    }

    /* a delete fixup */

    /*
        下面进行红黑树的平衡操作 
        temp是替代节点 上面已经将替换操作执行完成了 因为被删除的是黑色节点(红色节点上面就直接返回了)
        所以 1.如果当前替代删除节点的temp也是黑色的话 就出现了黑+黑的情况 我们需要除去这个黑色
             2.如果当前替代删除节点的temp是红色的话 直接设置为黑色节点即可
    */
    while (temp != *root && ngx_rbt_is_black(temp)) {

		// w 兄弟节点
        if (temp == temp->parent->left) {
            w = temp->parent->right;

            if (ngx_rbt_is_red(w)) {
				/*
					case1情况：当前节点黑+黑 兄弟节点是红色节点

					操作方法：
					将兄弟接点设置为黑色 将父节点设置为红色 对父节点进行左旋
					目的 是将当前节点的兄弟节点转换为黑色进行处理(case 2/3/4情况)
				*/
                ngx_rbt_black(w);
                ngx_rbt_red(temp->parent);
                ngx_rbtree_left_rotate(root, sentinel, temp->parent);
                w = temp->parent->right;
            }

			//下面是兄弟节点是黑色的处理情况
            if (ngx_rbt_is_black(w->left) && ngx_rbt_is_black(w->right)) {
				/*
					case2情况：被删除节点兄弟节点的 左子和右子节点都是黑色

					操作方法：
					将兄弟节点设置为红色 将当前删除节点设置为当前节点的父节点
				*/
                ngx_rbt_red(w);
                temp = temp->parent;

            } else {
                if (ngx_rbt_is_black(w->right)) {
					/*
						笔记中记录的是 兄弟节点的右子节点是黑色 左子节点是红色是case3情况 
						这里不用判断左子节点 因为如果左子节点也是黑色的话 就会进入上面的if判断(左右子节点都是黑色的情况)
						所以 这个if判断中 既然满足了右子节点是黑色 隐含的满足条件就是左子节点肯定是红色
					*/
					/*
						case3情况：被删除节点兄弟节点的 右子节点是黑色的

						操作方法(目的 将右子节点转换为红色 即case4)：
						将右子节点设置为红色 右子节点的左子节点设置为黑色 将右子节点进行右旋
					*/
                    ngx_rbt_black(w->left);
                    ngx_rbt_red(w);
                    ngx_rbtree_right_rotate(root, sentinel, w);
                    w = temp->parent->right;
                }

				/*
					case4情况：被删除节点兄弟节点的 右子节点是红色的

					操作方法：
					将父节点的颜色赋值给兄弟节点 将父节点设置为黑色 将兄弟节点的右子节点设置为黑色 对父节点进行左旋 
					设置被删除节点为根节点(注意 这里不是设置根节点 而是将当前节点设置为根节点 意味着这是最后一次操作 直接将根节点设置为黑色 即退出函数)
				*/
                ngx_rbt_copy_color(w, temp->parent);
                ngx_rbt_black(temp->parent);
                ngx_rbt_black(w->right);
                ngx_rbtree_left_rotate(root, sentinel, temp->parent);
                temp = *root;
            }

        } else {
			//下面操作与上面只是 左右的区别 镜像一下就好 操作相同
            w = temp->parent->left;

            if (ngx_rbt_is_red(w)) {
                ngx_rbt_black(w);
                ngx_rbt_red(temp->parent);
                ngx_rbtree_right_rotate(root, sentinel, temp->parent);
                w = temp->parent->left;
            }

            if (ngx_rbt_is_black(w->left) && ngx_rbt_is_black(w->right)) {
                ngx_rbt_red(w);
                temp = temp->parent;

            } else {
                if (ngx_rbt_is_black(w->left)) {
                    ngx_rbt_black(w->right);
                    ngx_rbt_red(w);
                    ngx_rbtree_left_rotate(root, sentinel, w);
                    w = temp->parent->left;
                }

                ngx_rbt_copy_color(w, temp->parent);
                ngx_rbt_black(temp->parent);
                ngx_rbt_black(w->left);
                ngx_rbtree_right_rotate(root, sentinel, temp->parent);
                temp = *root;
            }
        }
    }

    ngx_rbt_black(temp);
}


static ngx_inline void
ngx_rbtree_left_rotate(ngx_rbtree_node_t **root, ngx_rbtree_node_t *sentinel,
    ngx_rbtree_node_t *node)
{
    //左旋节点的 右自节点
    ngx_rbtree_node_t  *temp;

    temp = node->right;
    node->right = temp->left;

    if (temp->left != sentinel) {
        temp->left->parent = node;
    }

    temp->parent = node->parent;

    
    if (node == *root) {
        //左旋节点是根节点 直接将左旋节点的右子节点设置为根节点
        *root = temp;

    } else if (node == node->parent->left) {
        //左旋节点是父节点的 左子树
        node->parent->left = temp;

    } else {
        //左旋节点是父节点的 右子树
        node->parent->right = temp;
    }

    temp->left = node;
    node->parent = temp;
}


static ngx_inline void
ngx_rbtree_right_rotate(ngx_rbtree_node_t **root, ngx_rbtree_node_t *sentinel,
    ngx_rbtree_node_t *node)
{
    //右旋节点的 左节点
    ngx_rbtree_node_t  *temp;

    temp = node->left;
    node->left = temp->right;

    if (temp->right != sentinel) {
        temp->right->parent = node;
    }

    temp->parent = node->parent;

    if (node == *root) {
        //右旋节点是根节点 直接将右旋节点的左子节点设置为根节点
        *root = temp;

    } else if (node == node->parent->right) {
        //右旋节点是父节点的 右子树
        node->parent->right = temp;

    } else {
        //右旋节点是父节点的 左子树
        node->parent->left = temp;
    }

    temp->right = node;
    node->parent = temp;
}

ngx_rbtree_node_t *ngx_rbtree_lookup(ngx_thread_volatile ngx_rbtree_t *tree,  ngx_uint_t key, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t *pFindNode = tree->root;

    while(pFindNode != sentinel)
    {
        if(pFindNode->key == key)
        {
            break;
        }

        pFindNode = pFindNode->key < key ? pFindNode->right : pFindNode->left;
    }

    return pFindNode;
}

void TraversalRbtree(ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    if(node->left != sentinel)
    {
        TraversalRbtree(node->left, sentinel);
    }

    printf("%u ", node->key);

    if(node->right != sentinel)
    {
        TraversalRbtree(node->right, sentinel);
    }
}

ngx_rbtree_node_t *ngx_rbtree_next(ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    if(node->right != sentinel)
    {
        for(node = node->right; node->left != sentinel; node = node->left)
            /* void */;
    }
    else
    {
        ngx_rbtree_node_t *temp = node->parent;

        //父节点的默认值是NULL
        while(temp != NULL /* temp != sentinel */ && temp->right == node)
        {
            node = temp;
            temp = temp->parent;
        }

        node = temp;
    }

    if(node != NULL && node != sentinel)
        return node;
    return NULL;
}

ngx_rbtree_node_t *ngx_rbtree_prev(ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    if(node->left != sentinel)
    {
        for(node = node->left; node->right != sentinel; node = node->right)
            /* void */;
    }
    else
    {
        ngx_rbtree_node_t *temp = node->parent;
        while(temp != NULL && temp->left == node)
        {
            node = temp;
            temp = temp->parent;
        }

        node = temp;
    }

    if(node != NULL && node != sentinel)
        return node;
    return NULL;
}

