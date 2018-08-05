
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


//����
static ngx_inline void ngx_rbtree_left_rotate(ngx_rbtree_node_t **root,
    ngx_rbtree_node_t *sentinel, ngx_rbtree_node_t *node);

//����
static ngx_inline void ngx_rbtree_right_rotate(ngx_rbtree_node_t **root,
    ngx_rbtree_node_t *sentinel, ngx_rbtree_node_t *node);


void
ngx_rbtree_insert(ngx_thread_volatile ngx_rbtree_t *tree,
    ngx_rbtree_node_t *node)
{
	//�ƶ�ԭ���ǽ���ɫ�ڵ㲻������ �ƶ���root�ڵ��ʱ�� ��root�ڵ�����Ϊ��ɫ����

    ngx_rbtree_node_t  **root, *temp, *sentinel;

    /* a binary tree insert */

    root = (ngx_rbtree_node_t **) &tree->root;
    sentinel = tree->sentinel;

    //��û������ ������Ľڵ���Ϊ���ڵ�
    if (*root == sentinel) {
        node->parent = NULL;
        node->left = sentinel;
        node->right = sentinel;
        ngx_rbt_black(node);
        *root = node;

        return;
    }

	//���ݹ������ڵ�
    tree->insert(*root, node, sentinel);

    /* re-balance tree */

    //���ݺ���������� ���е��� ʹ֮����������������������
    while (node != *root && ngx_rbt_is_red(node->parent)) {
		//���ڵ�ĸ��ڵ��Ǻ�ɫ��ʱ�� ˵����Ҫ�����������

        if (node->parent == node->parent->parent->left) {
			//���ڵ��� �游�ڵ�� ��ڵ�
            temp = node->parent->parent->right;

			/*
                temp������ڵ� ����ڵ��Ǻ�ɫ
                case1�����
                
                ����������
                ֱ�ӽ����ڵ�������ڵ�����Ϊ��ɫ �游�ڵ�����Ϊ��ɫ ��֤�����Ӻ�ɫ�ڵ����Ŀ
                ִ�����֮�� ��������
            */
            if (ngx_rbt_is_red(temp)) {
                ngx_rbt_black(node->parent);
                ngx_rbt_black(temp);
                ngx_rbt_red(node->parent->parent);
                node = node->parent->parent;

            } else {
                /*
                    ����ڵ��Ǻ�ɫ�ڵ� ����ʹ������ķ���
                    case2�������ǰ�ڵ��� ��ɫ���ڵ���ҽڵ� ��Ҫ��ת �ƶ���һ�� ���㴦��

                    ����������
                    ֱ���� ���ڵ�������� �Ϳ��Գ�����������case3
                */
                if (node == node->parent->right) {
                    node = node->parent;
                    ngx_rbtree_left_rotate(root, sentinel, node);
                }

                /*
                    case3�������ǰ�ڵ��� ��ɫ���ڵ����ڵ� ��һ�� ֱ�Ӳ���

                    ����������
                    �����ڵ�����Ϊ��ɫ ���游�ڵ�����Ϊ��ɫ ���游�ڵ��������
                    ��������Ĳ��� ���ڵ�������游�ڵ�(��Ȼ�Ǻ�ɫ ��������ٺ�ɫ�ڵ�) �游�ڵ�������
                */
                ngx_rbt_black(node->parent);
                ngx_rbt_red(node->parent->parent);
                ngx_rbtree_right_rotate(root, sentinel, node->parent->parent);
            }

        } else {
            //�������������ֻ�� ���ҵ����� ����һ�¾ͺ� ������ͬ


			//���ڵ��� �游�ڵ�� �ҽڵ�
            temp = node->parent->parent->left;

			//temp������ڵ� ����ڵ��Ǻ�ɫ�Ļ� ֱ�ӽ����ڵ�������ڵ�����Ϊ��ɫ �游�ڵ�����Ϊ��ɫ Ȼ�����ִ��
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

    //���ø��ڵ�Ϊ��ɫ
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
    ngx_rbt_red(node);          //��ʱȫ������Ϊ��ɫ�ڵ�
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
    // ɾ������û���ṩɾ���Ĳ���ָ�� ������������˶��� ��һ�������˽ڵ��ɾ�� �ڶ��������˺�����ı��

    ngx_uint_t           red;
    ngx_rbtree_node_t  **root, *sentinel, *subst, *temp, *w;

    /* a binary tree delete */

    root = (ngx_rbtree_node_t **) &tree->root;
    sentinel = tree->sentinel;

    // ����ڵ�temp ɾ���ڵ�subst
    if (node->left == sentinel) {
        // Ѱ��ɾ���ڵ�1
        temp = node->right;
        subst = node;

    } else if (node->right == sentinel) {
        // Ѱ��ɾ���ڵ�2
        temp = node->left;
        subst = node;

    } else {
        // Ѱ��ɾ���ڵ�3
        /*
            ����������е㲻һ��  ��������ڵ���ҪѰ��һ�� ��Ϊ�����������нڵ�
            ����ʵ����ɾ���Ľڵ��� �����ҵ������½ڵ�subst ��subst�����ӻ����ӽڵ������
        */
        
        subst = ngx_rbtree_min(node->right, sentinel);

        if (subst->left != sentinel) {
            temp = subst->left;
        } else {
            temp = subst->right;
        }
    }

    // Ҫɾ���Ľڵ��Ǹ��ڵ� ֱ��ɾ�� ������Ӵ�����Ϊ���ڵ㼴��
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

    // �滻����  (������ڵ� ����Ϊ��ǰҪɾ���Ľڵ�)

    // 1.���ñ�ɾ���ڵ�� ���ڵ�ָ���ӽڵ��ָ��
    if (subst == subst->parent->left) {
        subst->parent->left = temp;

    } else {
        subst->parent->right = temp;
    }

    // 2.���ñ�ɾ���ڵ� ָ�򸸽ڵ��ָ��
    if (subst == node) {
        // ��ɾ���ڵ�� ���ӻ������� ����һ���ڵ����ڱ��ڵ�
        temp->parent = subst->parent;

    } else {
        /*
            ���������� Ѱ��ɾ���ڵ�3 �����  ����������ҵ��������ɾ���ڵ�Ľڵ�
            ������Ҫ�������2����
            1.�������ӽڵ���� �����
            2.����� ���� ��ɾ���ڵ�

            �����subst  �������ӽڵ�temp  ɾ���ڵ�node
        */

        // substΪ����ڵ�  tempΪ����ڵ�subst���ӽڵ�(����Ҫɾ���Ľڵ���ʵ��node�ڵ�  ����ֻ��Ҫ���滻node�ڵ��subst ת��Ϊ��ɾ��subst�ڵ�)
        if (subst->parent == node) {
            temp->parent = subst;

        } else {
            temp->parent = subst->parent;
        }

        // �������subst�滻node�ڵ�Ĳ��� ����ָ��֮��Ĳ���(���� ˫��� ����һ���ڵ���Ҫ��������ָ��)
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

    // �����ɾ���ڵ��Ǻ�ɫ�ڵ� ֱ�ӷ��� ���ý��к�����ĵ���
    if (red) {
        return;
    }

    /* a delete fixup */

    /*
        ������к������ƽ����� 
        temp������ڵ� �����Ѿ����滻����ִ������� ��Ϊ��ɾ�����Ǻ�ɫ�ڵ�(��ɫ�ڵ������ֱ�ӷ�����)
        ���� 1.�����ǰ���ɾ���ڵ��tempҲ�Ǻ�ɫ�Ļ� �ͳ����˺�+�ڵ���� ������Ҫ��ȥ�����ɫ
             2.�����ǰ���ɾ���ڵ��temp�Ǻ�ɫ�Ļ� ֱ������Ϊ��ɫ�ڵ㼴��
    */
    while (temp != *root && ngx_rbt_is_black(temp)) {

		// w �ֵܽڵ�
        if (temp == temp->parent->left) {
            w = temp->parent->right;

            if (ngx_rbt_is_red(w)) {
				/*
					case1�������ǰ�ڵ��+�� �ֵܽڵ��Ǻ�ɫ�ڵ�

					����������
					���ֵܽӵ�����Ϊ��ɫ �����ڵ�����Ϊ��ɫ �Ը��ڵ��������
					Ŀ�� �ǽ���ǰ�ڵ���ֵܽڵ�ת��Ϊ��ɫ���д���(case 2/3/4���)
				*/
                ngx_rbt_black(w);
                ngx_rbt_red(temp->parent);
                ngx_rbtree_left_rotate(root, sentinel, temp->parent);
                w = temp->parent->right;
            }

			//�������ֵܽڵ��Ǻ�ɫ�Ĵ������
            if (ngx_rbt_is_black(w->left) && ngx_rbt_is_black(w->right)) {
				/*
					case2�������ɾ���ڵ��ֵܽڵ�� ���Ӻ����ӽڵ㶼�Ǻ�ɫ

					����������
					���ֵܽڵ�����Ϊ��ɫ ����ǰɾ���ڵ�����Ϊ��ǰ�ڵ�ĸ��ڵ�
				*/
                ngx_rbt_red(w);
                temp = temp->parent;

            } else {
                if (ngx_rbt_is_black(w->right)) {
					/*
						�ʼ��м�¼���� �ֵܽڵ�����ӽڵ��Ǻ�ɫ ���ӽڵ��Ǻ�ɫ��case3��� 
						���ﲻ���ж����ӽڵ� ��Ϊ������ӽڵ�Ҳ�Ǻ�ɫ�Ļ� �ͻ���������if�ж�(�����ӽڵ㶼�Ǻ�ɫ�����)
						���� ���if�ж��� ��Ȼ���������ӽڵ��Ǻ�ɫ ���������������������ӽڵ�϶��Ǻ�ɫ
					*/
					/*
						case3�������ɾ���ڵ��ֵܽڵ�� ���ӽڵ��Ǻ�ɫ��

						��������(Ŀ�� �����ӽڵ�ת��Ϊ��ɫ ��case4)��
						�����ӽڵ�����Ϊ��ɫ ���ӽڵ�����ӽڵ�����Ϊ��ɫ �����ӽڵ��������
					*/
                    ngx_rbt_black(w->left);
                    ngx_rbt_red(w);
                    ngx_rbtree_right_rotate(root, sentinel, w);
                    w = temp->parent->right;
                }

				/*
					case4�������ɾ���ڵ��ֵܽڵ�� ���ӽڵ��Ǻ�ɫ��

					����������
					�����ڵ����ɫ��ֵ���ֵܽڵ� �����ڵ�����Ϊ��ɫ ���ֵܽڵ�����ӽڵ�����Ϊ��ɫ �Ը��ڵ�������� 
					���ñ�ɾ���ڵ�Ϊ���ڵ�(ע�� ���ﲻ�����ø��ڵ� ���ǽ���ǰ�ڵ�����Ϊ���ڵ� ��ζ���������һ�β��� ֱ�ӽ����ڵ�����Ϊ��ɫ ���˳�����)
				*/
                ngx_rbt_copy_color(w, temp->parent);
                ngx_rbt_black(temp->parent);
                ngx_rbt_black(w->right);
                ngx_rbtree_left_rotate(root, sentinel, temp->parent);
                temp = *root;
            }

        } else {
			//�������������ֻ�� ���ҵ����� ����һ�¾ͺ� ������ͬ
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
    //�����ڵ�� ���Խڵ�
    ngx_rbtree_node_t  *temp;

    temp = node->right;
    node->right = temp->left;

    if (temp->left != sentinel) {
        temp->left->parent = node;
    }

    temp->parent = node->parent;

    
    if (node == *root) {
        //�����ڵ��Ǹ��ڵ� ֱ�ӽ������ڵ�����ӽڵ�����Ϊ���ڵ�
        *root = temp;

    } else if (node == node->parent->left) {
        //�����ڵ��Ǹ��ڵ�� ������
        node->parent->left = temp;

    } else {
        //�����ڵ��Ǹ��ڵ�� ������
        node->parent->right = temp;
    }

    temp->left = node;
    node->parent = temp;
}


static ngx_inline void
ngx_rbtree_right_rotate(ngx_rbtree_node_t **root, ngx_rbtree_node_t *sentinel,
    ngx_rbtree_node_t *node)
{
    //�����ڵ�� ��ڵ�
    ngx_rbtree_node_t  *temp;

    temp = node->left;
    node->left = temp->right;

    if (temp->right != sentinel) {
        temp->right->parent = node;
    }

    temp->parent = node->parent;

    if (node == *root) {
        //�����ڵ��Ǹ��ڵ� ֱ�ӽ������ڵ�����ӽڵ�����Ϊ���ڵ�
        *root = temp;

    } else if (node == node->parent->right) {
        //�����ڵ��Ǹ��ڵ�� ������
        node->parent->right = temp;

    } else {
        //�����ڵ��Ǹ��ڵ�� ������
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

        //���ڵ��Ĭ��ֵ��NULL
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

