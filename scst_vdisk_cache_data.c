#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/slab.h>
#include <linux/notifier.h>
#include <linux/cpu.h>
#include <linux/gfp.h>
#include <linux/string.h>
#include <linux/bitops.h>
#include <linux/rcupdate.h>
#include <linux/mm.h>

#include "scst_vdisk_cache_data.h"

#include "flag.h"

#define count_cmt(fmt)          "SC: [%d %s] "fmt
#define count_info(fmt, ...)	\
        // printk(KERN_INFO count_cmt(fmt), __LINE__, __func__, ##__VA_ARGS__)
#define count_err(fmt, ...)	    \
        printk(KERN_ERR count_cmt(fmt), __LINE__, __func__, ##__VA_ARGS__)

#define tree_cmt(fmt)           "SC: [%d %s] "fmt
#define tree_info(fmt, ...)	    \
        // printk(KERN_INFO tree_cmt(fmt), __LINE__, __func__, ##__VA_ARGS__)
#define tree_e_cmt(fmt)           "SC: ERROR [%d %s] "fmt
#define tree_err(fmt, ...)	    \
        printk(KERN_INFO tree_e_cmt(fmt), __LINE__, __func__, ##__VA_ARGS__)


static int sc_page_count = 0;
spinlock_t sc_count_lock;


void insert_node_in_lrulist(struct list_head *lru_list, 
                            struct list_head *lru_list_head)
{
    list_add(lru_list, lru_list_head);
}


void delete_node_in_lrulist(struct list_head *lru_list_head)
{
    if(unlikely (list_empty(lru_list_head)))
        tree_info("there is a bug! can not delete the empty list!!\n");
    list_del(lru_list_head->prev);		
}


void move_node_in_lrulist(struct list_head *list, 
                          struct list_head *lru_list_head_2)
{
    list_move(list, lru_list_head_2);
}


int is_cache_full_data(atomic_t count)
{
    tree_info("start! count: %d, MAX_COUNT_OF_CACHE_DATA :%d,\
              CACHE_CAPACITY_DATA: %d\n",
              atomic_read(&count),
              MAX_COUNT_OF_CACHE_DATA,
              CACHE_CAPACITY_DATA);	
    if(atomic_read(&count) >= (int)MAX_COUNT_OF_CACHE_DATA)
        return 1;
    else
        return 0;	
}

struct vdisk_cache_data *alloc_data_cache_struct(
        struct data_cache_radix_tree_root *root,
        sector_t lba_align,
        int devs)
{
    tree_info("lba_align: %lu\n", lba_align);
    struct vdisk_cache_data *vdisk_cache_new;
    int i;
    
    vdisk_cache_new = (struct vdisk_cache_data *)kmalloc((sizeof(struct vdisk_cache_data) + devs * sizeof(struct r5cdev)), GFP_KERNEL);
    if(!vdisk_cache_new)
        tree_err("alloc cache struct failed !\n");

    memset(vdisk_cache_new, 0, ((sizeof(struct vdisk_cache_data) + devs * sizeof(struct r5cdev))));

    INIT_LIST_HEAD(&vdisk_cache_new->for_free_list);
    INIT_LIST_HEAD(&vdisk_cache_new->lru);
    atomic_set(&vdisk_cache_new->dirty_pages, 0);
    atomic_set(&vdisk_cache_new->filling_pages, 0);

    // add vfd to a list, for free space
    spin_lock(&root->for_vcd_free_list_lock);
    list_add(&vdisk_cache_new->for_free_list, 
             &root->for_vcd_free_list_head);
    atomic_inc(&root->total_vcd);
    spin_unlock(&root->for_vcd_free_list_lock);
        
    tree_info("alloc vcd: %lu %p, alloc_vcds: %d\n",
              lba_align,
              vdisk_cache_new, 
              atomic_read(&root->total_vcd));

    vdisk_cache_new->lba_align = lba_align;
    for (i = 0; i < devs; i++) 
    {
		struct r5cdev *cdev = &vdisk_cache_new->dev[i];
        spin_lock_init(&cdev->lock);
        cdev->page = NULL;
		cdev->sector = -1;
        cdev->flag = 0;
    }
    tree_info("success devs: %d, lba_align: %lu\n", devs, lba_align);
    return vdisk_cache_new;
}

#define STRIPE_SECTORS_TREE		8

struct vdisk_cache_data *insert_item_in_cache(
        struct vdisk_cache_data *vdisk_cache_insert, 
        int item, int disks, int logical_sector,
        struct page *page, int rw)
{
    sector_t old_dev_sector;
    if(vdisk_cache_insert == NULL) 
        return NULL; 
	struct r5cdev *cdev = &vdisk_cache_insert->dev[item];
    tree_info("start!devs->sector: %d, disks %d, item %d, page %p, rw: %d\n",
            logical_sector, disks, item, page, rw);
    old_dev_sector = cdev->sector;
    cdev->sector = logical_sector;

    if(cdev->page != NULL)
    {
        if(logical_sector != old_dev_sector)
            count_err("logical_sector %lu != old_sector %lu\n",
                    logical_sector, old_dev_sector);
        count_info("old_sector: %lu, old_page: %p\n", old_dev_sector, cdev->page);
        count_info("new_sector: %lu, new_page: %p\n", logical_sector, page);

        if(test_bit(VCD_PAGE_DIRTY, &cdev->flag) /*cdev->dirty == 1*/ && rw == 1)
            __free_page(cdev->page);
        // TODO: free page
    }
    else 
    {
	    cdev->page = page;

        spin_lock(&sc_count_lock);
        sc_page_count++;
        count_info("insert sector: %lu, %p, pages %d in tree\n", 
                   logical_sector, page, sc_page_count);
        spin_unlock(&sc_count_lock);
    }
	tree_info("success item %d, logical_sector: %lu\n", item, logical_sector);
    return vdisk_cache_insert;
}



struct vdisk_cache_data *insert_item_in_readcache(
                struct vdisk_cache_data *vdisk_cache_insert,
                int item, int disks, int logical_sector)
{
    struct r5cdev *cdev= &vdisk_cache_insert->dev[item];
    int i ;
    if(vdisk_cache_insert == NULL) 
        return NULL; 
    cdev->sector = logical_sector;
	tree_info("i %d, item %d, logical_sector %lu\n",
               i, item, logical_sector);
    return vdisk_cache_insert;
}


//XQ Liao
static void data_cache_radix_tree_node_ctor(void *node)
{
    memset(node, 0, sizeof(struct data_cache_radix_tree_node));
}


static unsigned long long __maxindex_data(unsigned int height)
{
    unsigned int tmp = height * DATA_CACHE_RADIX_TREE_MAP_SHIFT;
    unsigned long long index = (~0UL >> (DATA_CACHE_RADIX_TREE_INDEX_BITS - tmp - 1)) >> 1;

    if (tmp >= DATA_CACHE_RADIX_TREE_INDEX_BITS)
        index = ~0UL;
    return index;
}


static inline unsigned long long data_cache_radix_tree_maxindex(
                                        unsigned int height)
{
    return data_height_to_maxindex[height];
}


static void data_cache_radix_tree_init_maxindex(void)
{
    unsigned int i;
    for (i = 0; i < ARRAY_SIZE_S(data_height_to_maxindex); i++)
    {
        data_height_to_maxindex[i] = __maxindex_data(i);
        tree_info("height: %d max_node: %lu\n", 
                 i, data_height_to_maxindex[i]);
    }
}


static inline void data_tag_set(struct data_cache_radix_tree_node *node,
                                unsigned int tag,
        int offset)
{
    __set_bit(offset, node->tags[tag]);
}


static inline void data_tag_clear(struct data_cache_radix_tree_node *node,
                                  unsigned int tag, int offset)
{
    __clear_bit(offset, node->tags[tag]);
}


static inline int data_tag_get(struct data_cache_radix_tree_node *node,
                               unsigned int tag, int offset)
{
    return test_bit(offset, node->tags[tag]);
}


static inline void data_root_tag_clear(struct data_cache_radix_tree_root *root,
                                       unsigned int tag)
{
    root->gfp_mask &= ~(1 << (tag + __GFP_BITS_SHIFT));
}


static inline void data_root_tag_clear_all(
                                struct data_cache_radix_tree_root *root)
{
    root->gfp_mask &= __GFP_BITS_MASK;
}


static inline int data_root_tag_get(struct data_cache_radix_tree_root *root,
                                    unsigned int tag)
{
    return root->gfp_mask & (1 << (tag + __GFP_BITS_SHIFT));
}



/*
 * Returns 1 if any slot in the node has this tag set.
 * Otherwise returns 0.
 */
static inline int data_any_tag_set(struct data_cache_radix_tree_node *node,
                                   unsigned int tag)
{
    int idx;
    for (idx = 0; idx < (int)DATA_CACHE_RADIX_TREE_TAG_LONGS; idx++) 
    {
        if (node->tags[tag][idx])
            return 1;
    }
    return 0;
}


static inline gfp_t data_root_gfp_mask(struct data_cache_radix_tree_root *root)
{
    return root->gfp_mask & __GFP_BITS_MASK;
}


static struct data_cache_radix_tree_node *data_cache_radix_tree_node_alloc(
                        struct data_cache_radix_tree_root *root,
                        sector_t lba)
{
    struct data_cache_radix_tree_node *ret;
    gfp_t gfp_mask = data_root_gfp_mask(root);
    tree_info("start!\n");
    ret = kmem_cache_alloc(data_cache_radix_tree_node_cachep, gfp_mask);
    if (ret == NULL)
    {
        tree_err("alloc cache_radix_tree node failed!\n");
        return NULL;
    }
    ret->count = 0;
    ret->hit_hot_count = 0;
    ret->lba = lba;
    INIT_LIST_HEAD(&ret->lru_list_entry);
    INIT_LIST_HEAD(&ret->cold_list_entry);
    INIT_LIST_HEAD(&ret->read_list_entry);
    /*int i;
      for (i = 0; i < HOT_COLD_GROUP_NUM; i++)
      INIT_LIST_HEAD(ret->cold_cache_entry+ i);*/
    INIT_LIST_HEAD(&ret->cold_cache_entry_one);
	INIT_LIST_HEAD(&ret->cold_cache_entry_two);
	INIT_LIST_HEAD(&ret->cold_cache_entry_three);
    INIT_LIST_HEAD(&ret->for_free_list);
    memset(ret->hot, 0, HOT_COLD_GROUP_NUM);
    memset(ret->qsort_locate, 0, 16);
    memset(ret->hot_cold_cache, 0, HOT_COLD_GROUP_NUM);
	memset(ret->delete_hot_flag, 0, HOT_COLD_GROUP_NUM);
    ret->local_flag = 0;
    ret->hot_flag = 0;
    ret->once_delete_flag = 0;
	ret->flag_delete = 0;
	ret->flush_delete = 0;
	ret->hot_count = 0;
	ret->read_flag = 0;
	ret->write_flag = 0;
	ret->exist_flag = 0;
	ret->noexist_flag = 0;
	ret->cold_hot_flag = 0;
	ret->need_delete_flag = 0;

    spin_lock(&root->for_free_list_lock);
    list_add(&ret->for_free_list, &root->for_free_list_head);
    atomic_inc(&root->total_node);
    tree_info("add node %p to list, count: %d\n",
             ret, atomic_read(&root->total_node));
    spin_unlock(&root->for_free_list_lock);

    return ret;
}


void data_cache_radix_tree_node_free(struct data_cache_radix_tree_root *root, struct data_cache_radix_tree_node *node)
{
    tree_info("start!\n");
    spin_lock(&root->for_free_list_lock);
    atomic_dec(&root->total_node);
    list_del_init(&node->for_free_list);
    tree_info("del node %p to list, count: %d\n",
             node, atomic_read(&root->total_node));
    kmem_cache_free(data_cache_radix_tree_node_cachep, node);
    spin_unlock(&root->for_free_list_lock);
}

	
static inline void ** __lookup_node_data(
                struct data_cache_radix_tree_root * root,
                unsigned long index)
{
    unsigned int height, shift;
    struct data_cache_radix_tree_node **slot;

    height = root->height;
    tree_info("start!root->height %d, index %d \n", root->height, index);
    if (index > data_cache_radix_tree_maxindex(height))
        return NULL;

    if (height == 0 && root->rnode)
        return (void **)&root->rnode;

    shift = (height - 1) * DATA_CACHE_RADIX_TREE_MAP_SHIFT;
    slot = &root->rnode;

    while (height > 1) 
    {
        if (*slot == NULL)
            return NULL;

        slot = (struct data_cache_radix_tree_node **)
            ((*slot)->slots +
             ((index >> shift) & DATA_CACHE_RADIX_TREE_MAP_MASK));
        tree_info("slot: %p\n", slot);
        shift -= DATA_CACHE_RADIX_TREE_MAP_SHIFT;
        height--;
    }
    return (void **)slot;
}


static void *cache_radix_tree_find_node(struct data_cache_radix_tree_root *root,
                                        unsigned long index)
{
    void **node;
    node = __lookup_node_data(root, index);
    return node != NULL ? *node : NULL;
}

struct data_cache_radix_tree_node *lookup_data_node_in_tree(
                            struct data_cache_radix_tree_root *root,  
                            unsigned long index)
{
    struct data_cache_radix_tree_node *node = NULL;
    tree_info("index %d\n", index);
    node = cache_radix_tree_find_node(root, index);
    if(node == NULL)
        tree_info("node == NULL, index %d\n", index);
    else 
        tree_info("node->height %d, index %d\n", node->height, index);
    return node;
}

static int data_cache_radix_tree_extend(struct data_cache_radix_tree_root *root,
                                        unsigned long index)
{
    struct data_cache_radix_tree_node *node;
    unsigned int height;
    int tag;
    tree_info("staart!\n index %d\n",index);
    /* Figure out what the height should be.  */
    height = root->height + 1;
    while (index > data_cache_radix_tree_maxindex(height))
        height++;

    if (root->rnode == NULL) 
    {
        root->height = height;
        tree_info("root->rnode == NULL, root->height %d\n", root->height);
        goto out;
    }

    do 
    {
        if (!(node = data_cache_radix_tree_node_alloc(root,index)))
            return -ENOMEM;

        /* Increase the height.  */
        node->slots[0] = root->rnode;

        /* Propagate the aggregated tag info into the new root */
        for (tag = 0; tag < CACHE_RADIX_TREE_MAX_TAGS_DATA; tag++) 
        {
            if (data_root_tag_get(root, tag))
                data_tag_set(node, tag, 0);
        }

        node->count = 1;
        node->hot_flag = 1;
        node->hit_hot_count = 1;
        root->rnode = node;
        root->height++;
        tree_info("root->height %d\n", root->height);
    } 
    while (height > root->height);
out:
    return 0;
}


static inline void data_cache_radix_tree_shrink(
                                struct data_cache_radix_tree_root *root)
{
    /* try to shrink tree height */
    while (root->height > 0 &&
            root->rnode->count == 1 &&
            root->rnode->slots[0]) 
    {
        struct data_cache_radix_tree_node *to_free = root->rnode;

        root->rnode = to_free->slots[0];
        root->height--;
        /* must only free zeroed nodes into the slab */
        data_tag_clear(to_free, 0, 0);
        data_tag_clear(to_free, 1, 0);
        to_free->slots[0] = NULL;
        to_free->count = 0;
        data_cache_radix_tree_node_free(root, to_free);
    }
}


void *data_cache_radix_tree_tag_clear(struct data_cache_radix_tree_root *root,
                                      unsigned long index, unsigned int tag)
{
    struct data_cache_radix_tree_path path[DATA_CACHE_RADIX_TREE_MAX_PATH], *pathp = path;
    struct data_cache_radix_tree_node *slot = NULL;
    unsigned int height, shift;

    height = root->height;
    if (index > data_cache_radix_tree_maxindex(height))
        goto out;

    shift = (height - 1) * DATA_CACHE_RADIX_TREE_MAP_SHIFT;
    pathp->node = NULL;
    slot = root->rnode;

    while (height > 0) 
    {
        int offset;

        if (slot == NULL)
            goto out;

        offset = (index >> shift) & DATA_CACHE_RADIX_TREE_MAP_MASK;
        pathp[1].offset = offset;
        pathp[1].node = slot;
        slot = slot->slots[offset];
        pathp++;
        shift -= DATA_CACHE_RADIX_TREE_MAP_SHIFT;
        height--;
    }

    if (slot == NULL)
        goto out;

    while (pathp->node) 
    {
        if (!data_tag_get(pathp->node, tag, pathp->offset))
            goto out;
        data_tag_clear(pathp->node, tag, pathp->offset);
        if (data_any_tag_set(pathp->node, tag))
            goto out;
        pathp--;
    }

    /* clear the root's tag bit */
    if (data_root_tag_get(root, tag))
        data_root_tag_clear(root, tag);

out:
    return slot;
}


struct data_cache_radix_tree_node *insert_cache_data_in_tree(
                        struct data_cache_radix_tree_root *root,
                        unsigned long index, void *item)
{
    struct data_cache_radix_tree_node *node = NULL;
    struct data_cache_radix_tree_node *slot;
    unsigned int height, shift;
    int offset;
    int error;
    tree_info("index %d, data_cache_radix_tree_maxindex(root->height) %d\n",
              index, data_cache_radix_tree_maxindex(root->height));
    if (index >= data_cache_radix_tree_maxindex(root->height)) 
    {
        error = data_cache_radix_tree_extend(root, index);
        if (error)
        {
            tree_info("tree_extend return error = %d\n", error);
            return NULL;
        }
    }

    slot = root->rnode;
    height = root->height;
    shift = (height - 1) * DATA_CACHE_RADIX_TREE_MAP_SHIFT;
    tree_info("height: %d, shift: %d\n", height, shift);
    offset = 0;                     /* uninitialised var warning */
    while (height > 0) 
    {
        if (slot == NULL) 
        {
            /* Have to add a child node.  */
            if (!(slot = data_cache_radix_tree_node_alloc(root, index)))
            {
                tree_info("node_alloc failed, no memory\n");
                return NULL;
            }
            if (node) 
            {
                node->slots[offset] = slot;
                node->count++;
                node->hot_flag++;
            } 
            else
            {
                root->rnode = slot;
            }
        }
        offset = (index >> shift) & DATA_CACHE_RADIX_TREE_MAP_MASK;
        node = slot;
        slot = node->slots[offset];
        tree_info("slot: %p\n", slot);
        shift -= DATA_CACHE_RADIX_TREE_MAP_SHIFT;
        //node->lba=index;
        height--;
    }

    if (node) 
    {
        tree_info("cache_insert->start_tv_sec %d, start_tv_usec %d \n",
                node->start_tv_sec,node->start_tv_usec);
        node->count++;
        node->hit_hot_count++;
        node->hot_flag++;
        node->slots[offset] = item;
        BUG_ON(data_tag_get(node, 0, offset));
        BUG_ON(data_tag_get(node, 1, offset));
    } 
    else tree_info("tree_wrong_test\n");
    return node;
}


void *delete_node_in_tree(struct data_cache_radix_tree_root *root, 
                          unsigned long index)
{
    struct data_cache_radix_tree_path path[DATA_CACHE_RADIX_TREE_MAX_PATH + 1],*pathp = path;
    struct data_cache_radix_tree_node *slot = NULL;
    struct data_cache_radix_tree_node *to_free;
    unsigned int height, shift;	
    int tag;
    int offset;
    height = root->height;	
    tree_info("height is %d index is %d \n",height,index);
    if (index >= data_cache_radix_tree_maxindex(height))
        goto out;
    slot = root->rnode;
	if(slot) tree_info("slot_lba is %d \n",slot->lba);
    if(height == 0 && root->rnode) 
    {
        data_root_tag_clear_all(root);
        root->rnode = NULL;
        goto out;
    }

    shift = (height - 1) * DATA_CACHE_RADIX_TREE_MAP_SHIFT;
    pathp->node = NULL;

    do 
    {
        if (slot == NULL)
            goto out;

        pathp++;
        offset = (index >> shift) & DATA_CACHE_RADIX_TREE_MAP_MASK;
        pathp->offset = offset;
        pathp->node = slot;
        slot = slot->slots[offset];
        tree_info("slot: %p\n", slot);
        shift -= DATA_CACHE_RADIX_TREE_MAP_SHIFT;
        height--;
    } while (height > 1);

    if (slot == NULL)
        goto out;
    tree_info("last slot: %p\n", slot);
    slot = NULL;
    /*
     * Clear all tags associated with the just-deleted item
     */
    for (tag = 0; tag < CACHE_RADIX_TREE_MAX_TAGS_DATA; tag++)
    {
        if (data_tag_get(pathp->node, tag, pathp->offset))
            data_cache_radix_tree_tag_clear(root, index, tag);
    }
    to_free = NULL;
    /* Now free the nodes we do not need anymore */
    while (pathp->node) 
    {
        pathp->node->slots[pathp->offset] = NULL;
        pathp->node->count--;
        if(to_free)
        {
            tree_info("to_free->lba %d, index %d\n", to_free->lba, index);
            data_cache_radix_tree_node_free(root, to_free);
        }
        if (pathp->node->count) 
        {
            if (pathp->node == root->rnode)//the most important in this function
                data_cache_radix_tree_shrink(root);
            goto out;//如果count不为0，则在此退出
        }

        /* Node with zero slots in use so free it */
        to_free = pathp->node;
        pathp--;
    }
    data_root_tag_clear_all(root);
    root->height = 0;
    root->rnode = NULL;
    if(to_free)
    {
        tree_info("to_free->lba is %d index is %d \n",to_free->lba,index);
        data_cache_radix_tree_node_free(root, to_free);
    }
out:
    return NULL;
}



struct data_cache_radix_tree_root *data_cache_radix_tree_init(
                                struct data_cache_radix_tree_root *root,
                                int devs)
{
    if(!root)
        root = kmalloc(sizeof(struct data_cache_radix_tree_root), GFP_KERNEL);
    memset(root, 0, (sizeof(struct data_cache_radix_tree_root)));
    data_cache_radix_tree_node_cachep = kmem_cache_create("data_cache_radix_tree_node",
            sizeof(struct data_cache_radix_tree_node), 0,
            SLAB_PANIC, data_cache_radix_tree_node_ctor);
    tree_info("start!\n");
    if(data_cache_radix_tree_node_cachep)
    {
        tree_info("*****data_cache_radix_tree_node_cachep is not NULL*****\n");
    }
    data_cache_radix_tree_init_maxindex();
    spin_lock_init(&sc_count_lock);

    INIT_LIST_HEAD(&root->for_free_list_head); 
    spin_lock_init(&root->for_free_list_lock); 
    atomic_set(&root->total_node, 0);

    INIT_LIST_HEAD(&root->for_vcd_free_list_head);
    spin_lock_init(&root->for_vcd_free_list_lock);
    atomic_set(&root->total_vcd, 0);
    return root;
    //hotcpu_notifier(cache_radix_tree_callback, 0);
}


void data_cache_radix_tree_destroy(struct data_cache_radix_tree_root *root,
        int disks)
{	
    tree_info("****data_cache_radix_tree_destory begin****\n");

    struct data_cache_radix_tree_node *node;
    struct vdisk_cache_data *vcd;
    int i, j;
    spin_lock(&root->for_free_list_lock); 
    while(!list_empty_careful(&root->for_free_list_head))
    {
        node = list_first_entry(&root->for_free_list_head,
                struct data_cache_radix_tree_node, 
                for_free_list);
        if(node)
        {
            list_del_init(&node->for_free_list);
            /*
            for(i = 0; i < 64; i++)
            {
                if((vcd = node->slots[i]) != NULL)
                {
                    for(j = 0; j < disks; j++)
                    {
                        if(vcd->dev[j].page != NULL && 
                          (vcd->dev[j].fread == 1 || vcd->dev[j].wflags == 1))
                        {
                            tree_info("kfree page %lu %p\n",
                                    vcd->dev[j].sector,
                                    vcd->dev[j].page);
                            __free_page(&vcd->dev[j].page);
                            vcd->dev[j].page = NULL;
                        }
                    }
                    tree_info("kfree vdisk_cache_data %lu, %p\n",
                            vcd->lba_align, vcd);
                    kfree(vcd);
                }
                node->slots[i] = NULL;
            }
            atomic_dec(&root->total_node);
            tree_info("kmem_cache_free tree_node %lu, %p, count: %d\n",
                             node->lba, node, 
                             atomic_read(&root->total_node));
            */
            
            atomic_inc(&root->total_node);
            tree_info("kmem_cache_free %p, alloc_radix_nodes: %d\n",
                    node,
                    atomic_read(&root->total_node));

            kmem_cache_free(data_cache_radix_tree_node_cachep, node);
        }
        else 
            break;
    }
    spin_unlock(&root->for_free_list_lock); 

    spin_lock(&root->for_vcd_free_list_lock);
    while(!list_empty_careful(&root->for_vcd_free_list_head))
    {
        vcd = list_first_entry(&root->for_vcd_free_list_head,
                struct vdisk_cache_data, 
                for_free_list);
        if(vcd)
        {
            list_del_init(&vcd->for_free_list);
            for(j = 0; j < disks; j++)
            {
                if(vcd->dev[j].page != NULL) 
                {
                    tree_info("kfree page %lu %p\n",
                            vcd->dev[j].sector,
                            vcd->dev[j].page);
                    __free_page(&vcd->dev[j].page);
                    vcd->dev[j].page = NULL;
                }
            }
            atomic_dec(&root->total_vcd);
            tree_info("kfree vdisk_cache_data %lu, %p, alloc_vcds: %d\n",
                    vcd->lba_align, vcd,
                    atomic_read(&root->total_vcd));
            kfree(vcd);
        }
        else 
            break;
    }
    spin_unlock(&root->for_vcd_free_list_lock);

    kmem_cache_destroy(data_cache_radix_tree_node_cachep);
    printk("****data_cache_radix_tree_destory end****\n");
}


