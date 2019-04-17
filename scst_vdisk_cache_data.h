/*
 *  write by yw_raid,
 *  use the static to avoid conflict with kernel tree
 *  1.lru list operation
 *  2.modify __maxindex()`s return type to unsigned long long
 *  3.ignore type conversion for unsigned long long to unsigned long
 *  4.modify cache_radix_tree_maxindex()`s return type to unsigned long long
 *  5.max_path is 0~11,there is a array to record the conversion for 
 *    max_index and height.in fact 0~6 is enough, this point should be
 *    discussed.
 */

#include <linux/sched.h>
#include <linux/preempt.h>
#include <linux/types.h>
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
#include <asm/atomic.h>


#include <linux/kthread.h>
#include <linux/async_tx.h>
#include <linux/async.h>
#include <linux/seq_file.h>
#include <linux/cpu.h>
#include <linux/slab.h>
#include <linux/ratelimit.h>
#include <linux/nodemask.h>
#include <linux/flex_array.h>
//#include <linux/sched/signal.h>
#include <linux/timer.h>
#include <linux/init.h>

#include <trace/events/block.h>

#include <linux/time.h>
#include <linux/timex.h>
#include <linux/rtc.h>



#ifndef PAGE_SHIFT_DATA
#define PAGE_SHIFT_DATA 12
#endif
#ifndef SECTOR_SHIFT_DATA
#define SECTOR_SHIFT_DATA  9
#endif
#define HOT_COLD_GROUP_NUM 3


#define CACHE_RADIX_TREE_MAP_SHIFT 6
#define BITS_PER_LONG_LEN 32
#define CACHE_RADIX_TREE_MAP_SIZE	(1UL << CACHE_RADIX_TREE_MAP_SHIFT)
#define CACHE_RADIX_TREE_MAP_MASK	(CACHE_RADIX_TREE_MAP_SIZE-1)
#define CACHE_RADIX_TREE_TAG_LONGS	\
    ((CACHE_RADIX_TREE_MAP_SIZE + BITS_PER_LONG_LEN - 1) / BITS_PER_LONG_LEN)
#define CACHE_RADIX_TREE_INDEX_BITS  (8 * sizeof(unsigned long)) //8 is CHAR_BIT
#define CACHE_RADIX_TREE_MAX_PATH (CACHE_RADIX_TREE_INDEX_BITS/CACHE_RADIX_TREE_MAP_SHIFT + 2) //max is 12
#define ARRAY_SIZE_S(x) (sizeof(x) / sizeof((x)[0]))


#define SECTS_OF_PAGE_DATA  (PAGE_SIZE >> SECTOR_SHIFT_DATA)

#define CACHE_RADIX_TREE_MAX_TAGS_DATA 2

#define DATA_INVALID    4 
#define DATA_UPTODATE   5
#define DATA_DIRTY      6
#define DATA_LOCKED     7
#define DATA_WPREF      8

#define CACHE_PER_NODE_SHIFT 6


//  CACHE_CAPACITY_SHIFT_DATA   23
//  CACHE_CAPACITY_DATA         1 << 23 = 8388608
//  MAX_COUNT_OF_CACHE_DATA     8388608 >> 12 = 2048
//  2048 * (3 * 4k) = 24M
//
//  CACHE_CAPACITY_SHIFT_DATA   29
//  CACHE_CAPACITY_DATA         1 << 29 = 536870912
//  MAX_COUNT_OF_CACHE_DATA     131072
//  131072 * (3 * 4k) = 1536M
//
// 23 ---- 24M
// 24 ---- 48M
// 25 ---- 96M
// 26 ---- 192M
// 27 ---- 384M
// 28 ---- 768M
// 29 ---- 1536M
#define CACHE_CAPACITY_SHIFT_DATA 27 //write cache capacity
#define CACHE_CAPACITY_DATA  (1UL << CACHE_CAPACITY_SHIFT_DATA)
#define MAX_COUNT_OF_CACHE_DATA (CACHE_CAPACITY_DATA >> PAGE_SHIFT_DATA)
#define MAX_COUNT_OF_READ (MAX_COUNT_OF_CACHE_DATA >> 1)

//cache的容量计算还是以node为单位


struct vdisk_cache_data
{
    unsigned long       lba_align;
    struct list_head    lru;
    struct list_head    for_free_list;
    void                *vfd;
    atomic_t            dirty_pages;
    atomic_t            filling_pages;
    void                *vcd;
#define VCD_IN_DIRTY                0
#define VCD_IN_REPLACE              1
#define VCD_IN_CLEAN                2
#define VCD_WITH_REPLACE_PAGES      3
#define VCD_IS_FLUSING              4
#define VCD_IS_FLUSING_ALL          5
#define VCD_IS_FILLING              6
    unsigned long       flag;


    struct r5cdev {
        spinlock_t      lock;
        sector_t	    sector;	
        struct page	    *page;
        struct vdisk_cache_data *vcd;
        unsigned int    length;
        unsigned int    offset;

        // int             dirty;
        // int             flush;
#define VCD_PAGE_DIRTY          0
#define VCD_PAGE_FLUSHING_ALL   1
#define VCD_PAGE_FLUSHING       2
#define VCD_PAGE_FILLING        3
        unsigned long   flag;


        struct page     *replace_page;
        unsigned int    replace_length;
        unsigned int    replace_offset;
        // struct block_device *rdev;
    } dev[1]; 
};

struct data_cache_radix_tree_root {
    unsigned int		height;
    gfp_t			gfp_mask;
    struct data_cache_radix_tree_node	*rnode;
    struct list_head    for_free_list_head;
    spinlock_t          for_free_list_lock;
    atomic_t            total_node;
    
    struct list_head    for_vcd_free_list_head;
    spinlock_t          for_vcd_free_list_lock;
    atomic_t            total_vcd;
};

struct blockio_cache_data_to_copy {
    struct vdisk_cache_data *cache_to_copy;
    struct list_head read_cache_list_entry;
};

#define DATA_CACHE_RADIX_TREE_INIT(mask)	{					\
    .height = 0,							\
    .gfp_mask = (mask),						\
    .rnode = NULL,							\
}

#define DATA_CACHE_RADIX_TREE(name, mask) \
    struct data_cache_radix_tree_root name = DATA_CACHE_RADIX_TREE_INIT(mask)

#define INIT_DATA_CACHE_RADIX_TREE(root, mask)					\
    do {									\
        (root)->height = 0;						\
        (root)->gfp_mask = (mask);					\
        (root)->rnode = NULL;						\
    } while (0);     

#define DATA_CACHE_RADIX_TREE_MAP_SHIFT 6
#define DATA_BITS_PER_LONG_LEN 32
#define DATA_CACHE_RADIX_TREE_MAP_SIZE	(1UL << DATA_CACHE_RADIX_TREE_MAP_SHIFT)
#define DATA_CACHE_RADIX_TREE_MAP_MASK	(DATA_CACHE_RADIX_TREE_MAP_SIZE-1)
#define DATA_CACHE_RADIX_TREE_TAG_LONGS	\
    ((DATA_CACHE_RADIX_TREE_MAP_SIZE + DATA_BITS_PER_LONG_LEN - 1) / DATA_BITS_PER_LONG_LEN)
#define DATA_CACHE_RADIX_TREE_INDEX_BITS  (8 * sizeof(unsigned long)) //8 is CHAR_BIT
#define DATA_CACHE_RADIX_TREE_MAX_PATH (DATA_CACHE_RADIX_TREE_INDEX_BITS/DATA_CACHE_RADIX_TREE_MAP_SHIFT + 2) //max is 12
#define ARRAY_SIZE_S(x) (sizeof(x) / sizeof((x)[0]))


struct data_cache_radix_tree_node {
    unsigned long   lba;
    unsigned int	height;
    int	            count;
    int             hit_hot_count;
    int             start_tv_sec;
    int             start_tv_usec;
    int             local_flag;
    void		*slots[DATA_CACHE_RADIX_TREE_MAP_SIZE];//每个slot存放一个page信息
    unsigned long	tags[CACHE_RADIX_TREE_MAX_TAGS_DATA][DATA_CACHE_RADIX_TREE_TAG_LONGS];
	struct list_head flush_lru_list_entry;
    struct list_head lru_list_entry;
    struct list_head cold_list_entry;
    struct list_head cold_cache_entry_one;
	struct list_head cold_cache_entry_two;
	struct list_head cold_cache_entry_three;
	struct list_head read_list_entry;
	struct list_head for_free_list;
	int             once_delete_flag;
    int             hot_flag;
    int             hot[HOT_COLD_GROUP_NUM];  
    int             hot_cold_cache[HOT_COLD_GROUP_NUM]; 
    int             flag_delete;
	int             flush_delete;
    int             hot_count;
	int             read_flag;
	int             write_flag;
	int             exist_flag;
	int             noexist_flag;
	int             qsort_locate[16];
	int             delete_hot_flag[HOT_COLD_GROUP_NUM];
	int             cold_hot_flag;
	int             need_delete_flag;
};

struct data_cache_radix_tree_path {
    struct data_cache_radix_tree_node *node;
    int offset;
};

static unsigned long  data_height_to_maxindex[DATA_CACHE_RADIX_TREE_MAX_PATH];
static unsigned long  flush_height_to_maxindex[DATA_CACHE_RADIX_TREE_MAX_PATH];

static struct kmem_cache *data_cache_radix_tree_node_cachep;
extern void insert_node_in_lrulist(struct list_head *lru_list, struct list_head *lru_list_head);
extern void delete_node_in_lrulist(struct list_head *lru_list_head);
extern void move_node_in_lrulist(struct list_head *list, struct list_head *lru_list_head_2);
extern int is_cache_full_data(atomic_t count);
extern struct data_cache_radix_tree_root *data_cache_radix_tree_init(struct data_cache_radix_tree_root *root, int devs);

extern struct data_cache_radix_tree_node *lookup_data_node_in_tree(struct data_cache_radix_tree_root *root,  unsigned long index);
 extern void *delete_node_in_tree(struct data_cache_radix_tree_root *root, unsigned long index);
extern struct data_cache_radix_tree_node *insert_cache_data_in_tree(struct data_cache_radix_tree_root *root,
        unsigned long index, void *item);
extern  void data_cache_radix_tree_node_free(struct data_cache_radix_tree_root *root, struct data_cache_radix_tree_node *node);
extern struct vdisk_cache_data *insert_item_in_readcache(struct vdisk_cache_data *vdisk_cache_insert,int item,int disks,int logical_sector);
extern struct vdisk_cache_data *insert_item_in_cache(struct vdisk_cache_data *vdisk_cache_insert,int item,int disks,int logical_sector,struct page *page,int rw);
extern struct vdisk_cache_data *alloc_data_cache_struct(struct data_cache_radix_tree_root *root, sector_t lba_align,int devs);

extern void  data_cache_radix_tree_destroy(struct data_cache_radix_tree_root *root, int disks);

