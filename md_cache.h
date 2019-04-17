
#ifndef _SHMETA_H
#define _SHMETA_H
#include <linux/raid/xor.h>
#include <linux/dmaengine.h>
#include "md.h"
#include "bplustree.h"
//#include "scst_vdisk_cache_data.h"


#define PAGE_BITS (PAGE_SIZE << 3)
#define PAGE_BIT_SHIFT (PAGE_SHIFT + 3)

#define BITSPERWORD 32  
#define SHIFT 5  
#define MASK 0x1F  
#define STRIPE_SECTORS_MAKE		8
#define MD_NR_STRIPE_HASH_LOCKS 8

#define BITMAP_SPACE 512

#define BITMAP_SHIFT 10
//#define READ_BITMAP_PAGE_NUM 1024
#define READ_BITMAP_PAGE_NUM 102400

#define NUM_INT_IN_PAGE 1024
#define CACHE_HASH_LOCKS_MASK (MD_NR_STRIPE_HASH_LOCKS - 1)
#define PAGE_NUM_CACHE 1024*32

#define MD_CHUNK_LIST_NUM 8
#define CACHE_STRIPE_SIZE		PAGE_SIZE
#define CACHE_STRIPE_SHIFT		(CACHE_STRIPE_SIZE - 9)
#define CACHE_STRIPE_SECTORS		(CACHE_STRIPE_SIZE>>9)
#define CACHE_NR_HASH			(PAGE_SIZE / sizeof(struct hlist_head))
#define CACHE_HASH_MASK		(CACHE_NR_HASH - 1)
#define SM_HASH_LOCKS           8
#define SM_SHIFT                (PAGE_SHIFT - 3)
#define SM_HASH_LOCKS_MASK      (SM_HASH_LOCKS - 1)
#define SM_SECTORS              8
#define CHUNK_SHIFT             10


#define SM_SHIFT                       3 //  (PAGE_SHIFT - 3)
#define DEV_META_BLANK                  -1

#define SM_INACTIVE_LIST_NUM            8

#define SM_FLUSH_HASH                   128
typedef unsigned long stripe_sec;
typedef sector_t block_sec;
typedef unsigned char disk_no;

struct update_meta {
    stripe_sec new_sector;
    block_sec logical_sector;
    bool another_wait;
    struct list_head lru;
};


struct nhlist_head {
    struct nhlist_node* head;
    struct nhlist_node* tail;
};


struct nhlist_node {
    struct nhlist_node* next;
    struct nhlist_node* pre;
    block_sec logical_sector;
    // int count;
};


enum{
    VFD_VALID = 1,
    VFD_FLUSH_ALL = 2,
    VFD_FROM_RECLAIM = 33,
};
#define SM_FLAGS_NUM        25

enum{
    // stripe state
    SM_WRITTEN = 0,
    SM_DYNAMIC,
    SM_DIRTY,
    SM_DYNAMIC_CHANGED,
    SM_LOCKED,

    // which list the stripe is in
    SM_BLANK,
    SM_IN_PARTICLE,
    SM_IN_RECOMBINE,
    SM_IN_INACTIVE,
    SM_IN_RETRY,
    SM_RECOMBINING,
    SM_IN_FLUSH,
    SM_IN_LOCKED,
    SM_DEAD,
    SM_FREE,
    
    SM_IN_RECLAIM_LIST,

    SM_RECLAIMING,

    SM_HANDLE_BIO,
    SM_UPDATE_WAIT_RECLAIM,

    SM_OTHER_LOADING_META_NOW,
};

struct shmeta {
    stripe_sec sector;           // 32 bit
    stripe_sec lba_align;
    struct hlist_node hash;         // 2 * point
    struct list_head lru;           // 2 * point
    unsigned short times;           // 16 bit
    unsigned long flags;
    disk_no pdisk;
    void* us;
    void* vfd;
    struct devmeta {
        sector_t lba;           // 64 bit
        sector_t bi_sector;     // 64 bit
        unsigned long lso;          // 32 bit
        unsigned int psn;
    }dmeta[1];
};


enum{
    // about update
    MT_IN_UPDATE = 0,
    MT_UPDATE_ALREADY,
    MT_UPDATE_BEGIN,
    MT_WAIT_fOR_UDT,

    // about recombine
    MT_FORCE_RECOMBINE,
    MT_RECOMBINING,
    MT_RECOMBINED,

    // about flush
    MT_FLUSH_FORCE,
    MT_FLUSHING_METADATA,
    MT_FLUSHED_METADATA,

    // about reclaim
    MT_FORCE_RECLAIM,
    MT_RECLAIMING,
    MT_RECLAIMED,
    
    MT_UPDATED,
    MT_UPDATING,

    FLASH_IO_TH_NOW,

    MT_IN_FLUSH_METADATA,
    MT_IN_FLUSH_RECLAIM,

    MT_READING,
    MT_READED,

    MT_RECLAIM_WAIT_UPDATE,
    MT_UPDATE_WAIT_RECLAIM,
    MT_WAIT_FOR_BLANK,
    MT_GET_A_BLANK,

    NO_SM_TO_RECLAIM,

    MT_WILL_STOP,
    MT_FLUSH_ALL_PARTICLE,
};

#define RETURN_VFD_NUM 4

struct updating_shmeta {
    int remaining_blocks;
    int type;
    int pdisk;
    int datanum;
    stripe_sec sector;
    stripe_sec align;
    struct vdisk_flush_data *vfd;
    struct shmeta *sm;
    struct list_head lru;
};

struct r5meta {
    struct cache_tree_data *ctd; 
    void *bitmap;
	void *mtd;

    // parameter about raid scale
    unsigned int disks;
    unsigned int max_degrade;
    unsigned int devnum;
    unsigned int max_shmeta;
    unsigned long flags;

    // whole hash table
    struct hlist_head   *hashtbl;
    struct list_head    *flush_list;
    int                 *hash_list_size;
    int                 *hashtbl_count;

    // shmeta's lists
    struct list_head inactive_list[SM_INACTIVE_LIST_NUM + 1]; 
    struct list_head blank_list;
    struct list_head free_list;
    struct list_head particle_list;
    struct list_head recombine_list;
    struct list_head retry_list;
    struct list_head locked_list;

    struct vdisk_flush_data *recombined_vfd_return[RETURN_VFD_NUM];
    struct updating_shmeta *full_dynamic_sm_wait_handle;

    // blank shmeta in update bio shmeta
    struct shmeta* blank_sm_avail;
    spinlock_t blank_sm_avail_lock;

    // blank page
    int blank_size_in_page;

    // locks
    spinlock_t inactive_list_lock;
    spinlock_t particle_list_lock;
    spinlock_t blank_list_lock;
    spinlock_t free_list_lock;
    spinlock_t hashtbl_lock;
    spinlock_t retry_list_lock;
    spinlock_t flush_list_lock;
    spinlock_t recombine_list_lock;
    spinlock_t meta_page_lock;
    spinlock_t counters_lock;
    spinlock_t locked_list_lock;

    // shmeta's lists counters
    atomic_t active_sm;
    atomic_t cached_inactive_shmeta;
    atomic_t empty_inactive_list_nr;
    atomic_t cached_particle_shmeta;
    atomic_t cached_recombined_shmeta;
    atomic_t cached_blank_shmeta;
    atomic_t cached_retry_shmeta;
    atomic_t cached_free_shmeta;
    atomic_t cached_flush_shmeta;
    atomic_t cached_locked_shmeta;

    // threads
    atomic_t  updating;
    struct md_thread *flush_thread;
    struct md_thread *update_thread;
    struct md_thread *reclaim_thread;

    // for update bio
    wait_queue_head_t wait_for_flush_queue;
    wait_queue_head_t wait_for_update_finish;
    wait_queue_head_t wait_for_blank_shmeta;
    wait_queue_head_t wait_for_reclaim_queue;

    // about reclaim
    struct list_head* reclaim_lists;
    atomic_t reclaim_lists_count;
    spinlock_t reclaim_lists_lock;
    
    // atomic_t owned;
    int updating_vfd_blocks;
    int updating_vfds;
    int alloc_updating_shmeta;
    int max_alloc_updating_shmeta;

    // about updating_shmeta
    struct list_head updating_shmeta_list;
    struct list_head updated_shmeta_list;
    spinlock_t updating_shmeta_list_lock;
    spinlock_t updated_shmeta_list_lock;
    spinlock_t updating_vfd_blocks_lock;
    spinlock_t update_shmeta_lock;
   
    // devices
    struct block_device **md_bds;

    // about READ 
    struct md_thread *read_thread;
    wait_queue_head_t wait_for_read_queue;
    struct list_head read_list;
    struct list_head readed_list;
    spinlock_t read_list_lock;
    spinlock_t readed_list_lock;
    
    // about bplus_tree
    struct bplus_tree *blank_bptree;
    struct bplus_tree *reclaim_bptree;
    atomic_t blank_in_bptree;
    atomic_t reclaim_in_bptree;
    spinlock_t blank_bptree_lock;
    spinlock_t reclaim_bptree_lock;

    int bplus_pages_remain_each;
    atomic_t save_stripe_sectors_page;
    wait_queue_head_t wait_for_save_sectors_finish;

    wait_queue_head_t wait_for_load_a_block_finish;
};
  

extern void setup_shmeta(struct cache_tree_data* cdata, int max_shmeta);
extern void r5meta_stop(struct r5meta* meta);
extern bool check_flag(int flag, unsigned short * shflag);
extern void clear_flag(int flag, unsigned short * shflag);
extern void set_flag(int flag, unsigned short * shflag);
extern sector_t get_new_logical_address(struct cache_tree_data *ctd, 
                                 sector_t logical_address);

extern struct vdisk_flush_data *get_a_vfd(struct mddev *mddev);

extern void return_vfd(struct mddev *mddev, struct vdisk_flush_data *vfd);

// md_cache about
struct bio_test
{
    struct list_head	lru_list;	
    struct list_head	alloc_lru;	
	struct hlist_node	hash;
    sector_t            lba;
    int                 flag;
    int                 dirty_pages;
    struct r5plug 
    {
        spinlock_t      lock;
        sector_t        sector; 
        struct page	    *page;
        int             valid;
        unsigned int    length;
        unsigned int    offset;
        struct bio_vec  *bv;
    } dev[1]; 
};



struct cache_tree_data {
    struct mddev                        *mdd;
	struct block_device                 *bd;
	struct r5meta                       *cache_r5meta;
    sector_t                            remaining_sectors;

#define     MDC_FLUSH_VCDS_FORCE        1
    unsigned long                       _flags;

    // mdc_make_request function lock
    wait_queue_head_t	                mdc_make_request_queue;

    // radix tree
    spinlock_t                          radix_tree_lock_data; 
    struct data_cache_radix_tree_root   *data_cache_tree_root;


    //**********************************************
    //* write about
    // bio_test
    atomic_t                            bio_test_count;
    struct list_head                    alloc_bio_test_list;
    spinlock_t		                    alloc_bio_test_list_lock;

    wait_queue_head_t	                bio_test_queue;
	struct list_head                    bio_test_list;
    spinlock_t		                    bio_test_lock;
	// bio_test hash table
    struct hlist_head	                *bt_hashtbl;
	spinlock_t                          bio_test_hash_lock[CACHE_HASH_MASK + 1];


    // plug 
    struct list_head                    plug_list;
    atomic_t                            plug_list_count;
    spinlock_t                          plug_list_lock;




    // total count
    atomic_t                            vdisk_cache_data_count;
    // replace vdisk cache data 
    atomic_t                            replace_vdisk_cache_data_count;
    struct list_head                    replace_vdisk_cache_data_list;
    spinlock_t                          replace_vdisk_cache_data_list_lock;
 
    // dirty vdisk cache data
    atomic_t                            dirty_vdisk_cache_data_count;
    struct list_head                    dirty_vdisk_cache_data_list;
    spinlock_t                          dirty_vdisk_cache_data_list_lock;
 
    // clean vdisk cache data
    atomic_t                            clean_vdisk_cache_data_count;
    struct list_head                    clean_vdisk_cache_data_list;
    spinlock_t                          clean_vdisk_cache_data_list_lock;
  
    // vdisk flush data 
    struct list_head                    vdisk_flush_data_list;
    spinlock_t                          vdisk_flush_data_list_lock;
    atomic_t                            vdisk_flush_data_count;
  
    // vdisk flush data 
    struct list_head                    reclaim_vfds_list;
    spinlock_t                          reclaim_vfds_list_lock;
    atomic_t                            reclaim_vfds_count;
     
    struct list_head                    alloc_vdisk_flush_data_list;
    spinlock_t		                    alloc_vdisk_flush_data_list_lock;


    // flush about
    wait_queue_head_t	                wait_for_vcds_flush_queue;


    wait_queue_head_t	                wait_for_bt_read_page_queue;

    //**********************************************
    //* read about
    // bio read cache 
    struct list_head                    bio_read_cache_list;
    atomic_t                            bio_read_cache_count;
    atomic_t                            bio_read_cache_list_count;
    spinlock_t                          bio_read_cache_list_lock;

    // reading list
    struct list_head                    reading_list;
    atomic_t                            reading_count;
    spinlock_t                          reading_list_lock;

    // add read page about
    struct list_head                    add_read_page_list;
    atomic_t                            add_read_page_count;
    spinlock_t                          add_read_page_list_lock;

    struct list_head                    alloc_bio_read_cache_list;
    spinlock_t                          alloc_bio_read_cache_list_lock;

    // thread
	struct md_thread	                *bio_test_unplug_thread;
	struct md_thread	                *vdisk_cache_data_flush_thread;
	struct md_thread	                *read_thread;
	struct md_thread	                *add_read_page_to_radix_tree_thread;


    //**********************************************
    // flush all about
    int                                 will_free;
    int                                 in_flush_all;
    struct list_head                    flush_all_vfds_list;
    spinlock_t                          flush_all_vfds_list_lock;
    atomic_t                            flush_all_vfds_count;
    atomic_t                            flush_all_vfds_pages;
    wait_queue_head_t	                wait_for_flush_io_queue;
    struct task_struct                  *flush_all_thread;

};


struct bio_read_cache
{
	struct bio	        *bi;
    sector_t            sector;
    sector_t            new_logical;
	struct list_head    lru;	
    struct list_head	alloc_lru;	
    int                 valid;
	int                 bio_num;
    struct page         *page;
    bool                bio_page;
    
    unsigned int    length;
    unsigned int    offset;
    
    struct vdisk_cache_data *vcd;
    int             vcd_idx;
};


struct raid5_per
{
    char *name;
    struct list_head list;
    void (*flush_cache_io)(struct mddev *mddev,struct page *pagg_test,struct block_device *bddev,sector_t logical_sector);
    void (*release_cache_stripe)(struct mddev *mddev,int num);
};


struct vdisk_flush_data
{
    unsigned long lba_align;


    // for recombine, dele later
    // struct list_head dirty_list_entry;



    struct list_head lru;
    struct list_head	alloc_lru;	
    struct r5fdev 
    {
		sector_t	sector;
        unsigned int offset;
        unsigned int length;
		struct page	*page;
        struct r5cdev *cdev;

        int         dirty;
#define VFD_PAGE_DIRTY      0
#define VFD_PAGE_RECLAIM    1
        //unsigned long flag;        

        // struct block_device *rdev;
	} dev[1];
};

#endif

