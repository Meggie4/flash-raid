/*************************************************************************
	> File Name: shmeta.c
	> Author: yms 
	> Mail: meow@meow.com 
	> Created Time: Mon 10 Jul 2017 09:57:35 AM CST
    > Version: 2018/3/1
 ************************************************************************/


#include "metadata.h"
#include "meta_bitmap.h"
#include "scst_vdisk_cache_data.h"
#include "flag.h"

#include <linux/kthread.h>
#include <linux/types.h>
#include <linux/delay.h>



// about bug
//#define bug_handle_stripe_in_particle
//#define PRINT_INFO
//#define DEBUG_RECOMBINE
// #define BUG_READ


#define rc_info(fmt,...)  \
    printk(KERN_ERR rc_fmt(fmt), __LINE__, __func__, ##__VA_ARGS__)

#define rc_err(fmt,...) \
    printk(KERN_ERR rc_fmt_err(fmt), __LINE__, __func__, ##__VA_ARGS__)


static int devnum = 0;

// mddev thread times
#define R5M_RECLAIM_WAKEUP_INTERVAL     (1 * HZ)
#define R5M_FLUSH_WAKEUP_INTERVAL       (5 * HZ)

#define DEV_RECLAIMING                  -2
// max shmetas in kernel
#define SM_MAX_SHMETA                   2048

// min blank shmeta in kernel(reclaim thread concerned)
#define SM_MIN_BLANK_STRIPE             512

// about reclaim(remark reclaim thread start)
#define SM_RECLAIM_START                64 // 16
#define SM_MAX_RECLAIM_LIMIT            256

// about flush metadatas
#define SM_FLUSH_META_LIMIT             256 // 32 // 64
#define SM_FLUSH_META_MIN_LIMIT         32  //64

//#define FLUSH_BLANK_SHMETA              true

// flush hash about
#define SM_FLUSH_HASH_M                 (int)(SM_FLUSH_HASH - 1)
#define FLUSH_HASH(sector)              (int)(((sector >> 3) & SM_FLUSH_HASH_M))

// about nhlist(my hash table)
#define NHLIST_HEAD_INIT(list_head) \
        list_head->head = list_head->tail = NULL
#define NHLIST_NODE_INIT(list_node) \
        list_node->next = list_node->pre = NULL
#define NHlist_empty_careful(list_head)     \
        list_head->head == NULL

#define bpkey(sector)  (sector >> 3)

#define KZALLOC_SM(sm) \
    (sm = kmalloc(sizeof(struct shmeta) + \
                 sizeof(struct devmeta) * (devnum - 1), GFP_KERNEL))

#define CHECK_SM_VALID(sm) \
    ((sm->flags & (~((1UL << SM_FLAGS_NUM) - 1))) == 0)

#define CLEAR_RECLAIM_FLAGS(sm) \
    sm->flags &= 0x00ffff;
/*
 *shmeta about
 */
#define foreach_dev(devmeta, sm, i)\
    for (i = 0,devmeta = &sm->dmeta[0]; i < devnum; i++, devmeta++)

#define CLEAR_BI_SECTOR(sm, i) \
    for (i = 0; i < devnum; i++)  sm->dmeta[i].bi_sector = DEV_META_BLANK;

#define LBA_MASK(sector)\
    ((sector >> 3) << 3)

#define META_HASH_LBA(lba)  (int)(lba % 8)

#define transfer_stripe_sector_to_lba_align(meta, sector) (sector >> 3)
#define transfer_lba_align_to_stripe_sector(meta, sector) (sector << 3)


#define RETURN_VFD(meta, vfd, datanum) \
    {\
        int rfv = 0;\
        for(; rfv < RETURN_VFD_NUM; rfv++)\
        {\
            if(meta->recombined_vfd_return[rfv] != NULL)\
                continue;\
            else\
            {\
                meta->recombined_vfd_return[rfv] = (struct vdisk_flush_data*)(vfd);\
                break;\
            }\
        }\
        if(rfv == RETURN_VFD_NUM) \
            sm_err("recombined_vfd_return no place to put\n"); \
        CHANGE_VFD_BLOCKS(meta, -datanum);\
    }


#define RETURN_FULL_VFD(meta, sm, datanum) \
    {\
        int rfv = 0;\
        for(; rfv < RETURN_VFD_NUM; rfv++)\
        {\
            if(meta->recombined_vfd_return[rfv] != NULL)\
                continue;\
            else\
            {\
                meta->recombined_vfd_return[rfv] = (struct vdisk_flush_data*)(sm->vfd);\
                break;\
            }\
        }\
        if(rfv == RETURN_VFD_NUM) \
            sm_err("recombined_vfd_return no place to put\n"); \
        sm->vfd = NULL;\
        CHANGE_VFD_BLOCKS(meta, -datanum);\
    }


/*
 * update unit about
 */
#define INIT_US(us) \
    {\
        us->sector = DEV_META_BLANK; \
        us->sm = NULL; \
        us->vfd = NULL; \
        us->remaining_blocks = 0; \
    }


#define ADD_US_UPDATED(meta, us) \
    { \
        us->vfd = NULL;\
        spin_lock(&meta->updated_shmeta_list_lock); \
        list_del_init(&us->lru); \
        list_add_tail(&us->lru, &meta->updated_shmeta_list); \
        spin_unlock(&meta->updated_shmeta_list_lock); \
        INIT_US(us); \
    }


#define MOVE_US_UPDATED(meta, us) \
    { \
        spin_lock(&meta->updating_shmeta_list_lock); \
        spin_lock(&meta->updated_shmeta_list_lock); \
        list_del_init(&us->lru); \
        list_add_tail(&us->lru, &meta->updated_shmeta_list); \
        spin_unlock(&meta->updated_shmeta_list_lock); \
        spin_unlock(&meta->updating_shmeta_list_lock); \
        INIT_US(us); \
    }


#define ADD_US_UPDATING(meta, us) \
    { \
        spin_lock(&meta->updating_shmeta_list_lock); \
        list_add_tail(&us->lru, &meta->updating_shmeta_list); \
        spin_unlock(&meta->updating_shmeta_list_lock);\
    }


#define ADD_SM_PARTICLE_WITH_LOCK(meta, sm) \
    { \
        spin_lock(&meta->particle_list_lock); \
        ADD_SM_PARTICLE_WITHOUT_LOCK(meta, sm); \
        spin_unlock(&meta->particle_list_lock); \
    }


#define ADD_SM_RECOMBINE_WITH_LOCK(meta, sm) \
    { \
        spin_lock(&meta->recombine_list_lock); \
        ADD_SM_RECOMBINE_WITHOUT_LOCK(meta, sm); \
        spin_unlock(&meta->recombine_list_lock); \
    }


#define ADD_SM_INVALID_LIST_WITH_LOCK(meta, sm) \
    { \
        spin_lock(&meta->inactive_list_lock); \
        ADD_SM_INVALID_LIST_WITHOUT_LOCK(meta, sm); \
        spin_unlock(&meta->inactive_list_lock); \
    }


#define ADD_SM_RETRY_LIST_WITH_LOCK(meta, sm) \
    { \
        spin_lock(&meta->retry_list_lock); \
        ADD_SM_RETRY_LIST_WITHOUT_LOCK(meta, sm);\
        spin_unlock(&meta->retry_list_lock);\
    }


#define ADD_SM_FREE_LIST_WITH_LOCK(meta, sm) \
    { \
        spin_lock(&meta->free_list_lock); \
        ADD_SM_FREE_LIST_WITHOUT_LOCK(meta, sm);\
        spin_unlock(&meta->free_list_lock);\
    }


#define ADD_SM_FLUSH_LIST_WITH_LOCK(meta, sm, hash) \
    { \
        spin_lock(&meta->flush_list_lock); \
        ADD_SM_FLUSH_LIST_WITHOUT_LOCK(meta, sm, hash); \
        spin_unlock(&meta->flush_list_lock); \
    }


#define DEL_SM_RECLAIM_LIST_WITH_LOCK(meta, sm) \
    { \
        spin_lock(&meta->reclaim_lists_lock); \
        DEL_SM_RECLAIM_LIST_WITHOUT_LOCK(meta, sm); \
        spin_unlock(&meta->reclaim_lists_lock); \
    }


#define DEL_SM_RETRY_LIST_WITH_LOCK(meta, sm) \
    { \
        spin_lock(&meta->retry_list_lock); \
        DEL_SM_RETRY_LIST_WITHOUT_LOCK(meta, sm);\
        spin_unlock(&meta->retry_list_lock); \
    }


#define DEL_SM_INACTIVE_LIST_WITH_LOCK(meta, sm) \
    { \
        spin_lock(&meta->inactive_list_lock); \
        DEL_SM_INACTIVE_LIST_WITHOUT_LOCK(meta, sm);\
        spin_unlock(&meta->inactive_list_lock); \
    }


#define DEL_SM_BLANK_LIST_WITH_LOCK(meta, sm) \
    { \
        spin_lock(&meta->blank_list_lock); \
        DEL_SM_BLANK_LIST_WITHOUT_LOCK(meta, sm); \
        spin_unlock(&meta->blank_list_lock); \
    }


#define DEL_SM_PARTICLE_LIST_WITH_LOCK(meta, sm) \
    { \
        spin_lock(&meta->particle_list_lock); \
        DEL_SM_PARTICLE_LIST_WITHOUT_LOCK(meta, sm); \
        spin_unlock(&meta->particle_list_lock); \
    }


#define DEL_SM_FREE_LIST_WITH_LOCK(meta, sm) \
    { \
        spin_lock(&meta->free_list_lock); \
        DEL_SM_FREE_LIST_WITHOUT_LOCK(meta, sm);\
        spin_unlock(&meta->free_list_lock); \
    }


#define DEL_SM_RECOMBINE_LIST_WITH_LOCK(meta, sm) \
    { \
        spin_lock(&meta->recombine_list_lock); \
        DEL_SM_RECOMBINE_LIST_WITHOUT_LOCK(meta, sm);\
        spin_unlock(&meta->recombine_list_lock); \
    }


#define GET_INACTIVE_LIST_HEAD_SM_WITHOUT_LOCK(meta, sm, hash) \
    { \
        sm = list_first_entry(&meta->inactive_list[hash], \
                                  struct shmeta, lru); \
        if(sm && test_bit(SM_IN_INACTIVE, &sm->flags)) \
            DEL_SM_INACTIVE_LIST_WITHOUT_LOCK(meta, sm) \
        else \
            sm = NULL; \
    }


#define ADD_RU_READ_LIST_WITH_LOCK(meta, ru) \
    {\
        spin_lock(&meta->read_list_lock); \
        list_add(&ru->lru, &meta->read_list); \
        spin_unlock(&meta->read_list_lock);\
    }


struct read_unit{
    sector_t origin_read_adr;
    sector_t new_read_adr;
    struct list_head lru;
};



enum {
    PARTICLE_STATIC = 1,
    PARTICLE_DYNAMIC,
    FULL_STATIC,
    FULL_DYNAMIC,
};


void flush_shmeta(struct r5meta *meta);
bool set_block_invalid(struct r5meta *meta, 
        stripe_sec sh_sector, disk_no psn);
int compute_pdisk(struct r5meta *meta, stripe_sec new_sector);
bool load_blocks_put_cache(struct r5meta *meta, struct shmeta *sm, 
                           unsigned short flag);
struct shmeta *put_full_stripe_to_blank_stripe(struct r5meta *meta, 
                                              struct shmeta *sm, int datanum);

void inline CHANGE_VFD_BLOCKS(struct r5meta *meta, int num)
{
    spin_lock(&meta->updating_vfd_blocks_lock);
    meta->updating_vfd_blocks += num; 
    spin_unlock(&meta->updating_vfd_blocks_lock); 
    if(meta->updating_vfd_blocks > 5) 
        sm_err("updating_vfd_blocks: %d", meta->updating_vfd_blocks);
#ifdef PRINT_INFO
    else
        sm_info("updating_vfd_blocks: %d", meta->updating_vfd_blocks);
#endif
}



static spinlock_t pa_lock;
#ifdef PRINT_INFO
void print_vfd(struct vdisk_flush_data *vfd)
{
    int i = 0;
    sm_info("vfd->lba_align: %lu, %p\n", vfd->lba_align, vfd);
    for(i = 0; i < devnum; ++i)
    {
        sm_info("vfd(%lu %p)[%d]: %ld, off: %d, len: %d, page: %p, dirty: %d\n",
                vfd->lba_align, vfd, i, vfd->dev[i].sector, 
                vfd->dev[i].offset, vfd->dev[i].length, 
                vfd->dev[i].page, vfd->dev[i].dirty);
    }
}


void print_shmeta(struct shmeta *sm)
{
    int i = 0;
    struct vdisk_flush_data *vfd = sm->vfd;
    
    sm_info("===========================================\n");
    
    sm_info("sector %lu, lba_align: %lu, sm: %p, vfd: %p, us: %p\n", 
            sm->sector, sm->lba_align, sm, sm->vfd, sm->us);

    sm_info("sector %lu, times %d, locked: %d, dirty: %d\n", 
            sm->sector, sm->times, 
            test_bit(SM_LOCKED, &sm->flags), 
            test_bit(SM_DIRTY, &sm->flags));

    sm_info("sector: %lu, written: %d, dynamic: %d, blank: %d, flags: %lu\n", 
            sm->sector,
            test_bit(SM_WRITTEN, &sm->flags), 
            test_bit(SM_DYNAMIC, &sm->flags), 
            test_bit(SM_BLANK, &sm->flags), sm->flags);
    sm_info("sector: %lu, parity: %d\n", sm->sector, sm->pdisk);

    for(i = 0; i < devnum; ++i)
    {
        sm_info("sm(%lu %p)[%d]: lba: %ld, lso: %ld, psn: %d, bi_sector: %ld\n",
               sm->sector, sm, i, sm->dmeta[i].lba, sm->dmeta[i].lso, 
               sm->dmeta[i].psn, sm->dmeta[i].bi_sector);
    }
    if(vfd)
        print_vfd(vfd);
    sm_info("===========================================\n");
}



static void print_all_shmeta(struct r5meta *meta)
{
    struct shmeta *sm;
    int i = 0, count = 0, sum = 0, hashsum = 0;
    bool destoryed = false;
    bool fault = false;
    spin_lock(&pa_lock);
    
    // all counters
    sm_info("updating_vfd_blocks: %d\n", meta->updating_vfd_blocks);
    sm_info("active_sm: %d, particle: %d, recombined: %d, inactive: %d, retry: %d, free: %d, flush: %d, locked: %d\n",
        atomic_read(&meta->active_sm), 
        atomic_read(&meta->cached_particle_shmeta),
        atomic_read(&meta->cached_recombined_shmeta),
        atomic_read(&meta->cached_inactive_shmeta),
        atomic_read(&meta->cached_retry_shmeta),
        atomic_read(&meta->cached_free_shmeta),
        atomic_read(&meta->cached_flush_shmeta),
        atomic_read(&meta->cached_locked_shmeta));
    sm_info("blank: %d, blank_in_bptree: %d\n",
        atomic_read(&meta->cached_blank_shmeta),
        atomic_read(&meta->blank_in_bptree));
    sm_info("reclaim_lists: %d, reclaim_in_bptree: %d\n", 
        atomic_read(&meta->reclaim_lists_count), 
        atomic_read(&meta->reclaim_in_bptree));
    int y = 0, a1 = 0, a2 = 0;
    bool crashed1 = false, crashed2 = false;
    spin_lock(&meta->reclaim_lists_lock);
    list_for_each_entry(sm, &meta->reclaim_lists[1], lru)
        a1++;
    sm_info("reclaim list[1]: %d\n", a1);
    list_for_each_entry(sm, &meta->reclaim_lists[0], lru)
        a2++;
    sm_info("reclaim list[0]: %d\n", a2);
    spin_unlock(&meta->reclaim_lists_lock);
    if(a1 + a2 != atomic_read(&meta->reclaim_lists_count))
        sm_err("reclaim list error!\n");
    spin_unlock(&pa_lock);
    return;
}

#endif


/*
 *hash table operations about
 */

void inline REMOVE_SHMETA_HASH(struct r5meta *meta, 
                               struct shmeta *sm, int i)
{
#ifdef PRINT_INFO
    sm_info("remove hash for sm: %lu, hash: %d, p: %p\n",
            sm->sector, i, sm);
#endif
    spin_lock(&meta->hashtbl_lock);
    if(hlist_unhashed(&sm->hash))
        sm_err("sm %lu %p is unhashed!\n", sm->sector, sm);
    hlist_del_init(&sm->hash);
    meta->hashtbl_count[i]--;
#ifdef PRINT_INFO
    sm_info("hash table hash %d count %d\n", 
            i, meta->hashtbl_count[i]);
#endif
    if(hlist_empty(&meta->hashtbl[i]))
    {
        if(meta->hashtbl_count[i] != 0)
        {
            sm_err("hashtbl_count[%d] = %d, but will init\n",
                   i, meta->hashtbl_count[i]);
            meta->hashtbl_count[i] = 0; 
        }
        INIT_HLIST_HEAD(&meta->hashtbl[i]); 
    }
    INIT_HLIST_NODE(&sm->hash); 
    spin_unlock(&meta->hashtbl_lock); 
    atomic_dec(&meta->active_sm);
}


/*
 *change list about
 */
void inline ADD_SM_PARTICLE_WITHOUT_LOCK(struct r5meta *meta, 
                                         struct shmeta *sm)
{
    if(list_empty_careful(&meta->particle_list))
        INIT_LIST_HEAD(&meta->particle_list);
    list_add_tail(&sm->lru, &meta->particle_list);
    set_bit(SM_IN_PARTICLE, &sm->flags);
    atomic_inc(&meta->cached_particle_shmeta);
#ifdef PRINT_INFO
    sm_info("add sm %lu (%lu) to particle_list, %p, count: %d\n",
                sm->sector, sm->flags, sm,
                atomic_read(&meta->cached_particle_shmeta));
#endif
}


///////////////
void inline ADD_SM_RECOMBINE_WITHOUT_LOCK(struct r5meta *meta, 
                                          struct shmeta *sm)
{
    int dddd = 0;
    struct vdisk_flush_data *vfd = sm->vfd;
    while(dddd < devnum)
    {
        if(sm->dmeta[dddd].lba == DEV_META_BLANK &&
           sm->dmeta[dddd].bi_sector != DEV_META_BLANK)
        {
            sm->dmeta[dddd].lba = sm->dmeta[dddd].bi_sector; 
            if(vfd != NULL &&
               sm->dmeta[dddd].bi_sector == vfd->dev[dddd].sector)
            {
                sm->dmeta[dddd].lso = sm->sector;
                sm->dmeta[dddd].psn = dddd;
            }
        }
        dddd++;
    }
    CLEAR_BI_SECTOR(sm, dddd);
    if(list_empty_careful(&meta->recombine_list))
        INIT_LIST_HEAD(&meta->recombine_list);
    list_add(&sm->lru, &meta->recombine_list); 
    set_bit(SM_IN_RECOMBINE, &sm->flags);
    clear_bit(SM_LOCKED, &sm->flags);
    atomic_inc(&meta->cached_recombined_shmeta);
#ifdef PRINT_INFO
    sm_info("add sm %lu (%lu) to recombine_list, %p, count %d\n",
                sm->sector, sm->flags, sm,
                atomic_read(&meta->cached_recombined_shmeta));
        print_shmeta(sm);
#endif
}


///////////////
void inline ADD_SM_INVALID_LIST_WITHOUT_LOCK(struct r5meta *meta, 
                                             struct shmeta *sm)
{
    int smhash = (HASH(sm->sector) & (SM_INACTIVE_LIST_NUM - 1));
    if(smhash > SM_INACTIVE_LIST_NUM)
    {
        sm_err("add sm %lu invalid_list %d\n", sm->sector, smhash);
    } 
    else
    {
        if(list_empty_careful(&meta->inactive_list[smhash]))
            INIT_LIST_HEAD(&meta->inactive_list[smhash]);
        list_add_tail(&sm->lru, &meta->inactive_list[smhash]);
        set_bit(SM_IN_INACTIVE, &sm->flags);
        atomic_inc(&meta->cached_inactive_shmeta);
#ifdef PRINT_INFO
        sm_info("add sm %lu (%lu) to inactive_list[%d], %p, count %d\n",
                sm->sector, sm->flags, smhash, sm,
                atomic_read(&meta->cached_inactive_shmeta));
#endif
    }
}

void inline ADD_SM_INVALID_LIST_DIRTY_WITH_LOCK(struct r5meta *meta,
                                                struct shmeta *sm)
{
    spin_lock(&meta->inactive_list_lock);
    if(list_empty_careful(&meta->inactive_list[SM_INACTIVE_LIST_NUM]))
        INIT_LIST_HEAD(&meta->inactive_list[SM_INACTIVE_LIST_NUM]);
    list_add(&sm->lru, &meta->inactive_list[SM_INACTIVE_LIST_NUM]);
    spin_unlock(&meta->inactive_list_lock);
    set_bit(SM_IN_INACTIVE, &sm->flags);
    atomic_inc(&meta->cached_inactive_shmeta);
#ifdef PRINT_INFO
    sm_info("add sm %lu (%lu) to inactive_list[%d], %p, count %d\n",
            sm->sector, sm->flags, SM_INACTIVE_LIST_NUM,
            sm, atomic_read(&meta->cached_inactive_shmeta));
#endif
}

///////////////
void inline ADD_SM_RETRY_LIST_WITHOUT_LOCK(struct r5meta *meta, 
                                           struct shmeta *sm)
{
    if(list_empty_careful(&meta->retry_list))
        INIT_LIST_HEAD(&meta->retry_list);
    list_add(&sm->lru, &meta->retry_list);
    set_bit(SM_IN_RETRY, &sm->flags);
    atomic_inc(&meta->cached_retry_shmeta);
#ifdef PRINT_INFO 
     sm_info("add sm %lu (%lu) to retry_list, %p, count %d\n",
                sm->sector, sm->flags, sm,
                atomic_read(&meta->cached_retry_shmeta));
#endif
}


///////////////
void inline ADD_SM_FREE_LIST_WITHOUT_LOCK(struct r5meta *meta, 
                                          struct shmeta *sm)
{
    if(list_empty_careful(&meta->free_list))
        INIT_LIST_HEAD(&meta->free_list);
    sm->flags = 0;
    set_bit(SM_FREE, &sm->flags);
    list_add_tail(&sm->lru, &meta->free_list);
    atomic_inc(&meta->cached_free_shmeta);
#ifdef PRINT_INFO
    sm_info("add sm %lu (%lu) to free_list, %p, count %d\n",
                sm->sector, sm->flags, sm,
                atomic_read(&meta->cached_free_shmeta));
#endif
}


///////////////
void inline ADD_SM_FLUSH_LIST_WITHOUT_LOCK(struct r5meta *meta, 
                                           struct shmeta *sm, 
                                           int hash)
{
    if(list_empty_careful(&meta->flush_list[hash]))
        INIT_LIST_HEAD(&meta->flush_list[hash]);
    list_add(&sm->lru, &meta->flush_list[hash]);
    set_bit(SM_IN_FLUSH, &sm->flags);
    atomic_inc(&meta->cached_flush_shmeta);
#ifdef PRINT_INFO
    sm_info("add sm %lu (%lu) to flush_list[%d], %p, count %d\n",
            sm->sector, sm->flags, hash, sm,
            atomic_read(&meta->cached_flush_shmeta));
#endif
}

/*
 *DEL LIST ABOUT
 */
//////////////
void inline DEL_SM_RECLAIM_LIST_WITHOUT_LOCK(struct r5meta *meta, 
                                             struct shmeta *sm)
{
    list_del_init(&sm->lru);
    atomic_dec(&meta->reclaim_lists_count);
    clear_bit(SM_IN_RECLAIM_LIST, &sm->flags);
#ifdef PRINT_INFO
    sm_info("del sm %lu (%lu) from reclaim_list, %p, count %d\n",
                sm->sector, sm->flags, sm,
                atomic_read(&meta->reclaim_lists_count));
#endif
}


//////////////
void inline DEL_SM_RETRY_LIST_WITHOUT_LOCK(struct r5meta *meta, 
                                           struct shmeta *sm)
{
    list_del_init(&sm->lru);
    if(list_empty_careful(&meta->retry_list))
        INIT_LIST_HEAD(&meta->retry_list);
    atomic_dec(&meta->cached_retry_shmeta);
    clear_bit(SM_IN_RETRY, &sm->flags);
#ifdef PRINT_INFO
    sm_info("del sm %lu (%lu) from retry_list, %p, count %d\n",
            sm->sector, sm->flags, sm,
            atomic_read(&meta->cached_retry_shmeta));
#endif
}


//////////////
void inline DEL_SM_INACTIVE_LIST_WITHOUT_LOCK(struct r5meta *meta, 
                                              struct shmeta *sm)
{
    list_del_init(&sm->lru);
    atomic_dec(&meta->cached_inactive_shmeta);
    clear_bit(SM_IN_INACTIVE, &sm->flags);
#ifdef PRINT_INFO
    sm_info("del sm %lu (%lu) from inactive_list, %p, count %d\n",
            sm->sector, sm->flags, sm,
            atomic_read(&meta->cached_inactive_shmeta));
#endif
}

//////////////
void inline DEL_SM_BLANK_LIST_WITHOUT_LOCK(struct r5meta *meta, 
                                           struct shmeta *sm)
{
    list_del_init(&sm->lru);
    if(list_empty_careful(&meta->blank_list))
        INIT_LIST_HEAD(&meta->blank_list);
    atomic_dec(&meta->cached_blank_shmeta);
#ifdef PRINT_INFO
    sm_info("del sm %lu (%lu) from blank_list, %p, count %d\n",
            sm->sector, sm->flags, sm,
            atomic_read(&meta->cached_blank_shmeta));
#endif
}

//////////////
void inline DEL_SM_PARTICLE_LIST_WITHOUT_LOCK(struct r5meta *meta, 
                                              struct shmeta *sm)
{
    list_del_init(&sm->lru);
    if(list_empty_careful(&meta->particle_list))
        INIT_LIST_HEAD(&meta->particle_list);
    atomic_dec(&meta->cached_particle_shmeta);
    clear_bit(SM_IN_PARTICLE, &sm->flags);
#ifdef PRINT_INFO
    sm_info("del sm %lu (%lu) from particle_list, %p, count %d\n",
            sm->sector, sm->flags, sm,
            atomic_read(&meta->cached_particle_shmeta));
#endif
}

//////////////
void inline DEL_SM_FREE_LIST_WITHOUT_LOCK(struct r5meta *meta, 
                                          struct shmeta *sm)
{
    list_del_init(&sm->lru);
    if(list_empty_careful(&meta->free_list))
        INIT_LIST_HEAD(&meta->free_list);
    atomic_dec(&meta->cached_free_shmeta);
    clear_bit(SM_FREE, &sm->flags);
#ifdef PRINT_INFO
    sm_info("del sm %lu (%lu) from free_list, %p, count %d\n",
            sm->sector, sm->flags, sm,
            atomic_read(&meta->cached_free_shmeta));
#endif
}


//////////////
void inline DEL_SM_RECOMBINE_LIST_WITHOUT_LOCK(struct r5meta *meta,
                                               struct shmeta *sm)
{
    list_del_init(&sm->lru);
    if(list_empty_careful(&meta->recombine_list))
        INIT_LIST_HEAD(&meta->recombine_list);
    atomic_dec(&meta->cached_recombined_shmeta);
    clear_bit(SM_IN_RECOMBINE, &sm->flags);
#ifdef PRINT_INFO
    sm_info("del sm %lu (%lu) from recombine_list, %p, count %d\n",
            sm->sector, sm->flags, sm,
            atomic_read(&meta->cached_recombined_shmeta));
#endif
}
 


void inline ADD_RU_READED_LIST_WITH_LOCK(struct r5meta *meta, 
                                         struct read_unit *ru)
{
    spin_lock(&meta->readed_list_lock);
    list_add(&ru->lru, &meta->readed_list);
    spin_unlock(&meta->readed_list_lock);
#ifdef PRINT_INFO
    sm_info("add ru->logical: %lu to readed_list, %p\n",
                ru->origin_read_adr, ru);
#endif
}


/*
 *counter hash list operations:
 */ 
void nhlist_add_tail(struct nhlist_node *node, struct nhlist_head *head)
{
    if(head->tail == NULL)
        head->tail = head->head = node;
    else 
    {
        node->pre = head->tail;
        node->next = NULL;
        head->tail->next = node;
        head->tail = node;
    }
    return;
}


void nhlist_add_head(struct nhlist_node *node, struct nhlist_head *head)
{
    if(head->head == NULL)
        head->tail = head->head = node;
    else
    {
        node->next = head->head;
        node->pre = NULL;
        head->head->pre = node;
        head->head = node;
    }
    return;
}


struct nhlist_node *nhlist_del_head(struct nhlist_head *head)
{
    struct nhlist_node *node;
    if(head->head == NULL)
        return NULL;
    node = head->head;
    head->head = node->next;
    if(head->head == NULL)
        head->tail = NULL;
    NHLIST_NODE_INIT(node);
    return node;
}


struct nhlist_node *nhlist_del_tail(struct nhlist_head *head)
{
    struct nhlist_node *node, *pre;
    if(head->tail == NULL)
        return NULL;
    node = head->tail;
    pre = node->pre;
    if(pre)
        pre->next = NULL;
    else
        NHLIST_HEAD_INIT(head);
    NHLIST_NODE_INIT(node);
    return node;
}


struct nhlist_node *nhlist_del_node(struct nhlist_node *node, struct nhlist_head *head)
{
    struct nhlist_node *pre, *next;
    pre = node->pre;
    next = node->next;

    if(pre)
        pre->next = next;
    else 
        head->head = next;

    if(next)
        next->pre = pre;
    else
        head->tail = pre;
    NHLIST_NODE_INIT(node);
    return node;
}




void copy_shmeta(struct shmeta *to, struct shmeta *from)
{
    int i = 0;
    to->sector = from->sector;
    to->pdisk = from->pdisk;
    to->flags = from->flags;
    to->lba_align = from->lba_align;
    for(i = 0; i < devnum; i++)
    {
        to->dmeta[i].lso = from->dmeta[i].lso;
        to->dmeta[i].bi_sector = from->dmeta[i].bi_sector;
        to->dmeta[i].psn = from->dmeta[i].psn;
        to->dmeta[i].lba = from->dmeta[i].lba;
    }
    return;
}


int check_devmeta_num(struct shmeta *sm)
{
    int count = 0;
    int i;
    i = 0;
    while(i < devnum)
    {
        if(-1 != sm->dmeta[i].bi_sector)
            count++;
        i++;
    }
    return count;
}

static inline void sm_set_bi_stripes(struct bio *bio, unsigned int cnt)
{
    atomic_t *segments = (atomic_t *)&bio->bi_phys_segments;
    atomic_set(segments, cnt);
    return;
}


inline int shmeta_lbas(struct shmeta *sm)
{
    struct devmeta *dm;
    int i = 0, count = 0;
    foreach_dev(dm, sm, i)
        if(dm->lba != DEV_META_BLANK)
            count++;
    return count;
}


bool vfd_blank(struct vdisk_flush_data *vfd)
{
    int i = 0;
#ifdef PRINT_INFO
    sm_info("vfd->lba_align: %lu, %p\n", vfd->lba_align, vfd);
#endif
    while(i < devnum)
    {
        if(vfd->dev[i].dirty == 1 || vfd->dev[i].dirty == 33)
            return false;
        i++;
    }
    return true;
}

static spinlock_t pa_lock;

enum {
    META_DESTROYED = 0,
    META_IS_HANDLING_NOW,
    META_GET,
};


int load_sm_metadata_keep_bptree(struct r5meta *meta, struct shmeta *sm)
{
    struct meta_data *mtd;
    int blocks;
    if(!meta || !sm ||
       (mtd = meta->mtd) == NULL)
    {
        sm_err("para NULL\n");
        return META_DESTROYED;
    }
    if(!load_shmeta_metadata(meta, mtd, sm))
    {
        if(test_bit(SM_OTHER_LOADING_META_NOW, &sm->flags))
        {
            ADD_SM_FREE_LIST_WITH_LOCK(meta, sm);
            return META_IS_HANDLING_NOW;
        }
        else
        {
            // sm_err("load_shmeta_metadata failed! %lu\n", sm->sector);
            return META_DESTROYED;
        }
    }
     
    blocks = shmeta_lbas(sm);
    if(blocks == 0)
    {
        set_bit(SM_BLANK, &sm->flags);
        spin_lock(&meta->blank_bptree_lock);
        if( bplus_tree_delete(meta->blank_bptree, bpkey(sm->sector)) != -1)
            atomic_dec(&meta->blank_in_bptree);
        spin_unlock(&meta->blank_bptree_lock);
    }
    else if(blocks < devnum)
    {
        spin_lock(&meta->reclaim_bptree_lock);
        if(bplus_tree_delete(meta->reclaim_bptree, bpkey(sm->sector)) != -1)
           atomic_dec(&meta->reclaim_in_bptree);
        spin_unlock(&meta->reclaim_bptree_lock);
    }
    if(sm->pdisk < 0 || sm->pdisk > devnum)
        sm->pdisk = compute_pdisk(meta, sm->sector);
    return META_GET;
}



/*
 * compute stripe logical_sector by a block logical_sector
unsigned long compute_new_sector(struct r5meta *meta, block_sec r_sector)
{
    sector_t stripe;
	sector_t chunk_number;
	unsigned int chunk_offset;
    struct mddev *mddev = meta->ctd->mddev;
	unsigned long new_sector;
	int sectors_per_chunk = mddev->chunk_sectors;
	int data_disks = devnum;

	chunk_offset = sector_div(r_sector, sectors_per_chunk);
	chunk_number = r_sector;

    stripe = chunk_number;
    sector_div(stripe, data_disks);

    new_sector = (sector_t)stripe * sectors_per_chunk + chunk_offset;
	return new_sector;
}

int compute_block_disk(struct r5meta *meta, stripe_sec new_sector, 
                        block_sec logical_sector, disk_no *pdisk)
{
	sector_t chunk_number, first_sector, stripe2;
	unsigned int chunk_offset;
    struct mddev *mddev;
	int sectors_per_chunk, dix;

    if(meta == NULL || 
       (meta->ctd) == NULL || 
       (mddev = meta->ctd->mddev) == NULL)
        return -1;

	sectors_per_chunk = mddev->chunk_sectors;
	chunk_offset = sector_div(new_sector, sectors_per_chunk);
	chunk_number = new_sector; 
    first_sector = chunk_number * 1024 * devnum + chunk_offset;
    dix = ((logical_sector - first_sector) / 1024);
	stripe2 = chunk_number;
    if(*pdisk == -1)
		*pdisk = dix - sector_div(stripe2, devnum + meta->max_degrade);
    return (dix + (*pdisk) >= devnum ? dix + (*pdisk) - devnum : 
                                    dix + (*pdisk));
}

*/

/*
 * compute stripe logical_sector, data disk, parity disks
 * by a block logical_sector
 */
unsigned long compute_sector(struct r5meta *meta, sector_t r_sector,
			    int *dd_idx, int *pdisk, int *qdisk)
{
	sector_t stripe, stripe2;
	sector_t chunk_number;
	unsigned int chunk_offset;
    struct mddev *mddev;
    struct cache_tree_data *ctd;
	unsigned long new_sector;

    if(!meta || (ctd = meta->ctd) == NULL || 
       (mddev = ctd->mdd) == NULL)
    {
        sm_err("para NULL\n");
        return 0;
    }
	int sectors_per_chunk = mddev->chunk_sectors;
    int raid_disks = meta->disks;
	int data_disks = raid_disks - meta->max_degrade;

	chunk_offset = sector_div(r_sector, sectors_per_chunk);
	chunk_number = r_sector;

    stripe = chunk_number;
	*dd_idx = sector_div(stripe, data_disks);
	stripe2 = stripe;
	
    *pdisk = *qdisk = -1;
	switch(mddev->level) {
	case 5:
		*pdisk = data_disks - sector_div(stripe2, raid_disks);
		*dd_idx = (*pdisk + 1 + *dd_idx) % raid_disks;
		break;
	case 6:
		*pdisk = raid_disks - 1 - sector_div(stripe2, raid_disks);
		*qdisk = (*pdisk + 1) % raid_disks;
		*dd_idx = (*pdisk + 2 + *dd_idx) % raid_disks;
		break;
	}

    new_sector = (sector_t)stripe  *sectors_per_chunk + chunk_offset;
    if(*dd_idx >= *pdisk)
        *dd_idx = *dd_idx - 1;
	return new_sector;
}


block_sec compute_new_logical_sector(struct r5meta *meta, 
            unsigned long new_sector, int disk_num, int pdisk)
{
	sector_t chunk_number, first_sector;
	unsigned int chunk_offset;
    struct mddev *mddev;
    struct cache_tree_data *ctd;
	int sectors_per_chunk;


    if(meta == NULL ||
       (ctd = meta->ctd) == NULL ||
       (mddev = ctd->mdd) == NULL)
        return NULL;

    if(pdisk < 0 || pdisk > devnum || disk_num < 0 || disk_num >= devnum)
        sm_err("new_sector: %lu, disk_num: %d, pdisk: %d value invalid\n", 
               new_sector, disk_num, pdisk);
	sectors_per_chunk = mddev->chunk_sectors;

	chunk_offset = sector_div(new_sector, sectors_per_chunk);
	chunk_number = new_sector;

    first_sector = chunk_number * 1024 * devnum + chunk_offset;

    return (disk_num >= pdisk ? first_sector + (disk_num - pdisk) * 1024 :
            first_sector + (devnum - pdisk + disk_num) * 1024);
}


struct shmeta *compute_new_sector_reverse(struct r5meta *meta, 
                                stripe_sec new_sector, struct shmeta *sm)
{
	sector_t stripe, stripe2, chunk_number, first_sector;
	unsigned int chunk_offset;
    struct mddev *mddev;
    struct cache_tree_data *ctd;
	int sectors_per_chunk, raid_disks, data_disks, i, dd_idx, pdisk, qdisk;
    int disk_no = 0;
	
    if(meta == NULL || sm == NULL ||
       (ctd = meta->ctd) == NULL ||
       (mddev = ctd->mdd) == NULL)
        return NULL;
	sectors_per_chunk = mddev->chunk_sectors;
	raid_disks = meta->disks;
	data_disks = devnum;

	chunk_offset = sector_div(new_sector, sectors_per_chunk);
	chunk_number = new_sector;
    sm->lba_align = (chunk_number * sectors_per_chunk + chunk_offset) / 8;
    pdisk = sm->pdisk;

    first_sector = chunk_number * 1024 * devnum + chunk_offset;
    i = 0;
    while(i < devnum)
    {
        disk_no = ((i + pdisk >= devnum) ? i + pdisk - devnum : i + pdisk);
        sm->dmeta[disk_no].lso = sm->sector;
        sm->dmeta[disk_no].lba = first_sector;
        sm->dmeta[disk_no].psn = disk_no;
        sm->dmeta[disk_no].bi_sector = DEV_META_BLANK;
        i++;
        first_sector += 1024;
    }
	return sm;
}


int compute_pdisk(struct r5meta *meta, stripe_sec stripe_sector)
{
    sector_t chunk_number, stripe, stripe2;
	unsigned int chunk_offset;
    struct mddev *mddev;
    struct cache_tree_data *ctd;
	int stripe_per_chunk, sectors_per_chunk;
    int pdisk, qdisk, raid_disks, data_disks, dd_idx;

    if(meta == NULL || (ctd = meta->ctd) == NULL ||
       (mddev = ctd->mdd) == NULL)
        return -1;
    sectors_per_chunk = mddev->chunk_sectors;
	stripe_per_chunk = sectors_per_chunk / 8;
    raid_disks = meta->disks;
	data_disks = raid_disks - meta->max_degrade;
	chunk_offset = sector_div(stripe_sector, sectors_per_chunk);
    chunk_number = stripe_sector;

    stripe = chunk_number;
	dd_idx = sector_div(stripe, data_disks);
	stripe2 = stripe * devnum;
	
	switch(mddev->level) {
	case 5:
		pdisk = data_disks - sector_div(chunk_number, raid_disks);
		break;
	case 6:
		pdisk = raid_disks - 1 - sector_div(chunk_number, raid_disks);
		qdisk = (pdisk + 1) % raid_disks;
		break;
	}
	return pdisk;
}



void insert_blank_shmeta_to_bplus_tree(struct r5meta *meta, 
                                      struct shmeta *sm)
{
    struct meta_data *mtd;
    if(!meta || !sm || (mtd = meta->mtd) == NULL)
    {
        sm_err("paras NULL\n");
        return;
    }
#ifdef PRINT_INFO 
    sm_info("add sm %lu to blank_bptree\n", sm->sector); 
#endif
    // if(atomic_read(&meta->blank_in_bptree) < 40960)
    {
        spin_lock(&meta->blank_bptree_lock);
        bplus_tree_insert(meta->blank_bptree, sm->sector >> 3, sm->sector);
        atomic_inc(&meta->blank_in_bptree);
        spin_unlock(&meta->blank_bptree_lock);
#ifdef PRINT_INFO
        sm_info("add sm %lu to blank_bptree end, count: %d\n", 
            sm->sector, atomic_read(&meta->blank_in_bptree));
#endif
    }
    change_metadata(mtd, sm, HASH(sm->sector));
    sm->vfd = NULL;
    REMOVE_SHMETA_HASH(meta, sm, HASH(sm->sector));
    return;
}


/*
 * keep blank list sorted by logical_sector
 */
void insert_blank_shmeta(struct r5meta *meta, struct shmeta *sm)
{
    if(!meta || !sm)
    {
        sm_err("paras NULL\n");
        return;
    }

    set_bit(SM_BLANK, &sm->flags); 
    atomic_inc(&meta->cached_blank_shmeta);
    spin_lock(&meta->blank_list_lock);
    list_add_tail(&sm->lru, &meta->blank_list);
    spin_unlock(&meta->blank_list_lock);
    sm->vfd = NULL;
#ifdef PRINT_INFO
    sm_info("add shmeta %lu with flags %lu to blank list, %p\n", 
            sm->sector, sm->flags, sm);
#endif
    return;
}


void insert_reclaim_shmeta_to_bplus_tree(struct r5meta *meta, 
                                         struct shmeta *sm)
{
    struct meta_data *mtd;
    
    if(!meta || !sm || (mtd = meta->mtd) == NULL)
    {
        sm_err("paras NULL\n");
        return;
    }
#ifdef PRINT_INFO
    sm_info("add sm %lu to reclaim_bptree\n", sm->sector); 
#endif
    // if(atomic_read(&meta->reclaim_in_bptree) < 40960)
    {
        spin_lock(&meta->reclaim_bptree_lock);
        bplus_tree_insert(meta->reclaim_bptree, bpkey(sm->sector), sm->sector);
        atomic_inc(&meta->reclaim_in_bptree);
        spin_unlock(&meta->reclaim_bptree_lock);
#ifdef PRINT_INFO
        sm_info("add sm %lu to reclaim_bptree end, count: %d\n", 
            sm->sector, atomic_read(&meta->reclaim_in_bptree));
#endif
    }
    change_metadata(mtd, sm, HASH(sm->sector));
    sm->vfd = NULL;
    REMOVE_SHMETA_HASH(meta, sm, HASH(sm->sector));
    return;
}


void insert_reclaim_shmeta(struct r5meta *meta, struct shmeta *sm, 
                           int num)
{
    if(!meta || !sm)
    {
        sm_err("paras NULL\n");
        return;
    }

    if(test_bit(NO_SM_TO_RECLAIM, &meta->flags))
        clear_bit(NO_SM_TO_RECLAIM, &meta->flags);
    if(num < devnum - 1 && num >= 0) 
    {
        if(list_empty_careful(&meta->reclaim_lists[num]))
        {
#ifdef PRINT_INFO
            sm_info("init reclaim_lists[%d]\n", num);
#endif
            INIT_LIST_HEAD(&meta->reclaim_lists[num]);
        }
        set_bit(SM_IN_RECLAIM_LIST, &sm->flags); 
        spin_lock(&meta->reclaim_lists_lock);
        list_add(&sm->lru, &meta->reclaim_lists[num]);
        spin_unlock(&meta->reclaim_lists_lock);
        atomic_inc(&meta->reclaim_lists_count);
#ifdef PRINT_INFO
        sm_info("add sm %lu (%lu) to reclaim_list[%d], %p, count %d\n",
                sm->sector, sm->flags, num, sm,
                atomic_read(&meta->reclaim_lists_count)); 
#endif
    } 
    else 
        sm_err("invalid num = %d\n", num);
    return;
}



struct shmeta *get_active_shmeta(struct r5meta *meta, 
                                 stripe_sec new_sector, 
                                 int pdisk, int qdisk)
{
    struct shmeta *sm = NULL;
    int hash, inactive_hash, i;
    bool retrying = false;

    if(!meta)
    {
        sm_err("meta is NULL\n");
        return NULL;
    }

retry_get_active_shmeta:
    spin_lock(&meta->free_list_lock);
    if(!list_empty_careful(&meta->free_list) && 
        atomic_read(&meta->cached_free_shmeta) > 0)
    {
        sm = list_first_entry(&meta->free_list, struct shmeta, lru);
        if(!sm || !test_bit(SM_FREE, &sm->flags))
        {
            sm_err("sm: %lu, flags, %lu, %p, in free_list, init\n", 
                   sm->sector, sm->flags, sm);
            INIT_LIST_HEAD(&meta->free_list);
        }
        else
        {
            list_del_init(&sm->lru);
            spin_unlock(&meta->free_list_lock);
#ifdef PRINT_INFO
            sm_info("del sm %lu flags %lu from free list\n", 
                    sm->sector, sm->flags);
#endif
            atomic_dec(&meta->cached_free_shmeta);
            if(sm)
            {
#ifdef PRINT_INFO
                sm_info("use free shmeta for shmeta %lu, %p\n", 
                        new_sector, sm);
#endif
                goto already_find;
            }
        }
    }
    spin_unlock(&meta->free_list_lock);

    hash = HASH(new_sector);
    inactive_hash = hash & (SM_INACTIVE_LIST_NUM - 1);
    if(atomic_read(&meta->active_sm) >= meta->max_shmeta)
    {
        spin_lock(&meta->inactive_list_lock);
        while(!list_empty_careful(&meta->inactive_list[inactive_hash]))
        {
            // GET_INACTIVE_LIST_HEAD_SM_WITHOUT_LOCK(meta, sm, hash);
            sm = list_first_entry(&meta->inactive_list[inactive_hash], 
                                  struct shmeta, lru);
            if(!sm || !test_bit(SM_IN_INACTIVE, &sm->flags))
            {
                sm_err("sm: %lu, flags: %lu, %p, in inactive_list[%d], init\n",
                        sm->sector, sm->flags, sm, inactive_hash);
                INIT_LIST_HEAD(&meta->inactive_list[inactive_hash]);
            }
            else
            {
                list_del_init(&sm->lru);
                if(!test_bit(SM_DIRTY, &sm->flags))
                {
#ifdef PRINT_INFO
                    sm_info("del sm %lu flags %lu from inactive_list[%d]\n", 
                            sm->sector, sm->flags, inactive_hash);
#endif
                    spin_unlock(&meta->inactive_list_lock);
                    atomic_dec(&meta->cached_inactive_shmeta);
                    
                    REMOVE_SHMETA_HASH(meta, sm, HASH(sm->sector));
#ifdef PRINT_INFO
                    sm_info("use inactive shmeta[%d] for shmeta %lu, %p\n", 
                            inactive_hash, new_sector, sm);
#endif
                    goto already_find;
                }
                else
                    list_add_tail(&sm->lru, 
                                  &meta->inactive_list[SM_INACTIVE_LIST_NUM]);
            }
        }
        spin_unlock(&meta->inactive_list_lock);

        i = 0;
        while(i < SM_INACTIVE_LIST_NUM)
        {
            spin_lock(&meta->inactive_list_lock);
            while(!list_empty_careful(&meta->inactive_list[i]))
            {
                sm = list_first_entry(&meta->inactive_list[i], 
                                      struct shmeta, lru);
                if(!sm || !test_bit(SM_IN_INACTIVE, &sm->flags))
                {
                    sm_err("sm: %lu, flags: %lu, %p, in inactive_list[%d], init\n",
                        sm->sector, sm->flags, sm, i);
                    INIT_LIST_HEAD(&meta->inactive_list[i]);
                }
                else
                {
                    list_del_init(&sm->lru);
                    if(!test_bit(SM_DIRTY, &sm->flags))
                    {
#ifdef PRINT_INFO
                        sm_info("del sm %lu flag %lu from inactive_list[%d]\n", 
                            sm->sector, sm->flags, i);
#endif
                        spin_unlock(&meta->inactive_list_lock);
                
                        atomic_dec(&meta->cached_inactive_shmeta);
                        REMOVE_SHMETA_HASH(meta, sm, HASH(sm->sector));
#ifdef PRINT_INFO
                        sm_info("use inactive shmeta2[%d] for shmeta %lu, %p\n", 
                                i, new_sector, sm);
#endif
                        goto already_find;
                    }
                    else
                        list_add_tail(&sm->lru, 
                                  &meta->inactive_list[SM_INACTIVE_LIST_NUM]);
                }
            }
            spin_unlock(&meta->inactive_list_lock);
            i++;
        }
     
        for(i = 0; i < devnum - 1; i++)
        {
            spin_lock(&meta->reclaim_lists_lock);
            if(!list_empty_careful(&meta->reclaim_lists[i]))
            {
                sm = list_last_entry(&meta->reclaim_lists[i], struct shmeta, lru);
                if(sm && test_bit(SM_IN_RECLAIM_LIST, &sm->flags))
                {
                    DEL_SM_RECLAIM_LIST_WITHOUT_LOCK(meta, sm);         
                    spin_unlock(&meta->reclaim_lists_lock);

                    insert_reclaim_shmeta_to_bplus_tree(meta, sm); 
#ifdef PRINT_INFO
                    sm_info("use reclaim shmeta2[%d] for shmeta %lu, %p\n", 
                            i, new_sector, sm);
#endif
                    goto already_find;
                }
            }
            spin_unlock(&meta->reclaim_lists_lock);
        }
        
        spin_lock(&meta->blank_list_lock);
        if(!list_empty_careful(&meta->blank_list))
        {
            sm = list_first_entry(&meta->blank_list, struct shmeta, lru);
            if(sm && test_bit(SM_BLANK, &sm->flags))
            {
                DEL_SM_BLANK_LIST_WITHOUT_LOCK(meta, sm);         
                spin_unlock(&meta->blank_list_lock);

                insert_blank_shmeta_to_bplus_tree(meta, sm);
#ifdef PRINT_INFO
                sm_info("use blank shmeta2 for shmeta %lu, %p\n", 
                        new_sector, sm);
#endif
                goto already_find;
            }
        }
        spin_unlock(&meta->blank_list_lock);


        if(!retrying/*  && (
            atomic_read(&meta->cached_recombined_shmeta) > 
            SM_FLUSH_META_MIN_LIMIT / *|| 
            atomic_read(&meta->cached_blank_shmeta)      <
            SM_MIN_BLANK_STRIPE  )*/)
        {
#ifdef PRINT_INFO
            sm_info("be ready to flush_shmeta\n");
#endif
            flush_shmeta(meta);
            retrying = true;
            goto retry_get_active_shmeta;
        }
        else
        {
            spin_lock(&meta->blank_list_lock);
            if(!list_empty_careful(&meta->blank_list))
            {
                list_for_each_entry_reverse(sm, &meta->blank_list, lru)
                {
                    if(!sm || !test_bit(SM_BLANK, &sm->flags))
                    {
                        sm_err("sm: %lu, flags: %lu, %p in blank_list",
                                sm->sector, sm->flags, sm);
                        INIT_LIST_HEAD(&meta->blank_list);
                        break;
                    }
                    list_del_init(&sm->lru);
#ifdef PRINT_INFO
                    sm_info("del sm %lu flags %lu from blank_list\n", 
                            sm->sector, sm->flags);
#endif
                    atomic_dec(&meta->cached_blank_shmeta);
                    spin_unlock(&meta->blank_list_lock);

                    insert_blank_shmeta_to_bplus_tree(meta, sm);
                    goto already_find;
                }
            }
            spin_unlock(&meta->blank_list_lock);
            sm_err("no shmeta to use\n");
#ifdef PRINT_INFO
            print_all_shmeta(meta);
#endif
            return NULL;
        }
    }
    else
    { 
        KZALLOC_SM(sm);
#ifdef PRINT_INFO
        sm_info("kzalloc SM: %p\n", sm);
#endif
        memset(sm, 0, sizeof(struct shmeta) + sizeof(struct devmeta) * (devnum - 1));
        if(NULL == sm) 
            goto retry_get_active_shmeta;

        INIT_HLIST_NODE(&sm->hash);

#ifdef PRINT_INFO
        sm_info("alloc shmeta %lu, %p\n", new_sector, sm);
#endif
    }
already_find:
    sm->times = 0;
    sm->flags = 0;
    sm->sector = new_sector;
    sm->lba_align = DEV_META_BLANK;

    i = 0;
    while(i < devnum)
    {
        sm->dmeta[i].lso = DEV_META_BLANK;
        sm->dmeta[i].bi_sector = DEV_META_BLANK;
        sm->dmeta[i].psn = DEV_META_BLANK;
        sm->dmeta[i].lba = DEV_META_BLANK;
        i++;
    }
    if(pdisk != DEV_META_BLANK) 
        sm->pdisk = pdisk;
    else if(new_sector != DEV_META_BLANK)
        sm->pdisk = compute_pdisk(meta, new_sector);
    sm->vfd = NULL;
    INIT_LIST_HEAD(&sm->lru);
#ifdef PRINT_INFO
    sm_info("get_active_shmeta finished\n");
#endif
    return sm;
}


struct shmeta *load_reclaim_shmeta(struct r5meta *meta)
{
    struct shmeta *sm;
    struct bplus_tree *reclaim_tree;
    unsigned long reclaim_sector;
    struct meta_data *mtd;
    if(!meta || 
       (reclaim_tree = meta->reclaim_bptree) == NULL ||
       (mtd = meta->mtd) == NULL)
    {
        sm_err("meta_page is NULL\n");
        return NULL;
    }

    spin_lock(&meta->reclaim_bptree_lock);
    reclaim_sector = bplus_tree_delete_first(reclaim_tree);
    atomic_dec(&meta->reclaim_in_bptree);
    spin_unlock(&meta->reclaim_bptree_lock);

    if((sm = get_active_shmeta(meta, reclaim_sector, -1, -1)) == NULL)
    {
        sm_err("get_active_shmeta failed for sh %lu, need flush.\n",
                reclaim_sector);
        return NULL;
    }
retry_load_reclaim_sm:
    sm->sector = reclaim_sector;
    sm->lba_align = transfer_stripe_sector_to_lba_align(meta, reclaim_sector);
    sm->pdisk = compute_pdisk(meta, sm->sector);
    if(load_shmeta_metadata(meta, mtd, sm))
    {
        // TODO: check 
        // INSERT_SHMETA_HASH(meta, sm, HASH(sm->sector));
#ifdef PRINT_INFO
        sm_info("after load_sm_metadata_keep_bptree\n");
        print_shmeta(sm);       
#endif
        return sm;
    }
    else
    {
        /*
        sector_t old_reclaim_sector = reclaim_sector;
        reclaim_sector = bplus_tree_replace_first(reclaim_tree,
                                                    old_reclaim_sector);
        */
        if(atomic_read(&meta->reclaim_in_bptree) == 0)
            return NULL;
        spin_lock(&meta->reclaim_bptree_lock);
        reclaim_sector = bplus_tree_delete_first(reclaim_tree);
        atomic_dec(&meta->reclaim_in_bptree);
        spin_unlock(&meta->reclaim_bptree_lock);
        goto retry_load_reclaim_sm;
    }
}


struct shmeta *load_blank_shmeta(struct r5meta *meta)
{
    struct shmeta *sm;
    struct bplus_tree *blank_tree;
    unsigned long blank_sector;
    struct meta_data *mtd;
    if(!meta || 
       (blank_tree = meta->blank_bptree) == NULL ||
       (mtd = meta->mtd) == NULL)
    {
        sm_err("meta_page is NULL\n");
        return NULL;
    }

    spin_lock(&meta->blank_bptree_lock);
    blank_sector = bplus_tree_delete_first(blank_tree);
    atomic_dec(&meta->blank_in_bptree);
    spin_unlock(&meta->blank_bptree_lock);

    if((sm = get_active_shmeta(meta, blank_sector, -1, -1)) == NULL)
    {
        sm_err("get_active_shmeta failed for sh %lu, need flush.\n",
                blank_sector);
        return NULL;
    }
retry_load_blank_sm:
    sm->sector = blank_sector;
    sm->lba_align = transfer_stripe_sector_to_lba_align(meta, blank_sector);
    sm->pdisk = DEV_META_BLANK;
    if(load_shmeta_metadata(meta, mtd, sm))
    {
        set_bit(SM_BLANK, &sm->flags);
        sm->pdisk = compute_pdisk(meta, sm->sector);
        // TODO: check 
        // INSERT_SHMETA_HASH(meta, sm, HASH(sm->sector));
#ifdef PRINT_INFO
        sm_info("after load_sm_metadata_keep_bptree\n");
        print_shmeta(sm);       
#endif
        return sm;
    }
    else
    {
        if(atomic_read(&meta->blank_in_bptree) == 0)
            return NULL;
        spin_lock(&meta->blank_bptree_lock);
        blank_sector = bplus_tree_delete_first(blank_tree);
        atomic_dec(&meta->blank_in_bptree);
        spin_unlock(&meta->blank_bptree_lock);
        goto retry_load_blank_sm;
    }
}


struct shmeta *get_blank_shmeta(struct r5meta *meta)
{
    struct shmeta *sm = NULL;
    int retryed = 0;

    if(!meta)
    {
        sm_err("meta is NULL");
        return NULL;
    }

retry_get_blank_shmeta:
    spin_lock(&meta->blank_list_lock);
    if(!list_empty_careful(&meta->blank_list))
    {
        sm = list_first_entry(&meta->blank_list, struct shmeta, lru);

        if(sm && test_bit(SM_BLANK, &sm->flags))
        {
#ifdef PRINT_INFO
            sm_info("del sm %lu flags %lu from blank_list\n", 
                        sm->sector, sm->flags);
#endif
            list_del_init(&sm->lru);

            spin_unlock(&meta->blank_list_lock);
            atomic_dec(&meta->cached_blank_shmeta);
#ifdef PRINT_INFO
            sm_info("get new blank shmeta %lu, %p, %lu\n",
                   sm->sector, sm, sm->flags);
#endif
            return sm;
        }
    }
    spin_unlock(&meta->blank_list_lock);
 
    if(atomic_read(&meta->blank_in_bptree) > 0)
    {
        if((sm = load_blank_shmeta(meta)) != NULL)
        {
#ifdef PRINT_INFO
            sm_info("get new blank shmeta %lu, %p, %lu\n",
                       sm->sector, sm, sm->flags);
#endif
            return sm;
        }
    }
  
    if(retryed == 2)
    {
        sm_err("reclaimed and still no blank shmeta to use\n");
        return NULL;
    }
#ifdef PRINT_INFO
    sm_info("no vaild blank space to use. force to reclaim space\n");
#endif
    set_bit(MT_FORCE_RECLAIM, &meta->flags);
    clear_bit(MT_RECLAIMED, &meta->flags);
    clear_bit(MT_GET_A_BLANK, &meta->flags);

    set_bit(MT_WAIT_FOR_BLANK, &meta->flags);
    md_wakeup_thread(meta->reclaim_thread);
    wait_event(meta->wait_for_reclaim_queue, 
               (test_bit(MT_GET_A_BLANK, &meta->flags) || 
                test_bit(MT_RECLAIMED, &meta->flags) ||
                test_bit(NO_SM_TO_RECLAIM, &meta->flags)));
    clear_bit(MT_GET_A_BLANK, &meta->flags);
    retryed++;
#ifdef PRINT_INFO
    sm_info("wake up and retry\n");
#endif
    goto retry_get_blank_shmeta;
}


struct shmeta *find_shmeta(struct r5meta *meta, stripe_sec sector)
{
    struct shmeta *sm;
    int hash = HASH(sector), count = 0;
    bool destoryed = false;
    sector_t last_one = -1;
#ifdef PRINT_INFO
    sm_info("find shmeta: %lu, hash: %d\n", sector, hash);
#endif
    spin_lock(&meta->hashtbl_lock);
    hlist_for_each_entry(sm, &meta->hashtbl[hash], hash)
    {
        if(sm == NULL)
            break;

        if(sm->sector == last_one)
        {
            sm_err("hash table destoryed!(a->next = a) hash: %d\n", hash);
#ifdef PRINT_INFO
            print_shmeta(sm);
#endif
            destoryed = true;
            break;
        }
        if(count > 512)
        {
            sm_err("hash table destoryed!(count > 512) hash: %d\n", hash);
            destoryed = true;
            break;
        }
        
        if(HASH(sm->sector) != hash)
            sm_err("sm %lu %p flag: %lu in hash %d, real_hash: %d\n", 
                    sm->sector, sm, sm->flags, hash, HASH(sm->sector));
        last_one = sm->sector;
        if(sm->sector == sector)
        {
#ifdef PRINT_INFO
            sm_info("find shmeta: %lu, hash: %d, flags: %d, in cache\n", 
                    sector, hash, sm->flags);
#endif
            spin_unlock(&meta->hashtbl_lock);
            return sm;
        }
        count++;
    }
    count = 0;
    last_one = -1;
    if(destoryed)
    {
        hlist_for_each_entry(sm, &meta->hashtbl[hash], hash)
        {
            if(sm == NULL)
                break;
            sm_err("destoryed hash list %d: %lu, %p\n", hash, sm->sector, sm);
            if(sm->sector == last_one)
            {
                sm_err("hash table destoryed!(a->next = a) hash: %d\n", hash);
#ifdef PRINT_INFO
            print_shmeta(sm);
#endif
                break;
            }
            if(count > 512)
            {
                sm_err("hash table destoryed!(count > 512) hash: %d\n", hash);
                break;
            }
            last_one = sm->sector;
            count++;
        }
    }
    spin_unlock(&meta->hashtbl_lock);
    return NULL;
}


void merge_shmetas(struct r5meta *meta, struct shmeta *sm1, 
                   struct shmeta *sm2, struct shmeta *sm3,
                   bool sm2_locked)
{
    int i, j, z;
    struct devmeta *dev1, *dev2;
    bool sh1_blank;
    struct vdisk_flush_data *vfd1, *vfd2;
    struct page *page_pos;
    sector_t new_logical_sector, dev2_sector;
    spinlock_t lock;
    spin_lock_init(&lock);

    if(meta == NULL)
    {
        sm_err("meta is NULL\n");
        return; 
    }

    sh1_blank = test_bit(SM_BLANK, &sm1->flags);
 
    vfd1 = sm1->vfd;
    vfd2 = sm2->vfd;

#ifdef PRINT_INFO
    sm_info("merge before\n");
    print_shmeta(sm1);
    print_shmeta(sm2);
#endif
    foreach_dev(dev2, sm2, i)
    {
        if(dev2->bi_sector == DEV_META_BLANK)
            continue;

        foreach_dev(dev1, sm1, j)
        {
            if(dev1->bi_sector == DEV_META_BLANK)
            {
                dev2_sector = dev2->bi_sector;
                dev1->lba = dev1->bi_sector = dev2_sector;
                dev2->bi_sector = DEV_META_BLANK;
                dev2->lso = sm1->sector;
                dev2->psn = j;

                new_logical_sector = compute_new_logical_sector(meta,
                                        sm1->sector, j, sm1->pdisk);
                    
                if(vfd1)
                {
                    vfd1->dev[j].sector = new_logical_sector;
                    if(vfd2)
                    {
                        z = 0;
                        while(z < devnum)
                        {
                            spin_lock(&lock);
                            if(vfd2->dev[z].sector == dev2_sector)
                            {   
                                vfd1->dev[j].page = vfd2->dev[z].page;
                                vfd1->dev[j].cdev = vfd2->dev[z].cdev;
                                vfd1->dev[j].dirty = vfd2->dev[z].dirty;
                                vfd1->dev[j].offset = vfd2->dev[z].offset;
                                vfd1->dev[j].length = vfd2->dev[z].length;

                                vfd2->dev[z].page = NULL;
                                vfd2->dev[z].cdev = NULL;
                                vfd2->dev[z].dirty = 0;

                                spin_unlock(&lock);
                                break;
                            }
                            z++;
                            spin_unlock(&lock);
                        }
                    }
                }
                break;
            }
                
        }
    }

    if(!test_bit(SM_DYNAMIC, &sm1->flags))
    {
        set_bit(SM_DYNAMIC_CHANGED, &sm1->flags);
        set_bit(SM_DYNAMIC, &sm1->flags); 
    }
    if(!test_bit(SM_DYNAMIC, &sm2->flags))
    {
        set_bit(SM_DYNAMIC_CHANGED, &sm2->flags);
        set_bit(SM_DYNAMIC, &sm2->flags); 
    }

    set_bit(SM_DIRTY, &sm1->flags);
    set_bit(SM_DIRTY, &sm2->flags);
    set_bit(SM_LOCKED, &sm1->flags);
    clear_bit(SM_LOCKED, &sm2->flags);
    
#ifdef PRINT_INFO
    sm_info("after before\n");
    print_shmeta(sm1);
    print_shmeta(sm2);
#endif

    return;
}


struct shmeta *recombine_2_shmeta(struct r5meta *meta, 
        struct shmeta *sm1, struct shmeta *sm2,
        bool is_retry_recombine)
{
    bool sm1_fw, sm1_dmc, sm2_fw, sm2_dmc, 
         sm1_blk, sm2_blk, sm1_locked, sm2_locked, ori_vfd;
    int sm1_devnum, sm2_devnum;
    struct shmeta *sm_temp, *sm_blank;
    struct vdisk_flush_data *r_vfd, *vfd;
    struct devmeta *dev;
    struct mddev *mddev;
    struct cache_tree_data *ctd;
    if(!meta || !sm1 || !sm2 ||
      (ctd = meta->ctd) == NULL ||
      (mddev = ctd->mdd) == NULL)
    {
        sm_err("pare NULL\n");
        return NULL;
    }

    sm1_fw = !test_bit(SM_WRITTEN, &sm1->flags);
    sm1_dmc = test_bit(SM_DYNAMIC, &sm1->flags);
    sm2_fw = !test_bit(SM_WRITTEN, &sm2->flags);
    sm2_dmc = test_bit(SM_DYNAMIC, &sm2->flags);
    sm1_blk = test_bit(SM_BLANK, &sm1->flags);
    sm2_blk = test_bit(SM_BLANK, &sm2->flags);
    sm1_locked = test_bit(SM_LOCKED, &sm1->flags);
    sm2_locked = test_bit(SM_LOCKED, &sm2->flags);

    sm1_devnum = check_devmeta_num(sm1);
    sm2_devnum = check_devmeta_num(sm2);
    sm_blank = NULL;
    r_vfd = NULL;
    ori_vfd = true;

#ifdef PRINT_INFO 
    sm_info("\n\n\n\n&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&:\n");
    sm_info("sm1_fw: %d, sm1_dmc: %d, sm2_fw: %d, sm2_dmc: %d\n",
           sm1_fw, sm1_dmc, sm2_fw, sm2_dmc);
    print_shmeta(sm1);
    print_shmeta(sm2);
#endif
 

    if(!sm1_locked && sm2_locked)
    {
        sm_temp = sm1;
        sm1 = sm2;
        sm2 = sm_temp;
        
        sm1_fw = !test_bit(SM_WRITTEN, &sm1->flags);
        sm1_dmc = test_bit(SM_DYNAMIC, &sm1->flags);
        sm2_fw = !test_bit(SM_WRITTEN, &sm2->flags);
        sm2_dmc = test_bit(SM_DYNAMIC, &sm2->flags);
        sm1_blk = test_bit(SM_BLANK, &sm1->flags);
        sm2_blk = test_bit(SM_BLANK, &sm2->flags);
        sm1_locked = test_bit(SM_LOCKED, &sm1->flags);
        sm2_locked = test_bit(SM_LOCKED, &sm2->flags);
    }
    else if(sm1_locked && sm2_locked)
    {
        list_add_tail(&sm1->lru, &meta->locked_list);
        list_add_tail(&sm2->lru, &meta->locked_list);
        atomic_inc(&meta->cached_locked_shmeta);
        atomic_inc(&meta->cached_locked_shmeta);
        set_bit(SM_IN_LOCKED, &sm1->flags);
        set_bit(SM_IN_LOCKED, &sm2->flags);

        clear_bit(SM_RECOMBINING, &sm1->flags);
        clear_bit(SM_RECOMBINING, &sm2->flags);

#ifdef PRINT_INFO
        sm_info("add shmeta %lu with flags %lu to locked list, %p\n", 
                sm1->sector, sm1->flags, sm1);
        sm_info("add shmeta %lu with flags %lu to locked list, %p\n", 
                sm2->sector, sm2->flags, sm2);
#endif
        return NULL;
    }

    if(sm1_fw && sm2_fw)
    {
#ifdef PRINT_INFO
        sm_info("type 1, two kongxian\n");
#endif
        merge_shmetas(meta, sm1, sm2, NULL, sm2_locked); 
    }
    else if( sm1_fw == !sm2_fw )
    {       
        if(!sm1_dmc && !sm2_dmc) 
        {
#ifdef PRINT_INFO
            sm_info("type 2, a static and a kongxian\n");
#endif
            if(!sm1_fw)
            {
                sm_temp = sm1;
                sm1 = sm2;
                sm2 = sm_temp;
                
                sm1_fw = !test_bit(SM_WRITTEN, &sm1->flags);
                sm1_dmc = test_bit(SM_DYNAMIC, &sm1->flags);
                sm2_fw = !test_bit(SM_WRITTEN, &sm2->flags);
                sm2_dmc = test_bit(SM_DYNAMIC, &sm2->flags);
                sm1_blk = test_bit(SM_BLANK, &sm1->flags);
                sm2_blk = test_bit(SM_BLANK, &sm2->flags);
                sm1_locked = test_bit(SM_LOCKED, &sm1->flags);
                sm2_locked = test_bit(SM_LOCKED, &sm2->flags);
            }   
        }
        else if(sm1_blk || sm2_blk) 
        {
#ifdef PRINT_INFO
            sm_info("type 3, a blank and a kongxian\n");
#endif
            if(!sm1_blk && !sm1_locked)
            {
                sm_temp = sm1;
                sm1 = sm2;
                sm2 = sm_temp;
                
                sm1_fw = !test_bit(SM_WRITTEN, &sm1->flags);
                sm1_dmc = test_bit(SM_DYNAMIC, &sm1->flags);
                sm2_fw = !test_bit(SM_WRITTEN, &sm2->flags);
                sm2_dmc = test_bit(SM_DYNAMIC, &sm2->flags);
                sm1_blk = test_bit(SM_BLANK, &sm1->flags);
                sm2_blk = test_bit(SM_BLANK, &sm2->flags);
                sm1_locked = test_bit(SM_LOCKED, &sm1->flags);
                sm2_locked = test_bit(SM_LOCKED, &sm2->flags);
            }
        }
        else
        {
#ifdef PRINT_INFO
            sm_info("type 4, a non-blank and a kongxian\n");        
#endif
            if(!sm1_fw)
            {
                sm_temp = sm1;
                sm1 = sm2;
                sm2 = sm_temp;
                
                sm1_fw = !test_bit(SM_WRITTEN, &sm1->flags);
                sm1_dmc = test_bit(SM_DYNAMIC, &sm1->flags);
                sm2_fw = !test_bit(SM_WRITTEN, &sm2->flags);
                sm2_dmc = test_bit(SM_DYNAMIC, &sm2->flags);
                sm1_blk = test_bit(SM_BLANK, &sm1->flags);
                sm2_blk = test_bit(SM_BLANK, &sm2->flags);
                sm1_locked = test_bit(SM_LOCKED, &sm1->flags);
                sm2_locked = test_bit(SM_LOCKED, &sm2->flags);
            }   
        }
 
        merge_shmetas(meta, sm1, sm2, NULL, sm2_locked);
    }
    else if(!sm1_fw && !sm2_fw)   
    {
#ifdef PRINT_INFO
        if(!sm1_dmc && !sm2_dmc)
            sm_info("type 5, two static\n");
        else if(sm1_dmc == !sm2_dmc && (sm1_blk || sm2_blk))
            sm_info("type 6, one static and one blank\n");
        else if(sm1_dmc == !sm2_dmc && !sm1_blk && !sm2_blk)
            sm_info("type 7, one static and one non-blank\n");
        else if(sm1_dmc && sm2_dmc && sm1_blk && sm2_blk)
            sm_info("type 8, two blank\n");
        else if(sm1_dmc && sm2_dmc && (sm1_blk || sm2_blk))
            sm_info("type 9, one blank dynamic and a non-blank dynamic\n");
        else if(sm1_dmc && sm2_dmc && !sm1_blk && !sm2_blk)
            sm_info("type 10, two non-blank dynamic\n");
#endif

        if(sm1_blk)
            sm_blank = sm1;
        else if(sm2_blk)
        {
            sm_temp = sm1;
            sm1 = sm2;
            sm2 = sm_temp;

            sm_blank = sm1;

            sm1_fw = !test_bit(SM_WRITTEN, &sm1->flags);
            sm1_dmc = test_bit(SM_DYNAMIC, &sm1->flags);
            sm2_fw = !test_bit(SM_WRITTEN, &sm2->flags);
            sm2_dmc = test_bit(SM_DYNAMIC, &sm2->flags);
            sm1_blk = test_bit(SM_BLANK, &sm1->flags);
            sm2_blk = test_bit(SM_BLANK, &sm2->flags);
            sm1_locked = test_bit(SM_LOCKED, &sm1->flags);
            sm2_locked = test_bit(SM_LOCKED, &sm2->flags);
        }
        else
        {
            sm_blank = get_blank_shmeta(meta);
            if(sm_blank)
                set_bit(SM_RECOMBINING, &sm_blank->flags);
            else
            {
                clear_bit(SM_RECOMBINING, &sm1->flags);
                clear_bit(SM_RECOMBINING, &sm2->flags);
                ADD_SM_RETRY_LIST_WITHOUT_LOCK(meta, sm1);
                ADD_SM_RETRY_LIST_WITHOUT_LOCK(meta, sm2);
                CHANGE_VFD_BLOCKS(meta, -sm1_devnum);
                CHANGE_VFD_BLOCKS(meta, -sm2_devnum);
                return NULL;
            }
        }
       
        // handle return vfd;
        if (sm_blank != NULL && sm_blank != sm1 && sm_blank != sm2)
        {
#ifdef PRINT_INFO
            print_shmeta(sm_blank);
#endif
            if(sm_blank->vfd == NULL)
            {
                ori_vfd = false;
                if((vfd = sm1->vfd) != NULL)
                {
                    r_vfd = vfd;
                    r_vfd->lba_align = 
                        transfer_stripe_sector_to_lba_align(meta, 
                                                sm_blank->sector);
                }
                else
                {
                    sm_err("sm1->vfd = NULL\n");
                    if((vfd = sm2->vfd) != NULL)
                    {
                        r_vfd = vfd;
                        r_vfd->lba_align = 
                            transfer_stripe_sector_to_lba_align(meta, 
                                                sm_blank->sector);
                    }
                    else
                    {
                        sm_err("sm2->vfd == NULL\n");
                        r_vfd = NULL;
                    }
                }
                sm_blank->vfd = r_vfd;
            }
        }

        // merge shmeta;
        if (sm1 == sm_blank)
            merge_shmetas(meta, sm_blank, sm2, NULL, sm2_locked);
        else
        {
            if(sm1)
            {
                merge_shmetas(meta, sm_blank, sm1, sm2, sm1_locked);
                sm1_devnum = shmeta_lbas(sm1);
                if(sm1_devnum == 0)
                    insert_blank_shmeta(meta, sm1);
                else if(sm1_devnum < devnum)
                    insert_reclaim_shmeta(meta, sm1, 
                                          devnum - sm1_devnum - 1);
                else
                    ADD_SM_INVALID_LIST_DIRTY_WITH_LOCK(meta, sm1);
                
                if((vfd = sm1->vfd) != NULL && vfd != r_vfd)
                {
#ifdef PRINT_INFO
                    sm_info("return vfd with align: %lu, %p\n",
                            vfd->lba_align, vfd);
#endif
                    // kfree(vfd);
                    return_vfd(mddev, vfd);
                }
                clear_bit(SM_RECOMBINING, &sm1->flags);
                sm1->vfd = NULL;
                
#ifdef PRINT_INFO
                sm_info("\n\nafter recombine\n");
                if(sm1)
                    print_shmeta(sm1);
#endif
           }
            merge_shmetas(meta, sm_blank, sm2, NULL, sm2_locked);
        }
    }

    sm2_devnum = check_devmeta_num(sm2);
    
#ifdef PRINT_INFO
    if(sm2)
        print_shmeta(sm2);
#endif

    if(sm2_devnum == 0)
    {
        int a = shmeta_lbas(sm2);

        if(test_bit(SM_BLANK, &sm2->flags) || a == 0)
            insert_blank_shmeta(meta, sm2);
        else if(a < devnum)
            insert_reclaim_shmeta(meta, sm2, devnum - a - 1);
        else 
            ADD_SM_INVALID_LIST_DIRTY_WITH_LOCK(meta, sm2);
        if((vfd = sm2->vfd) != NULL && vfd != r_vfd)
        {
#ifdef PRINT_INFO
            sm_info("return vfd with align: %lu, %p\n",
                    vfd->lba_align, vfd);
#endif
            // kfree(vfd);
            return_vfd(mddev, vfd);
        }
        sm2->vfd = NULL;
    }
    else
    {
        if(is_retry_recombine)
        {
            ADD_SM_RETRY_LIST_WITHOUT_LOCK(meta, sm2);
        }
        else if(test_bit(MT_FLUSH_ALL_PARTICLE, &meta->flags))
        {
            RETURN_FULL_VFD(meta, sm2, 0);
            ADD_SM_INVALID_LIST_DIRTY_WITH_LOCK(meta, sm2);
        }
        else
        {
            ADD_SM_PARTICLE_WITH_LOCK(meta, sm2);
        }
    }
    clear_bit(SM_RECOMBINING, &sm2->flags);

#ifdef PRINT_INFO
    if(sm1 != NULL)
    {
        sm_info("sm1:\n");
        print_shmeta(sm1);
    }
    if(sm2 != NULL)
    {
        sm_info("sm2:\n");
        print_shmeta(sm2);
    }
    if (sm_blank != NULL && sm_blank != sm1 && sm_blank != sm2)
    {
        sm_info("sm blank:\n");
        print_shmeta(sm_blank);
    }
    sm_info("&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&:\n\n\n\n");
#endif

   return (sm_blank != NULL ? sm_blank : sm1);
}




struct shmeta* set_mapping_invalid(struct r5meta *meta, stripe_sec sh_sector, disk_no psn, sector_t mapping_sm)
{
    struct shmeta *sm = NULL;
    struct devmeta *dmeta = NULL;
    int invalid_num, i, dev_num, load_result;

    if(meta == NULL)
    {
        sm_err("meta is NULL\n");
        return false;
    }
#ifdef PRINT_INFO
    sm_info("sh_sector: %lu, psn: %d\n", sh_sector, psn);
#endif
    if(sh_sector == -1)
        return false;
set_mapping_invalid_retry:
    sm = find_shmeta(meta, sh_sector);
    if(!sm)
    {
        sm = get_active_shmeta(meta, -1, -1, -1);
        if(sm == NULL)
        {
            sm_err("kzalloc sm failed\n");
            return NULL;
        }
        sm->sector = sh_sector;
        sm->lba_align = transfer_stripe_sector_to_lba_align(meta, sh_sector);
        sm->pdisk = DEV_META_BLANK;
#ifdef PRINT_INFO 
        sm_info("load shmeta\n");
#endif
        load_result = load_sm_metadata_keep_bptree(meta, sm);
        if(load_result == META_DESTROYED) 
        {
            sm_err("set stripe %lu, block %d invalid failed\n",
                   sh_sector, psn);
            ADD_SM_FREE_LIST_WITH_LOCK(meta, sm);
            return NULL;
        }
        else if(load_result == META_IS_HANDLING_NOW) 
        {
            sm_err("set stripe %lu, block %d invalid, some is handle meta\n",
                   sh_sector, psn);
            ADD_SM_FREE_LIST_WITH_LOCK(meta, sm);
            mdelay(10);
            goto set_mapping_invalid_retry;
        }

#ifdef PRINT_INFO
        print_shmeta(sm);
#endif

        if(sm->dmeta[psn].lso != mapping_sm)
            sm_err("meta wrong! sm(%lu)->dmeta[%d].lso = %lu mapping_sm: %lu\n",
                  sm->sector, psn, sm->dmeta[psn].lso, mapping_sm);
        sm->dmeta[psn].lso = DEV_RECLAIMING;
        sm->dmeta[psn].psn = DEV_META_BLANK;
#ifdef PRINT_INFO
        print_shmeta(sm);
#endif
        invalid_num = 0;
        foreach_dev(dmeta, sm, i)
            if(dmeta->lba == DEV_META_BLANK)
                invalid_num++;
        
        dev_num = check_devmeta_num(sm);
#ifdef PRINT_INFO
        sm_info("invalid_num: %d, dev_num: %d\n", invalid_num, dev_num);
#endif

        if(invalid_num == devnum /*test_bit(SM_BLANK, &sm->flags)*/)
            insert_blank_shmeta(meta, sm);
        else if(invalid_num > 0)
            insert_reclaim_shmeta(meta, sm, invalid_num - 1);
        else 
            ADD_SM_INVALID_LIST_DIRTY_WITH_LOCK(meta, sm);
        set_bit(SM_DIRTY, &sm->flags);
    }
    else 
    {
#ifdef PRINT_INFO
        sm_info("ori sm:\n");
        print_shmeta(sm);
#endif
        if(sm->dmeta[psn].lso != mapping_sm)
            sm_err("meta wrong! sm(%lu)->dmeta[%d].lso = %lu mapping_sm: %lu\n",
                  sm->sector, psn, sm->dmeta[psn].lso, mapping_sm);
        sm->dmeta[psn].lso = DEV_RECLAIMING;
        sm->dmeta[psn].psn = DEV_META_BLANK;
#ifdef PRINT_INFO
        sm_info("sm in cache, after set invalid: \n");
        print_shmeta(sm);
#endif
        invalid_num = 0;
        foreach_dev(dmeta, sm, i)
            if(dmeta->lba == DEV_META_BLANK)
                invalid_num++;
        
        dev_num = check_devmeta_num(sm);
#ifdef PRINT_INFO
        sm_info("invalid_num: %d, dev_num: %d\n", invalid_num, dev_num);
#endif
        set_bit(SM_DIRTY, &sm->flags);
    }
    return sm; 
}


bool set_block_invalid(struct r5meta *meta, stripe_sec sh_sector, disk_no psn)
{
    struct shmeta *sm = NULL;
    struct devmeta *dmeta = NULL;
    int invalid_num, i, dev_num, load_result;

    if(meta == NULL)
    {
        sm_err("meta is NULL\n");
        return false;
    }
#ifdef PRINT_INFO
    sm_info("sh_sector: %lu, psn: %d\n", sh_sector, psn);
#endif
    if(sh_sector == -1)
        return false;
set_block_invalid_retry:
    sm = find_shmeta(meta, sh_sector);
    if(!sm)
    {
        sm = get_active_shmeta(meta, sh_sector, -1, -1);
        if(sm == NULL)
        {
            sm_err("get_active_shmeta failed\n");
            return false;
        }
        sm->sector = sh_sector;
        sm->lba_align = transfer_stripe_sector_to_lba_align(meta, sh_sector);
        sm->pdisk = DEV_META_BLANK;
#ifdef PRINT_INFO
        sm_info("load shmeta\n");
#endif
        load_result = load_sm_metadata_keep_bptree(meta, sm);
        if(load_result == META_DESTROYED) 
        {
            sm_err("set stripe %lu, block %d invalid failed\n",
                   sh_sector, psn);
            ADD_SM_FREE_LIST_WITH_LOCK(meta, sm);
            return NULL;
        }
        else if(load_result == META_IS_HANDLING_NOW) 
        {
            sm_err("set stripe %lu, block %d invalid, some is handle meta\n",
                   sh_sector, psn);
            ADD_SM_FREE_LIST_WITH_LOCK(meta, sm);
            mdelay(10);
            goto set_block_invalid_retry;
        }
#ifdef PRINT_INFO
        sm_info("after load shmeta\n"); 
        print_shmeta(sm);
#endif
        if(sm->dmeta[psn].lba == DEV_META_BLANK)
            sm_err("meta wrong! sm(%lu)->dmeta[%d].lba = %lu\n",
                  sm->sector, psn, DEV_META_BLANK);
        sm->dmeta[psn].lba = DEV_META_BLANK;
#ifdef PRINT_INFO
        print_shmeta(sm);
#endif

        invalid_num = 0;
        foreach_dev(dmeta, sm, i)
            if(dmeta->lba == DEV_META_BLANK)
                invalid_num++;
        
        dev_num = check_devmeta_num(sm);

#ifdef PRINT_INFO
        sm_info("invalid_num: %d, dev_num: %d\n", invalid_num, dev_num);
#endif
        if(invalid_num == devnum /*test_bit(SM_BLANK, &sm->flags)*/ )
            insert_blank_shmeta(meta, sm);
        else
            insert_reclaim_shmeta(meta, sm, invalid_num - 1);
        set_bit(SM_DIRTY, &sm->flags);
        return true;
    }
    else 
    {
#ifdef PRINT_INFO
        sm_info("ori sm:\n");
        print_shmeta(sm);
#endif
        if(sm->dmeta[psn].lba == DEV_META_BLANK)
            sm_err("meta wrong! sm(%lu)->dmeta[%d].lba = %lu\n",
                  sm->sector, psn, DEV_META_BLANK);
        sm->dmeta[psn].lba = DEV_META_BLANK;
#ifdef PRINT_INFO
        sm_info("sm in cache, after set invalid: \n");
        print_shmeta(sm);
#endif
        invalid_num = 0;
        foreach_dev(dmeta, sm, i)
            if(dmeta->lba == DEV_META_BLANK)
                invalid_num++;
        
        dev_num = check_devmeta_num(sm);
#ifdef PRINT_INFO
        sm_info("invalid_num: %d, dev_num: %d\n", invalid_num, dev_num);
#endif
        set_bit(SM_DIRTY, &sm->flags);

        if(test_bit(SM_RECOMBINING, &sm->flags) ||
           test_bit(SM_HANDLE_BIO, &sm->flags) ||
           test_bit(SM_IN_RETRY, &sm->flags) ||
           test_bit(SM_RECLAIMING, &sm->flags) ||
           test_bit(SM_IN_PARTICLE, &sm->flags) || 
           meta->blank_sm_avail == sm)
            return true;
        else if(test_bit(SM_IN_RECLAIM_LIST, &sm->flags))
        {
            if(invalid_num == devnum)
            {                
                DEL_SM_RECLAIM_LIST_WITH_LOCK(meta, sm);
                insert_blank_shmeta(meta, sm);
            }
            else if(invalid_num < devnum)
            {
                spin_lock(&meta->reclaim_lists_lock);
                list_del_init(&sm->lru);
                list_add(&sm->lru, &meta->reclaim_lists[invalid_num - 1]);
                spin_unlock(&meta->reclaim_lists_lock);
                
#ifdef PRINT_INFO
                sm_info("move %lu with flags %lu to reclaim_list[%d], %p\n",
                        sm->sector, sm->flags, invalid_num - 1, sm);
#endif
            }
            else 
                sm_err("sector: %lu, disk: %d, invalid_num num ERROR: %d\n",
                       sh_sector, psn, invalid_num);
        }
        else
        {
            if(test_bit(SM_IN_INACTIVE, &sm->flags))
                DEL_SM_INACTIVE_LIST_WITH_LOCK(meta, sm)
            else if(test_bit(SM_IN_RECOMBINE, &sm->flags))
                DEL_SM_RECOMBINE_LIST_WITH_LOCK(meta, sm)
            else
            {
                sm_err("sector: %lu, disk: %d, flags: %lu\n", 
                       sh_sector, psn, sm->flags);
#ifdef PRINT_INFO
                print_shmeta(sm);
#endif
            }
            
            if(invalid_num == devnum)
                insert_blank_shmeta(meta, sm);
            else
                insert_reclaim_shmeta(meta, sm, invalid_num - 1);
        }
    }
    return true; 
}



void reclaim_shmetas(struct r5meta *meta)
{
    int i, j, count;
    unsigned short flag;
    struct shmeta *sm, *sm_t, *sm_temp;
    struct list_head *list;
    struct meta_data *mtd;

    if(meta == NULL || (mtd = meta->mtd) == NULL)
        return;


    j = count = 0; 
    flag = 0;
    sm = NULL;
    i = devnum - 2;
    list = &meta->reclaim_lists[i];
    sm_t = NULL;
    while(test_bit(MT_FORCE_RECLAIM, &meta->flags) && 
          (i >= 0 || (atomic_read(&meta->reclaim_in_bptree) > 0)))
    {
#ifdef PRINT_INFO
        sm_info("i = %d\n", i);
#endif
        if(test_bit(MT_WILL_STOP, &meta->flags))
        {
            return;
        }
        sm_t = NULL;
        if(list)
        {
            spin_lock(&meta->reclaim_lists_lock);
            if(!list_empty_careful(list))
            {
                sm_t = list_last_entry(list, struct shmeta, lru);
                if(!sm_t || !test_bit(SM_IN_RECLAIM_LIST, &sm_t->flags))
                {
                    sm_err("some wrong in reclaim_lists\n");
#ifdef PRINT_INFO
                    if(sm_t)
                        print_shmeta(sm_t);
#endif
                    INIT_LIST_HEAD(list);
                    i--;
                    if(i >= 0)
                        list = &meta->reclaim_lists[i];
                    else 
                        list = NULL;
                    spin_unlock(&meta->reclaim_lists_lock);
                    continue;
                }
#ifdef PRINT_INFO
                print_shmeta(sm_t);
#endif
                list_del_init(&sm_t->lru);
#ifdef PRINT_INFO
                sm_info("del sm %lu flags %lu from reclaim_list[%d]\n", 
                            sm_t->sector, sm_t->flags, i);
#endif
                atomic_dec(&meta->reclaim_lists_count);
                clear_bit(SM_IN_RECLAIM_LIST, &sm_t->flags);
                set_bit(SM_RECLAIMING, &sm_t->flags);
                spin_unlock(&meta->reclaim_lists_lock);
            }
            else
            {
#ifdef PRINT_INFO
                sm_info("init reclaim_lists[%d]\n", i);
#endif
                INIT_LIST_HEAD(list);
                i--;
                if(i >= 0)
                    list = &meta->reclaim_lists[i];
                else 
                    list = NULL;
                spin_unlock(&meta->reclaim_lists_lock);
                continue;
            }
        }

        if(!sm_t)
        {
            if(atomic_read(&meta->reclaim_in_bptree) > 0)
            {
                if((sm_t = load_reclaim_shmeta(meta)) == NULL)
                {
                    sm_err("load reclaim shmeta failed\n");
                    break;
                }
                set_bit(SM_RECLAIMING, &sm_t->flags);
            }
            else
                break;
        }
        
        flag = 0;
        for(j = 0; j < devnum; j++)
            if(sm_t->dmeta[j].lba != DEV_META_BLANK)
                set_flag(j, &flag);
        if(flag != 0)
            load_blocks_put_cache(meta, sm_t, flag);
        insert_blank_shmeta(meta, sm_t);

        clear_bit(SM_RECLAIMING, &sm_t->flags);

        if(test_bit(MT_WAIT_FOR_BLANK, &meta->flags))
        {
            set_bit(MT_GET_A_BLANK, &meta->flags);
            wake_up(&meta->wait_for_blank_shmeta);
            clear_bit(MT_WAIT_FOR_BLANK, &meta->flags);
        }
        if(test_bit(SM_UPDATE_WAIT_RECLAIM, &sm_t->flags))
            wake_up(&meta->wait_for_reclaim_queue);
        if(count++ >= devnum || test_bit(MT_FLUSH_ALL_PARTICLE, &meta->flags))
            break;
    }
    if(count == 0)
    {
        sm_err("no shmeta to reclaim!\n");
        set_bit(NO_SM_TO_RECLAIM, &meta->flags);
    }
#ifdef PRINT_INFO
    sm_info("reclaim shmeta finish\n");
#endif
    return;
}


static void r5m_reclaim_thread(struct md_thread *thread)
{
    struct mddev *mddev;
    struct r5meta *meta;
    struct cache_tree_data *ctd;

    if(!thread || 
       (mddev = thread->mddev) == NULL ||
       (ctd = mddev->ctd) == NULL ||
       (meta = ctd->cache_r5meta) == NULL)
    {
        rc_err("para NULL\n");
        return;
    }

    if(!test_bit(MT_FORCE_RECLAIM, &meta->flags)/* &&
       (atomic_read(&meta->reclaim_lists_count) < SM_RECLAIM_START || 
       ((atomic_read(&meta->blank_in_bptree) + atomic_read(&meta->cached_blank_shmeta))
        > SM_MIN_BLANK_STRIPE)) */)
    {
#ifdef PRINT_INFO
        sm_info("no need reclaim\n");
#endif
        clear_bit(MT_FORCE_RECLAIM, &meta->flags);
        clear_bit(MT_RECLAIMING, &meta->flags);
        set_bit(MT_RECLAIMED, &meta->flags);
        wake_up(&meta->wait_for_reclaim_queue);
        return;
    }
#ifdef PRINT_INFO
    sm_info("RECLAIM NOW!\n");
#endif
    set_bit(MT_RECLAIMING, &meta->flags);
    reclaim_shmetas(meta);
   
    clear_bit(MT_FORCE_RECLAIM, &meta->flags);
    clear_bit(MT_RECLAIMING, &meta->flags);
    set_bit(MT_RECLAIMED, &meta->flags);
#ifdef PRINT_INFO
    print_all_shmeta(meta);
#endif
    wake_up(&meta->wait_for_reclaim_queue);
    return;
}

void flush_all_shmeta(struct r5meta *meta)
{
    struct shmeta *sm;
    int hash;
    int i = 0, j, total = 0;
    struct devmeta *dm;
    struct list_head temp;
    struct meta_data *mtd;

    if(meta == NULL || 
       (mtd = meta->mtd) == NULL)
    {
        sm_err("meta or bitmap or mtd is NULL\n");
        return;
    }

    if(test_bit(MT_IN_FLUSH_RECLAIM, &meta->flags))
    {
#ifdef PRINT_INFO
        sm_info("reclaim flush metadata is running\n");
#endif
        wait_event(meta->wait_for_flush_queue, 
                   !test_bit(MT_IN_FLUSH_RECLAIM, &meta->flags));
#ifdef PRINT_INFO
        sm_info("wake up\n");
#endif
    }
    set_bit(MT_IN_FLUSH_METADATA, &meta->flags);

    INIT_LIST_HEAD(&temp);
    memset(meta->hash_list_size, 0, sizeof(int) * SM_FLUSH_HASH);

    while(i < SM_HASH_NUM_FOR_HASH_TABLE)
    {
#ifdef PRINT_INFO
        sm_info("i = %d\n", i);
#endif
        spin_lock(&meta->hashtbl_lock);
        while(!hlist_empty(&meta->hashtbl[i]))
        {
            sm = container_of(meta->hashtbl[i].first, struct shmeta, hash);
            if(!sm)
                break;
#ifdef PRINT_INFO
            print_shmeta(sm);
#endif
            hlist_del_init(&sm->hash);
            if(test_bit(SM_DIRTY, &sm->flags))
            {
                hash = FLUSH_HASH(sm->sector);
                meta->hash_list_size[hash]++;
                total++;
        
                if(sm->lba_align == DEV_META_BLANK)
                    sm->lba_align = transfer_stripe_sector_to_lba_align(meta, 
                                        sm->sector);

                foreach_dev(dm, sm, j)
                {
                    if(dm->bi_sector != DEV_META_BLANK)
                        if(dm->lba == DEV_META_BLANK)
                            dm->lba = dm->bi_sector;
                }
                ADD_SM_FLUSH_LIST_WITH_LOCK(meta, sm, hash);
            }
            else
            {
#ifdef PRINT_INFO
                sm_info("kfree shmeta %lu %p\n", sm->sector, sm);
#endif
                sm->flags = 0;
                kfree(sm);
            }
        }
        spin_unlock(&meta->hashtbl_lock);
        i++;
    }

    if(total == 0)
        return;

    flush_metadata_by_others(mtd);
         
#ifdef PRINT_INFO
    sm_info("begin to handle list\n");
#endif
    i = 0;
    while(i < SM_FLUSH_HASH)
    {
#ifdef PRINT_INFO
        sm_info("handle flush list: %d\n", i);
#endif
        spin_lock(&meta->flush_list_lock);
        while(!list_empty_careful(&meta->flush_list[i]))
        {
            sm = list_first_entry(&meta->flush_list[i], struct shmeta, lru);
            if(!sm || !test_bit(SM_IN_FLUSH, &sm->flags))
                break;
            list_del_init(&sm->lru);
            kfree(sm);
        }
        INIT_LIST_HEAD(&meta->flush_list[i]);
        i++;
        spin_unlock(&meta->flush_list_lock);
    }
    return;
}


void flush_shmeta(struct r5meta *meta)
{
    struct shmeta *sm;
    int hash;
    int i = 0, j, total = 0;
    struct devmeta *dm;
    struct list_head temp;
    struct meta_data *mtd;

    if(meta == NULL || 
       (mtd = meta->mtd) == NULL)
    {
        sm_err("meta or bitmap or mtd is NULL\n");
        return;
    }

    if(test_bit(MT_IN_FLUSH_RECLAIM, &meta->flags))
    {
#ifdef PRINT_INFO
        sm_info("reclaim flush metadata is running\n");
#endif
        wait_event(meta->wait_for_flush_queue, 
                   !test_bit(MT_IN_FLUSH_RECLAIM, &meta->flags));
#ifdef PRINT_INFO
        sm_info("wake up\n");
#endif
    }
    set_bit(MT_IN_FLUSH_METADATA, &meta->flags);

    INIT_LIST_HEAD(&temp);
    memset(meta->hash_list_size, 0, sizeof(int) * SM_FLUSH_HASH);

#ifdef PRINT_INFO
    sm_info("handle recombine_list\n");
#endif
    spin_lock(&meta->recombine_list_lock);
    while(!list_empty_careful(&meta->recombine_list))
    {
        sm = list_first_entry(&meta->recombine_list, struct shmeta, lru); 

        if(!sm || !test_bit(SM_IN_RECOMBINE, &sm->flags))
            break;
        list_del_init(&sm->lru);
        
#ifdef PRINT_INFO
        sm_info("del sm %lu flags %lu from recombined_list, %p\n", 
                        sm->sector, sm->flags, sm);
#endif

        spin_unlock(&meta->recombine_list_lock);
        atomic_dec(&meta->cached_recombined_shmeta);

        hash = FLUSH_HASH(sm->sector);
        meta->hash_list_size[hash]++;
        total++;
        
        if(sm->lba_align == DEV_META_BLANK)
            sm->lba_align = transfer_stripe_sector_to_lba_align(meta, 
                    sm->sector);

        foreach_dev(dm, sm, i)
        {
            if(dm->bi_sector != DEV_META_BLANK)
                if(dm->lba == DEV_META_BLANK)
                    dm->lba = dm->bi_sector;
        }
        clear_bit(SM_DIRTY, &sm->flags);
        clear_bit(SM_LOCKED, &sm->flags);
        clear_bit(SM_DYNAMIC_CHANGED, &sm->flags);
        ADD_SM_FLUSH_LIST_WITH_LOCK(meta, sm, hash);
        spin_lock(&meta->recombine_list_lock);
    }
    INIT_LIST_HEAD(&meta->recombine_list);
    spin_unlock(&meta->recombine_list_lock);


#ifdef PRINT_INFO
    sm_info("handle inactive_list[dirty]\n");
#endif
    spin_lock(&meta->inactive_list_lock);
    while(!list_empty_careful(&meta->inactive_list[SM_INACTIVE_LIST_NUM]))
    {
        sm = list_first_entry(&meta->inactive_list[SM_INACTIVE_LIST_NUM], 
                            struct shmeta, lru); 
        if(!sm || !test_bit(SM_IN_INACTIVE, &sm->flags))
            break;
        list_del_init(&sm->lru);
#ifdef PRINT_INFO
        sm_info("del sm %lu flags %lu from inactive_list[%d], %p\n", 
                        sm->sector, sm->flags, SM_INACTIVE_LIST_NUM, sm);
#endif

        spin_unlock(&meta->inactive_list_lock);
        atomic_dec(&meta->cached_inactive_shmeta);

        hash = FLUSH_HASH(sm->sector);
        meta->hash_list_size[hash]++;
        total++;
 
        if(sm->lba_align == -1)
            sm->lba_align = transfer_stripe_sector_to_lba_align(meta, 
                    sm->sector);
     
        clear_bit(SM_DIRTY, &sm->flags);
        clear_bit(SM_LOCKED, &sm->flags);
        clear_bit(SM_DYNAMIC_CHANGED, &sm->flags);
        ADD_SM_FLUSH_LIST_WITH_LOCK(meta, sm, hash);
        spin_lock(&meta->inactive_list_lock);
    }
    spin_unlock(&meta->inactive_list_lock);

#ifdef PRINT_INFO
    print_all_shmeta(meta);
#endif

#ifdef FLUSH_BLANK_SHMETA       
    // sm_info("handle blank_list\n");
    spin_lock(&meta->blank_list_lock);
    while( !list_empty_careful(&meta->blank_list) )
    {
        sm = list_first_entry(&meta->blank_list, struct shmeta, lru); 
        if(!sm || !test_bit(SM_BLANK, &sm->flags))
            break;
        list_del_init(&sm->lru);
        if(test_bit(SM_DIRTY, &sm->flags))
        {
            if(sm->lba_align == -1)
                sm->lba_align = transfer_stripe_sector_to_lba_align(meta, 
                    sm->sector);

            hash = FLUSH_HASH(sm->sector);
            atomic_dec(&meta->cached_blank_shmeta);
            meta->hash_list_size[hash]++;
            total++;
            clear_bit(SM_DYNAMIC_CHANGED, &sm->flags);
            clear_bit(SM_LOCKED, &sm->flags);
            clear_bit(SM_DIRTY, &sm->flags);
            
            // sm_info("del sm %lu flags %lu from blank_list, %p\n", 
            //             sm->sector, sm->flags, sm);

            ADD_SM_FLUSH_LIST_WITH_LOCK(meta, sm, hash);
        }
        else
            list_add(&sm->lru, &temp);
    }
    INIT_LIST_HEAD(&meta->blank_list);
    if(!list_empty_careful(&temp))
        list_splice(&temp, &meta->blank_list);
    spin_unlock(&meta->blank_list_lock);
#endif

    if(total == 0)
        return;

    i = 0;
    while(i < SM_FLUSH_HASH)
    {
        //sm_info("hash: %d, size: %d\n", i, meta->hash_list_size[i]);
        i++;
    }
    flush_metadata_by_others(mtd);
         
#ifdef PRINT_INFO
    sm_info("begin to handle list\n");
#endif
    i = 0;
    while(i < SM_FLUSH_HASH)
    {
#ifdef PRINT_INFO
        sm_info("handle flush list: %d\n", i);
#endif
        spin_lock(&meta->flush_list_lock);
        while(!list_empty_careful(&meta->flush_list[i]))
        {
            sm = list_first_entry(&meta->flush_list[i], struct shmeta, lru);
            if(!sm || !test_bit(SM_IN_FLUSH, &sm->flags))
                break;
            list_del_init(&sm->lru);
            atomic_dec(&meta->cached_flush_shmeta);
            clear_bit(SM_IN_FLUSH, &sm->flags);
#ifdef PRINT_INFO
            sm_info("del sm %lu flags %lu in flush_list[%d], %p\n", 
                        sm->sector, sm->flags, i, sm);
#endif

            spin_unlock(&meta->flush_list_lock);

            if(test_bit(SM_DEAD, &sm->flags))
            {
                sm_err("kfree DEAD sm: %lu with flags %lu\n", 
                       sm->sector, sm->flags);
                sm->flags = 0;
                ADD_SM_FREE_LIST_WITH_LOCK(meta, sm);
                //kfree(sm);
                atomic_dec(&meta->cached_flush_shmeta);
                spin_lock(&meta->flush_list_lock);
                continue;
            }
#ifdef FLUSH_BLANK_SHMETA
            else if(test_bit(SM_BLANK, &sm->flags))
                insert_blank_shmeta(meta, sm);
#endif
            else if(test_bit(SM_IN_RECOMBINE, &sm->flags)) 
            {
                clear_bit(SM_IN_RECOMBINE, &sm->flags);
                CLEAR_BI_SECTOR(sm, j);
                
                int m = shmeta_lbas(sm);
                clear_bit(SM_IN_INACTIVE, &sm->flags);
                if(m == devnum)
                    ADD_SM_INVALID_LIST_WITH_LOCK(meta, sm)
                else if(m > 0)
                    insert_reclaim_shmeta(meta, sm, devnum - m - 1);
                else 
                    insert_blank_shmeta(meta, sm);
            }
            else if(test_bit(SM_IN_INACTIVE, &sm->flags)) 
            {
                int m = shmeta_lbas(sm);
                clear_bit(SM_IN_INACTIVE, &sm->flags);
                if(m == devnum)
                    ADD_SM_INVALID_LIST_WITH_LOCK(meta, sm)
                else if(m > 0)
                    insert_reclaim_shmeta(meta, sm, devnum - m - 1);
                else 
                    insert_blank_shmeta(meta, sm);
            }
            else
            {
                sm_err("strange state %lu in stripe %lu, %p\n", 
                        sm->flags, sm->sector, sm);
                break;
            }
            set_bit(SM_WRITTEN, &sm->flags);
            spin_lock(&meta->flush_list_lock);
        }
        INIT_LIST_HEAD(&meta->flush_list[i]);
        i++;
        spin_unlock(&meta->flush_list_lock);
    }
    clear_bit(MT_IN_FLUSH_METADATA, &meta->flags);
    wake_up(&meta->wait_for_flush_queue);
#ifdef PRINT_INFO
    sm_info("return r5m_flush_thread\n");
#endif
    return;
}




void recombine_shmeta(struct r5meta *meta)
{
    int z = 0, datanum;
    struct shmeta *sm, *sm_t;
    sector_t last_recombine_shmeta = -1;
    struct devmeta *dev;

    if(!meta)
    {
        sm_err("NULL meta\n");
        return;
    }

#ifdef PRINT_INFO
    sm_info("\n");
#endif
    sm = sm_t = NULL;

    spin_lock(&meta->particle_list_lock);
    while(!list_empty_careful(&meta->particle_list))
    {
        sm_t = list_first_entry(&meta->particle_list, struct shmeta, lru);

        if(!sm_t || !test_bit(SM_IN_PARTICLE, &sm_t->flags))
        {
            spin_unlock(&meta->particle_list_lock);
            break;
        }

        DEL_SM_PARTICLE_LIST_WITHOUT_LOCK(meta, sm_t);
        spin_unlock(&meta->particle_list_lock);
        set_bit(SM_RECOMBINING, &sm_t->flags);
        if(last_recombine_shmeta == sm_t->sector)
        {
            ADD_SM_RETRY_LIST_WITHOUT_LOCK(meta, sm_t);
            continue;
        }
    
        if(sm == NULL)
        {
            sm = sm_t;
            if(sm && !test_bit(SM_LOCKED, &sm->flags))
            {
                if(!list_empty_careful(&meta->locked_list))
                {
                    spin_lock(&meta->locked_list_lock);
                    sm_t = list_first_entry(&meta->locked_list, 
                                            struct shmeta, lru);
                    list_del_init(&sm_t->lru);
#ifdef PRINT_INFO
                    sm_info("del sm %lu flags %lu in locked_list, %p\n", 
                        sm->sector, sm->flags, sm);
#endif

                    atomic_dec(&meta->cached_locked_shmeta);
                    clear_bit(SM_IN_LOCKED, &sm_t->flags);
                    spin_unlock(&meta->locked_list_lock);
                    goto get_recombine;
                }
            }
        }
        else 
        {
get_recombine:
            sm = recombine_2_shmeta(meta, sm, sm_t, false);
            if(sm && check_devmeta_num(sm) == devnum)
            {
                clear_bit(SM_RECOMBINING, &sm->flags);
                clear_bit(SM_BLANK, &sm->flags);
#ifdef PRINT_INFO
                print_shmeta(sm);
#endif
                set_bit(SM_WRITTEN, &sm->flags);
                ADD_SM_RECOMBINE_WITH_LOCK(meta, sm);
                CLEAR_BI_SECTOR(sm, z);
                
                RETURN_FULL_VFD(meta, sm, devnum);
                sm->vfd = NULL;
                sm = sm_t = NULL;
            }
        }
        spin_lock(&meta->particle_list_lock);
    }

    INIT_LIST_HEAD(&meta->particle_list);
#ifdef PRINT_INFO
    sm_info("after recombine particle:\n");
#endif
    if(sm)
    {
        datanum = 0;
        for(z = 0; z < devnum; z++)
            if(sm->dmeta[z].bi_sector != DEV_META_BLANK)
                datanum++;
        if(datanum == devnum)
        {
            put_full_stripe_to_blank_stripe(meta, sm, datanum);
        }
        else 
        {
            clear_bit(SM_RECOMBINING, &sm->flags);
            ADD_SM_PARTICLE_WITHOUT_LOCK(meta, sm);
#ifdef PRINT_INFO
            print_shmeta(sm);
#endif
        }
    }
    spin_unlock(&meta->retry_list_lock);
    spin_unlock(&meta->particle_list_lock);
#ifdef PRINT_INFO
    print_all_shmeta(meta);
#endif
    if(meta->updating_vfd_blocks >= devnum)
        sm_err("updating_vfd_blocks = %d\n", meta->updating_vfd_blocks);
    return;
}



void r5m_read_thread(struct md_thread *thread)
{
    struct mddev *mdd;
    struct cache_tree_data *ctd;
    struct r5meta *meta;
    struct meta_bitmap *bitmap;
    sector_t new_logical_sector, new_sector, logical_address;
    struct shmeta *sm;
    int ddisk, pdisk, qdisk, load_result;
    struct devmeta *dm;
    struct read_unit *ru;
            
    if((thread) == NULL ||
       (mdd = thread->mddev) == NULL ||
       (ctd = mdd->ctd) == NULL ||
       (meta = ctd->cache_r5meta) == NULL || 
       (bitmap = meta->bitmap) == NULL)
    {
        sm_err("parameters NULL\n");
        if(meta)
        {
            clear_bit(MT_READING, &meta->flags);
            wake_up(&meta->wait_for_read_queue);
        }
        return;
    }
 
    set_bit(MT_READING, &meta->flags);
    spin_lock(&meta->read_list_lock);
    while(!list_empty_careful(&meta->read_list))
    {
        ru = list_first_entry(&meta->read_list, struct read_unit, lru);
        if(!ru)
            break;
        list_del_init(&ru->lru);
        spin_unlock(&meta->read_list_lock);

#ifdef BUG_READ
        sm_info("del ru->logical: %lu from read_list\n",
                ru->origin_read_adr);
#endif

        logical_address = ru->origin_read_adr;
        new_sector = compute_sector(meta, logical_address, 
                                    &ddisk, &pdisk, &qdisk);
#ifdef BUG_READ
        sm_info("READ: logical_address: %lu, new_sector: %lu,\
                ddisk: %d, pdisk: %d\n", 
                logical_address, new_sector, ddisk, pdisk);
#endif     
        sm = find_shmeta(meta, new_sector);
        if(!sm && !check_bitmap(bitmap, new_sector, DYNAMIC_BITMAP))
        {
            ru->new_read_adr = logical_address;
#ifdef BUG_READ
            sm_info("READ: sm: %lu logical: %lu is static stripe\n", 
                    new_sector, logical_address);
#endif     
            spin_lock(&meta->read_list_lock);
            continue;
        }
        if(!sm)
        {
            sm = get_active_shmeta(meta, new_sector, pdisk, qdisk);
            if(!sm)
            {
                sm_err("get shmeta failed\n");
                ru->new_read_adr = logical_address;
#ifdef BUG_READ
                sm_info("READ: sm: %lu logical: %lu get sm metadata failed\n", 
                         new_sector, logical_address);
#endif     
 
                spin_lock(&meta->read_list_lock);
                continue;
            }
            sm->sector = new_sector;
            sm->lba_align = transfer_stripe_sector_to_lba_align(meta, 
                                                            sm->sector);
            sm->pdisk = DEV_META_BLANK;
            
            load_result = load_sm_metadata_keep_bptree(meta, sm);
            if(load_result == META_DESTROYED) 
            {
                sm_err("load shmeta meta failed,or lso = -1\n");
#ifdef PRINT_INFO
                print_shmeta(sm);
#endif
                sm->sector = -1;
                clear_bit(SM_DIRTY, &sm->flags);
                    
                ru->new_read_adr = logical_address;
#ifdef BUG_READ
                sm_info("READ: sm: %lu logical: %lu get sm metadata META_DESTORYED\n", 
                         new_sector, logical_address);
#endif      
                ADD_SM_FREE_LIST_WITH_LOCK(meta, sm);
                spin_lock(&meta->read_list_lock);
                continue;
            }
            else if(load_result == META_IS_HANDLING_NOW) 
            {
                sm_err("read block %lu failed, some is handle meta\n",
                       logical_address);
                ADD_SM_FREE_LIST_WITH_LOCK(meta, sm);
                mdelay(10);
                spin_lock(&meta->read_list_lock);
                list_add_tail(&ru->lru, &meta->read_list);
                continue;    
            }


            int m = shmeta_lbas(sm);
            clear_bit(SM_IN_INACTIVE, &sm->flags);
            if(m == devnum)
                ADD_SM_INVALID_LIST_WITH_LOCK(meta, sm)
            else if(m > 0)
                insert_reclaim_shmeta(meta, sm, devnum - m - 1);
            else 
                insert_blank_shmeta(meta, sm);
        }
  
        dm = &sm->dmeta[ddisk];

        if(dm->lso == new_sector && dm->psn == ddisk)
        {
            ru->new_read_adr = logical_address;
#ifdef BUG_READ
            sm_info("new_read_adr = logical_address: %lu\n", logical_address);
            print_shmeta(sm);
#endif
 
        }
        else if(sm->dmeta[ddisk].lso == -1)
        {
#ifdef BUG_READ
            sm_info("lso == -1\n");
            print_shmeta(sm);
#endif
            ru->new_read_adr = logical_address;
        }
        else if(sm->dmeta[ddisk].lso != -2)
        {
            pdisk = compute_pdisk(meta, dm->lso);
            new_logical_sector = compute_new_logical_sector(meta, 
                                dm->lso, dm->psn, pdisk);
#ifdef BUG_READ
            if(sm)
                print_shmeta(sm);
            sm_info("logic block: %lu at stripe %lu, ddisk: %d, adr: %lu\n",
                    logical_address, dm->lso, dm->psn,
                    new_logical_sector);
#endif

            ru->new_read_adr = new_logical_sector;
        }
        else if(sm->dmeta[ddisk].lso == -2)
        {
            // TODO
            // READ PAGE IN REACLAIM
#ifdef BUG_READ
            sm_info("lso == -2\n");
            if(sm)
                print_shmeta(sm);
            sm_info("logic block: %lu at stripe %lu, ddisk: %d, adr: %lu\n",
                    logical_address, dm->lso, dm->psn,
                    new_logical_sector);
#endif

            ru->new_read_adr = logical_address;
        }
        spin_lock(&meta->read_list_lock);
    }
    INIT_LIST_HEAD(&meta->read_list);
    spin_unlock(&meta->read_list_lock);
    clear_bit(MT_READING, &meta->flags);
    wake_up(&meta->wait_for_read_queue);
    return;
}



sector_t get_new_logical_address(struct cache_tree_data *ctd, 
                                 sector_t logical_address)
{
    struct r5meta *meta;
    struct read_unit ru;
    sector_t new_logical_sector;

    if(ctd == NULL ||
       (meta = ctd->cache_r5meta) == NULL) 
    {
        sm_err("ctd NULL\n");
        return logical_address;
    }
    
    if(test_bit(MT_READING, &meta->flags))
    {
        wait_event(meta->wait_for_read_queue, !test_bit(MT_READING, &meta->flags));
#ifdef BUG_READ
        sm_info("wake up1, logical_address: %lu\n", logical_address);
#endif
    }
    set_bit(MT_READING, &meta->flags);

    ru.origin_read_adr = logical_address;
    ru.new_read_adr = -1;
    INIT_LIST_HEAD(&ru.lru);
    ADD_RU_READ_LIST_WITH_LOCK(meta, (&ru)); 

    set_bit(MT_READING, &meta->flags);
    md_wakeup_thread(meta->read_thread);
    wait_event(meta->wait_for_read_queue, !test_bit(MT_READING, &meta->flags));
#ifdef BUG_READ
    sm_info("wake up2, logical_address: %lu, new_logical_sector: %lu\n",
            logical_address, ru.new_read_adr);
#endif

    new_logical_sector = ru.new_read_adr;
    
    spin_lock(&meta->readed_list_lock);
    list_del_init(&ru.lru);
    spin_unlock(&meta->readed_list_lock);
    //new_logical_sector = logical_address;
    return new_logical_sector;
}


struct load_a_block_by_mddev_temp
{
    struct r5meta *meta;
    int flag;
};

static void load_a_block_by_mddev_endio(struct bio *bi)
{
    struct load_a_block_by_mddev_temp *pri = bi->bi_private;
    struct r5meta *meta = pri->meta;
    pri->flag = 1;
    wake_up(&meta->wait_for_load_a_block_finish);
    return;
}


bool load_a_block(struct r5meta *meta, struct page *p, 
                  unsigned long logical_sector, int ddisk)
{
    struct bio *bi;

    if(meta == NULL || p == NULL ||
       ddisk < 0 || ddisk >= devnum ||
       meta->md_bds[ddisk] == NULL)
    {
        sm_err("para NULL\n");
        return false;
    }

    if((bi = bio_alloc(GFP_NOIO, 2)) == NULL)
    {
        sm_err("bi create failed\n");
        return false;
    }

    bi->bi_iter.bi_sector = logical_sector;
#ifdef PRINT_INFO
    sm_info("bio sector: %lu\n", bi->bi_iter.bi_sector);
#endif

    bi->bi_rw = READ;
    bi->bi_bdev = meta->md_bds[ddisk]; 
    bio_add_page(bi, p, PAGE_SIZE, 0);
#ifdef PRINT_INFO
    sm_info("reclaim read dev %d sector %lu page %p begin\n", 
            ddisk, logical_sector, p);
#endif

    submit_bio_wait(bi->bi_rw, bi);
    
#ifdef PRINT_INFO
    sm_info("reclaim read dev %d sector %lu page %p finished\n", 
            ddisk, logical_sector, p);
#endif

    return true;
}


bool load_a_block_by_mddev(struct r5meta *meta, struct page *p, 
                  unsigned long logical_sector, int ddisk, int pdisk)
{
    struct bio *bi;
    struct load_a_block_by_mddev_temp *temp = kmalloc(sizeof(struct load_a_block_by_mddev_temp), GFP_KERNEL);
    temp->flag = 0;
    temp->meta = meta;
    
    struct cache_tree_data *ctd;
    struct mddev *mddev;
    if(meta == NULL || (ctd = meta->ctd) == NULL ||
       (mddev = ctd->mdd) == NULL)
        return;


    if(meta == NULL || p == NULL ||
       ddisk < 0 || ddisk >= devnum ||
       meta->md_bds[ddisk] == NULL)
    {
        sm_err("para NULL\n");
        return false;
    }

    if((bi = bio_alloc(GFP_NOIO, 2)) == NULL)
    {
        sm_err("bi create failed\n");
        return false;
    }

//#ifdef REMIANING_BLOCKS
    bi->bi_iter.bi_sector = compute_new_logical_sector(meta, logical_sector,
                        ddisk, pdisk) + ctd->remaining_sectors;
//#else
    // bi->bi_iter.bi_sector = compute_new_logical_sector(meta, logical_sector,
    //                                                   ddisk, pdisk);
//#endif

    bi->bi_rw = READ;
    bio_add_page(bi, p, PAGE_SIZE, 0);
    bi->bi_end_io = load_a_block_by_mddev_endio;
    sm_set_bi_stripes(bi, 1);
    bi->bi_private = temp;
#ifdef PRINT_INFO
    sm_info("bio sector: %lu, logical_sector: %lu\n", 
            bi->bi_iter.bi_sector, logical_sector);
#endif
    mddev->pers->make_request(mddev, bi);
    wait_event(meta->wait_for_load_a_block_finish, temp->flag == 1);
#ifdef PRINT_INFO
    sm_info("finished! bio sector: %lu, logical_sector: %lu\n", 
            bi->bi_iter.bi_sector, logical_sector);
#endif

    kfree(temp);
    return true;
}



bool load_blocks_put_cache(struct r5meta *meta, struct shmeta *sm, 
                           unsigned short flag)
{
    struct vdisk_flush_data *vfd = NULL;
    struct cache_tree_data *ctd = NULL;
    struct page *p;
    int ddisk, pdisk, qdisk, i, j;
    struct shmeta *sm_ori;
    struct devmeta *dm;
    sector_t stripe_lba = 0;
    struct mddev *mdd;

    struct vdisk_flush_data *vfds[16] = {NULL};
    int pages = 0;
    int point = 0;

#ifdef PRINT_INFO
    sm_info("sm->sector: %lu, flag: %u\n", sm->sector, flag);
#endif

    if(!meta || !sm || (ctd = meta->ctd) == NULL ||
       (mdd = ctd->mdd) == NULL)
    {
        sm_err("para NULL\n");
        return false;
    }

    //struct cache_pool *pool = ctd->pool;
    ddisk = pdisk = qdisk = i = j = 0;

    for(i = 0; i < devnum; i++)
    {
        if(!check_flag(i, &flag))
            continue;
#ifdef PRINT_INFO
        sm_info("ready to read sm %lu block %d(%lu)\n", 
                sm->sector, i, sm->dmeta[i].lba);
#endif

        p = alloc_page(GFP_KERNEL);
#ifdef SM_META_IN_MDDEV 
        if(!load_a_block_by_mddev(meta, p, sm->sector, i, sm->pdisk))
#else
        if(!load_a_block(meta, p, sm->sector, i))
#endif
        {
            sm_err("load block %d at sm %lu wrong\n",
                  i, sm->sector);
#ifdef PRINT_INFO
            sm_info("free page: %p\n", vfd->dev[i].sector, p);
#endif
            __free_page(p);
            p = NULL;
            // kfree(vfd);
            return_vfd(mdd, vfd);
            return false;
        }
        dm = &sm->dmeta[i];
        if(dm->lba != -1 &&(dm->lso != sm->sector || dm->psn != i))
        {
            stripe_lba = compute_sector(meta, dm->lba, &ddisk, &pdisk, &qdisk);
            if((sm_ori = set_mapping_invalid(meta, stripe_lba, ddisk, sm->sector)) == NULL)
                return false;
            
            vfd = NULL;
            for(j = 0; j < point; j++)
                if(vfds[j] && vfds[j]->lba_align == sm_ori->lba_align)
                    vfd = vfds[j];

            if(!vfd)
            {
                vfd = get_a_vfd(mdd);
                vfd->lba_align = sm_ori->lba_align;
                vfds[point] = vfd;
                point++;
            }
            vfd->dev[ddisk].sector = dm->lba;
            vfd->dev[ddisk].dirty = 33;
            vfd->dev[ddisk].page = p;
            vfd->dev[ddisk].offset = 0;
            vfd->dev[ddisk].length = PAGE_SIZE;
            vfd->dev[ddisk].cdev = NULL;
            pages++;
        }
        else
        {
            if(dm->lso != -1 && dm->lso != -2 && (dm->lso != sm->sector || dm->psn != i))
            {
                stripe_lba = compute_sector(meta, dm->lba, &ddisk, &pdisk, &qdisk);
                if((sm_ori = set_mapping_invalid(meta, stripe_lba, ddisk, sm->sector)) == NULL)
                    return false;
            }

            vfd = NULL;
            for(j = 0; j < point; j++)
                if(vfds[j] && vfds[j]->lba_align == sm->lba_align)
                    vfd = vfds[j];

            if(!vfd)
            {
                vfd = get_a_vfd(mdd);
                vfd->lba_align = sm->lba_align;
                vfds[point] = vfd;
                point++;
            }

            sm->dmeta[i].lso = DEV_RECLAIMING;    
            vfd->dev[i].sector = dm->lba;
            vfd->dev[i].dirty = 33;
            vfd->dev[i].page = p;
            vfd->dev[i].offset = 0;
            vfd->dev[i].length = PAGE_SIZE;
            vfd->dev[i].cdev = NULL; 
            pages++;
        }
#ifdef PRINT_INFO
        sm_info("end to read sm %lu block %d\n", sm->dmeta[i].lba, i);
#endif
        sm->dmeta[i].lba = DEV_META_BLANK;
    }  

    for(j = 0; j < point; j++)
    {
        if((vfd = vfds[j]) != NULL)
        {
            if(test_bit(MT_WILL_STOP, &meta->flags))
            {
                /*
                spin_lock(&ctd->flush_all_vfds_list_lock);
                atomic_inc(&ctd->flush_all_vfds_count);
                list_add(&vfd->dirty_list_entry, &ctd->flush_all_vfds_list);
                spin_unlock(&ctd->flush_all_vfds_list_lock);
                */
            }
            else
            {
                spin_lock(&ctd->reclaim_vfds_list_lock);
                list_add_tail(&vfd->lru, &ctd->reclaim_vfds_list);
                atomic_inc(&ctd->reclaim_vfds_count);
                spin_unlock(&ctd->reclaim_vfds_list_lock);
#ifdef PRINT_INFO
                sm_info("add vfd %lu to cache\n", vfd->lba_align);
#endif
            }
        }   
    }
    /*
    while(pages)
    {
        atomic_inc(&ctd->flush_all_vfds_pages);
        pages--;
    }
    */
    md_wakeup_thread(mdd->thread_flush);
    return true;
}


struct shmeta *put_full_stripe_to_blank_stripe(struct r5meta *meta, 
                                              struct shmeta *sm, int datanum)
{
    int j = 0;
    struct shmeta *sm_new = NULL;
    struct devmeta *dm = NULL, *dm_new = NULL;
    struct vdisk_flush_data *vfd = NULL;

    if(!meta || !sm || !sm->vfd)
    {
        sm_err("para NULL\n");
        return NULL;
    }

    vfd = sm->vfd;
    if((sm_new = get_blank_shmeta(meta)) == NULL || 
        !test_bit(SM_BLANK, &sm_new->flags))
    {
        sm_err("no blank shmeta to use\n");
        ADD_SM_RETRY_LIST_WITH_LOCK(meta, sm);
#ifdef PRINT_INFO
        print_all_shmeta(meta);
#endif
        return NULL;
    }
#ifdef PRINT_INFO
    sm_info("\n-------------sm: \n");
    print_shmeta(sm);
    sm_info("-------------sm_blank: \n");
    print_shmeta(sm_new);
#endif
    // choose a dm to put the block
    sm->vfd = NULL;
    sm_new->vfd = vfd;
    if((vfd->lba_align = sm_new->lba_align) == DEV_META_BLANK)
        vfd->lba_align = sm_new->lba_align = 
                      transfer_stripe_sector_to_lba_align(meta, sm_new->sector);
    if(sm_new->pdisk < 0 || sm_new->pdisk > devnum)
        sm_new->pdisk = compute_pdisk(meta, sm_new->sector);
    for(j = 0; j < devnum; j++)
    {
        // 1108 if(vfd->dev[j].dirty != 1 || vfd->dev[j].dirty == 33)
        if(vfd->dev[j].dirty != 1 && vfd->dev[j].dirty != 33)
            continue;
        dm = &sm->dmeta[j];
        dm_new = &sm_new->dmeta[j];
        if(dm_new->bi_sector == DEV_META_BLANK &&
           dm_new->lba == DEV_META_BLANK)
        {
            if(dm->lso != DEV_META_BLANK )
            {
                if(dm->lso == DEV_RECLAIMING)
                    dm->lso = DEV_META_BLANK;
                else
                {
                    if(dm->lso == sm->sector)
                        sm->dmeta[dm->psn].lba = DEV_META_BLANK;
                    else if(dm->lso == sm_new->sector)
                        sm_new->dmeta[dm->psn].lba = DEV_META_BLANK;
                    else
                        set_block_invalid(meta, dm->lso, dm->psn);
                }    
            }   
            dm->lso = sm_new->sector;
            dm->psn = j;
            dm_new->lba = dm_new->bi_sector = vfd->dev[j].sector;
            sm_new->times++;
        }
        else
            sm_err("dm_new->bi_sector = %lu, dm_new->lba = %lu\n",
                  dm_new->bi_sector, dm_new->lba);
        vfd->dev[j].sector = compute_new_logical_sector(meta, 
                                    sm_new->sector, j, sm_new->pdisk);
        dm->bi_sector = DEV_META_BLANK;
    }

    sm->vfd = NULL;
    sm_new->vfd = vfd;

    // handle sm
    clear_bit(SM_IN_PARTICLE, &sm->flags);
    clear_bit(SM_RECOMBINING, &sm->flags);
    clear_bit(SM_HANDLE_BIO, &sm->flags);
    j = shmeta_lbas(sm);
    if(j == 0)
        insert_blank_shmeta(meta, sm);
    else if(j < devnum)
        insert_reclaim_shmeta(meta, sm, devnum - j - 1);
    else
        ADD_SM_INVALID_LIST_DIRTY_WITH_LOCK(meta, sm);
   
    // handle sm_new
    clear_bit(SM_BLANK, &sm_new->flags);
    set_bit(SM_WRITTEN, &sm_new->flags);
    ADD_SM_RECOMBINE_WITH_LOCK(meta, sm_new);
    RETURN_FULL_VFD(meta, sm_new, datanum);

    set_bit(SM_DIRTY, &sm_new->flags); 
#ifdef PRINT_INFO
    sm_info("\nOVER-------------sm: \n");
    print_shmeta(sm);
    sm_info("OVER-------------sm_blank: \n");
    print_shmeta(sm_new);
#endif

    return sm_new;
}


bool handle_stripe_in_particle_list(struct r5meta *meta, 
                    struct shmeta *sm, struct vdisk_flush_data *vfd)
{
    int i = 0, j = 0;
    struct shmeta *sm_new = NULL;
    struct devmeta *dm, *dm_new;
    sector_t logical_sector;
    struct vdisk_flush_data *vfd_new;
    struct mddev *mddev;
    struct cache_tree_data *ctd;

#ifdef PRINT_INFO
    print_vfd(vfd);
    print_shmeta(sm);
#endif
    if(!meta || !sm || !vfd ||
       (ctd = meta->ctd) == NULL ||
       (mddev = ctd->mdd) == NULL)
    {
        sm_err("pare NULL\n");
        return false;
    }

    for(i = 0; i < devnum; i++)
    {
        // handle written blocks
        if(vfd->dev[i].dirty != 1 &&
           vfd->dev[i].dirty != 33)
            continue;
        if(vfd->dev[i].dirty == 33)
        {
            if(sm->dmeta[i].lso != DEV_RECLAIMING)
            {
                vfd->dev[i].dirty = -1;
#ifdef PRINT_INFO
                sm_info("free page: %lu %p\n", vfd->dev[i].sector, vfd->dev[i].page);
#endif
                __free_page(vfd->dev[i].page);
                vfd->dev[i].page = NULL;
                vfd->dev[i].cdev = NULL;
                CHANGE_VFD_BLOCKS(meta, -1);
                continue;
            }
            else
            {
                sm->dmeta[i].lso = DEV_META_BLANK;
                sm->dmeta[i].psn = DEV_META_BLANK;
            }
        }
        logical_sector = vfd->dev[i].sector;
        dm = sm->dmeta + i;
#ifdef PRINT_INFO
        sm_info("logical: %lu, dm->sector: %lu, i: %d\n",
                logical_sector, dm->lba, i);
#endif


        if(dm->bi_sector != DEV_META_BLANK && 
            dm->bi_sector != logical_sector)
        {
            spin_lock(&meta->blank_sm_avail_lock);
            if(meta->blank_sm_avail == NULL)
                meta->blank_sm_avail = get_blank_shmeta(meta);
            sm_new = meta->blank_sm_avail;
            if(sm_new == NULL || 
               !test_bit(SM_BLANK, &sm_new->flags))
            {
                sm_err("no blank shmeta to use\n");
#ifdef PRINT_INFO
                print_all_shmeta(meta);
#endif
                spin_unlock(&meta->blank_sm_avail_lock);
                return false;
            }
    
#ifdef PRINT_INFO
            sm_info("sm: %lu, dm->bi: %lu, bi: %lu, blank: %lu\n", 
                    sm->sector, dm->bi_sector, logical_sector, sm_new->sector);
 
            sm_info("sm: \n");
            print_shmeta(sm);
            sm_info("sm_blank: \n");
            print_shmeta(sm_new);
#endif

            // choose a dm to put the block
            foreach_dev(dm_new, sm_new, j)
            {
                if(dm_new->bi_sector == DEV_META_BLANK)
                {
                    if(dm->lso == DEV_RECLAIMING)
                        dm->lso = DEV_META_BLANK;
                    else if(dm->lso != DEV_META_BLANK)
                    {
                        if(dm->lso == sm->sector)
                            sm->dmeta[dm->psn].lba = DEV_META_BLANK;
                        else if(dm->lso == sm_new->sector)
                            sm_new->dmeta[dm->psn].lba = DEV_META_BLANK;
                        else
                            set_block_invalid(meta, dm->lso, dm->psn);
                        dm->lso = sm_new->sector;
                        dm->psn = j;
                        dm_new->bi_sector = logical_sector;
                        sm_new->times++;
                        set_bit(SM_LOCKED, &sm_new->flags);
                        set_bit(SM_DIRTY, &sm_new->flags);
                    }
					break;
                }
            }
#ifdef PRINT_INFO
            sm_info("after merge:\n");
            sm_info("sm: \n");
            print_shmeta(sm);
            sm_info("sm_blank: \n");
            print_shmeta(sm_new);
#endif

            // change vfd sector
            if(sm_new->vfd == NULL)
                sm_new->vfd = vfd;
            vfd_new = sm_new->vfd;
            if(vfd_new->dev[j].dirty != 1 && vfd_new->dev[j].dirty != 33)
            {
                vfd_new->dev[j].page = vfd->dev[i].page;
                vfd_new->dev[j].cdev = vfd->dev[i].cdev;
                vfd_new->dev[j].dirty = vfd->dev[i].dirty;
                vfd_new->dev[j].offset = vfd->dev[i].offset;
                vfd_new->dev[j].length = vfd->dev[i].length;
                vfd_new->dev[j].sector = compute_new_logical_sector
                        (meta, sm_new->sector, j, sm_new->pdisk);
                vfd->dev[i].page = NULL;
                vfd->dev[i].cdev = NULL;
                vfd->dev[i].dirty = -1;
            }

            if(check_devmeta_num(sm_new) == devnum)
            {
                clear_bit(SM_BLANK, &sm_new->flags);
                set_bit(SM_WRITTEN, &sm_new->flags);
                ADD_SM_RECOMBINE_WITH_LOCK(meta, sm_new);
                RETURN_FULL_VFD(meta, sm_new, devnum);
                if(sm_new == meta->blank_sm_avail)
                    meta->blank_sm_avail = NULL;
                sm_new = NULL;
            }
            spin_unlock(&meta->blank_sm_avail_lock);
        }
        else
        {
            dm->bi_sector = logical_sector;
            set_bit(SM_DIRTY, &sm->flags);
            vfd_new = sm->vfd;
            if(vfd_new != NULL)
            {
                if(vfd_new->dev[i].page != NULL)
                {
#ifdef PRINT_INFO
                    sm_info("free page: %lu %p\n", vfd_new->dev[i].sector, vfd_new->dev[i].page);
#endif
                    __free_page(vfd_new->dev[i].page);
                    CHANGE_VFD_BLOCKS(meta, -1);
                }
                if(sm->dmeta[i].lso != -1 && sm->dmeta[i].lso != -2)
                    set_block_invalid(meta, sm->dmeta[i].lso, sm->dmeta[i].psn);

                vfd_new->dev[i].sector = vfd->dev[i].sector;
                vfd_new->dev[i].page = vfd->dev[i].page;
                vfd_new->dev[i].cdev = vfd->dev[i].cdev;
                vfd_new->dev[i].dirty = vfd->dev[i].dirty;
                vfd_new->dev[i].offset = vfd->dev[i].offset;
                vfd_new->dev[i].length = vfd->dev[i].length;
 
                vfd->dev[i].page = NULL;
                vfd->dev[i].cdev = NULL;
                vfd->dev[i].dirty = -1;
            }
            else 
                sm_err("sm->vfd == NULL\n");
        }
    }

    clear_bit(SM_HANDLE_BIO, &sm->flags);
    int k = check_devmeta_num(sm);
    if(sm)
    {
        if(k == devnum)
        {
            DEL_SM_PARTICLE_LIST_WITH_LOCK(meta, sm);
            set_bit(SM_WRITTEN, &sm->flags);
            ADD_SM_RECOMBINE_WITH_LOCK(meta, sm);
            RETURN_FULL_VFD(meta, sm, devnum);
        } 
        else if(k == 0)
        {
            DEL_SM_PARTICLE_LIST_WITH_LOCK(meta, sm);
            j = shmeta_lbas(sm);
            if(j == 0)
                insert_blank_shmeta(meta, sm);
            else if(j < devnum)
                insert_reclaim_shmeta(meta, sm, devnum - j - 1);
            else
                ADD_SM_INVALID_LIST_DIRTY_WITH_LOCK(meta, sm);
        }
    }

    if(meta->blank_sm_avail != NULL)
    {
        ADD_SM_PARTICLE_WITH_LOCK(meta, meta->blank_sm_avail);
        meta->blank_sm_avail = NULL;
    }

    j = 0;
    for(i = 0; i < devnum; i++)
        if(vfd->dev[i].dirty == 1 || vfd->dev[i].dirty == 33)
            j = 1;
#ifdef PRINT_INFO
    sm_info("kfree vfd?\n");
    print_shmeta(sm);
    print_vfd(vfd);
#endif

    if(j == 0)
    {
        // kfree(vfd);
        return_vfd(mddev, vfd);
    }
    return true;
}


void change_dynamic_stripe_to_static_stripe(struct r5meta *meta, 
                                            struct shmeta *sm, 
                                            struct vdisk_flush_data *vfd,
                                            //bool from_reclaim, 
                                            bool need_remove_hash,
                                            int datanum)
{
    int idx = 0;
    struct devmeta *dm;
    struct meta_bitmap *bitmap;
    struct metadata *mtd;

    if(!meta || !sm || !vfd ||
       (bitmap = meta->bitmap) == NULL ||
       (mtd = meta->mtd) == NULL)
    {
        sm_err("parameters NULL\n");
        return;
    }

    for(idx = 0; idx < devnum; idx++)
    {
        dm = &sm->dmeta[idx];
        if(dm->lso == DEV_RECLAIMING)
            dm->lso = DEV_META_BLANK;
        else if(dm->lso != DEV_META_BLANK && dm->lso != sm->sector)
        {
            struct page *p = alloc_page(GFP_KERNEL);
            int pdisk = compute_pdisk(meta, dm->lso);
            if(load_a_block_by_mddev(meta, p, dm->lso, dm->psn, pdisk))
            {
                vfd->dev[idx].page = p;
                vfd->dev[idx].dirty = 33;
                vfd->dev[idx].length = PAGE_SIZE;
                vfd->dev[idx].offset = 0;
                vfd->dev[idx].sector = compute_new_logical_sector(meta,
                                       sm->sector, idx, sm->pdisk);
 
#ifdef PRINT_INFO
                sm_info("load old page put vfd: lso: %lu. psn: %d, page: %p, sec: %lu\n",
                        dm->lso, dm->psn, p, vfd->dev[idx].sector);
                print_shmeta(sm);
#endif
            }
            else
                sm_err("load error!\n");

            set_block_invalid(meta, dm->lso, dm->psn);
        }
    }
    change_bitmap(bitmap, sm->sector, DYNAMIC_BITMAP, CLEAR);
    reset_metadata_zero(mtd, sm->sector, sm->lba_align);
    
    if(need_remove_hash)
        REMOVE_SHMETA_HASH(meta, sm, HASH(sm->sector));

    sm->sector = DEV_META_BLANK;
    ADD_SM_FREE_LIST_WITH_LOCK(meta, sm);
    RETURN_FULL_VFD(meta, sm, 0);
    return;
}



struct shmeta *del_sm_from_origin_list(struct r5meta *meta, struct shmeta *sm, 
                             bool will_kill)
{
    struct shmeta *replace, *sm_t;
retry_del_sm_from_origin_list:
    spin_lock(&meta->reclaim_lists_lock);
    if(test_bit(SM_RECLAIMING, &sm->flags))
    {
        set_bit(SM_UPDATE_WAIT_RECLAIM, &sm->flags);
        spin_unlock(&meta->reclaim_lists_lock);
        wait_event(meta->wait_for_reclaim_queue,
                   !test_bit(SM_RECLAIMING, &sm->flags));
        clear_bit(SM_UPDATE_WAIT_RECLAIM, &sm->flags);
    }
    else
        spin_unlock(&meta->reclaim_lists_lock);
    if(test_bit(SM_HANDLE_BIO, &sm->flags))
        return sm;
    else if(test_bit(SM_IN_FLUSH, &sm->flags)) 
    {
#ifdef PRINT_INFO
        sm_info("sm %lu in flush\n", sm->sector);
#endif
        replace = get_active_shmeta(meta, sm->sector, sm->pdisk, -1);
        if(replace)
        {
            copy_shmeta(replace, sm);
            REMOVE_SHMETA_HASH(meta, sm, HASH(sm->sector));
            INSERT_SHMETA_HASH(meta, replace, HASH(replace->sector));              
            set_bit(SM_DEAD, &sm->flags);
            clear_bit(SM_IN_FLUSH, &replace->flags);
            sm->vfd = NULL;
            sm = replace;
        }
        else
            sm_err("ori sm in flush & get replace failed: %lu\n",
                   sm->sector);
    }
    else if(test_bit(SM_IN_RECLAIM_LIST, &sm->flags))
        DEL_SM_RECLAIM_LIST_WITH_LOCK(meta, sm)
    else if(sm == meta->blank_sm_avail)
    {
#ifdef PRINT_INFO
        sm_info("sm == blank_sm_avail, %p\n", sm);
        print_shmeta(sm);
#endif
    }                
    else if(test_bit(SM_IN_RECOMBINE, &sm->flags)) 
        DEL_SM_RECOMBINE_LIST_WITH_LOCK(meta, sm)
    else if(test_bit(SM_IN_RETRY, &sm->flags))
        DEL_SM_RETRY_LIST_WITH_LOCK(meta, sm)
    else if(test_bit(SM_IN_INACTIVE, &sm->flags))
        DEL_SM_INACTIVE_LIST_WITH_LOCK(meta, sm)
    else if(test_bit(SM_BLANK, &sm->flags))
        DEL_SM_BLANK_LIST_WITH_LOCK(meta, sm)
    else
        sm_err("sm %lu with flags %lu\n", sm->sector, sm->flags);
    set_bit(SM_HANDLE_BIO, &sm->flags);
    return sm;
}


bool handle_full_dynamic_stripe(struct r5meta *meta, 
                            struct updating_shmeta *us)
{
    stripe_sec new_sector;
    struct shmeta *sm, *sm_new, *sm_temp;
    struct vdisk_flush_data *vfd;
    struct devmeta *dm;
    bool sm_in_kernel = true;
    int idx, datanum, other_sm_blocks;
    unsigned short flag;
    struct meta_bitmap *bitmap;
    int load_result;
    struct cache_tree_data *ctd;
    struct mddev *mddev;
  
    if(!meta || !us ||
       (bitmap = meta->bitmap) == NULL ||
       (ctd = meta->ctd) == NULL ||
       (mddev = ctd->mdd) == NULL)
    {
        sm_err("para NULL\n");
        return false;
    }
    
    idx = datanum = flag = other_sm_blocks = 0;
    new_sector = us->sector;
    datanum = us->datanum;
    vfd = us->vfd;
    sm = us->sm;
    sm_new = NULL;
#ifdef PRINT_INFO
    sm_info("handle stripe: %lu, lba_align: %lu\n", 
            new_sector, vfd->lba_align);

    print_vfd(vfd);
#endif

handle_full_dynamic_stripe_retry:
    if(sm == NULL)
        if((sm = find_shmeta(meta, new_sector)) != NULL &&
            !test_bit(SM_IN_PARTICLE, &sm->flags))
            del_sm_from_origin_list(meta, sm, false);

    // find shmeta in cache
    if(sm && test_bit(SM_IN_PARTICLE, &sm->flags))
    {
        CHANGE_VFD_BLOCKS(meta, datanum);
        ADD_US_UPDATED(meta, us);
        handle_stripe_in_particle_list(meta, sm, vfd);
        return true;
    }
    if(sm == NULL)
    {
#ifdef PRINT_INFO
        sm_info("sm is not in cache\n");
#endif
        if((sm = get_active_shmeta(meta, new_sector, -1, -1)) == NULL)
        {
            ADD_US_UPDATED(meta, us);
            sm_err("get_active_shmeta failed for sh %lu\n", new_sector);
            return false;
        }
        sm->sector = new_sector;
        sm->lba_align = vfd->lba_align;
        sm->pdisk = us->pdisk;
        
#ifdef PRINT_INFO
        sm_info("load_sm_metadata_keep_bptree\n");
#endif
        load_result = load_sm_metadata_keep_bptree(meta, sm);
        if(load_result == META_DESTROYED) 
        {
            if(check_bitmap(bitmap, new_sector, DYNAMIC_BITMAP))
            {
                ADD_US_UPDATED(meta, us);
                sm_err("load shmeta metadata failed, %p\n", sm);
                sm->sector = DEV_META_BLANK;
                ADD_SM_FREE_LIST_WITH_LOCK(meta, sm);
                return false;
            }
            else
            {
                ADD_US_UPDATED(meta, us);
                RETURN_VFD(meta, us->vfd, datanum);
                return true;
            }
        }
        else if(load_result == META_IS_HANDLING_NOW) 
        {
            sm_err("set stripe %lu, some is handle meta\n", new_sector);
            ADD_SM_FREE_LIST_WITH_LOCK(meta, sm);
            sm = NULL;
            goto handle_full_dynamic_stripe_retry;
        }
        sm_in_kernel = false;
    }
   
#ifdef PRINT_INFO
    if(sm != NULL)
        print_shmeta(sm);
#endif

    ADD_US_UPDATED(meta, us);
    datanum = 0;
    for(idx = 0; idx < devnum; idx++)
    {
        dm = &sm->dmeta[idx];
        if((dm->lba != DEV_META_BLANK && dm->lso != new_sector) ||
           (dm->bi_sector != DEV_META_BLANK && 
            dm->bi_sector != vfd->dev[idx].sector))
        {
            other_sm_blocks++;
            set_flag(idx, &flag);
        }

        if(vfd->dev[idx].dirty == 1)
        {
            if(dm->lso == DEV_META_BLANK)
                change_bitmap(bitmap, vfd->dev[idx].sector, WRITTEN_BITMAP, SET);
            else if(dm->lso == DEV_RECLAIMING)
                dm->lso = DEV_META_BLANK;
            else if(dm->lso == new_sector)
                dm->lba = -1;
            else
                set_block_invalid(meta, dm->lso, dm->psn);
            dm->lso = -1;
            dm->psn = -1;
            dm->bi_sector = vfd->dev[idx].sector;
            datanum++;
        }
        else if(vfd->dev[idx].dirty == 33)
        { 
            if(dm->lso == DEV_RECLAIMING)
            {
                dm->bi_sector = vfd->dev[idx].sector;
                datanum++;
            }
            else
            {
                if(vfd->dev[idx].page != NULL)
                {
#ifdef PRINT_INFO
                    sm_info("free page: %lu %p\n", 
                            vfd->dev[idx].sector, vfd->dev[idx].page);
#endif
                    __free_page(vfd->dev[idx].page);
                }
            }
        }
    }

    if(datanum == 0)
    {
        // kfree(vfd);
        return_vfd(mddev, vfd);
        datanum = shmeta_lbas(sm);

        if(datanum == 0)
            insert_blank_shmeta(meta, sm);
        else if(datanum < devnum)
            insert_reclaim_shmeta(meta, sm, devnum - datanum - 1);
        else if(test_bit(SM_DIRTY, &sm->flags))
        {
            ADD_SM_INVALID_LIST_DIRTY_WITH_LOCK(meta, sm);
        }
        else
        {
            ADD_SM_INVALID_LIST_WITH_LOCK(meta, sm);
        }
        return;
    }

    sm->vfd = vfd; 
    // handle vfd
    if(other_sm_blocks < ((devnum >> 1) + 1))
    {
        if(other_sm_blocks != 0)
            load_blocks_put_cache(meta, sm, flag);
        change_dynamic_stripe_to_static_stripe(meta, sm, vfd, 
                            /*from_reclaim,*/ true, datanum);
    }
    else
    {
        CHANGE_VFD_BLOCKS(meta, datanum);
        for(idx = 0; idx < devnum; idx++)
        {
            // 1108 if(vfd->dev[idx].dirty != 1 || vfd->dev[idx].dirty != 33)
            if(vfd->dev[idx].dirty != 1 && vfd->dev[idx].dirty != 33)
                continue;
            if(sm->dmeta[idx].lso == sm->sector)
            {
                sm->dmeta[idx].lba = DEV_META_BLANK;
                sm->dmeta[idx].lso = DEV_META_BLANK;
                sm->dmeta[idx].psn = DEV_META_BLANK;
            }
            else if(sm->dmeta[idx].lso != DEV_META_BLANK && 
                    sm->dmeta[idx].lso != DEV_RECLAIMING)
            {
                set_block_invalid(meta, sm->dmeta[idx].lso, sm->dmeta[idx].psn);
                sm->dmeta[idx].lso = DEV_META_BLANK;
                sm->dmeta[idx].psn = DEV_META_BLANK;
            }
        }
        if(datanum == devnum)
        {
            sm->vfd = vfd;
            sm_new = put_full_stripe_to_blank_stripe(meta, sm, datanum);
        }
        else
        {
            sm->vfd = vfd;
            clear_bit(SM_HANDLE_BIO, &sm->flags);
            ADD_SM_PARTICLE_WITH_LOCK(meta, sm);
        }
    }
#ifdef PRINT_INFO
    print_shmeta(sm);
#endif
    return true;
}


bool handle_particle_static_stripe(struct r5meta *meta, 
                            struct updating_shmeta *us)
{
    stripe_sec new_sector;
    struct shmeta *sm, *sm_new;
    struct vdisk_flush_data *vfd;
    struct devmeta *dm;
	struct meta_data *mtd;
    int i, datanum;
    bool written = false, new_get = false;
    struct meta_bitmap *bitmap;

    if(!meta || !us ||
       (mtd = meta->mtd) == NULL ||
       (bitmap = meta->bitmap) == NULL)
    {
        sm_err("para NULL\n");
        return false;
    }
    
    datanum = 0;
    new_sector = us->sector;
    vfd = us->vfd;
    sm = us->sm;
    sm_new = NULL;
#ifdef PRINT_INFO
    sm_info("\nhandle stripe: %lu, lba_align: %lu\n", 
            new_sector, vfd->lba_align);
#endif
    ADD_US_UPDATED(meta, us);

    if(!sm && (sm = find_shmeta(meta, new_sector) != NULL))
    {
        if(test_bit(SM_IN_PARTICLE, &sm->flags))
        {
            handle_stripe_in_particle_list(meta, sm, vfd);
            return true;
        }
        else
            del_sm_from_origin_list(meta, sm, false);
    }

    if(!sm && (sm = get_active_shmeta(meta, new_sector, -1, -1)) != NULL)
    {
        sm->sector = new_sector;
        sm->pdisk = us->pdisk;
        sm = compute_new_sector_reverse(meta, new_sector, sm);
        new_get = true;
    }

    if(!sm)
    {
        sm_err("sm is NULL\n");
        return false;
    }
           
#ifdef PRINT_INFO
    if(sm != NULL)
        print_shmeta(sm);
#endif


    for(i = 0; i < devnum; i++)
    {
        if(vfd->dev[i].dirty == 1)
        {
            dm = sm->dmeta + i;
            if(new_get)
            {
                if(check_and_set_bitmap(bitmap, vfd->dev[i].sector,
                                        WRITTEN_BITMAP))
                {
                    written = true;
                    set_bit(SM_WRITTEN, &sm->flags);
                }
                    dm->lba = DEV_META_BLANK;
                    dm->lso = DEV_META_BLANK;
                    dm->psn = DEV_META_BLANK;
            }
            dm->bi_sector = vfd->dev[i].sector;
            datanum++;
        }
        else if(vfd->dev[i].dirty == 33)
        {
            CHANGE_VFD_BLOCKS(meta, -1);
#ifdef PRINT_INFO
            sm_info("free page: %lu %p\n", vfd->dev[i].sector, vfd->dev[i].page);
#endif
            __free_page(vfd->dev[i].page);
            vfd->dev[i].dirty = 0;
            vfd->dev[i].page = NULL;
            vfd->dev[i].cdev = NULL;
        }
        else
        {
            if(new_get)
            {
                if(!check_bitmap(bitmap, sm->dmeta[i].lba, WRITTEN_BITMAP))
                {
                    sm->dmeta[i].lba = DEV_META_BLANK;
                    sm->dmeta[i].lso = DEV_META_BLANK;
                    sm->dmeta[i].psn = DEV_META_BLANK;
                }
                else if(!written) 
                {
                    written = true;
                    set_bit(SM_WRITTEN, &sm->flags);
                }
            }
        }
    }
    if(datanum == 0)
    {
        sm->sector = DEV_META_BLANK;
        ADD_SM_FREE_LIST_WITH_LOCK(meta, sm);
        return;
    }
    if(new_get)
        INSERT_SHMETA_HASH(meta, sm, HASH(sm->sector));
    sm->lba_align = vfd->lba_align;
    if(sm->vfd)
    {
        sm_err("sm vfd valid\n");
    }
    sm->vfd = vfd;
   
    change_bitmap(bitmap, new_sector, DYNAMIC_BITMAP, SET);

    clear_bit(SM_HANDLE_BIO, &sm->flags);
    ADD_SM_PARTICLE_WITH_LOCK(meta, sm);
#ifdef PRINT_INFO
    print_shmeta(sm);
#endif
    return true; 
}

bool handle_particle_dynamic_stripe(struct r5meta *meta, 
                            struct updating_shmeta *us)
{
    struct shmeta *sm, *sm_new;
    struct devmeta *dm;
    stripe_sec new_sector;
    struct vdisk_flush_data *vfd;
    struct meta_bitmap *bitmap;
    int i, valid_blocks = 0, load_result;
    bool removed = false;
    struct mddev *mddev;
    struct cache_tree_data *ctd;
   
    if(!meta || !us ||
       (bitmap = meta->bitmap) == NULL ||
       (ctd = meta->ctd) == NULL ||
       (mddev = ctd->mdd) == NULL)
    {
        sm_err("para NULL\n");
        return false;
    }
    
    new_sector = us->sector;
    vfd = us->vfd;
    sm = us->sm;
    sm_new = NULL;
#ifdef PRINT_INFO
    sm_info("handle stripe: %lu, lba_align: %lu\n", new_sector, vfd->lba_align);

    print_vfd(vfd);
#endif
handle_particle_dynamic_stripe_retry:
    if(sm == NULL)
        if((sm = find_shmeta(meta, new_sector)) != NULL && 
            !test_bit(SM_IN_PARTICLE, &sm->flags))
            del_sm_from_origin_list(meta, sm, false);

    if(sm == NULL)
    {
#ifdef PRINT_INFO
        sm_info("sm is not in cache\n");
#endif
        if((sm = get_active_shmeta(meta, new_sector, -1, -1)) == NULL)
        {
            sm_err("get_active_shmeta failed for sh %lu\n", new_sector);
            ADD_US_UPDATED(meta, us);
            return false;
        }
        sm->sector = new_sector;
        sm->lba_align = vfd->lba_align;
        sm->pdisk = us->pdisk;
                
#ifdef PRINT_INFO
        sm_info("load_sm_metadata_keep_bptree\n");
#endif
        load_result = load_sm_metadata_keep_bptree(meta, sm);
        if(load_result == META_DESTROYED) 
        {            
            if(check_bitmap(bitmap, new_sector, DYNAMIC_BITMAP) == true)
            {
                sm_err("load shmeta metadata failed, %p\n", sm);
                sm->sector = DEV_META_BLANK;
                ADD_SM_FREE_LIST_WITH_LOCK(meta, sm);
                ADD_US_UPDATED(meta, us);
                return false;
            }
            else
            {
                handle_particle_static_stripe(meta, us);
                return true;
            }
        }
        else if(load_result == META_IS_HANDLING_NOW) 
        {
            sm_err("set stripe %lu, some is handle meta\n", new_sector);
            ADD_SM_FREE_LIST_WITH_LOCK(meta, sm);
            sm = NULL;
            mdelay(10);
            goto handle_particle_dynamic_stripe_retry;
        }
   
#ifdef PRINT_INFO
    if(sm != NULL)
        print_shmeta(sm);
#endif


        sm->vfd = vfd;

        ADD_US_UPDATED(meta, us);

        set_bit(SM_DYNAMIC, &sm->flags); 
        set_bit(SM_WRITTEN, &sm->flags);

        if(shmeta_lbas(sm) == 0)
            set_bit(SM_BLANK, &sm->flags);
        
        i = 0;
        while(i < devnum)
        {
            dm = sm->dmeta + i;
            if(vfd->dev[i].dirty == 1)
            {
                valid_blocks++;
                dm->bi_sector = vfd->dev[i].sector;
                if(dm->lso == DEV_META_BLANK)
                    change_bitmap(bitmap, vfd->dev[i].sector, WRITTEN_BITMAP, SET);
                else if(dm->lso == sm->sector)
                {
                    dm->lba = DEV_META_BLANK;
                    dm->lso = DEV_META_BLANK;
                    dm->psn = DEV_META_BLANK;
                }
                else if(dm->lso == DEV_RECLAIMING)
                    dm->lso = DEV_META_BLANK;
                else if(dm->lso != DEV_RECLAIMING)
                {
                    set_block_invalid(meta, dm->lso, dm->psn);
                    dm->lso = DEV_META_BLANK;
                    dm->psn = DEV_META_BLANK;
                }
            }
            else if(vfd->dev[i].dirty == 33)
            {
                if(dm->lso == DEV_RECLAIMING)
                {
                    valid_blocks++;
                    dm->bi_sector = vfd->dev[i].sector;
                    // vfd->dev[i].dirty = 1;
                }
                else 
                {
                    CHANGE_VFD_BLOCKS(meta, -1);
#ifdef PRINT_INFO
                    sm_info("free page: %lu %p\n", vfd->dev[i].sector, vfd->dev[i].page);
#endif
                    __free_page(vfd->dev[i].page);
                    vfd->dev[i].page = NULL;
                    vfd->dev[i].cdev = NULL;
                    vfd->dev[i].dirty = -1;
                }
            }
            i++;
        }
        if(valid_blocks)
            ADD_SM_PARTICLE_WITH_LOCK(meta, sm)
        else
        {
            int j = shmeta_lbas(sm);
            if(j == 0)
                insert_blank_shmeta(meta, sm);
            else if(j < devnum)
                insert_reclaim_shmeta(meta, sm, devnum - j - 1);
            else
            {
                if(test_bit(SM_DIRTY, &sm->flags))
                {
                    ADD_SM_INVALID_LIST_DIRTY_WITH_LOCK(meta, sm);
                }
                else
                {
                    ADD_SM_INVALID_LIST_WITH_LOCK(meta, sm);
                }
            }
            sm->vfd = NULL;
            //kfree(vfd);
            return_vfd(mddev, vfd);
        }
#ifdef PRINT_INFO
        print_shmeta(sm);
#endif
    }
    else
    {   
#ifdef PRINT_INFO
        if(sm != NULL)
            print_shmeta(sm);
#endif


        ADD_US_UPDATED(meta, us);
        if(test_bit(SM_IN_PARTICLE, &sm->flags))
            handle_stripe_in_particle_list(meta, sm, vfd);
        else
        {
            for(i = 0; i < devnum; i++)
            {
                dm = sm->dmeta + i;
                if(vfd->dev[i].dirty == 1)
                {
                    valid_blocks++;
 
                    dm->bi_sector = vfd->dev[i].sector;
                    if(dm->lso == DEV_META_BLANK)
                        change_bitmap(bitmap, vfd->dev[i].sector, 
                                      WRITTEN_BITMAP, SET);
                    else if(dm->lso == sm->sector)
                    {
                        dm->lba = DEV_META_BLANK;
                        dm->lso = DEV_META_BLANK;
                        dm->psn = DEV_META_BLANK;
                    }
                    else if(dm->lso == DEV_RECLAIMING)
                        dm->lso = DEV_META_BLANK;
                    else if(dm->lso != DEV_RECLAIMING)
                    {
                        set_block_invalid(meta, dm->lso, dm->psn);
                        dm->lso = DEV_META_BLANK;
                        dm->psn = DEV_META_BLANK;
                    }
                }
                else if(vfd->dev[i].dirty == 33)
                {
                    if(dm->lso == DEV_RECLAIMING)
                    {
                        valid_blocks++;
                        dm->bi_sector = vfd->dev[i].sector;
                        // vfd->dev[i].dirty = 1;
                    }
                    else
                    {
                        CHANGE_VFD_BLOCKS(meta, -1);
#ifdef PRINT_INFO
                        sm_info("free page: %lu %p\n", vfd->dev[i].sector, vfd->dev[i].page);
#endif
                        __free_page(vfd->dev[i].page);
                        vfd->dev[i].page = NULL;
                        vfd->dev[i].cdev = NULL;
                        vfd->dev[i].dirty = -1;
                    }
                }
            }
            clear_bit(SM_HANDLE_BIO, &sm->flags);
            if(valid_blocks)
            {
                sm->vfd = vfd;
                ADD_SM_PARTICLE_WITH_LOCK(meta, sm);
            }
            else
            {
                sm->vfd = NULL;
                
                int j = shmeta_lbas(sm);
                if(j == 0)
                    insert_blank_shmeta(meta, sm);
                else if(j < devnum)
                    insert_reclaim_shmeta(meta, sm, devnum - j - 1);
                else
                {
                    if(test_bit(SM_DIRTY, &sm->flags))
                    {
                        ADD_SM_INVALID_LIST_DIRTY_WITH_LOCK(meta, sm);
                    }
                    else
                    {
                        ADD_SM_INVALID_LIST_WITH_LOCK(meta, sm);
                    }
                }
                // kfree(vfd);
                return_vfd(mddev, vfd);
            }
#ifdef PRINT_INFO
            print_shmeta(sm);
#endif
        }
    }
    return true;
}

void reclaim_stop(struct r5meta *meta)
{
    if (meta == NULL)
    {
        sm_err("meta is NULL\n");
        return;
    }

    if(NULL != meta->reclaim_thread)
    {
        if(test_bit(MT_RECLAIMING, &meta->flags))
        {
            wait_event(meta->wait_for_reclaim_queue, 
                       !test_bit(MT_RECLAIMING, &meta->flags));
        }
        md_unregister_thread(&meta->reclaim_thread);
        meta->reclaim_thread = NULL;
    }
    return;
}



struct shmeta *find_a_place(struct r5meta *meta)
{
    struct shmeta *sm = NULL;
    spin_lock(&meta->blank_list_lock);
    if(!list_empty_careful(&meta->blank_list))
    {
        sm = list_first_entry(&meta->blank_list, struct shmeta, lru);
        list_del_init(&sm->lru);
        atomic_dec(&meta->cached_blank_shmeta);
        spin_unlock(&meta->blank_list_lock);
        return sm;
    }
    spin_unlock(&meta->blank_list_lock);

    int i = devnum - 2;
    struct list_head *list;
    while(i >= 0)
    {
        list = &meta->reclaim_lists[i];
        spin_lock(&meta->reclaim_lists_lock);
        if(!list_empty_careful(list))
        {
            sm = list_last_entry(list, struct shmeta, lru);
            list_del_init(&sm->lru);
            atomic_dec(&meta->reclaim_lists_count);
            spin_unlock(&meta->reclaim_lists_lock);
            return sm;
        }
        spin_unlock(&meta->reclaim_lists_lock);
      
        i--;
    }
    sm = load_reclaim_shmeta(meta);
    return sm;
}

void flush_last_particle_shmeta(struct r5meta *meta, struct shmeta *sm)
{
    int i = 0, j = 0;
    struct vdisk_flush_data *vfd;
    struct shmeta *re = NULL;
    if(!sm || (vfd = sm->vfd) == NULL)
        return;
    for(i = 0; i < devnum; i++)
    {
        if(vfd->dev[i].dirty == 1 || vfd->dev[i].dirty == 33)
        {
            if(!re)
            {
                re = find_a_place(meta);
                j = 0;
            }
            for(; j < devnum; j++)
            {
                if(re->dmeta[j].lba == DEV_META_BLANK)
                {
                    re->dmeta[j].lba = vfd->dev[i].sector;
                    sm->dmeta[i].lso = re->sector;
                    sm->dmeta[i].psn = j;

                    vfd->dev[i].sector = compute_new_logical_sector(meta,
                                                 re->sector, j, re->pdisk);
                }
            }
            if(j == devnum && re)
            {
                ADD_SM_INVALID_LIST_DIRTY_WITH_LOCK(meta, re);
                re = NULL;
            }
        }
    }
    RETURN_FULL_VFD(meta, sm,  0);
    ADD_SM_INVALID_LIST_DIRTY_WITH_LOCK(meta, sm);

    return;
}


void flush_all_particle_list(struct r5meta *meta)
{
    struct shmeta *sm = NULL;
    struct vdisk_flush_data *vfd = NULL;
    int i;
    bool use_ori_place = true;

    recombine_shmeta(meta); 
    if(!list_empty_careful(&meta->particle_list))
        sm = list_first_entry(&meta->particle_list, struct shmeta, lru);
    if(sm && sm->vfd)
    {
        DEL_SM_PARTICLE_LIST_WITH_LOCK(meta, sm);

        vfd = sm->vfd;
        for(i = 0; i < devnum; i++)
            if(sm->dmeta[i].lba != -1 && sm->dmeta[i].lba != sm->dmeta[i].bi_sector)
                use_ori_place = false;

        if(use_ori_place)
        {
            set_bit(SM_DIRTY, &sm->flags);
            ADD_SM_INVALID_LIST_DIRTY_WITH_LOCK(meta, sm);
            RETURN_VFD(meta, vfd, 0)
        }
        else
            flush_last_particle_shmeta(meta, sm);
        atomic_set(&meta->cached_particle_shmeta, 0);
        atomic_set(&meta->updating_vfd_blocks, 0);
    }
    return;
}


void update_vfd_thread(struct md_thread *thread)
{
    struct r5meta *meta;
    struct cache_tree_data *ctd;
    struct vdisk_flush_data *vfd;
    struct meta_bitmap *bitmap;
	struct meta_data *mtd;
    struct mddev *mdd;
    struct updating_shmeta *us;
    int z;
    
    if((thread) == NULL ||
       (mdd = thread->mddev) == NULL ||
       (ctd = mdd->ctd) == NULL ||
       (meta = ctd->cache_r5meta) == NULL || 
       (bitmap = meta->bitmap) == NULL ||
       (mtd = meta->mtd) == NULL )
    {
        sm_err("parameters NULL\n");
        set_bit(MT_UPDATED, &meta->flags);
        clear_bit(MT_UPDATING, &meta->flags);
        wake_up(&meta->wait_for_update_finish);
        return;
    }

#ifdef PRINT_INFO
    sm_info("\n\n\n\n\n\n\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
#endif
    set_bit(MT_UPDATING, &meta->flags);
    if(meta->full_dynamic_sm_wait_handle != NULL)
    {
        handle_full_dynamic_stripe(meta, meta->full_dynamic_sm_wait_handle);
        meta->full_dynamic_sm_wait_handle = NULL;
    }
    if(meta->updating_vfd_blocks >= devnum || 
       test_bit(MT_FLUSH_ALL_PARTICLE, &meta->flags))
    {
#ifdef PRINT_INFO
        sm_info("\n\n\nmeta->updating_vfd_blocks: %d\n",
                meta->updating_vfd_blocks);
#endif
        spin_lock(&meta->updating_shmeta_list_lock);
        while(!list_empty_careful(&meta->updating_shmeta_list))
        {
            // get us
            us = list_first_entry(&meta->updating_shmeta_list, 
                                  struct updating_shmeta, lru);
            if(us == NULL || (vfd = us->vfd) == NULL)
                break;
            list_del_init(&us->lru);
    
#ifdef PRINT_INFO
            sm_info("handle us: us->sector = %lu\n", vfd->lba_align);
            print_vfd(vfd);
#endif

            if(us->type == FULL_DYNAMIC)
                ;// handle_full_dynamic_stripe(meta, us);
            else if(us->type == PARTICLE_DYNAMIC)
                handle_particle_dynamic_stripe(meta, us);
            else if(us->type == PARTICLE_STATIC)
                handle_particle_static_stripe(meta, us);
            else
            {
                sm_err("strange us %lu type %d\n", us->sector, us->type);
                continue;
            }
        }
        INIT_LIST_HEAD(&meta->updating_shmeta_list);
        spin_unlock(&meta->updating_shmeta_list_lock);
 
#ifdef PRINT_INFO
        sm_info("handle vfds over\n");
        print_all_shmeta(meta);
#endif
       
        if(meta->updating_vfd_blocks >= devnum || 
                test_bit(MT_FLUSH_ALL_PARTICLE, &meta->flags))
            recombine_shmeta(meta);
    }
    if(test_bit(MT_FLUSH_ALL_PARTICLE, &meta->flags))
        flush_all_particle_list(meta);

    if(atomic_read(&meta->cached_recombined_shmeta) > SM_FLUSH_META_LIMIT)
        flush_shmeta(meta);
#ifdef PRINT_INFO
    sm_info("update_vfd_thread finished\n");
    print_all_shmeta(meta);
#endif
    set_bit(MT_UPDATED, &meta->flags);
    clear_bit(MT_UPDATING, &meta->flags);
    wake_up(&meta->wait_for_update_finish);
#ifdef PRINT_INFO
    sm_info("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n\n\n\n\n\n\n\n");
#endif
    return;
}




struct vdisk_flush_data** update_shmeta(struct cache_tree_data *ctd_data, 
                  struct vdisk_flush_data *vfd_data, bool flush_all)
{
    int i, z, pdisk, qdisk, ddisk, type;
    int datanum;
    bool dynamic_stripe = false, written_stripe = false, valid = false;
    sector_t new_sector, a_valid_block_sector;
    struct r5meta *meta;
    struct meta_bitmap *bitmap;
    struct cache_tree_data *ctd;
    struct vdisk_flush_data *vfd, *vfd1;
    struct updating_shmeta *us;
    struct shmeta *sm = NULL;
    struct mddev *mddev;

    if((ctd = ctd_data) == NULL || 
       (vfd = vfd_data) == NULL ||
       (meta = ctd->cache_r5meta) == NULL || 
       (mddev = ctd_data->mdd) == NULL ||
       (bitmap = meta->bitmap) == NULL)
    {
        sm_err("updata shmeta finish 1: para NULL\n");
        return NULL;
    }

#ifdef PRINT_INFO
    sm_info("-----------------------------------------\n");
#endif
    spin_lock(&meta->update_shmeta_lock);

    datanum = 0;
    i = 0;
    new_sector = -1;

    // count datanum
    while(i < devnum)
    {
        if(vfd->dev[i].dirty == 1 || 
           vfd->dev[i].dirty == 33)
        {
            datanum++;
            a_valid_block_sector = vfd->dev[i].sector;
        }
        i++;
    }
#ifdef PRINT_INFO
    sm_info("%lu: datanum: %d\n", vfd->lba_align, datanum);
    print_vfd(vfd);
#endif
    // information
    new_sector = compute_sector(meta, a_valid_block_sector, 
                                &ddisk, &pdisk, &qdisk);
    sm = find_shmeta(meta, new_sector);
    if(sm != NULL) 
    {
        // check valid?
#ifdef PRINT_INFO 
        sm_info("find sm %lu %p in cache\n", sm->sector, sm);
        print_shmeta(sm);
#endif
        valid = false;
        for(i = 0; i < devnum; i++)
        {
            if(vfd->dev[i].dirty == 1)
                valid = true;
            else if(vfd->dev[i].dirty == 33)
            {
                if(sm->dmeta[i].lso != DEV_RECLAIMING)
                {
#ifdef PRINT_INFO
                    sm_info("free page: %lu %p\n", vfd->dev[i].sector, vfd->dev[i].page);
#endif
                    __free_page(vfd->dev[i].page);
                    vfd->dev[i].page = NULL;
                    vfd->dev[i].cdev = NULL;
                    vfd->dev[i].dirty = -1;
                }
                else
                    valid = true;
            }
        }
        if(!valid)
        {
            //kfree(vfd);
            spin_unlock(&meta->update_shmeta_lock);
            return_vfd(mddev, vfd);
            goto update_no_recombine;
        }
#ifdef PRINT_INFO
        sm_info("%lu: datanum: %d\n", vfd->lba_align, datanum);
#endif 

        dynamic_stripe = test_bit(SM_DYNAMIC, &sm->flags);
        written_stripe = test_bit(SM_WRITTEN, &sm->flags);
        if(test_bit(SM_IN_PARTICLE, &sm->flags))
        {
            /*
            vfd1 = sm->vfd;
            copy_vfd_clean_sm(meta, sm, vfd1, vfd);
            DEL_SM_PARTICLE_LIST_WITH_LOCK(meta, sm);
            */
        }
        else
            sm = del_sm_from_origin_list(meta, sm, false);

        if(test_bit(SM_HANDLE_BIO, &sm->flags))
            sm = NULL;
    }
    else
        dynamic_stripe = check_bitmap(bitmap, new_sector, DYNAMIC_BITMAP);

    // handle full-first-write shmeta
    if(datanum > (devnum >> 1))
    {
        if(dynamic_stripe)
        {
#ifdef PRINT_INFO
            sm_info("lba_align: %lu is full dynamic, datanum: %d\n", 
                    vfd->lba_align, datanum);
#endif

            type = FULL_DYNAMIC;
        }
        else
        {
#ifdef PRINT_INFO
            sm_info("lba_align: %lu is full static, datanum: %d\n", 
                    vfd->lba_align, datanum);
#endif

            z = 0;
            while(z < devnum)
            {
                if(vfd->dev[z].dirty == 1 &&
                   vfd->dev[z].sector != DEV_META_BLANK)
                   check_and_set_bitmap(bitmap, vfd->dev[z].sector,
                                        WRITTEN_BITMAP);
                z++;
            }
            spin_unlock(&meta->update_shmeta_lock);
            
            for(z = 0; z < RETURN_VFD_NUM; z++)
            {
                if(meta->recombined_vfd_return[z] != NULL)
                    continue;
                else
                {
                    meta->recombined_vfd_return[z] = vfd;
                    break;
                }
            }
            if(z == RETURN_VFD_NUM) 
                sm_err("recombined_vfd_return no place to put\n"); 
            
            if(test_bit(MT_FLUSH_ALL_PARTICLE, &meta->flags))
            {
                clear_bit(MT_UPDATED, &meta->flags);
                md_wakeup_thread(meta->update_thread);
                wait_event(meta->wait_for_update_finish, 
                           test_bit(MT_UPDATED, &meta->flags));
                clear_bit(MT_UPDATING, &meta->flags);
                clear_bit(MT_UPDATED, &meta->flags);
                return meta->recombined_vfd_return;
            }
            return meta->recombined_vfd_return;
        }
    }
    else if(datanum > 0)
    {
        if(dynamic_stripe)
        {
#ifdef PRINT_INFO
            sm_info("lba_align: %lu is particle dynamic, datanum: %d\n", 
                    vfd->lba_align, datanum);
#endif

            type = PARTICLE_DYNAMIC;
        }
        else
        {
#ifdef PRINT_INFO
            sm_info("lba_align: %lu is particle static, datanum: %d\n", 
                    vfd->lba_align, datanum);
#endif

            type = PARTICLE_STATIC;
        }
    }
    else
    {
#ifdef PRINT_INFO
        sm_info("vfd strange!\n");
#endif
        spin_unlock(&meta->update_shmeta_lock);
        goto update_no_recombine;
    }

    // get updating_shmeta
    if(!list_empty_careful(&meta->updated_shmeta_list))
    {
        spin_lock(&meta->updated_shmeta_list_lock);
        us = list_first_entry(&meta->updated_shmeta_list, 
                              struct updating_shmeta, lru);
        list_del_init(&us->lru);
        spin_unlock(&meta->updated_shmeta_list_lock);
    }
    else if(meta->alloc_updating_shmeta < meta->max_alloc_updating_shmeta)
    {
        us = kmalloc(sizeof(struct updating_shmeta), GFP_KERNEL);
        memset(us, 0, sizeof(struct updating_shmeta));
        meta->alloc_updating_shmeta++;
#ifdef PRINT_INFO
        sm_info("alloc_updating_shmeta: %d, max_alloc_updating_shmeta: %d\n",
                meta->alloc_updating_shmeta, meta->max_alloc_updating_shmeta);
#endif

    }
    else 
    {
        sm_err("alloc_updating_shmeta: %d, max_alloc_updating_shmeta: %d\n",
                meta->alloc_updating_shmeta, meta->max_alloc_updating_shmeta);
#ifdef PRINT_INFO
        print_all_shmeta(meta);
#endif
        sm_err("updating_vfd_blocks: %d\n", meta->updating_vfd_blocks);
        spin_unlock(&meta->update_shmeta_lock);
        goto update_no_recombine;
    }

    us->sector = DEV_META_BLANK; 
    us->sm = sm; 
    us->sector = new_sector;
    us->datanum = datanum;
    us->vfd = vfd;
    us->align = vfd->lba_align;
    us->remaining_blocks = datanum;
    us->type = type;
    us->pdisk = pdisk;
    ADD_US_UPDATING(meta, us);

    if(type == FULL_DYNAMIC)
    {
        if(meta->full_dynamic_sm_wait_handle != NULL)
            sm_err("meta->full_dynamic_sm_wait_handle: %p\n", 
                    meta->full_dynamic_sm_wait_handle);
        meta->full_dynamic_sm_wait_handle = us;

        clear_bit(MT_UPDATED, &meta->flags);
        md_wakeup_thread(meta->update_thread);
        wait_event(meta->wait_for_update_finish, 
                   test_bit(MT_UPDATED, &meta->flags));
        clear_bit(MT_UPDATING, &meta->flags);
        clear_bit(MT_UPDATED, &meta->flags);
#ifdef PRINT_INFO
        sm_info("wake up\n");
#endif
        spin_unlock(&meta->update_shmeta_lock);
        return meta->recombined_vfd_return;
    }

    CHANGE_VFD_BLOCKS(meta, datanum);
    if(meta->updating_vfd_blocks >= devnum)
    {
        clear_bit(MT_UPDATED, &meta->flags);
        md_wakeup_thread(meta->update_thread);
        wait_event(meta->wait_for_update_finish, 
                    test_bit(MT_UPDATED, &meta->flags));
#ifdef PRINT_INFO
        sm_info("wake up\n");
#endif
        clear_bit(MT_UPDATING, &meta->flags);
        clear_bit(MT_UPDATED, &meta->flags);
        
        // check
        if(atomic_read(&meta->cached_particle_shmeta) != 0 &&
           meta->updating_vfd_blocks == 0)
        {
            sm_err("some wrong in particle_list\n");
            sm = list_first_entry(&meta->particle_list,
                                struct shmeta, lru);
#ifdef PRINT_INFO
            if(sm != NULL)
                print_shmeta(sm);
#endif
        }

        spin_unlock(&meta->update_shmeta_lock);
        return meta->recombined_vfd_return;
    }
#ifdef PRINT_INFO
    sm_info("update shmeta finish 5, wait another to recombine\n");
#endif
    spin_unlock(&meta->update_shmeta_lock);


update_no_recombine:
    if(test_bit(MT_FLUSH_ALL_PARTICLE, &meta->flags))
    {
        clear_bit(MT_UPDATED, &meta->flags);
        md_wakeup_thread(meta->update_thread);
        wait_event(meta->wait_for_update_finish, 
                   test_bit(MT_UPDATED, &meta->flags));
        clear_bit(MT_UPDATING, &meta->flags);
        clear_bit(MT_UPDATED, &meta->flags);
        return meta->recombined_vfd_return;
    }
    return NULL;
}

static void flush_stripe_sectors_endio(struct bio *bi)
{
    struct return_save_pages* rsp = bi->bi_private;
    struct r5meta *meta = rsp->meta;
    atomic_dec(&meta->save_stripe_sectors_page);
#ifdef PRINT_INFO
    sm_info("free page: %p\n", rsp->page);
#endif
    __free_page(rsp->page);
    kfree(rsp);
    if(atomic_read(&meta->save_stripe_sectors_page) == 0)
        wake_up(&meta->wait_for_save_sectors_finish);
    return;
}

void r5_save_stripe_sectors(struct r5meta *meta)
{
    struct return_save_pages *rsp;
    sector_t start_sec = 0;
    struct cache_tree_data *ctd;
    struct mddev *mddev;
    if(meta == NULL || (ctd = meta->ctd) == NULL ||
       (mddev = ctd->mdd) == NULL)
        return;
    atomic_set(&meta->save_stripe_sectors_page, 0);
    init_waitqueue_head(&meta->wait_for_save_sectors_finish);
    if(atomic_read(&meta->blank_in_bptree) > 0)
    {
        if((rsp = save_stripe_sectors(meta->blank_bptree)) != NULL)
        {
            while(rsp && rsp->page)
            {
                rsp->meta = meta;
                struct bio *bi = bio_alloc(GFP_NOIO, 2);

	            bi->bi_iter.bi_sector = start_sec;
                bi->bi_rw = WRITE;
                bio_add_page(bi, rsp->page, PAGE_SIZE, 0);
                bi->bi_private = rsp;
                bi->bi_end_io = flush_stripe_sectors_endio;
                sm_set_bi_stripes(bi, 1);
                atomic_inc(&meta->save_stripe_sectors_page);
                rsp = rsp->next;
                start_sec += 8;
                mddev->pers->make_request(mddev, bi);

            }
        }
    }
    if(atomic_read(&meta->reclaim_in_bptree) > 0)
    {
        start_sec = meta->bplus_pages_remain_each;
        if((rsp = save_stripe_sectors(meta->reclaim_bptree)) != NULL)
        {
            while(rsp && rsp->page)
            {
                rsp->meta = meta;
                struct bio *bi = bio_alloc(GFP_NOIO, 2);

	            bi->bi_iter.bi_sector = start_sec;
                bi->bi_rw = WRITE;
                bio_add_page(bi, rsp->page, PAGE_SIZE, 0);
                bi->bi_private = rsp;
                bi->bi_end_io = flush_stripe_sectors_endio;
                sm_set_bi_stripes(bi, 1);
                atomic_inc(&meta->save_stripe_sectors_page);
                rsp = rsp->next;
                start_sec += 8;

                mddev->pers->make_request(mddev, bi);

            }
        }
    }
    wait_event(meta->wait_for_save_sectors_finish, 
               atomic_read(&meta->save_stripe_sectors_page) == 0);
    return;
}



void r5meta_stop(struct r5meta *meta)
{
    struct meta_bitmap *bitmap;
    struct meta_data *mtd;
    struct shmeta *sm;
    int i = 0;
    if (meta == NULL ||
       (bitmap = meta->bitmap) == NULL ||
       (mtd = meta->mtd) == NULL)  
    {
        sm_err("meta is NULL\n");
        return;
    }
#ifdef PRINT_INFO
    sm_info("start!\n");
#endif
    if(NULL != meta->update_thread)
    {
        if(test_bit(MT_UPDATING, &meta->flags))
        {
#ifdef PRINT_INFO
            sm_info("wait for meta->update_thread finish\n");
#endif
            wait_event(meta->wait_for_update_finish, 
                        !test_bit(MT_UPDATING, &meta->flags));
#ifdef PRINT_INFO
            sm_info("wait for update wake up\n");
#endif
        }
        md_unregister_thread(&meta->update_thread);
#ifdef PRINT_INFO
        sm_info("unregistered update_vfd_thread\n");
#endif
    }

    if(NULL != meta->reclaim_thread)
    {
        if(test_bit(MT_RECLAIMING, &meta->flags))
        {
#ifdef PRINT_INFO
            sm_info("wait for meta->reclaim_thread finish\n");
#endif
            wait_event(meta->wait_for_reclaim_queue, 
                       !test_bit(MT_RECLAIMING, &meta->flags));
#ifdef PRINT_INFO
            sm_info("wait for reclaim wake up\n");
#endif
        }
        md_unregister_thread(&meta->reclaim_thread);
#ifdef PRINT_INFO
        sm_info("unregistered reclaim_thread\n");
#endif
    }

    if(NULL != meta->read_thread)
    {  
        md_unregister_thread(&meta->read_thread);
#ifdef PRINT_INFO
        sm_info("unregistered read_thread\n");
#endif
    }
    if(mtd)
    {
        flush_all_shmeta(meta);
        exit_metadata(mtd);
    }
    else
        sm_err("mtd is NULL\n");

    if(bitmap)
        meta_bitmap_stop(bitmap);
    else
        sm_err("bitmap is NULL\n");
#ifdef SM_SAVE_BPTREE       
    r5_save_stripe_sectors(meta);
#endif
    if(NULL != meta->hashtbl)
        kfree(meta->hashtbl);
    if(NULL != meta->reclaim_lists)
        kfree(meta->reclaim_lists);
    // kfree(meta->md_bds);
    kfree(meta);
#ifdef PRINT_INFO
    sm_info("stop r5meta successful\n");
#endif
    return;
}


void setup_shmeta(struct cache_tree_data *ctd, int max_shmeta)
{
    struct mddev *mddev;
    struct r5meta *meta;
    int disks, i, max_degrade;
    struct meta_bitmap *bitmap;
    struct md_rdev *rdev;

    // r5meta
    if(NULL == meta && 
       (meta = kmalloc(sizeof(struct r5meta), GFP_KERNEL)) ==NULL)
        return;
    memset(meta, 0, sizeof(struct r5meta)); 
    mddev = ctd->mdd;
	meta->ctd = ctd;
    ctd->cache_r5meta = meta;
    max_degrade = 0;
    
    if(5 == mddev->level)
        max_degrade = 1;
    else if(6 == mddev->level)
        max_degrade = 2;

    disks = mddev->raid_disks;
    devnum = disks - max_degrade;

    // parameters
    meta->disks = disks;
    meta->devnum = devnum;
    meta->max_degrade = max_degrade;
    meta->bplus_pages_remain_each = 32 * 8;
    if(max_shmeta == -1)
        meta->max_shmeta = SM_MAX_SHMETA; 
    else
        meta->max_shmeta = max_shmeta;


    meta->max_shmeta = 4096;
    meta->md_bds = kmalloc(sizeof(struct block_device*) * devnum,
                            GFP_KERNEL);
    memset(meta->md_bds, 0, sizeof(struct block_device*) * devnum);
    if(meta->md_bds == NULL)
        goto free_meta;

    i = 0;
    rdev_for_each(rdev, mddev)
    {
        if(rdev->raid_disk >= 0 && !test_bit(Faulty, &rdev->flags) && rdev->bdev)
        {
            meta->md_bds[i] = rdev->bdev;
            i++;
            // q = bdev_get_queue(rdev->bdev);
        }
    }


    // hash table
    if ((meta->hashtbl = kmalloc(PAGE_SIZE, GFP_KERNEL)) == NULL ||
        (meta->hashtbl_count = kmalloc(PAGE_SIZE, GFP_KERNEL)) == NULL ||
        (meta->flush_list = kmalloc(PAGE_SIZE, GFP_KERNEL)) == NULL ||
        (meta->hash_list_size = kmalloc(PAGE_SIZE, GFP_KERNEL)) == NULL)
        goto free_meta;

    memset(meta->hashtbl, 0, PAGE_SIZE);
    memset(meta->flush_list, 0, PAGE_SIZE);
    memset(meta->hash_list_size, 0, PAGE_SIZE);
    memset(meta->hashtbl_count, 0, PAGE_SIZE);

    // meta_bitmap
    if((bitmap = setup_meta_bitmap(meta, 0, meta->bplus_pages_remain_each << 1))
       == NULL) 
        goto free_meta;
 
    // metadata
    if((setup_metadata(meta, bitmap->written_end_sector, 
                       -1, bitmap->bd)) == NULL) 
        goto free_meta;

    for (i = 0; i < SM_INACTIVE_LIST_NUM + 1; i++)
        INIT_LIST_HEAD(meta->inactive_list + i);

    for (i = 0; i < SM_FLUSH_HASH; i++)
        INIT_LIST_HEAD(&meta->flush_list[i]);

    INIT_LIST_HEAD(&meta->retry_list);
    INIT_LIST_HEAD(&meta->free_list);
    INIT_LIST_HEAD(&meta->blank_list);
    INIT_LIST_HEAD(&meta->particle_list);
    INIT_LIST_HEAD(&meta->recombine_list);
    INIT_LIST_HEAD(&meta->locked_list);

    spin_lock_init(&meta->inactive_list_lock);
    spin_lock_init(&meta->particle_list_lock);
    spin_lock_init(&meta->hashtbl_lock);
    spin_lock_init(&meta->retry_list_lock);
    spin_lock_init(&meta->free_list_lock);
    spin_lock_init(&meta->blank_list_lock);
    spin_lock_init(&meta->flush_list_lock);
    spin_lock_init(&meta->recombine_list_lock);
    spin_lock_init(&meta->meta_page_lock);
    spin_lock_init(&meta->locked_list_lock);

    // about reclaim_thread
    meta->reclaim_lists = kmalloc(sizeof(struct list_head) * (devnum - 1),
                                  GFP_KERNEL);
    if(!meta->reclaim_lists)
    {
        sm_err("reclaim_lists create failed\n");
        goto free_meta;
    }
    memset(meta->reclaim_lists, 0, sizeof(struct list_head) * (devnum - 1));
    for(i = 0; i < devnum - 1; i++)
        INIT_LIST_HEAD(&meta->reclaim_lists[i]);

    atomic_set(&meta->reclaim_lists_count, 0);
    spin_lock_init(&meta->reclaim_lists_lock);

    // retry bio
    meta->flags = 0;

    // update and recombine thread.
    meta->update_thread = md_register_thread(update_vfd_thread, 
                                             mddev, "update_thread");
    if(!meta->update_thread)
        goto free_meta;
        
    
    meta->reclaim_thread = md_register_thread(r5m_reclaim_thread, 
                                              mddev, "reclaim_shmeta");
    if(!meta->reclaim_thread)
    {
        sm_err("reclaim_thread create failed\n");
        goto free_meta;
    }
    meta->reclaim_thread->timeout = R5M_RECLAIM_WAKEUP_INTERVAL;

    meta->read_thread = md_register_thread(r5m_read_thread, mddev,
                                            "read_thread");
    if(!meta->read_thread)
    {
        sm_err("read_thread create failed\n");
        goto free_meta;
    }

    for(i = 0; i < RETURN_VFD_NUM; i++)
        meta->recombined_vfd_return[i] = NULL;

    // about read
    INIT_LIST_HEAD(&meta->read_list);
    INIT_LIST_HEAD(&meta->readed_list);
    spin_lock_init(&meta->read_list_lock);
    spin_lock_init(&meta->readed_list_lock);


    // wait queue
    init_waitqueue_head(&meta->wait_for_flush_queue);
    init_waitqueue_head(&meta->wait_for_update_finish);
    init_waitqueue_head(&meta->wait_for_reclaim_queue);
    init_waitqueue_head(&meta->wait_for_read_queue);
    init_waitqueue_head(&meta->wait_for_blank_shmeta);
    init_waitqueue_head(&meta->wait_for_load_a_block_finish);

    // counters
    atomic_set(&meta->active_sm, 0);
    atomic_set(&meta->cached_particle_shmeta, 0);
    atomic_set(&meta->empty_inactive_list_nr, 0);
    atomic_set(&meta->cached_recombined_shmeta, 0);
    atomic_set(&meta->cached_inactive_shmeta, 0);
    atomic_set(&meta->cached_retry_shmeta, 0);
    atomic_set(&meta->cached_blank_shmeta, 0);
    atomic_set(&meta->cached_free_shmeta, 0);
    atomic_set(&meta->cached_flush_shmeta, 0);
    atomic_set(&meta->updating, 0);
    atomic_set(&meta->cached_locked_shmeta, 0);

    // about updating_shmeta
    INIT_LIST_HEAD(&meta->updating_shmeta_list);
    INIT_LIST_HEAD(&meta->updated_shmeta_list);
    spin_lock_init(&meta->updating_shmeta_list_lock);
    spin_lock_init(&meta->updating_vfd_blocks_lock);
    spin_lock_init(&meta->updated_shmeta_list_lock);

    meta->blank_sm_avail = NULL;
    meta->blank_size_in_page = 0;
    spin_lock_init(&meta->blank_sm_avail_lock);

    meta->updating_vfds = 0;
    meta->updating_vfd_blocks = 0;
    meta->alloc_updating_shmeta = 0;
    meta->max_alloc_updating_shmeta = 128;

    spin_lock_init(&meta->update_shmeta_lock);

    meta->blank_bptree = bplus_tree_init(32, 64);
    meta->reclaim_bptree = bplus_tree_init(32, 64);
    atomic_set(&meta->blank_in_bptree, 0);
    atomic_set(&meta->reclaim_in_bptree, 0);
    spin_lock_init(&meta->blank_bptree_lock);
    spin_lock_init(&meta->reclaim_bptree_lock);

    spin_lock_init(&pa_lock);
    return;

free_meta:
    r5meta_stop(meta);
    return;
}

