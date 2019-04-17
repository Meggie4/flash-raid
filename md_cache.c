#include <linux/raid/pq.h>
#include <linux/async_tx.h>
#include <linux/module.h>
#include <linux/async.h>
#include <linux/seq_file.h>
#include <linux/cpu.h>
#include <linux/slab.h>
#include <linux/ratelimit.h>
#include <linux/nodemask.h>
#include <linux/flex_array.h>
//#include <linux/sched/signal.h>
#include <trace/events/block.h>
#include <linux/time.h>
#include <linux/sysctl.h>
#include <linux/timer.h>
#include <linux/types.h>
#include <linux/init.h>
#include <trace/events/block.h>

#include <linux/time.h>
#include <linux/timex.h>
#include <linux/rtc.h>
#include <linux/delay.h>
#include <linux/slab.h>

#include<linux/init.h>
#include "md.h"
#include "md_cache.h"
#include "scst_vdisk_cache_data.h"
#include "flag.h"

//#define PRINT_INFO

#define mdc_fmt(fmt)            "mdc: [%d %s] "fmt
#define mdc_info(fmt, ...)      \
        printk(KERN_INFO mdc_fmt(fmt), __LINE__, __func__, ##__VA_ARGS__)


#define mdc_err_fmt(fmt)        "mdc ERROR: [%d %s] "fmt
#define mdc_err(fmt, ...)       \
        printk(KERN_ERR mdc_err_fmt(fmt), __LINE__, __func__, ##__VA_ARGS__)

#define BIO_TEST_HASH(sector)  ((sector >> 3) & CACHE_HASH_MASK)

#define MAX(a, b)   (((a) > (b)) ? (a) : (b))
#define MIN(a, b)   (((a) < (b)) ? (a) : (b))


static int read_bio_count = 0;
static int write_bio_count = 0;


static const struct mddev *Gmddev;
static struct kmem_cache *brc_pool;

//read过程使用的是hash_list,需不需要使用树来操作，可待尝试，函数已写好
extern struct vdisk_flush_data** update_shmeta(
                            struct cache_tree_data *mdc_data,
                            struct vdisk_flush_data *vfdata);

extern void reclaim_stop(struct r5meta *meta);


bool check_flag(int flag, unsigned short *shflag) 
{
    unsigned short MASK_FLAG = -1; 
    return 1 & ((*shflag) >> (flag & MASK_FLAG));
}

void clear_flag(int flag, unsigned short *shflag)
{
    unsigned short MASK_FLAG = -1; 
    if(flag == SM_DYNAMIC && check_flag(SM_DYNAMIC, shflag))
        *shflag |= (1<<(SM_DYNAMIC_CHANGED & MASK_FLAG));
    *shflag &= ~(1<<(flag & MASK_FLAG));
    return;
}

void set_flag(int flag, unsigned short *shflag)
{
    unsigned short MASK_FLAG = -1;
    if(flag == SM_DYNAMIC && !check_flag(SM_DYNAMIC, shflag))
        *shflag |= (1<<(SM_DYNAMIC_CHANGED & MASK_FLAG));
    *shflag |= (1<<(flag & MASK_FLAG));
    return;
}


static inline void cache_inc_bi_stripes(struct bio *bio, unsigned int cnt)
{
    atomic_t *segments = (atomic_t *)&bio->bi_phys_segments;
    atomic_inc(segments);
}

static inline void cache_set_bi_stripes(struct bio *bio, unsigned int cnt)
{
    atomic_t *segments = (atomic_t *)&bio->bi_phys_segments;
    atomic_set(segments, cnt);
}
static inline int cache_dec_bi_stripes(struct bio *bio)
{
    atomic_t *segments = (atomic_t *)&bio->bi_phys_segments;
    return atomic_sub_return(1, segments) & 0xffff;
}

/*
static inline void mycache_set_bi_stripes(struct bio *bio, unsigned int cnt)
{
    atomic_t *segments = (atomic_t *)&bio->bi_phys_segments;
    atomic_set(segments, cnt);
}
static inline int mycache_dec_bi_stripes(struct bio *bio)
{
    atomic_t *segments = (atomic_t *)&bio->bi_phys_segments;
    return atomic_sub_return(1, segments) & 0xffff;
}
*/

void clean_bt(struct bio_test *bt, int devnum)
{
#ifdef PRINT_INFO
    mdc_info("clean bt: %lu flag: %d, %p\n", bt->lba, bt->flag, bt);
#endif
    INIT_LIST_HEAD(&bt->lru_list);
    INIT_HLIST_NODE(&bt->hash);
    bt->lba = -1;
    bt->flag = 0;
    int idx = 0;
    while(idx < devnum)
    {
        bt->dev[idx].sector = -1;
        bt->dev[idx].page = NULL;
        bt->dev[idx].valid = 0;
        bt->dev[idx].offset = 0;
        bt->dev[idx].length = 0;
        ++idx;
    }
    return;
}


void clean_vfd(struct vdisk_flush_data *vfd, int devnum)
{
#ifdef PRINT_INFO
    mdc_info("clean vfd: %lu %p\n", vfd->lba_align, vfd);
#endif
    vfd->lba_align = -1;
    INIT_LIST_HEAD(&vfd->lru);
    int idx = 0;
    while(idx < devnum)
    {
        vfd->dev[idx].sector = -1;
        vfd->dev[idx].page = NULL;
        // vfd->dev[idx].flag = 0;
        vfd->dev[idx].dirty = 0;
        vfd->dev[idx].cdev = NULL;

        ++idx;
    }
    return;
}


struct vdisk_flush_data *get_a_vfd(struct mddev *mddev)
{
    struct vdisk_flush_data *vfd = NULL;
    struct cache_tree_data *ctd = mddev->ctd;
    int devnum = mddev->raid_disks - 1, m;
    // get a vfd to flush
    spin_lock(&ctd->vdisk_flush_data_list_lock);
    if(!list_empty_careful(&ctd->vdisk_flush_data_list))
    {
        vfd = list_first_entry(&ctd->vdisk_flush_data_list,
                              struct vdisk_flush_data,
                              lru);
        list_del_init(&vfd->lru);
        spin_unlock(&ctd->vdisk_flush_data_list_lock);
    }
    else
    {
        spin_unlock(&ctd->vdisk_flush_data_list_lock);
        int vfd_size = sizeof(struct vdisk_flush_data) + 
                   devnum * sizeof(struct r5fdev);

        vfd = (struct vdisk_flush_data *)kmalloc(vfd_size,
                                                 GFP_KERNEL);
            
        spin_lock(&ctd->alloc_vdisk_flush_data_list_lock);
        atomic_inc(&ctd->vdisk_flush_data_count);
        list_add(&vfd->alloc_lru, &ctd->alloc_vdisk_flush_data_list);
        spin_unlock(&ctd->alloc_vdisk_flush_data_list_lock);
    }
    clean_vfd(vfd, devnum);
    
#ifdef PRINT_INFO
    mdc_info("get vfd: %p\n", vfd);
#endif

    return vfd;
}

void return_vfd(struct mddev *mddev, 
                                   struct vdisk_flush_data *vfd)
{
    if(!mddev || !vfd)
        return;
#ifdef PRINT_INFO
    mdc_info("return vfd: %lu, %p\n", vfd->lba_align, vfd);
#endif
    struct cache_tree_data *ctd = mddev->ctd;
    clean_vfd(vfd, mddev->raid_disks - 1);
    spin_lock(&ctd->vdisk_flush_data_list_lock);
    list_add(&vfd->lru, &ctd->vdisk_flush_data_list);
    spin_unlock(&ctd->vdisk_flush_data_list_lock);
    return;
}



void clean_vdisk_cache_data(struct vdisk_cache_data *vcd, int devnum)
{
    int idx = 0;

    while(idx < devnum)
    {
        if(vcd->dev[idx].page != NULL)
        {
            // TODO: reclaim page for use 
#ifdef PRINT_INFO
            mdc_info("vcd: %lu %p, idx: %d, free page %p, p_count: %d\n", 
                     vcd->lba_align, vcd, idx, vcd->dev[idx].page, atomic_read(&vcd->dev[idx].page->_count));
#endif
            __free_page(vcd->dev[idx].page);
            vcd->dev[idx].page = NULL;
        }
        vcd->dev[idx].flag = 0;
        // vcd->dev[idx].dirty = 0;
        ++idx;
    }
    atomic_set(&vcd->dirty_pages, 0);
    return;
}


struct bio *cache_bio_alloc_mddev(gfp_t gfp_mask, int nr_iovecs,
        struct mddev *mddev)
{
    struct bio *b;

    if (!mddev || !mddev->bio_set)
        return bio_alloc(gfp_mask, nr_iovecs);

    b = bio_alloc_bioset(gfp_mask, nr_iovecs, mddev->bio_set);
    if (!b)
        return NULL;
    return b;
}

static struct dma_async_tx_descriptor *async_copy_cache_data(int frombio, 
                    struct bio *bio, struct page **page, sector_t sector, 
                    struct dma_async_tx_descriptor *tx, int no_skipcopy)
{
    struct bio_vec bvl;
    struct bvec_iter iter;
    struct page *bio_page;
    int page_offset;

    struct async_submit_ctl submit;
    enum async_tx_flags flags = 0;
    if (bio->bi_iter.bi_sector >= sector)
        page_offset = (signed)(bio->bi_iter.bi_sector - sector) * 512;
    else
        page_offset = (signed)(sector - bio->bi_iter.bi_sector) * -512;

#ifdef PRINT_INFO
    mdc_info("frombio: %d, bio: %p, page: %p, sector: %lu, page_offset: %d\n",
            frombio, bio, *page, sector, page_offset);
#endif
    if (frombio)
        flags |= ASYNC_TX_FENCE;
    init_async_submit(&submit, flags, tx, NULL, NULL, NULL);

    bio_for_each_segment(bvl, bio, iter) 
    {
        int len = bvl.bv_len;
        int bvl_off = bvl.bv_offset;
        int clen;
        int b_offset = 0;

        if (page_offset < 0) 
        {
            b_offset = -page_offset;
            page_offset += b_offset;
            len -= b_offset;
        }

        if (len > 0 && page_offset + len > 4096)
            clen = 4096 - page_offset;
        else
            clen = len;
        if (clen > 0) 
        {
            b_offset += bvl.bv_offset;
            bio_page = bvl.bv_page;

            if(frombio)
            {
                tx = async_memcpy(*page, bio_page, page_offset, b_offset, clen, &submit);
            }
            else
            {
                tx = async_memcpy(bio_page, *page, b_offset, page_offset, clen, &submit);
            }
        }
        submit.depend_tx = tx; 
        if (clen < len) 
        {
            break;
        }
        page_offset += len;
    }
    return tx;
}

static struct dma_async_tx_descriptor *async_page(struct page *page_from,
                                    struct page *page_to,
                                    struct dma_async_tx_descriptor *tx, 
                                    unsigned int offset, unsigned int length)
{
    struct bio_vec bvl;
    struct bvec_iter iter;
    struct page *bio_page;
    int page_offset;

    struct async_submit_ctl submit;
    enum async_tx_flags flags = 0;

#ifdef PRINT_INFO
    mdc_info("page_from: %p, page_to: %p, page_offset: %d, page_length: %d\n",
            page_from, page_to, offset, length);
    /* 
    int *cache = page_address(page_from);
    int *cache2 = page_address(page_to);
    mdc_info("from %d %d %d\n", cache[0], cache[1], cache[2]);
    mdc_info("to %d %d %d\n", cache2[0], cache2[1], cache2[2]);
    */
#endif
    /*
    if (frombio)
        flags |= ASYNC_TX_FENCE;
    */
    init_async_submit(&submit, flags, tx, NULL, NULL, NULL);

    tx = async_memcpy(page_to, page_from, offset, offset, length, &submit);
    submit.depend_tx = tx; 
    return tx;
}


sector_t cache_compute_sector(struct mddev *mddev, sector_t r_sector, 
                              int *dd_idx)
{
    sector_t stripe, stripe2;
    sector_t chunk_number;
    int pdisk, qdisk;
    unsigned int chunk_offset;
    unsigned long new_sector;
    int sectors_per_chunk = mddev->chunk_sectors;
    int raid_disks = mddev->raid_disks;
    int data_disks = raid_disks - 1;

    chunk_offset = sector_div(r_sector, sectors_per_chunk);
    chunk_number = r_sector;

    stripe = chunk_number;
    *dd_idx = sector_div(stripe, data_disks);
    stripe2 = stripe;

    pdisk = qdisk = -1;
    switch(mddev->level) 
    {
        case 5:
            pdisk = data_disks - sector_div(stripe2, raid_disks);
            *dd_idx = (pdisk + 1 + *dd_idx) % raid_disks;
            break;
        case 6:
            pdisk = raid_disks - 1 - sector_div(stripe2, raid_disks);
            qdisk = (pdisk + 1) % raid_disks;
            *dd_idx = (pdisk + 2 + *dd_idx) % raid_disks;
            break;
    }
    if(*dd_idx >= pdisk)
        *dd_idx = *dd_idx - 1;
    new_sector = (sector_t)stripe * sectors_per_chunk + chunk_offset;
    return new_sector;
}


struct bio_test *init_bio_test(struct mddev *mddev, sector_t sector)
{
    struct bio_test *bt_init ;
    int i, dev = mddev->raid_disks;

    struct cache_tree_data *ctd = mddev->ctd;
    
    spin_lock(&ctd->bio_test_lock);
    if(!list_empty_careful(&ctd->bio_test_list))
    {
        // get a bio_test for use from bio_test_list
        bt_init = list_first_entry(&ctd->bio_test_list,
                                  struct bio_test, lru_list);
        list_del_init(&bt_init->lru_list);
        spin_unlock(&ctd->bio_test_lock);
    }
    else
    {
        spin_unlock(&ctd->bio_test_lock);
        // alloc a bio_test
        bt_init = (struct bio_test *)kmalloc((sizeof(struct bio_test) 
                             + dev * sizeof(struct r5plug)), GFP_KERNEL);

        spin_lock(&ctd->alloc_bio_test_list_lock);
        atomic_inc(&ctd->bio_test_count);
#ifdef PRINT_INFO
        mdc_info("alloc: bio_test_count %d\n", atomic_read(&ctd->bio_test_count));
#endif
        list_add(&bt_init->alloc_lru, &ctd->alloc_bio_test_list);
        spin_unlock(&ctd->alloc_bio_test_list_lock);
    }

    if(!bt_init)
    {
        mdc_err("alloc bio_test struct failed !\n");
        return NULL;
    }
    
    clean_bt(bt_init, dev - 1);

    bt_init->lba = sector;
    return bt_init;
}


struct bio_test *find_bio_test(struct mddev *mddev, sector_t sector, 
                               int _hash)
{
    struct bio_test *bt_find = NULL;
    struct cache_tree_data *ctd = mddev->ctd;
  
    spin_lock(ctd->bio_test_hash_lock + _hash);
    hlist_for_each_entry(bt_find, &ctd->bt_hashtbl[_hash], hash)
    {
        if(bt_find->lba == sector)
        {
            spin_unlock(ctd->bio_test_hash_lock + _hash);

#ifdef PRINT_INFO
            mdc_info("find bt in sector: %lu, hash: %d\n",
                     sector, _hash);
#endif
            return bt_find;
        }
    }
    spin_unlock(ctd->bio_test_hash_lock + _hash);
    return NULL;
}


static inline void add_bio_test_to_hash(struct cache_tree_data *ctd, 
                                  struct bio_test *bt, int _hash)
{
    spin_lock(ctd->bio_test_hash_lock + _hash);
    hlist_add_head(&bt->hash, &ctd->bt_hashtbl[_hash]);
    spin_unlock(ctd->bio_test_hash_lock + _hash);
    return;
}



static void load_read_block_for_bt_endio(struct bio *bi)
{
    struct r5plug *rp;
    struct cache_tree_data *ctd = Gmddev->ctd;
    struct async_submit_ctl submit;
    struct dma_async_tx_descriptor *tx = NULL;
    struct bio_vec *bv;

    if((rp = bi->bi_private) != NULL)
    {
        bv = rp->bv;

        struct page *old_p = rp->page;
        struct page *old_p2 = bv->bv_page;
        struct page *new_p = bi->bi_io_vec[0].bv_page;

        tx = async_page(old_p, new_p, tx, rp->offset, rp->length);
        init_async_submit(&submit, ASYNC_TX_ACK, tx,  
                          NULL, NULL, NULL);
        async_trigger_callback(&submit);

        // TODO: check
        tx = async_page(old_p2, new_p, tx, bv->bv_offset, bv->bv_len);
        init_async_submit(&submit, ASYNC_TX_ACK, tx,  
                          NULL, NULL, NULL);
        async_trigger_callback(&submit);

#ifdef PRINT_INFO
        mdc_info("free page %p, p_count: %d\n", 
                 old_p, atomic_read(&old_p->_count));
#endif
        __free_page(old_p);
        rp->page = new_p;
        rp->offset = 0;
        rp->length = PAGE_SIZE;
        rp->valid = 1;
        wake_up(&ctd->wait_for_bt_read_page_queue);
    }
    else 
        mdc_err("cdev is NULL\n");
    return;
}

static int load_read_block_for_bt(struct mddev *mddev, 
                           sector_t new_logical,
                           struct r5plug *rp, 
                           struct page *p)
{
    struct cache_tree_data *ctd = mddev->ctd;
    struct bio *bi;

    bi = cache_bio_alloc_mddev(GFP_NOIO, 1, mddev);

    bio_add_page(bi, p, PAGE_SIZE, 0);
    bi->bi_iter.bi_sector = new_logical + 
                            ctd->remaining_sectors;
    bi->bi_rw = READ;
    bi->bi_private = rp;
    bi->bi_end_io = load_read_block_for_bt_endio;
    cache_set_bi_stripes(bi, 1);

#ifdef PRINT_INFO
    mdc_info("bi: %p, %lu, read_bio_count: %d\n", 
             bi, new_logical, ++read_bio_count);
#endif
    mddev->pers->make_request(mddev, bi);
    return 0;
}


static bool find_write_data_in_radix_tree(struct bio_test *bt,
                                         struct r5plug *rp,
                                          struct bio_vec *bv,
                                         sector_t sector,
                                         int item)
{
    struct mddev *mddev = Gmddev;
    struct cache_tree_data *ctd = mddev->ctd;
    struct vdisk_cache_data *cache_hitted = NULL;
    struct data_cache_radix_tree_node *node_hitted = NULL;
    sector_t insert_sector = bt->lba >> 3;
    sector_t pos = (insert_sector & CACHE_RADIX_TREE_MAP_MASK);
    
    spin_lock(&ctd->radix_tree_lock_data);
    node_hitted = lookup_data_node_in_tree(
                            ctd->data_cache_tree_root,
                            insert_sector);
    // find radix node
    if((node_hitted != NULL)) 
    {
#ifdef PRINT_INFO
        mdc_info("node_hitted->count: %d, node_hitted->lba: %d\n",
                 node_hitted->count, node_hitted->lba);
#endif
        cache_hitted = node_hitted->slots[pos];
    }
    spin_unlock(&ctd->radix_tree_lock_data);

    if(cache_hitted != NULL)
    {
        // stripe in radix tree
        struct r5cdev *cdev = &cache_hitted->dev[item];

        if(cdev->sector != sector && 
           cdev->sector != -1 && cdev->page)
            mdc_err("wrong page when find %lu but found %lu %p, dd_idx: %d\n",
                   sector, cdev->sector, cdev->page, item);
#ifdef PRINT_INFO
        else
            mdc_info("find %lu find %lu %p, dd_idx: %d, offset %d, length: %d\n", 
                     sector, cdev->sector, cdev->page, item, cdev->offset, cdev->length);
#endif
        if(cdev->page != NULL)
        {
            struct dma_async_tx_descriptor *tx = NULL;
            struct async_submit_ctl submit;
            tx = async_page(rp->page, cdev->page, tx, rp->offset, rp->length);
            init_async_submit(&submit, ASYNC_TX_ACK, tx, NULL, NULL, NULL);
            async_trigger_callback(&submit);
 
            struct dma_async_tx_descriptor *tx2 = NULL;
            struct async_submit_ctl submit2;
            tx2 = async_page(bv->bv_page, cdev->page, tx2, bv->bv_offset, bv->bv_len);
            init_async_submit(&submit2, ASYNC_TX_ACK, tx2, NULL, NULL, NULL);
            async_trigger_callback(&submit2);
               
            rp->page = NULL;
            rp->offset = rp->length = 0;
        }
        else
        {
            return false;
        }
    }
    else
    {
        return false;
    }
}


struct bio_test *insert_page_to_bio_test(struct bio_test *bt,
                                         struct bio_vec *bv,
                                         sector_t sector,
                                         int item)
{
    struct mddev *mddev = Gmddev;
    struct cache_tree_data *ctd = mddev->ctd;

    int i;
    if(bt == NULL) 
        return NULL; 

    struct r5plug *rp = &bt->dev[item];
    if(rp->valid == 1 && rp->page != NULL)
    {
        // use old page
        if((rp->offset + rp->length < bv->bv_offset) ||
           (bv->bv_offset + bv->bv_len < rp->offset))
        {
            // cant merge dirty data
            // 1. find data in radix tree or not
            if(find_write_data_in_radix_tree(bt, rp, bv, sector, item))
            {
                bt->dirty_pages -= 1;
                if(bt->dirty_pages == 0)
                {
                    spin_lock(&ctd->plug_list_lock);
                    list_del_init(&bt->lru_list);
                    spin_unlock(&ctd->plug_list_lock);

                    spin_lock(&ctd->bio_test_hash_lock[BIO_TEST_HASH(bt->lba)]);
                    hlist_del_init(&bt->hash);
                    spin_unlock(&ctd->bio_test_hash_lock[BIO_TEST_HASH(bt->lba)]);

                    // add to bio_test_list for free to use
                    spin_lock(&ctd->bio_test_lock);
                    list_add_tail(&bt->lru_list, &ctd->bio_test_list);
                    spin_unlock(&ctd->bio_test_lock);
                    return NULL;
                }
                return bt;
            }
            else
            {
                // 2. read and async 2 dirty data
                struct page *read_p = alloc_page(GFP_KERNEL);
                sector_t new_logical;
#ifdef PRINT_INFO
                mdc_info("alloc_page: %p, p_count: %d\n", 
                         read_p, atomic_read(&read_p->_count));
#endif

#ifdef USE_RECOMBINE_STRIPE
                if(ctd->cache_r5meta != NULL)
                    new_logical = get_new_logical_address(ctd, sector); 
                else
                    new_logical = sector;            
#else
                new_logical = sector;
#endif


#ifdef PRINT_INFO
                mdc_info("sector: %lu, new_logical: %lu\n", 
                         sector, new_logical);
#endif
                rp->bv = bv;
                load_read_block_for_bt(mddev, new_logical, rp, read_p);
                rp->valid = 0;
                wait_event(ctd->wait_for_bt_read_page_queue, rp->valid == 1);
                bt->dirty_pages -= 1;
                if(bt->dirty_pages == 0)
                {
                    spin_lock(&ctd->plug_list_lock);
                    list_del_init(&bt->lru_list);
                    spin_unlock(&ctd->plug_list_lock);

                    spin_lock(&ctd->bio_test_hash_lock[BIO_TEST_HASH(bt->lba)]);
                    hlist_del_init(&bt->hash);
                    spin_unlock(&ctd->bio_test_hash_lock[BIO_TEST_HASH(bt->lba)]);

                    // add to bio_test_list for free to use
                    spin_lock(&ctd->bio_test_lock);
                    list_add_tail(&bt->lru_list, &ctd->bio_test_list);
                    spin_unlock(&ctd->bio_test_lock);
                    return NULL;
                }
                return bt;
            }
        }
        else
        {
            // can merge dirty data
            struct page *pagg_test = rp->page;
            struct async_submit_ctl submit;
            struct dma_async_tx_descriptor *tx = NULL;
#ifdef PRINT_INFO
            mdc_info("use old page: %p\n", pagg_test);
#endif
            tx = async_page(bv->bv_page, pagg_test, tx, bv->bv_offset, bv->bv_len);
            init_async_submit(&submit, ASYNC_TX_ACK, tx, 
                              NULL, NULL, NULL);
            async_trigger_callback(&submit);
#ifdef PRINT_INFO
            mdc_info("update page %p p_count: %d sector: %lu to bt: %p, sector: %lu(idx :%d)\n",
                    pagg_test, atomic_read(&pagg_test->_count), sector, bt, bt->lba, item);
#endif
            int new_offset = MIN(rp->offset, bv->bv_offset);
            rp->length = MAX(rp->offset + rp->length, bv->bv_offset + bv->bv_len) - new_offset; 
            rp->offset = new_offset;
        }
    }
    else
    {
        struct async_submit_ctl submit;
        struct dma_async_tx_descriptor *tx = NULL;
        struct page *pagg_test = alloc_page(GFP_KERNEL);
#ifdef PRINT_INFO
        mdc_info("alloc_page: %p, p_count: %d\n", 
                 pagg_test, atomic_read(&pagg_test->_count));

#endif
        tx = async_page(bv->bv_page, pagg_test, tx, bv->bv_offset, bv->bv_len);
        init_async_submit(&submit, ASYNC_TX_ACK, tx, NULL, NULL, NULL);
        async_trigger_callback(&submit);
#ifdef PRINT_INFO
        mdc_info("insert page %p p_count: %d sector: %lu to bt: %p, sector: %lu(idx :%d)\n",
                pagg_test, atomic_read(&pagg_test->_count), sector, bt, bt->lba, item);
#endif
        rp->page = pagg_test;
        rp->valid = 1;
        rp->sector = sector;               
        rp->offset = bv->bv_offset;
        rp->length = bv->bv_len;
        bt->dirty_pages += 1;
    }
    return bt;
}


void transfer_bio_read_to_vdisk_cache_data(
                    struct cache_tree_data *ctd, 
                    struct vdisk_cache_data *vcd, 
                    struct bio_read_cache *brc, 
                    sector_t insert_sector, int dd_idx)
{
    struct r5cdev *cdev;
    if(vcd == NULL || brc == NULL) 
    {
        mdc_err("vcd or brc is NULL\n");
        return; 
    }

	cdev = &vcd->dev[dd_idx];
#ifdef PRINT_INFO
    mdc_info("vcd: %lu %p, dd_idx: %d, cdev: %p, brc: %d %p, page: %p\n",
            vcd->lba_align, vcd, dd_idx, cdev, brc->sector, brc, brc->page);
#endif
    vcd->lba_align = insert_sector; 
    // luoji ???
    if(/*cdev->dirty == 1*/test_bit(VCD_PAGE_DIRTY, &cdev->flag) &&
       cdev->page != NULL)
    {
        if(cdev->sector != brc->sector)
        {
            mdc_err("logical_sector %lu != old_sector %lu\n",
                    brc->sector, cdev->sector);
            // TODO: add page to page_pool
#ifdef PRINT_INFO
            mdc_info("free page %p count %d\n", brc->page,
                     atomic_read(&brc->page->_count));
#endif
            __free_page(brc->page);
            brc->page = NULL;
        }
	    cdev->page = brc->page;
    }
    else
    {
        clear_bit(VCD_PAGE_DIRTY, &cdev->flag);
        // cdev->dirty = 0;
	    cdev->page = brc->page;
        cdev->sector = brc->sector;
        brc->valid = 0;
        brc->page = NULL;
    }
    brc->sector = -1;
    return;
}




static void fill_page_endio(struct bio *bi)
{
    struct r5cdev *cdev;
    struct vdisk_cache_data *vcd;
    struct cache_tree_data *ctd = Gmddev->ctd;
    struct async_submit_ctl submit;
    struct dma_async_tx_descriptor *tx = NULL;

    if((cdev = bi->bi_private) != NULL)
    {
        struct page *old_p = cdev->page;
        struct page *new_p = bi->bi_io_vec[0].bv_page;

        tx = async_page(old_p, new_p, tx, cdev->offset, cdev->length);
        init_async_submit(&submit, ASYNC_TX_ACK, tx,  
                          NULL, NULL, NULL);
        async_trigger_callback(&submit);

#ifdef PRINT_INFO
        mdc_info("free page %p, p_count: %d\n", 
                 old_p, atomic_read(&old_p->_count));
#endif
        __free_page(old_p);
        cdev->page = new_p;
        clear_bit(VCD_PAGE_FILLING, &cdev->flag);
        cdev->offset = 0;
        cdev->length = PAGE_SIZE;

        vcd = cdev->vcd;
        atomic_dec(&vcd->filling_pages);
        if(atomic_read(&vcd->filling_pages) == 0)
            clear_bit(VCD_IS_FILLING, &vcd->flag);
    }
    else 
        mdc_err("cdev is NULL\n");
    return;
}




void fill_page(struct mddev *mddev, struct r5cdev *cdev)
{
    struct cache_tree_data *ctd = mddev->ctd;
    struct bio *bi;
    struct page *p = NULL;
    int devnum = mddev->raid_disks - 1;

    bi = cache_bio_alloc_mddev(GFP_NOIO, 1, mddev);
        
    p = alloc_page(GFP_KERNEL);
#ifdef PRINT_INFO
    mdc_info("alloc_page: %p, p_count: %d\n", 
            p, atomic_read(&p->_count));
#endif
    
    bio_add_page(bi, p, PAGE_SIZE, 0);

    sector_t new_logical;

#ifdef USE_RECOMBINE_STRIPE
    new_logical = get_new_logical_address(ctd, cdev->sector);
#else
    new_logical = cdev->sector;
#endif
 
#ifdef PRINT_INFO
    mdc_info("sector: %lu, new_logical: %lu\n", 
             cdev->sector, new_logical);
#endif
 
    bi->bi_iter.bi_sector = new_logical + ctd->remaining_sectors;
    bi->bi_rw = READ;
    bi->bi_private = cdev;
    bi->bi_end_io = fill_page_endio;
    cache_set_bi_stripes(bi, 1);

#ifdef PRINT_INFO
    mdc_info("bi: %p, %lu page: %p p_count: %d new sector: %lu, read_bio_count: %d, ori_off: %d, ori_len: %d\n", 
             bi, cdev->sector, p, atomic_read(&p->_count), 
             bi->bi_iter.bi_sector, ++read_bio_count, cdev->offset, cdev->length);
#endif
    mddev->pers->make_request(mddev, bi);
    return 0;

}

void transfer_bio_test_to_vdisk_cache_data(struct cache_tree_data *ctd, 
                                           struct vdisk_cache_data *vcd, 
                                           struct bio_test *bt, int disk_num)
{
    int idx = 0; 
    struct r5cdev *cdev;
    struct r5plug *rp;
    if(vcd == NULL || bt == NULL) 
    {
        mdc_err("vcd or bt is NULL\n");
        return; 
    }
#ifdef PRINT_INFO
    mdc_info("vcd: %lu %p, bt: %lu, %p, disk_num: %d\n",
            vcd->lba_align, vcd, bt->lba, bt, disk_num);
#endif
    vcd->lba_align = bt->lba >> 3;
    while(idx < disk_num)
    {
        if(bt->dev[idx].valid == 1)
        {
	        cdev = &vcd->dev[idx];
            rp = &bt->dev[idx];

            spin_lock(&cdev->lock);
            if(test_bit(VCD_PAGE_FLUSHING, &cdev->flag))
            {
                // cdev is flushing now, use replce
                if(cdev->replace_page == NULL)
                {
                    // replace has no page now!
                    cdev->replace_page = rp->page;
                    cdev->replace_offset = rp->offset;
                    cdev->replace_length = rp->length;

                    set_bit(VCD_WITH_REPLACE_PAGES, &vcd->flag);
                }
                else
                {
                    // replace has page now!
                    if(rp->offset <= cdev->replace_offset &&
                       (rp->offset + rp->length) >= (cdev->replace_offset + cdev->replace_length))
                    {
#ifdef PRINT_INFO
                        mdc_info("free page: %p, p_count: %d\n",
                                 cdev->replace_page, atomic_read(&cdev->replace_page->_count));
#endif
                        // free old page
                        __free_page(cdev->replace_page);
                        // just replace page
                        cdev->replace_page = rp->page;
                        cdev->replace_offset = rp->offset;
                        cdev->replace_length = rp->length;
                    }
                    else
                    {
                        // async
                        struct async_submit_ctl submit;
                        struct dma_async_tx_descriptor *tx = NULL;
#ifdef PRINT_INFO
                        mdc_info("replace page: %p has valid data, async\n", cdev->replace_page);
#endif
                        tx = async_page(rp->page, cdev->replace_page, tx, rp->offset, rp->length);
                        init_async_submit(&submit, ASYNC_TX_ACK, tx, 
                                          NULL, NULL, NULL);
                        async_trigger_callback(&submit);
    
                        // update offset and length
                        unsigned int new_offset = MIN(cdev->replace_offset, rp->offset);
                        cdev->replace_length = MAX(cdev->replace_offset + cdev->replace_length,
                                                  rp->offset + rp->length) - new_offset;
                        cdev->replace_offset = new_offset;
                        
#ifdef PRINT_INFO
                        mdc_info("free page: %p, p_count: %d\n",
                                 rp->page, atomic_read(&rp->page->_count));
#endif
                        // free new page
                        __free_page(rp->page);

                    }
                }
                // so wait flushing end, and write_page_endio will handle it!
            }
            else if(test_bit(VCD_PAGE_DIRTY, &cdev->flag) /*cdev->dirty == 1*/ &&
                    cdev->page != NULL)
            {
                if(cdev->sector != bt->dev[idx].sector)
                    mdc_err("logical_sector %lu != old_sector %lu\n",
                            bt->dev[idx].sector, cdev->sector);
                if(rp->offset <= cdev->offset && 
                  (rp->offset + rp->length) >= (cdev->offset + cdev->length))
                {
#ifdef PRINT_INFO
                    mdc_info("free page %p p_count %d\n", cdev->page,
                          atomic_read(&cdev->page->_count));
#endif
                    // just replace page
                    __free_page(cdev->page);
                    cdev->page = rp->page;
                    cdev->sector = rp->sector;
                    cdev->length = rp->length;
                    cdev->offset = rp->offset;
                }
                else
                {
                    // async valid data        
                    struct page *pagg_test = cdev->page;
                    struct async_submit_ctl submit;
                    struct dma_async_tx_descriptor *tx = NULL;
#ifdef PRINT_INFO
                    mdc_info("old page: %p has valid data, async\n", pagg_test);
#endif
                    tx = async_page(rp->page, cdev->page, tx, rp->offset, rp->length);
                    init_async_submit(&submit, ASYNC_TX_ACK, tx, 
                                      NULL, NULL, NULL);
                    async_trigger_callback(&submit);
 #ifdef PRINT_INFO
                    mdc_info("update page %p p_count: %d sector: %lu to bt: %p, sector: %lu(idx :%d)\n",
                            pagg_test, atomic_read(&pagg_test->_count), cdev->sector, bt, bt->lba, idx);
#endif
                   
#ifdef PRINT_INFO
                    mdc_info("free page %p p_count %d\n", rp->page,
                          atomic_read(&rp->page->_count));
#endif
                    __free_page(rp->page);

                    unsigned int new_offset = MIN(rp->offset, cdev->offset);
                    cdev->length = MAX(rp->offset + rp->length, cdev->offset + cdev->length) - cdev->offset; 
                    cdev->offset = new_offset;
                }
            }
            else
            {
                struct page *old_page = cdev->page;
                struct page *new_page = rp->page;

                set_bit(VCD_PAGE_DIRTY, &cdev->flag);
                atomic_inc(&vcd->dirty_pages);

                if(rp->offset != 0 || rp->length != 4096)
                {
                    if(old_page)
                    {
                        // async valid data        
                        struct async_submit_ctl submit;
                        struct dma_async_tx_descriptor *tx = NULL;
#ifdef PRINT_INFO
                        mdc_info("old page: %p has valid data, async\n", old_page);
#endif
                        tx = async_page(new_page, old_page, tx, rp->offset, rp->length);
                        init_async_submit(&submit, ASYNC_TX_ACK, tx, 
                                      NULL, NULL, NULL);
                        async_trigger_callback(&submit);

                        __free_page(new_page);
                        rp->valid = 0;
                        rp->page = NULL;
                        rp->offset = rp->length = 0;
                    }
                    else
                    {
                        cdev->page = rp->page;
                        cdev->sector = rp->sector;
                        cdev->length = rp->length;
                        cdev->offset = rp->offset;
                        cdev->vcd = vcd;
                        rp->valid = 0;
                        rp->page = NULL;

                        set_bit(VCD_PAGE_FILLING, &cdev->flag);
                        set_bit(VCD_IS_FILLING, &vcd->flag);
                        atomic_inc(&vcd->filling_pages);
                        fill_page(Gmddev, cdev);
                    }
                }
                else
                {
                    cdev->page = rp->page;
                    cdev->sector = rp->sector;
                    cdev->length = rp->length;
                    cdev->offset = rp->offset;
                    cdev->vcd = vcd;
                    rp->valid = 0;
                    rp->page = NULL;
                    rp->offset = rp->length = 0;

                    if(old_page)
                    {
#ifdef PRINT_INFO
                        mdc_info("free page %p p_count %d\n", 
                                 old_page,  atomic_read(&old_page->_count));
#endif
                        __free_page(old_page);
                    }
                }
            }
            spin_unlock(&cdev->lock);
            rp->valid = 0;
            rp->page = NULL;

#ifdef PRINT_INFO
            mdc_info("add idx: %d, page %p sector: %lu, p_count %d, to vcd %p dirty: %d, offset: %d, len: %d\n", 
                    idx,
                    cdev->page, 
                    cdev->sector,
                    atomic_read(&cdev->page->_count),
                    vcd,
                    atomic_read(&vcd->dirty_pages),
                    cdev->offset,
                    cdev->length);
#endif
        }
        ++idx;
    }
    bt->lba = -1;
    return;
}


void handle_bio_test_to_tree(struct mddev *mddev, 
                             struct bio_test *bt)
{
    struct cache_tree_data *ctd = mddev->ctd;
    if(!mddev || !bt)
        return;

#ifdef PRINT_INFO
    mdc_info("bt: %lu %p\n", bt->lba, bt);
#endif
    int devs = mddev->raid_disks, pos = 0;
    sector_t logical_sector = bt->lba, 
             insert_sector = (bt->lba >> 3);
    struct data_cache_radix_tree_node *node_hitted = NULL; 
    struct vdisk_cache_data* cache_hitted = NULL;
    int subs;

    node_hitted = lookup_data_node_in_tree(ctd->data_cache_tree_root,
                                           insert_sector);
    pos = (insert_sector & CACHE_RADIX_TREE_MAP_MASK);
    if(node_hitted)
    {
        cache_hitted = node_hitted->slots[pos];
    }

#ifdef PRINT_INFO
    mdc_info("node_hitted: %p, cache_hitted: %p, pos: %d\n",
            node_hitted, cache_hitted, pos);
#endif
    if(cache_hitted != NULL)
    { 
        // vdisk_cache_data in radix tree
#ifdef PRINT_INFO
        mdc_info("hit radix tree cache! bt: %lu, %p, cache_hitted: %lu %p\n",
                bt->lba, bt, cache_hitted->lba_align, cache_hitted);
#endif
        transfer_bio_test_to_vdisk_cache_data(ctd, cache_hitted, bt,
                                              devs - 1);
        // move node to lru head
        if(test_bit(VCD_IS_FLUSING, &cache_hitted->flag))
            ;
        else if(test_bit(VCD_IN_REPLACE, &cache_hitted->flag))
        {
            spin_lock(&ctd->replace_vdisk_cache_data_list_lock);
            clear_bit(VCD_IN_REPLACE, &cache_hitted->flag);
            list_del_init(&cache_hitted->lru);
            atomic_dec(&ctd->replace_vdisk_cache_data_count);
            spin_unlock(&ctd->replace_vdisk_cache_data_list_lock);

            spin_lock(&ctd->dirty_vdisk_cache_data_list_lock);
            set_bit(VCD_IN_DIRTY, &cache_hitted->flag);
            list_add(&cache_hitted->lru, &ctd->dirty_vdisk_cache_data_list);
            atomic_inc(&ctd->dirty_vdisk_cache_data_count);
            spin_unlock(&ctd->dirty_vdisk_cache_data_list_lock);
#ifdef PRINT_INFO
            mdc_info("move cache_hitted %p (count: %d) from replace_list to dirty list\n",
                    cache_hitted, atomic_read(&ctd->dirty_vdisk_cache_data_count));
#endif
        }
        else if(test_bit(VCD_IN_CLEAN, &cache_hitted->flag) /*cache_hitted->dirty == 0*/)
        {
            spin_lock(&ctd->clean_vdisk_cache_data_list_lock);
            clear_bit(VCD_IN_CLEAN, &cache_hitted->flag);
            list_del_init(&cache_hitted->lru);
            atomic_dec(&ctd->clean_vdisk_cache_data_count);
            spin_unlock(&ctd->clean_vdisk_cache_data_list_lock);

            spin_lock(&ctd->dirty_vdisk_cache_data_list_lock);
            set_bit(VCD_IN_DIRTY, &cache_hitted->flag);
            list_add(&cache_hitted->lru, &ctd->dirty_vdisk_cache_data_list);
            atomic_inc(&ctd->dirty_vdisk_cache_data_count);
            spin_unlock(&ctd->dirty_vdisk_cache_data_list_lock);
#ifdef PRINT_INFO
            mdc_info("move cache_hitted %p (count: %d) from clean_list to dirty list\n",
                    cache_hitted, atomic_read(&ctd->dirty_vdisk_cache_data_count));
#endif
        }
        else if(test_bit(VCD_IN_DIRTY, &cache_hitted->flag))
        {
            spin_lock(&ctd->dirty_vdisk_cache_data_list_lock);
            list_del_init(&cache_hitted->lru);
            set_bit(VCD_IN_DIRTY, &cache_hitted->flag);
            list_add(&cache_hitted->lru, &ctd->dirty_vdisk_cache_data_list);
            spin_unlock(&ctd->dirty_vdisk_cache_data_list_lock);
#ifdef PRINT_INFO
            mdc_info("move cache_hitted %p (count: %d) dirty list head\n",
                    cache_hitted, atomic_read(&ctd->dirty_vdisk_cache_data_count));
#endif
        }
        else
        {
            mdc_err("strange flag %d for vcd %lu %p\n", 
                   cache_hitted->flag, cache_hitted->lba_align, cache_hitted);
        }
    }
    else
    {
        if(!is_cache_full_data(ctd->vdisk_cache_data_count))
        {
            // alloc vdisk_cache_data
            cache_hitted = alloc_data_cache_struct(
                    ctd->data_cache_tree_root, 
                    insert_sector, devs);

            if(cache_hitted != NULL) 
            {
                atomic_inc(&ctd->vdisk_cache_data_count);
                transfer_bio_test_to_vdisk_cache_data(ctd, cache_hitted, bt,
                                                      devs - 1);
#ifdef PRINT_INFO
                mdc_info("cache not full alloc vcd: %lu, %p\n",
                        cache_hitted->lba_align, cache_hitted);
#endif
            }
            else
                mdc_err("cache not full but vcd alloc failed!\n");
        }
        else
        {
handle_bio_test_to_tree_retry:
            subs = atomic_read(&ctd->replace_vdisk_cache_data_count);
            if(subs <= 0)
            {
                spin_lock(&ctd->clean_vdisk_cache_data_list_lock);
                if(!list_empty_careful(&ctd->clean_vdisk_cache_data_list))
                {
                    cache_hitted = list_last_entry(
                                    &ctd->clean_vdisk_cache_data_list,
                                    struct vdisk_cache_data,
                                    lru);
                    atomic_dec(&ctd->clean_vdisk_cache_data_count);
                    list_del_init(&cache_hitted->lru);
                    clear_bit(VCD_IN_CLEAN, &cache_hitted->flag);
                    spin_unlock(&ctd->clean_vdisk_cache_data_list_lock);
                    md_wakeup_thread(ctd->vdisk_cache_data_flush_thread);
#ifdef PRINT_INFO 
                    mdc_info("subs: %d, use clean vcds: %lu, %p\n",
                            subs, cache_hitted->lba_align, cache_hitted);
#endif
                }
                else
                {
                    spin_unlock(&ctd->clean_vdisk_cache_data_list_lock);
                    // need to flush some vdisk_cache_data to raid 
                    set_bit(MDC_FLUSH_VCDS_FORCE, &ctd->_flags);
#ifdef PRINT_INFO
                    mdc_info("force to flush vcds\n");
#endif
                    md_wakeup_thread(ctd->vdisk_cache_data_flush_thread);
                    wait_event(ctd->wait_for_vcds_flush_queue,
                        atomic_read(&ctd->replace_vdisk_cache_data_count) > 0);
                    clear_bit(MDC_FLUSH_VCDS_FORCE, &ctd->_flags);
                }
            }        
            if(!cache_hitted)
            { 
                spin_lock(&ctd->replace_vdisk_cache_data_list_lock);
                if(!list_empty_careful(&ctd->replace_vdisk_cache_data_list))
                {
                    // use free vdisk_cache_data
                    cache_hitted = list_last_entry(
                                    &ctd->replace_vdisk_cache_data_list,
                                    struct vdisk_cache_data, 
                                    lru);
                    list_del_init(&cache_hitted->lru);
                    clear_bit(VCD_IN_REPLACE, &cache_hitted->flag);
                    atomic_dec(&ctd->replace_vdisk_cache_data_count);
                    
#ifdef PRINT_INFO 
                    if(cache_hitted)
                        mdc_info("subs: %d, use replace vcds: %lu, %p, count: %d\n",
                                subs, cache_hitted->lba_align, cache_hitted,
                                atomic_read(&ctd->replace_vdisk_cache_data_count));
#endif

                }
                else
                {
                    mdc_err("reset replace_vdisk_cache_data_list\n");
                    INIT_LIST_HEAD(&ctd->replace_vdisk_cache_data_list);
                    atomic_set(&ctd->replace_vdisk_cache_data_count, 0);
                }
                spin_unlock(&ctd->replace_vdisk_cache_data_list_lock);
            }

            if(cache_hitted)
            {
                // remove node from radix tree
                delete_node_in_tree(ctd->data_cache_tree_root,
                                   cache_hitted->lba_align);
    
                clean_vdisk_cache_data(cache_hitted, devs - 1);
    
                transfer_bio_test_to_vdisk_cache_data(ctd,
                                                      cache_hitted,
                                                      bt, devs - 1);
            }
            else
                goto handle_bio_test_to_tree_retry;
        }
        
        if(cache_hitted)
        {
            // move node to dirty lru head
            spin_lock(&ctd->dirty_vdisk_cache_data_list_lock);
            list_add(&cache_hitted->lru, 
                     &ctd->dirty_vdisk_cache_data_list);
            set_bit(VCD_IN_DIRTY, &cache_hitted->flag);
            atomic_inc(&ctd->dirty_vdisk_cache_data_count);
            spin_unlock(&ctd->dirty_vdisk_cache_data_list_lock);
#ifdef PRINT_INFO
            mdc_info("add cache_hitted %p (count %d) dirty list head\n",
                    cache_hitted, atomic_read(&ctd->dirty_vdisk_cache_data_count));
#endif

            // add vdisk_cache_data to radix tree
            spin_lock(&ctd->radix_tree_lock_data);
            node_hitted = insert_cache_data_in_tree(
                                ctd->data_cache_tree_root,
                                insert_sector, cache_hitted);
            spin_unlock(&ctd->radix_tree_lock_data);
        }
    }
    return;
}
        
void transfer_vdisk_cache_data_to_vfd(struct vdisk_cache_data *vcd, 
                                      struct vdisk_flush_data *vfd, 
                                      int devnum)
{
    int idx = 0;
    vfd->lba_align = vcd->lba_align;
    struct page *p;
#ifdef PRINT_INFO
    mdc_info("vcd: %lu %p,(dirty_pages: %d) vfd: %p\n", 
             vcd->lba_align, vcd,
             atomic_read(&vcd->dirty_pages),
             vfd);
#endif
    while(idx < devnum)
    {
        if(test_bit(VCD_PAGE_DIRTY, &vcd->dev[idx].flag) )
        {
            set_bit(VCD_PAGE_FLUSHING, &vcd->dev[idx].flag);
            p = vcd->dev[idx].page;
            vfd->dev[idx].page = p;
            vfd->dev[idx].sector = vcd->dev[idx].sector;
            vfd->dev[idx].cdev = &vcd->dev[idx];
            vcd->dev[idx].vcd = vcd;
            vfd->dev[idx].dirty = 1;
            
            vfd->dev[idx].offset = vcd->dev[idx].offset;
            vfd->dev[idx].length = vcd->dev[idx].length;

            atomic_inc_and_test(&p->_count);
#ifdef PRINT_INFO
            mdc_info("vfd %p idx %d page %p p_count: %d sector %lu\n",
                     vfd, idx, vfd->dev[idx].page, 
                     atomic_read(&p->_count),
                     vfd->dev[idx].sector);
#endif
        }
        ++idx;
    }
    return;
}




static void write_page_endio(struct bio *bi)
{
    struct r5cdev *dev = NULL;
    struct cache_tree_data *ctd = Gmddev->ctd;
    //bio_endio(bi);

    if((dev = bi->bi_private) == NULL)
    {
        struct bio_vec *bv;
        int mmp = 0;
        while(mmp < bi->bi_vcnt)
        {
            bv = &bi->bi_io_vec[mmp];
            if(bv->bv_page != NULL)
            {
#ifdef PRINT_INFO
                mdc_info("free page %p count %d\n", bv->bv_page,
                     atomic_read(&bv->bv_page->_count));
#endif
                __free_page(bv->bv_page);
                bv->bv_page = NULL;
            }
            mmp++;
        }
    }
    else
    {
        if(test_bit(VCD_PAGE_FLUSHING_ALL, &dev->flag) /*dev->flush == 1 */)
        {
            atomic_dec(&ctd->flush_all_vfds_pages);
        }
        else
        {
            struct vdisk_cache_data *vcd = dev->vcd;
            atomic_dec(&vcd->dirty_pages);
            clear_bit(VCD_PAGE_FLUSHING, &dev->flag);
            clear_bit(VCD_PAGE_DIRTY, &dev->flag);
#ifdef PRINT_INFO
            mdc_info("vcd %p dirty_pages: %d\n", vcd, atomic_read(&vcd->dirty_pages));
#endif
            spin_lock(&dev->lock);
            // free page
            
#ifdef PRINT_INFO
            mdc_info("vcd: %p, cdev: %p, free page: %p, p_count: %d\n", 
                     vcd, dev, dev->page, atomic_read(&dev->page->_count));
#endif
            __free_page(dev->page);

            if(dev->replace_page != NULL)
            {
                if(dev->replace_offset <= dev->offset &&
                   (dev->replace_offset + dev->replace_length) >= (dev->offset + dev->length))
                {
                    // just replace page
#ifdef PRINT_INFO
                    mdc_info("use replace, free page: %p p_count; %d but do not free\n", 
                             dev->page, atomic_read(&dev->page->_count));
#endif
                    __free_page(dev->page);

                    dev->page = dev->replace_page;
                    dev->offset = dev->replace_offset;
                    dev->length = dev->replace_length;
                }
                else
                {
                    // async 
                    struct async_submit_ctl submit;
                    struct dma_async_tx_descriptor *tx = NULL;
                    tx = async_page(dev->replace_page, dev->page, tx, dev->replace_offset, dev->replace_length);
                    init_async_submit(&submit, ASYNC_TX_ACK, tx, NULL, NULL, NULL);
                    async_trigger_callback(&submit);
                    
#ifdef PRINT_INFO
                    mdc_info("free page: %p p_count; %d\n", 
                             dev->replace_page, atomic_read(&dev->replace_page->_count));
#endif
                    __free_page(dev->replace_page);

                    unsigned int new_offset = MIN(dev->offset, dev->replace_offset);
                    dev->length = MAX(dev->offset + dev->length, dev->replace_offset + dev->replace_length) -
                                    new_offset;
                    dev->offset = new_offset;
                }
                set_bit(VCD_PAGE_DIRTY, &dev->flag);
                dev->replace_page = NULL;
                dev->replace_offset = dev->replace_length = 0;
            }
            spin_unlock(&dev->lock);
            
            // add to replace list 
            if(atomic_read(&vcd->dirty_pages) == 0)
            {
                if(test_bit(VCD_WITH_REPLACE_PAGES, &vcd->flag))
                {
                    int i = 0;
                    for(; i < Gmddev->raid_disks - 1; ++i)
                        if(test_bit(VCD_PAGE_DIRTY, &vcd->dev[i].flag))
                            atomic_inc(&vcd->dirty_pages);
                    if(atomic_read(&vcd->dirty_pages) > 0)
                    {
                        spin_lock(&ctd->dirty_vdisk_cache_data_list_lock);
                        list_add(&vcd->lru, &ctd->dirty_vdisk_cache_data_list);
                        atomic_inc(&ctd->dirty_vdisk_cache_data_count);
                        set_bit(VCD_IN_DIRTY, &vcd->flag);
                        spin_unlock(&ctd->dirty_vdisk_cache_data_list_lock);
#ifdef PRINT_INFO
                        mdc_info("add vcd %p dirty_pages: %d to diry_vdisk_cache_data_list, count: %d\n", 
                                vcd, atomic_read(&vcd->dirty_pages),
                                atomic_read(&ctd->replace_vdisk_cache_data_count));
#endif
                    }
                    else
                    {
                        // mdc_err("error, no dirty_pages but with VCD_WITH_REPLACE_PAGES\n");
                        clear_bit(VCD_WITH_REPLACE_PAGES, &vcd->flag);
                        spin_lock(&ctd->replace_vdisk_cache_data_list_lock);
                        list_add(&vcd->lru, &ctd->replace_vdisk_cache_data_list); 
                        atomic_inc(&ctd->replace_vdisk_cache_data_count);
                        set_bit(VCD_IN_REPLACE, &vcd->flag);
                        spin_unlock(&ctd->replace_vdisk_cache_data_list_lock);
#ifdef PRINT_INFO
                        mdc_info("add vcd %p dirty_pages: %d to replace_vdisk_cache_data_list, count: %d\n", 
                                vcd, atomic_read(&vcd->dirty_pages),
                                atomic_read(&ctd->replace_vdisk_cache_data_count));
#endif
                    }
                }
                else
                {
                    spin_lock(&ctd->replace_vdisk_cache_data_list_lock);
                    list_add(&vcd->lru, &ctd->replace_vdisk_cache_data_list); 
                    atomic_inc(&ctd->replace_vdisk_cache_data_count);
                    set_bit(VCD_IN_REPLACE, &vcd->flag);
                    clear_bit(VCD_IS_FLUSING, &vcd->flag);
                    spin_unlock(&ctd->replace_vdisk_cache_data_list_lock);
#ifdef PRINT_INFO
                    mdc_info("add vcd %p dirty_pages: %d to replace_vdisk_cache_data_list, count: %d\n", 
                            vcd, atomic_read(&vcd->dirty_pages),
                            atomic_read(&ctd->replace_vdisk_cache_data_count));
#endif
                }
                //if(test_bit(MDC_FLUSH_VCDS_FORCE, &ctd->_flags))
                wake_up(&ctd->wait_for_vcds_flush_queue);
            }
        }
    }
    if(ctd->will_free)
        wake_up(&ctd->wait_for_flush_io_queue);
    return;
}


static void write_page_flush_clean_endio(struct bio *bi)
{
    struct page *p;
    struct cache_tree_data *ctd = Gmddev->ctd;

    if((p = bi->bi_private) != NULL)
    {
       // __free_page(p);
    }
    atomic_dec(&ctd->flush_all_vfds_pages);
    if(ctd->will_free)
        wake_up(&ctd->wait_for_flush_io_queue);
    return;
}



void deal_with_full_vdisk_flush_data(struct mddev *mddev, 
                                     struct vdisk_flush_data *vfd)
{
    struct cache_tree_data *ctd = mddev->ctd;
    int devnum = mddev->raid_disks - 1;
    int idx = 0;
    while(idx < devnum)
    {
        if(vfd->dev[idx].dirty == 1 || vfd->dev[idx].dirty == 33)

        {
            struct bio *bi = cache_bio_alloc_mddev(GFP_NOIO, 1,
                                                   mddev);
            bio_add_page(bi, vfd->dev[idx].page, vfd->dev[idx].length, vfd->dev[idx].offset);
            bi->bi_iter.bi_sector = vfd->dev[idx].sector + 
                                    ctd->remaining_sectors;
            bi->bi_bdev = ctd->bd;
            bi->bi_rw = WRITE | REQ_SYNC;
            if(vfd->dev[idx].cdev == NULL && vfd->dev[idx].dirty == 1 )
            {
                bi->bi_private = vfd->dev[idx].page;
                bi->bi_end_io = write_page_flush_clean_endio;
            }
            else
            {
                bi->bi_private = vfd->dev[idx].cdev;
                bi->bi_end_io = write_page_endio;
            }
            cache_set_bi_stripes(bi, 1);
        
#ifdef PRINT_INFO
            mdc_info("vfd: %lu, %p bi: %p, idx: %d, page: %p, p_count: %d, sector: %lu, write_bio_count: %d, offset: %d, length: %d\n", 
                    vfd->lba_align,
                    vfd,
                    bi,
                    idx,
                    vfd->dev[idx].page, 
                    atomic_read(&vfd->dev[idx].page->_count),
                    bi->bi_iter.bi_sector,
                    ++write_bio_count,
                    vfd->dev[idx].offset, vfd->dev[idx].length);
#endif
            mddev->pers->make_request(mddev, bi);
            // TODO
            vfd->dev[idx].dirty = 0;
        }
        ++idx;
    }


    clean_vfd(vfd, devnum);
    spin_lock(&ctd->vdisk_flush_data_list_lock);
    list_add(&vfd->lru, &ctd->vdisk_flush_data_list);
    spin_unlock(&ctd->vdisk_flush_data_list_lock);
    return 0;
}


void print_vfds(struct vdisk_flush_data *vfd, int devnum)
{
    int i = 0;
    for(i = 0; i < devnum; ++i)
    {
        sm_info("vfd(%lu %p)[%d]: %ld, off: %d, len: %d, page: %p\n",
                vfd->lba_align, vfd, i, vfd->dev[i].sector, 
                vfd->dev[i].offset, vfd->dev[i].length, 
                vfd->dev[i].page);
    }
}




static void vdisk_cache_data_flush_thread(struct md_thread *thread)
{
    int count = 0;
    struct mddev *mddev = thread->mddev;
    struct cache_tree_data *ctd = mddev->ctd;
    struct r5meta* meta = ctd->cache_r5meta;
    struct vdisk_flush_data *vfd = NULL;
    struct vdisk_cache_data *vcd = NULL;
    struct vdisk_flush_data** sm_return = NULL;
    int devnum = mddev->raid_disks - 1, m;
    int vfd_size = sizeof(struct vdisk_flush_data) + 
                   devnum * sizeof(struct r5fdev);
    bool vfd_valid = false;

    spin_lock(&ctd->dirty_vdisk_cache_data_list_lock);
    while(!list_empty_careful(&ctd->reclaim_vfds_list)  || 
         (count < 128 && !list_empty_careful(&ctd->dirty_vdisk_cache_data_list)))
    {
        // get a vcd waiting to flush
        if(count < 128 && !list_empty_careful(&ctd->dirty_vdisk_cache_data_list))
        {
            vcd = list_last_entry(&ctd->dirty_vdisk_cache_data_list,
                                  struct vdisk_cache_data,
                                  lru);
            list_del_init(&vcd->lru);
            clear_bit(VCD_IN_DIRTY, &vcd->flag);
            atomic_dec(&ctd->dirty_vdisk_cache_data_count);
            spin_unlock(&ctd->dirty_vdisk_cache_data_list_lock);
#ifdef PRINT_INFO
            mdc_info("remove vcd %p dirty: %d (count %d) from dirty_vdisk_cache_data_list\n",
                     vcd, atomic_read(&vcd->dirty_pages),
                     atomic_read(&ctd->dirty_vdisk_cache_data_count));
#endif

            // get a vfd to flush
            spin_lock(&ctd->vdisk_flush_data_list_lock);
            if(!list_empty_careful(&ctd->vdisk_flush_data_list))
            {
                vfd = list_first_entry(&ctd->vdisk_flush_data_list,
                                      struct vdisk_flush_data,
                                      lru);
                list_del_init(&vfd->lru);
                spin_unlock(&ctd->vdisk_flush_data_list_lock);
            }
            else
            {
                spin_unlock(&ctd->vdisk_flush_data_list_lock);
                vfd = (struct vdisk_flush_data *)kmalloc(vfd_size,
                                                         GFP_KERNEL);
                spin_lock(&ctd->alloc_vdisk_flush_data_list_lock);
                atomic_inc(&ctd->vdisk_flush_data_count);
                list_add(&vfd->alloc_lru, &ctd->alloc_vdisk_flush_data_list);
                spin_unlock(&ctd->alloc_vdisk_flush_data_list_lock);
#ifdef PRINT_INFO
                mdc_info("alloc vfd: %p, count %d\n",
                        vfd, atomic_read(&ctd->vdisk_cache_data_count));
#endif
            }
            clean_vfd(vfd, devnum);

            // fill vdisk_flush_data 
            set_bit(VCD_IS_FLUSING, &vcd->flag);
            transfer_vdisk_cache_data_to_vfd(vcd, vfd, devnum);

            // handle ori vfd
#ifdef USE_RECOMBINE_STRIPE    
            sm_return = update_shmeta(ctd, vfd);

            for(m = 0; 
                sm_return && m < RETURN_VFD_NUM && 
                sm_return[m] != NULL; 
                m++)
            {
                // mdc_info("m: %d\n", m);
                // print_vfds(sm_return[m], 3);
                deal_with_full_vdisk_flush_data(mddev, sm_return[m]); 
                sm_return[m] = NULL;
            }
#else
            // flush to raid disks
            deal_with_full_vdisk_flush_data(mddev, vfd); 
#endif
        }

        // handle reclaim vfds
        struct vdisk_flush_data *reclaim_vfd = NULL;
        spin_lock(&ctd->reclaim_vfds_list_lock);
        while(atomic_read(&ctd->reclaim_vfds_count) > 0 &&
              !list_empty_careful(&ctd->reclaim_vfds_list))
        {
            reclaim_vfd = list_last_entry(&ctd->reclaim_vfds_list,
                                          struct vdisk_flush_data,
                                          lru);
            list_del_init(&reclaim_vfd->lru);
            atomic_dec(&ctd->reclaim_vfds_count);
            spin_unlock(&ctd->reclaim_vfds_list_lock);
#ifdef USE_RECOMBINE_STRIPE
            sm_return = update_shmeta(ctd, reclaim_vfd);

            for(m = 0; 
                sm_return && m < RETURN_VFD_NUM && 
                sm_return[m] != NULL; 
                m++)
            {
                deal_with_full_vdisk_flush_data(mddev, sm_return[m]); 
                sm_return[m] = NULL;
            }
#else
            // flush to raid disks
            deal_with_full_vdisk_flush_data(mddev, reclaim_vfd); 
#endif
            spin_lock(&ctd->reclaim_vfds_list_lock);
        }
        spin_unlock(&ctd->reclaim_vfds_list_lock);
        

        spin_lock(&ctd->dirty_vdisk_cache_data_list_lock);
        count++;
    }
    spin_unlock(&ctd->dirty_vdisk_cache_data_list_lock);


    if(ctd->will_free)
    {
        spin_lock(&ctd->flush_all_vfds_list_lock);
        while(atomic_read(&ctd->flush_all_vfds_count) > 0 &&
              !list_empty_careful(&ctd->flush_all_vfds_list))
        {
            vfd = list_first_entry(&ctd->flush_all_vfds_list,
                                   struct vdisk_flush_data,
                                   lru);
            vfd_valid = false;
            if(vfd)
            {
                list_del_init(&vfd->lru);
                atomic_dec(&ctd->flush_all_vfds_count);
#ifdef PRINT_INFO
                mdc_info("flush_all_vfds: %lu %p %d\n",
                         vfd->lba_align, vfd, 
                         atomic_read(&ctd->flush_all_vfds_count));
#endif
                spin_unlock(&ctd->flush_all_vfds_list_lock);

                for(m = 0; m < (mddev->raid_disks - 1); m++)
                    if((vfd->dev[m].dirty == 1 || vfd->dev[m].dirty == 33) && 
                       vfd->dev[m].page != NULL)
                        vfd_valid = true;
                if(!vfd_valid)
                {
                    // kfree(vfd);
#ifdef PRINT_INFO
                    mdc_info("vfd invalid! %lu %p flush_all_vfds: %d and reset 0\n",
                             vfd->lba_align, vfd,
                             atomic_read(&ctd->flush_all_vfds_count));
#endif
                    spin_lock(&ctd->flush_all_vfds_list_lock);
                    continue;
                }
#ifdef USE_RECOMBINE_STRIPE
                if(list_empty_careful(&ctd->flush_all_vfds_list))
                    set_bit(MT_WILL_STOP, &meta->flags);
                sm_return = update_shmeta(ctd, vfd); 

                for(m = 0; 
                    sm_return && m < RETURN_VFD_NUM &&
                    sm_return[m] != NULL; 
                    m++)
                {
                    deal_with_full_vdisk_flush_data(mddev,
                                                sm_return[m]); 
                    sm_return[m] = NULL;
                }
#else
                deal_with_full_vdisk_flush_data(mddev,
                                                vfd); 
#endif
                spin_lock(&ctd->flush_all_vfds_list_lock);
            }
            else
            {
                mdc_err("break error\n");
                mdc_err("flush_all_vfds_count: %d,\
                        flush_all_vfds_pages: %d\n",
                        atomic_read(&ctd->flush_all_vfds_count),
                        atomic_read(&ctd->flush_all_vfds_pages));

                atomic_set(&ctd->flush_all_vfds_count, 0);
                atomic_set(&ctd->flush_all_vfds_pages, 0);
                break;
            }
        }
        spin_unlock(&ctd->flush_all_vfds_list_lock);
        
        int wait_times = 0;
        while(atomic_read(&ctd->flush_all_vfds_pages) != 0 &&
              wait_times < 200)
        {
            wait_times++;
            mdelay(10);
        }
        if(wait_times >= 200)
        {
            atomic_set(&ctd->flush_all_vfds_count, 0);
            atomic_set(&ctd->flush_all_vfds_pages, 0);
        }
        wake_up(&ctd->wait_for_flush_io_queue);
    }
    return;
}

static void bio_test_unplug_thread(struct md_thread *thread)
{
    struct mddev *mddev = thread->mddev;
    struct cache_tree_data *ctd = mddev->ctd;
    struct r5meta* meta = ctd->cache_r5meta;
    struct bio_test *abt;

    spin_lock(&ctd->plug_list_lock);
    while(/*(ctd->will_free == 1 && 
           !list_empty_careful(&ctd->plug_list)) ||*/
          (atomic_read(&ctd->plug_list_count) > 1024 && 
           !list_empty_careful(&ctd->plug_list)))
    {
        // del from unplug list
        abt = list_last_entry(&ctd->plug_list, struct bio_test, lru_list);
        list_del_init(&abt->lru_list);
        spin_unlock(&ctd->plug_list_lock);

        // add bio_test to radix tree
        handle_bio_test_to_tree(mddev, abt);
        
        // del from hash table
        spin_lock(&ctd->bio_test_hash_lock[BIO_TEST_HASH(abt->lba)]);
        hlist_del_init(&abt->hash);
        spin_unlock(&ctd->bio_test_hash_lock[BIO_TEST_HASH(abt->lba)]);

        // add to bio_test_list for free to use
        spin_lock(&ctd->bio_test_lock);
        list_add_tail(&abt->lru_list, &ctd->bio_test_list);
        spin_unlock(&ctd->bio_test_lock);

        atomic_dec(&ctd->plug_list_count);
        if(atomic_read(&ctd->plug_list_count) <= 1024)
            wake_up(&ctd->bio_test_queue);

        spin_lock(&ctd->plug_list_lock);
    }
    spin_unlock(&ctd->plug_list_lock);
    if(ctd->will_free)
        wake_up(&ctd->wait_for_flush_io_queue);
    wake_up(&ctd->bio_test_queue);

    return;
}

static void return_read_data(void *rbi)
{
    struct bio *bi = rbi;
#ifdef PRINT_INFO
    mdc_info("bi: %p\n", bi);

#endif
    if(!cache_dec_bi_stripes(bi)/* == bi->ori_bi_phys_segments */)
    {
        bi->bi_next = NULL;
        bi->bi_iter.bi_size = 0;
        bio_endio(bi);
    }
    return;
}


/*
bool add_read_page_to_radix_tree(struct mddev *mddev, 
                                 struct bio_read_cache *brc)
{
    struct cache_tree_data *ctd = mddev->ctd;
    struct data_cache_radix_tree_node *node_hitted = NULL;
    struct vdisk_cache_data *cache_hitted = NULL;

    sector_t new_sector, insert_sector;
    sector_t logical_sector = brc->sector;
    int dd_idx, result, pos;
    int dev = mddev->raid_disks - 1;
    int subs;

    new_sector = cache_compute_sector(mddev, logical_sector,
                                      &dd_idx);
    insert_sector = (new_sector >> 3);
    pos = ((new_sector >> 3) & CACHE_RADIX_TREE_MAP_MASK);

    spin_lock(&ctd->radix_tree_lock_data);
    node_hitted = lookup_data_node_in_tree(
                                ctd->data_cache_tree_root,
                                insert_sector);
    if(node_hitted)
        cache_hitted = node_hitted->slots[pos];
    spin_unlock(&ctd->radix_tree_lock_data);

    if(cache_hitted != NULL)
    {
        struct r5cdev *cdev = &cache_hitted->dev[dd_idx];
        transfer_bio_read_to_vdisk_cache_data(ctd, cache_hitted,
                                             brc, insert_sector, dd_idx);
        if(cache_hitted->dirty == 0)
        {
            // move to clean_vdisk_cache_data_list head
            spin_lock(&ctd->clean_vdisk_cache_data_list_lock);
            list_del_init(&cache_hitted->lru);
            set_bit(VCD_IN_CLEAN, &cache_hitted->flag);
            list_add(&cache_hitted->lru, 
                     &ctd->clean_vdisk_cache_data_list);
            atomic_inc(&ctd->clean_vdisk_cache_data_count);
            spin_unlock(&ctd->clean_vdisk_cache_data_list_lock);
        }
        else
        {
            // move to dirty_vdisk_cache_data_list head
            spin_lock(&ctd->dirty_vdisk_cache_data_list_lock);
            list_del_init(&cache_hitted->lru);
            list_add(&cache_hitted->lru, 
                     &ctd->dirty_vdisk_cache_data_list);
            atomic_inc(&ctd->dirty_vdisk_cache_data_count);
            spin_unlock(&ctd->dirty_vdisk_cache_data_list_lock);
#ifdef PRINT_INFO
            mdc_info("add vcd %p (count %d) to dirty_vdisk_cache_data_list\n",
                    cache_hitted, atomic_read(&ctd->dirty_vdisk_cache_data_count));
#endif

        }
        return true;
    }
    else 
    {
        if(!is_cache_full_data(ctd->vdisk_cache_data_count))
        {
            // alloc vdisk_cache_data
            cache_hitted = alloc_data_cache_struct(
                    ctd->data_cache_tree_root, 
                    insert_sector, dev);

            if(cache_hitted != NULL) 
            {
                atomic_inc(&ctd->vdisk_cache_data_count);
                transfer_bio_read_to_vdisk_cache_data(ctd, cache_hitted,
                                             brc, insert_sector, dd_idx);
            }
        }
        else
        {
add_read_page_to_radix_tree_retry:
            subs = atomic_read(&ctd->replace_vdisk_cache_data_count);
            if(subs <= 0)
            {
                spin_lock(&ctd->clean_vdisk_cache_data_list_lock);
                if(!list_empty_careful(&ctd->clean_vdisk_cache_data_list))
                {
                    cache_hitted = list_last_entry(
                                &ctd->clean_vdisk_cache_data_list,
                                struct vdisk_cache_data,
                                lru);
                    list_del_init(&cache_hitted->lru);
                    atomic_dec(&ctd->clean_vdisk_cache_data_count);
                    spin_unlock(&ctd->clean_vdisk_cache_data_list_lock);
                    md_wakeup_thread(ctd->vdisk_cache_data_flush_thread);
                }
                else
                {
                    spin_unlock(&ctd->clean_vdisk_cache_data_list_lock);
                    // need to flush some vdisk_cache_data to raid 
                    set_bit(MDC_FLUSH_VCDS_FORCE, &ctd->_flags);
                    md_wakeup_thread(ctd->vdisk_cache_data_flush_thread);
                    wait_event(ctd->wait_for_vcds_flush_queue,
                        atomic_read(&ctd->replace_vdisk_cache_data_count) > 0);
                    clear_bit(MDC_FLUSH_VCDS_FORCE, &ctd->_flags);
                }
            }        
            if(!cache_hitted)
            {
                spin_lock(&ctd->replace_vdisk_cache_data_list_lock);
                if(!list_empty_careful(&ctd->replace_vdisk_cache_data_list))
                {
                    cache_hitted = list_last_entry(
                                    &ctd->replace_vdisk_cache_data_list,
                                    struct vdisk_cache_data, 
                                    lru);
                    list_del_init(&cache_hitted->lru);
                    atomic_dec(&ctd->replace_vdisk_cache_data_count);
                }
                else
                {
                    INIT_LIST_HEAD(&ctd->replace_vdisk_cache_data_list);
                    atomic_set(&ctd->replace_vdisk_cache_data_count, 0);
                }

                spin_unlock(&ctd->replace_vdisk_cache_data_list_lock);
            } 
            if(cache_hitted)
            {
                // remove node from radix tree
                delete_node_in_tree(ctd->data_cache_tree_root,
                                    cache_hitted->lba_align);
        
                clean_vdisk_cache_data(cache_hitted, mddev->raid_disks - 1);
    
                transfer_bio_read_to_vdisk_cache_data(ctd, 
                                                     cache_hitted,
                                                     brc, insert_sector, dd_idx);
            }
            else
                goto add_read_page_to_radix_tree_retry;
        }
        if(cache_hitted)
        {
            // move node to clean lru head
            cache_hitted->dirty = 0;
            spin_lock(&ctd->clean_vdisk_cache_data_list_lock);
            list_add(&cache_hitted->lru, 
                    &ctd->clean_vdisk_cache_data_list);
            atomic_inc(&ctd->clean_vdisk_cache_data_count);
            spin_unlock(&ctd->clean_vdisk_cache_data_list_lock);
       
            // add free vdisk_cache_data to radix tree
            spin_lock(&ctd->radix_tree_lock_data);
            node_hitted = insert_cache_data_in_tree(
                                ctd->data_cache_tree_root,
                                insert_sector, cache_hitted);
            spin_unlock(&ctd->radix_tree_lock_data);
        }
    }
    return true;
}


static void add_read_page_to_radix_tree_thread(struct md_thread *thread)
{
    struct mddev *mddev = thread->mddev;
    struct cache_tree_data *ctd = mddev->ctd;
    struct bio_read_cache *brc = NULL;

    spin_lock(&ctd->add_read_page_list_lock);
    while(!list_empty_careful(&ctd->add_read_page_list))
    {
        brc = list_last_entry(&ctd->add_read_page_list, 
                         struct bio_read_cache,
                         lru);
        list_del_init(&brc->lru);
        spin_unlock(&ctd->add_read_page_list_lock);

        // add_read_page_to_radix_tree(mddev, brc);
        
        kmem_cache_free(brc_pool, brc);
        spin_lock(&ctd->add_read_page_list_lock);
    }
    spin_unlock(&ctd->add_read_page_list_lock);

    return;
}
*/

static void load_read_block_endio(struct bio *rbi)
{
    struct bio_read_cache *brc = rbi->bi_private;
    struct bio *bi = brc->bi;
    struct mddev *mddev = Gmddev;
    struct cache_tree_data *ctd = mddev->ctd;
    int error = rbi->bi_error;
    sector_t logical_sector = brc->sector;
    // bio_put(rbi);


    if(!error)
    {
        if(brc->bio_page == false)
        {
#ifdef PRINT_INFO
            mdc_info("brc %lu %p->bio_page is NULL\n", 
                     brc->sector, brc);
#endif
            struct async_submit_ctl submit;
            struct dma_async_tx_descriptor *tx = NULL;
            tx = async_copy_cache_data(0, bi, &brc->page,
                    logical_sector, tx, 0);
            init_async_submit(&submit, ASYNC_TX_ACK, tx, 
                              return_read_data, bi, NULL);
            async_trigger_callback(&submit);
#ifdef PRINT_INFO
            mdc_info("free page %p p_count %d\n", brc->page,
                 atomic_read(&brc->page->_count));
#endif
            __free_page(brc->page);
        }
        else
        {
            // atomic_dec(&brc->page->_count);
            return_read_data((void*)bi);
            // if(atomic_read(&brc->page->_count) !=0)
            //    __free_page(brc->page);
        }
        brc->bi = NULL;
        brc->page = NULL;
        
        kmem_cache_free(brc_pool, brc);
    }
    else
    {
        mdc_err("error!\n");
        if(!cache_dec_bi_stripes(bi))
        {
            bi->bi_iter.bi_size = 0;
            bio_endio(bi);
        }
        kmem_cache_free(brc_pool, brc);
    }
    return;
}

static void load_read_block_endio_with_cdev(struct bio *rbi)
{
    struct bio_read_cache *brc = rbi->bi_private;
    struct bio *bi = brc->bi;
    struct mddev *mddev = Gmddev;
    struct cache_tree_data *ctd = mddev->ctd;
    int error = rbi->bi_error;
    sector_t logical_sector = brc->sector;
    struct vdisk_cache_data *vcd = brc->vcd;
    int dd_idx = brc->vcd_idx;
    struct r5cdev *cdev = &vcd->dev[dd_idx];
    // bio_put(rbi);

    if(!error)
    {
        // async cdev'page & rbi'page
        struct page *read_page = rbi->bi_io_vec[0].bv_page;
        rbi->bi_io_vec[0].bv_page = NULL;
 
        struct async_submit_ctl submit;
        struct dma_async_tx_descriptor *tx = NULL;
        tx = async_page(cdev->page, read_page, tx, cdev->offset, cdev->length);
        init_async_submit(&submit, ASYNC_TX_ACK, tx, NULL, NULL, NULL);
        async_trigger_callback(&submit);
#ifdef PRINT_INFO
        mdc_info("free old cdev page %lu %p, p_count: %d\n", 
                 cdev->page, cdev->sector, atomic_read(&cdev->page->_count));
#endif
        __free_page(cdev->page);
        cdev->page = read_page;
        cdev->offset = 0;
        cdev->length = PAGE_SIZE;

        // return read_data
        struct async_submit_ctl submit2;
        struct dma_async_tx_descriptor *tx2 = NULL;
        tx2 = async_copy_cache_data(0, bi, &brc->page,
                logical_sector, tx2, 0);
        init_async_submit(&submit2, ASYNC_TX_ACK, tx2, 
                          return_read_data, bi, NULL);
        async_trigger_callback(&submit2);

        /*
        __free_page(brc->page);
#ifdef PRINT_INFO
        mdc_info("free page %p count %d\n", brc->page,
                 atomic_read(&brc->page->_count));
#endif
        */
        brc->bi = NULL;
        brc->page = NULL;
        brc->vcd = NULL;
        brc->vcd_idx = 0;
        kmem_cache_free(brc_pool, brc);
    }
    else
    {
        mdc_err("error!\n");
        if(!cache_dec_bi_stripes(bi))
        {
            bi->bi_iter.bi_size = 0;
            bio_endio(bi);
        }
        kmem_cache_free(brc_pool, brc);
    }
    return;
}


static int load_read_block(struct mddev *mddev, 
                           sector_t logical_sector,
                           sector_t new_logical,
                           struct bio_read_cache *brc)
{
    struct cache_tree_data *ctd = mddev->ctd;
    struct bio *bi;
    struct async_submit_ctl submit;
    struct dma_async_tx_descriptor *tx = NULL;
    struct page *p = NULL;
    int devnum = mddev->raid_disks - 1;

    bi = cache_bio_alloc_mddev(GFP_NOIO, 1, mddev);
    if(brc->page == NULL)
    {
        p = alloc_page(GFP_KERNEL);
        brc->page = p;
        brc->bio_page = false;
#ifdef PRINT_INFO
        mdc_info("alloc_page %p, p_count: %d\n", 
                 p, atomic_read(&p->_count));
#endif
    }
    else
    {
        p = brc->page;
        //atomic_inc_and_test(&brc->page->_count);
#ifdef PRINT_INFO
        mdc_info("add page %p count %d\n", brc->page, 
                 atomic_read(&brc->page->_count));
#endif
        brc->bio_page = true;
    }

    brc->new_logical = new_logical;
    
    bio_add_page(bi, p, PAGE_SIZE, 0);
    bi->bi_iter.bi_sector = new_logical + 
                            ctd->remaining_sectors;
    bi->bi_bdev = ctd->bd;
    bi->bi_rw = READ;
    bi->bi_private = brc;
    bi->bi_end_io = load_read_block_endio;
    cache_set_bi_stripes(bi, 1);

#ifdef PRINT_INFO
    mdc_info("bi: %p, %lu, read_bio_count: %d\n", 
             bi, new_logical, ++read_bio_count);
#endif
    mddev->pers->make_request(mddev, bi);
    return 0;
}


static int load_read_block_with_cdev(struct mddev *mddev, 
                            sector_t logical_sector,
                            sector_t new_logical,
                            struct bio_read_cache *brc)
{
    struct cache_tree_data *ctd = mddev->ctd;
    struct bio *bi;
    struct async_submit_ctl submit;
    struct dma_async_tx_descriptor *tx = NULL;
    struct page *p = NULL;
    int devnum = mddev->raid_disks - 1;

    bi = cache_bio_alloc_mddev(GFP_NOIO, 1, mddev);
    p = alloc_page(GFP_KERNEL);
#ifdef PRINT_INFO
    mdc_info("alloc page: %p, p_count: %d\n",
             p, atomic_read(&p->_count));
#endif
    brc->new_logical = new_logical;
    
    bio_add_page(bi, p, PAGE_SIZE, 0);
    bi->bi_iter.bi_sector = new_logical + 
                            ctd->remaining_sectors;
    bi->bi_bdev = ctd->bd;
    bi->bi_rw = READ;
    bi->bi_private = brc;
    bi->bi_end_io = load_read_block_endio_with_cdev;
    cache_set_bi_stripes(bi, 1);

#ifdef PRINT_INFO
    mdc_info("bi: %p, %lu, read_bio_count: %d\n", 
             bi, new_logical, ++read_bio_count);
#endif
    mddev->pers->make_request(mddev, bi);
    return 0;
}

/*
static bool oldfind_read_data_in_radix_tree(struct mddev *mddev, 
                                        struct bio_read_cache *brc,
                                        sector_t logical,
                                        sector_t new_sector,
                                        int dd_idx)
{
    struct cache_tree_data *ctd = mddev->ctd;
    struct vdisk_cache_data *cache_hitted = NULL;
    struct data_cache_radix_tree_node *node_hitted = NULL;
    sector_t new_logical, insert_sector = new_sector >> 3;
    sector_t pos = (insert_sector & CACHE_RADIX_TREE_MAP_MASK);
    
    spin_lock(&ctd->radix_tree_lock_data);
    node_hitted = lookup_data_node_in_tree(
                            ctd->data_cache_tree_root,
                            insert_sector);
    // find radix node
    if((node_hitted != NULL) / *&& (node_hitted->count > 0) &&
       (node_hitted->count < 65) * /)
    {
#ifdef PRINT_INFO
        mdc_info("node_hitted->count: %d, node_hitted->lba: %d\n",
                 node_hitted->count, node_hitted->lba);
#endif
        cache_hitted = node_hitted->slots[pos];
    }
    spin_unlock(&ctd->radix_tree_lock_data);

    if(cache_hitted != NULL)
    {
        // stripe in radix tree
        struct r5cdev *cdev = &cache_hitted->dev[dd_idx];

        if(cdev->sector != logical && 
           cdev->sector != -1 && cdev->page)
            mdc_err("wrong page when find %lu but found %lu %p, dd_idx: %d\n",
                   logical, cdev->sector, cdev->page, dd_idx);
#ifdef PRINT_INFO
        else
            mdc_info("find %lu find %lu %p, dd_idx: %d\n", 
                     logical, cdev->sector, cdev->page, dd_idx);
#endif
        if(cdev->page != NULL)
        {
            // block data in cache tree
            struct dma_async_tx_descriptor *tx = NULL;
            struct async_submit_ctl submit;
            tx = async_copy_cache_data(0, brc->bi,
                                       &cdev->page,
                                       logical, tx, 0);
            init_async_submit(&submit, ASYNC_TX_ACK, tx, 
                        return_read_data, brc->bi, NULL);
            async_trigger_callback(&submit);
#ifdef PRINT_INFO
            mdc_info("cache_hitted! logical: %lu, page: %p\n",
                      logical, cdev->page, dd_idx);
#endif
            kmem_cache_free(brc_pool, brc);
            return true;
        }
    }
    
#ifdef USE_RECOMBINE_STRIPE
    if(ctd->cache_r5meta != NULL)
        new_logical = get_new_logical_address(ctd, logical); 
    else
        new_logical = logical;
                    
#else
    new_logical = logical;
#endif
    load_read_block(mddev, logical, new_logical, brc);
    return true;
}
*/

static bool find_read_data_in_radix_tree(struct mddev *mddev, 
                                        struct bio_read_cache *brc,
                                        struct r5plug *rp,
                                        sector_t logical,
                                        sector_t new_sector,
                                        int dd_idx)
{
    struct cache_tree_data *ctd = mddev->ctd;
    struct vdisk_cache_data *cache_hitted = NULL;
    struct data_cache_radix_tree_node *node_hitted = NULL;
    sector_t new_logical, insert_sector = new_sector >> 3;
    sector_t pos = (insert_sector & CACHE_RADIX_TREE_MAP_MASK);
    
    spin_lock(&ctd->radix_tree_lock_data);
    node_hitted = lookup_data_node_in_tree(
                            ctd->data_cache_tree_root,
                            insert_sector);
    // find radix node
    if((node_hitted != NULL) /*&& (node_hitted->count > 0) &&
       (node_hitted->count < 65) */)
    {
#ifdef PRINT_INFO
        mdc_info("node_hitted->count: %d, node_hitted->lba: %d, pos: %d\n",
                 node_hitted->count, node_hitted->lba, pos);
#endif
        cache_hitted = node_hitted->slots[pos];
    }
    spin_unlock(&ctd->radix_tree_lock_data);

    if(cache_hitted != NULL)
    {
        // stripe in radix tree
        struct r5cdev *cdev = &cache_hitted->dev[dd_idx];
#ifdef PRINT_INFO
        mdc_info("find cache_hitted: %p, r5cdev: %p\n", 
                 cache_hitted, cdev);
#endif

        if(cdev->sector != logical && 
           cdev->sector != -1 && cdev->page)
            mdc_err("wrong page when find %lu but found %lu %p, dd_idx: %d\n",
                   logical, cdev->sector, cdev->page, dd_idx);
#ifdef PRINT_INFO
        else
            mdc_info("find %lu find %lu %p, dd_idx: %d, offset %d, length: %d\n", 
                     logical, cdev->sector, cdev->page, dd_idx, cdev->offset, cdev->length);
#endif
        if(cdev->page != NULL)
        {
            if(rp)
            {
                // some newset data in bt
                // async bt'page to cdev'page first
#ifdef PRINT_INFO
                mdc_info("rp is valid: %p, rp->page: %p, offset: %d, length: %d\n",
                         rp, rp->page, rp->offset, rp->length);
#endif
                struct dma_async_tx_descriptor *tx = NULL;
                struct async_submit_ctl submit;
                tx = async_page(rp->page, cdev->page, tx, rp->offset, rp->length);
                init_async_submit(&submit, ASYNC_TX_ACK, tx, NULL, NULL, NULL);
                async_trigger_callback(&submit);
               
                int new_offset = MIN(cdev->offset, rp->offset);
                cdev->length = MAX(cdev->offset + cdev->length, rp->offset + rp->length) - cdev->offset;
                cdev->offset = new_offset; 

                rp->page = NULL;
                rp->valid = 0;
                rp->offset = rp->length = 0;

#ifdef PRINT_INFO
                mdc_info("transfer rp to brc: new offset %d, new length: %d\n", 
                        cdev->offset, cdev->length);
#endif
            }
            
            if(cdev->offset <= brc->offset && 
               (cdev->offset + cdev->length >= brc->offset + brc->length))
            {
                // block data in cache tree
                struct dma_async_tx_descriptor *tx = NULL;
                struct async_submit_ctl submit;
                tx = async_copy_cache_data(0, brc->bi,
                                           &cdev->page,
                                           logical, tx, 0);
                init_async_submit(&submit, ASYNC_TX_ACK, tx, 
                            return_read_data, brc->bi, NULL);
                async_trigger_callback(&submit);
#ifdef PRINT_INFO
                mdc_info("cache_hitted! logical: %lu, page: %p\n",
                          logical, cdev->page, dd_idx);
#endif
                kmem_cache_free(brc_pool, brc);
                return true;
            }
            else
            {
                // need load page first 

#ifdef USE_RECOMBINE_STRIPE
                if(ctd->cache_r5meta != NULL)
                    new_logical = get_new_logical_address(ctd, logical); 
                else
                    new_logical = logical;            
#else
                new_logical = logical;
#endif
 
#ifdef PRINT_INFO
                mdc_info("need load page first. logical: %lu, new_logical: %lu\n",
                        logical, new_logical);
#endif
                brc->vcd = cache_hitted;
                brc->vcd_idx = dd_idx;
                load_read_block_with_cdev(mddev, logical, new_logical, brc);
            }
        }
        else
        {
#ifdef PRINT_INFO
            mdc_info("cdev's page is NULL\n");
#endif


#ifdef USE_RECOMBINE_STRIPE
            if(ctd->cache_r5meta != NULL)
                new_logical = get_new_logical_address(ctd, logical); 
            else
                new_logical = logical;            
#else
            new_logical = logical;
#endif
            
#ifdef PRINT_INFO
            mdc_info("need load page first. logical: %lu, new_logical: %lu\n",
                    logical, new_logical);
#endif

            load_read_block(mddev, logical, new_logical, brc);
            return true;
        }
    }
    else
    {
#ifdef PRINT_INFO
        mdc_info("cache_hitted is NULL\n");
#endif


#ifdef USE_RECOMBINE_STRIPE
        if(ctd->cache_r5meta != NULL)
            new_logical = get_new_logical_address(ctd, logical); 
        else
            new_logical = logical;            
#else
        new_logical = logical;
#endif

#ifdef PRINT_INFO
            mdc_info("need load page first. logical: %lu, new_logical: %lu\n",
                    logical, new_logical);
#endif
        load_read_block(mddev, logical, new_logical, brc);
        return true;
    }
}



static void read_thread(struct md_thread *thread)
{
    struct mddev *mddev = thread->mddev;
    struct cache_tree_data *ctd = mddev->ctd;
    struct r5meta* meta = ctd->cache_r5meta;
    struct bio_read_cache *brc = NULL;
    struct bio_test *bt = NULL;
    sector_t logical, new_sector;
    int dd_idx = -1;
    
    spin_lock(&ctd->reading_list_lock);
    while(atomic_read(&ctd->reading_count) > 0 &&
          !list_empty_careful(&ctd->reading_list))
    {
        brc = list_last_entry(&ctd->reading_list,
                              struct bio_read_cache,
                              lru);
        list_del_init(&brc->lru);
        atomic_dec(&ctd->reading_count);
        spin_unlock(&ctd->reading_list_lock);

        // write block's sector
        logical = brc->sector;
        // write block's stripe's sector
        new_sector = cache_compute_sector(mddev, logical, &dd_idx);

        // data in bio_test?
        if((bt = find_bio_test(mddev, new_sector,
                               BIO_TEST_HASH(new_sector))) != NULL)
        {
#ifdef PRINT_INFO
            mdc_info("find bt: %p\n", bt);
#endif
            struct r5plug *rp = &bt->dev[dd_idx];
            if(rp->valid == 1 && rp->page != NULL)
            {
                if(rp->offset <= brc->offset && 
                      (rp->offset + rp->length >= brc->offset + brc->length))
                {
                    struct async_submit_ctl submit;
                    struct dma_async_tx_descriptor *tx = NULL;
#ifdef PRINT_INFO
                    mdc_info("cache hit bt %lu, %p, bt->offset: %d, bt->length: %d\n", 
                             bt->lba, bt, rp->offset, rp->length);
#endif
                    tx = async_copy_cache_data(0, brc->bi, 
                            &bt->dev[dd_idx].page, logical, tx, 0);
                    init_async_submit(&submit, ASYNC_TX_ACK, tx, 
                        return_read_data, brc->bi, NULL);
                    async_trigger_callback(&submit);        

                    /*
                    change_bio_page(brc->bi, &bt->dev[dd_idx].page, logical);
                    return_read_data((void*)brc->bi);
                    */
                    kmem_cache_free(brc_pool, brc);
                    spin_lock(&ctd->reading_list_lock);
                    continue;
                }
                else
                {
#ifdef PRINT_INFO
                    mdc_info("cache hit bt %lu, %p, bt->offset: %d, bt->length: %d, but need find cache\n", 
                             bt->lba, bt, rp->offset, rp->length);
#endif
                    find_read_data_in_radix_tree(mddev, brc, rp, logical, new_sector, dd_idx);
                    bt->dirty_pages -= 1;
                    if(bt->dirty_pages == 0)
                    {
                        // del bt from unplug list
                        spin_lock(&ctd->plug_list_lock);
                        atomic_dec(&ctd->plug_list_count);
                        list_del_init(&bt->lru_list);
                        spin_unlock(&ctd->plug_list_lock);

                        // del from hash table
                        spin_lock(&ctd->bio_test_hash_lock[BIO_TEST_HASH(bt->lba)]);
                        hlist_del_init(&bt->hash);
                        spin_unlock(&ctd->bio_test_hash_lock[BIO_TEST_HASH(bt->lba)]);
    
                        // add to bio_test_list for free to use
                        spin_lock(&ctd->bio_test_lock);
                        list_add_tail(&bt->lru_list, &ctd->bio_test_list);
                        spin_unlock(&ctd->bio_test_lock);
                    }
                }
            }
            else
            {
#ifdef PRINT_INFO
                mdc_info("find bt: %p, but rp is NULL\n", bt);
#endif
                find_read_data_in_radix_tree(mddev, brc, NULL, 
                                logical, new_sector, dd_idx);
            }
        }
        else
        {
#ifdef PRINT_INFO
            mdc_info("no bt\n");
#endif
            find_read_data_in_radix_tree(mddev, brc, NULL, 
                                logical, new_sector, dd_idx);
        }
        spin_lock(&ctd->reading_list_lock);
    }
    spin_unlock(&ctd->reading_list_lock);

    return;
}

void bio_test_plug(struct mddev *mddev, struct bio_test *bt)
{
    struct cache_tree_data *ctd = mddev->ctd;
    if(bt->flag == 0)
        return;

    if(atomic_read(&ctd->plug_list_count) >= 4096)
    {
#ifdef PRINT_INFO
        mdc_info("plug_list_count: %d, flushing\n", 
                 atomic_read(&ctd->plug_list_count));
#endif
        md_wakeup_thread(ctd->bio_test_unplug_thread);
        wait_event(ctd->bio_test_queue,
                  atomic_read(&ctd->plug_list_count) < 4000);
    }

    spin_lock(&ctd->plug_list_lock);
    list_add(&bt->lru_list, &ctd->plug_list);
    atomic_inc(&ctd->plug_list_count);
    spin_unlock(&ctd->plug_list_lock);
#ifdef PRINT_INFO
    mdc_info("plug_list_count: %d\n", atomic_read(&ctd->plug_list_count));
#endif
    return;
}


// raid5_make_cache_request
static void mdc_make_request(struct mddev *mddev, struct bio *bi)
{
    int dd_idx, remaining, num_bio;
    sector_t new_sector, logical_sector, last_sector,first_logical;
    DEFINE_WAIT(wait_make_cache);
    bool do_prepare, do_flush = false, align = false;
    struct dma_async_tx_descriptor *tx = NULL;
    struct cache_tree_data *ctd = mddev->ctd;
    struct bio_read_cache *brc = NULL;
    struct bio_test *bt_find;
    int dev, hash;
    const int rw = bio_data_dir(bi);
    
    //md_write_start(mddev, bi);

    logical_sector = bi->bi_iter.bi_sector & ~((sector_t)STRIPE_SECTORS_MAKE-1);
    first_logical = logical_sector;
    last_sector = bio_end_sector(bi);
    num_bio = bio_sectors(bi);

    // bi->bi_next = NULL;
    cache_set_bi_stripes(bi, 1);
    struct bio_vec *bv;
    sector_t sec = bi->bi_iter.bi_sector;

    // pages in bio are aligned or not
    if(logical_sector == sec)
        align = true;
    /*
    else
        mdc_err("bio unalign!\n");
    */
#ifdef PRINT_INFO
    mdc_info("bio: logical_sector: %lu, first_logical: %lu, last_sector: %lu\
             rw: %d, num_bio: %d, bi_idx: %d\n",
             logical_sector, first_logical, last_sector, rw, num_bio, bi->bi_iter.bi_idx);
#endif
    prepare_to_wait(&ctd->mdc_make_request_queue, &wait_make_cache,
                    TASK_UNINTERRUPTIBLE);
    int page_idx = bi->bi_iter.bi_idx;
    for (; logical_sector < last_sector; logical_sector += STRIPE_SECTORS_MAKE)
    {
        bt_find = NULL;  
        dev = mddev->raid_disks;
        new_sector = cache_compute_sector(mddev, logical_sector, &dd_idx);
        // write
        if(rw == WRITE)
        {
#ifdef PRINT_INFO
            mdc_info("handle write request! logical_sector: %lu \
                     new_sector: %lu\n",
                     logical_sector, new_sector);
#endif
            hash = BIO_TEST_HASH(new_sector);
            bt_find = find_bio_test(mddev, new_sector, hash);
            if(bt_find == NULL)
            {
                bt_find = init_bio_test(mddev, new_sector);
                bt_find = insert_page_to_bio_test(bt_find, &bi->bi_io_vec[page_idx],
                                         logical_sector, dd_idx);
                bt_find->flag = 1;
                add_bio_test_to_hash(ctd, bt_find, hash);
            }
            else
            {
                bt_find = insert_page_to_bio_test(bt_find, &bi->bi_io_vec[page_idx],
                                            logical_sector, dd_idx);
                bt_find->flag = 0;
            }
            bio_test_plug(mddev, bt_find);
        }
        else
        {
#ifdef PRINT_INFO
            mdc_info("handle read request! logical_sector: %lu \
                     new_sector: %lu\n",
                     logical_sector, new_sector);
#endif
            // read
            cache_inc_bi_stripes(bi, 1);

            brc = kmem_cache_alloc(brc_pool, GFP_ATOMIC);

            bv = &bi->bi_io_vec[page_idx];

            // fill bio_read_cache
            brc->bi = bi;           
            brc->sector = logical_sector;
            brc->valid = 1;

            brc->offset = bv->bv_offset;
            brc->length = bv->bv_len;
            if(align && bv->bv_page != NULL)
            {
                // atomic_inc_and_test(&bv->bv_page->_count);
#ifdef PRINT_INFO
                mdc_info("read page_idx: %d, page %p count %d\n", page_idx, bv->bv_page, 
                         atomic_read(&bv->bv_page->_count));
#endif
                brc->page = bv->bv_page;
            }
            else
            {
                brc->page = NULL;
            }
            spin_lock(&ctd->reading_list_lock);
            list_add(&brc->lru, &ctd->reading_list);
            atomic_inc(&ctd->reading_count);
            spin_unlock(&ctd->reading_list_lock);
        }
        page_idx++;
   }
    finish_wait(&ctd->mdc_make_request_queue, &wait_make_cache);

    if (rw == WRITE)
    {
        int remaining = cache_dec_bi_stripes(bi);
    	if (remaining == 0) {
#ifdef PRINT_INFO
            mdc_info("return write bi: %p\n", bi);
#endif
	    	//md_write_end(mddev);
		    bio_endio(bi);
    	}
    }
    else
    {
        if(!cache_dec_bi_stripes(bi))
        {
#ifdef PRINT_INFO
            mdc_info("return read bi: %p\n", bi);
#endif
            bio_endio(bi);
        }
        else 
        {
            md_wakeup_thread(ctd->read_thread);
        }

    }
    return;
}


static void free_list(struct cache_tree_data *ctd)
{
    // free bio_test
    struct bio_test *bt = NULL;
    spin_lock(&ctd->alloc_bio_test_list_lock);
    while(!list_empty_careful(&ctd->alloc_bio_test_list))
    {
        bt = list_first_entry(&ctd->alloc_bio_test_list,
                             struct bio_test, alloc_lru);
        if(!bt)
            break;
        list_del_init(&bt->alloc_lru);
        kfree(bt);
    }
    spin_unlock(&ctd->alloc_bio_test_list_lock);

    // free vdisk_flush_data
    struct vdisk_flush_data *vfd = NULL;
    spin_lock(&ctd->alloc_vdisk_flush_data_list_lock);
    while(!list_empty_careful(&ctd->alloc_vdisk_flush_data_list))
    {
        vfd = list_first_entry(&ctd->alloc_vdisk_flush_data_list,
                             struct vdisk_flush_data, alloc_lru);
        if(!vfd)
            break;
        list_del_init(&vfd->alloc_lru);
        kfree(vfd);
    }
    spin_unlock(&ctd->alloc_vdisk_flush_data_list_lock);


    // bio_test hash table
    kfree(ctd->bt_hashtbl);
    return;
}


void flush_all_handle_bt(struct mddev *mddev, struct bio_test *bt)
{
    int i = 0;
    struct cache_tree_data *ctd = mddev->ctd;
    struct vdisk_flush_data *vfd = get_a_vfd(mddev);
    if(!ctd || !vfd)
    {
        mdc_err("para NULL\n");
        return;
    }

    for(i = 0; i < (mddev->raid_disks - 1); ++i)
    {
        if(bt->dev[i].valid == 1)
        {
            vfd->dev[i].dirty = 1;
            vfd->dev[i].page = bt->dev[i].page;
            vfd->dev[i].sector = bt->dev[i].sector;
            vfd->dev[i].offset = bt->dev[i].offset;
            vfd->dev[i].length = bt->dev[i].length;

            bt->dev[i].valid = 0;
            bt->dev[i].page = NULL;
            bt->dev[i].sector = -1;
            
            atomic_inc(&ctd->flush_all_vfds_pages);
        }
    }
    vfd->lba_align = bt->lba >> 3;

    spin_lock(&ctd->flush_all_vfds_list_lock);
    list_add(&vfd->lru, &ctd->flush_all_vfds_list);
    atomic_inc(&ctd->flush_all_vfds_count);
    spin_unlock(&ctd->flush_all_vfds_list_lock);
    return;
}

       
void transfer_vdisk_cache_data_to_vfd_clean(struct cache_tree_data *ctd, 
                                            struct vdisk_cache_data *vcd, 
                                          struct vdisk_flush_data *vfd, 
                                      int devnum)
{
    int idx = 0;
    vfd->lba_align = vcd->lba_align;
    while(idx < devnum)
    {
        if(test_bit(VCD_PAGE_DIRTY, &vcd->dev[idx].flag) /*vcd->dev[idx].dirty == 1 */)
        {
            vfd->dev[idx].page = vcd->dev[idx].page;
            vfd->dev[idx].sector = vcd->dev[idx].sector;
            vfd->dev[idx].cdev = &vcd->dev[idx];
            vcd->dev[idx].vcd = vcd;
            
            clear_bit(VCD_PAGE_DIRTY, &vcd->dev[idx].flag);
            // vcd->dev[idx].dirty = 0;
            set_bit(VCD_PAGE_FLUSHING_ALL, &vcd->dev[idx].flag);
            // vcd->dev[idx].flush = 1;

            vfd->dev[idx].dirty = 1;

            vfd->dev[idx].offset = vcd->dev[idx].offset;
            vfd->dev[idx].length = vcd->dev[idx].length;
            atomic_inc(&ctd->flush_all_vfds_pages);
        }
        ++idx;
    }
    return;
}

int flush_all_thread(void *data)
{
    int bt_count = 0, dirty_bpt_count = 0;
    struct cache_tree_data *ctd = data;
    struct mddev *mddev = ctd->mdd;
    int disks = mddev->raid_disks;
    struct vdisk_flush_data *vfd = NULL;
    struct vdisk_cache_data *vcd = NULL;
    struct bio_test *bt = NULL;
#ifdef PRINT_INFO
    mdc_info("start\n");
#endif

    // handle bio_test plug list
    spin_lock(&ctd->plug_list_lock);
    while(!list_empty_careful(&ctd->plug_list))
    {
        bt = list_first_entry(&ctd->plug_list,
                              struct bio_test, 
                              lru_list);
#ifdef PRINT_INFO
        mdc_info("flush bt %lu %p, count: %d\n",
                  bt->lba, bt, ++bt_count);
#endif
        list_del_init(&bt->lru_list);
        atomic_dec(&ctd->plug_list_count);
        spin_unlock(&ctd->plug_list_lock);

        spin_lock(ctd->bio_test_hash_lock + BIO_TEST_HASH(bt->lba));
        hlist_del_init(&bt->hash);
        spin_unlock(ctd->bio_test_hash_lock + BIO_TEST_HASH(bt->lba));

        flush_all_handle_bt(mddev, bt);
        // kfree(bt);
        spin_lock(&ctd->plug_list_lock);
    }
    spin_unlock(&ctd->plug_list_lock);
    /*
    if(!list_empty_careful(&ctd->plug_list))
    {
        md_wakeup_thread(&ctd->bio_test_unplug_thread);
        wait_event()
    }
    */
    // handle dirty vdisk_cache_data 
    spin_lock(&ctd->dirty_vdisk_cache_data_list_lock);
    while(!list_empty_careful(&ctd->dirty_vdisk_cache_data_list))
    {
        vcd = list_first_entry(&ctd->dirty_vdisk_cache_data_list,
                               struct vdisk_cache_data,
                               lru);

        list_del_init(&vcd->lru);
        clear_bit(VCD_IN_DIRTY, &vcd->flag);
        atomic_dec(&ctd->dirty_vdisk_cache_data_count);
        spin_unlock(&ctd->dirty_vdisk_cache_data_list_lock);
#ifdef PRINT_INFO
        mdc_info("del vcd %p (count: %d) from dirty_vdisk_cache_data_count\n",
                vcd, atomic_read(&ctd->dirty_vdisk_cache_data_count));
#endif
        vfd = get_a_vfd(mddev);
        if(!vfd)
        {
            mdc_err("vfd NULL\n");
            break;
        }
        transfer_vdisk_cache_data_to_vfd_clean(ctd, vcd, vfd, disks - 1);

#ifdef PRINT_INFO
        mdc_info("flush vfd %lu %p, count: %d\n",
                  vfd->lba_align, vfd, ++dirty_bpt_count);
#endif
        spin_lock(&ctd->flush_all_vfds_list_lock);
        list_add(&vfd->lru, &ctd->flush_all_vfds_list);
        atomic_inc(&ctd->flush_all_vfds_count);
        spin_unlock(&ctd->flush_all_vfds_list_lock);

        spin_lock(&ctd->dirty_vdisk_cache_data_list_lock);
    }
    spin_unlock(&ctd->dirty_vdisk_cache_data_list_lock);
    
#ifdef PRINT_INFO
    mdc_info("flush_all_vfds_count: %d, flush_all_vfds_pages: %d\n",
             atomic_read(&ctd->flush_all_vfds_count),
             atomic_read(&ctd->flush_all_vfds_pages));
#endif
    md_wakeup_thread(ctd->vdisk_cache_data_flush_thread);
    ctd->in_flush_all = false;
    wake_up(&ctd->wait_for_flush_io_queue);

#ifdef PRINT_INFO
    mdc_info("end\n");
#endif
    return 0;
}



void flush_all(struct cache_tree_data *ctd)
{
    ctd->flush_all_thread = kthread_create(flush_all_thread, ctd, "md_flush_all");
    ctd->in_flush_all = true;
    wake_up_process(ctd->flush_all_thread);
    wait_event(ctd->wait_for_flush_io_queue,
                ((!ctd->in_flush_all) &&
                (atomic_read(&ctd->flush_all_vfds_pages) <= 0) &&
                (atomic_read(&ctd->flush_all_vfds_count) <= 0)));
    return;
}


static void cache_free(struct mddev *mddev, void *priv)
{
    struct cache_tree_data *ctd = priv;
    struct r5meta* meta = ctd->cache_r5meta;
#ifdef PRINT_INFO
    mdc_info("start!\n");
#endif

    // flush all about
    ctd->will_free = true;
    atomic_set(&ctd->flush_all_vfds_pages, 0);
    atomic_set(&ctd->flush_all_vfds_count, 0);
    INIT_LIST_HEAD(&ctd->flush_all_vfds_list);
    flush_all(ctd);

    if(meta)
        r5meta_stop(meta);
 
    md_unregister_thread(&ctd->bio_test_unplug_thread);
#ifdef PRINT_INFO
	mdc_info("unregistered bio_test_unplug_thread\n");
#endif
   
    md_unregister_thread(&ctd->vdisk_cache_data_flush_thread);
#ifdef PRINT_INFO
	mdc_info("unregistered vdisk_cache_data_flush_thread\n");
#endif

    md_unregister_thread(&ctd->read_thread);
#ifdef PRINT_INFO
	mdc_info("unregistered read_thread\n");
#endif



    data_cache_radix_tree_destroy(ctd->data_cache_tree_root,
                                 mddev->raid_disks - 1);
    free_list(ctd);
#ifdef PRINT_INFO
    mdc_info("kfree ctd %p\n", mddev->ctd);
#endif
    kfree(mddev->ctd);
    mddev->ctd = NULL;
    return;
}

static void clean_brc(void *node)
{
    memset(node, 0, sizeof(struct bio_read_cache));
}


static void md_cache_init(struct mddev *mddev)
{
    int devs, i, j;
    struct cache_tree_data *ctd;
    Gmddev = mddev;
    if(mddev->ctd == NULL)
    {
        brc_pool = kmem_cache_create("brc_pools",
            sizeof(struct bio_read_cache), 0,
            SLAB_PANIC, clean_brc);

        devs = mddev->raid_disks - 1;
#ifdef PRINT_INFO
        mdc_info("start devs is %d\n", devs); 
#endif
        ctd = kmalloc(sizeof(struct cache_tree_data), GFP_KERNEL);
        memset(ctd, 0, sizeof(struct cache_tree_data));
        ctd->mdd = mddev;
        ctd->bd = NULL;
        ctd->remaining_sectors = mddev->remaining_sectors * devs;
#ifdef PRINT_INFO
        mdc_info("ctd remaining_sectors: %d\n",
                ctd->remaining_sectors);
#endif
        // bio test about
        INIT_LIST_HEAD(&ctd->bio_test_list);
        spin_lock_init(&ctd->bio_test_lock);
        atomic_set(&ctd->bio_test_count, 0);
        init_waitqueue_head(&ctd->bio_test_queue);

        // bio test plug about
        INIT_LIST_HEAD(&ctd->plug_list);
        spin_lock_init(&ctd->plug_list_lock);
        atomic_set(&ctd->plug_list_count, 0);

        INIT_LIST_HEAD(&ctd->alloc_bio_test_list);
        spin_lock_init(&ctd->alloc_bio_test_list_lock);

        // bio test hash table
        if ((ctd->bt_hashtbl = kmalloc(PAGE_SIZE, GFP_KERNEL)) != NULL)
            memset(ctd->bt_hashtbl, 0, PAGE_SIZE);
        else 
            mdc_err("ctd->bt_hashtbl alloc wrong !\n");

        
        ctd->bio_test_unplug_thread = md_register_thread(bio_test_unplug_thread, mddev, "mdc_bt_unplug");
        if (!ctd->bio_test_unplug_thread ) 
            mdc_err("couldn't allocate thread %s\n", mdname(mddev));
        ctd->vdisk_cache_data_flush_thread = md_register_thread(vdisk_cache_data_flush_thread, mddev, "mdc_vcd_flush");
        if (!ctd->vdisk_cache_data_flush_thread) 
            mdc_err("couldn't allocate thread %s\n", mdname(mddev));
        ctd->read_thread = md_register_thread(read_thread, mddev, "mdc_read");
        if (!ctd->read_thread) 
            mdc_err("couldn't allocate thread %s\n", mdname(mddev));
        /*
        ctd->add_read_page_to_radix_tree_thread = md_register_thread(add_read_page_to_radix_tree_thread, mddev, "mdc_read");
        if (!ctd->add_read_page_to_radix_tree_thread) 
            mdc_err("couldn't allocate thread %s\n", mdname(mddev));
        */

        // vdisk cache data about
        INIT_LIST_HEAD(&ctd->dirty_vdisk_cache_data_list);
        INIT_LIST_HEAD(&ctd->clean_vdisk_cache_data_list);
        INIT_LIST_HEAD(&ctd->replace_vdisk_cache_data_list);
        spin_lock_init(&ctd->dirty_vdisk_cache_data_list_lock);
        spin_lock_init(&ctd->clean_vdisk_cache_data_list_lock);
        spin_lock_init(&(ctd->replace_vdisk_cache_data_list_lock));
        atomic_set(&ctd->vdisk_cache_data_count, 0);
        atomic_set(&ctd->dirty_vdisk_cache_data_count, 0);
        atomic_set(&ctd->clean_vdisk_cache_data_count, 0);
        atomic_set(&ctd->replace_vdisk_cache_data_count, 0);

        init_waitqueue_head(&ctd->wait_for_vcds_flush_queue);
        init_waitqueue_head(&ctd->mdc_make_request_queue);


        // vdisk flush data about
        INIT_LIST_HEAD(&ctd->vdisk_flush_data_list);
        atomic_set(&ctd->vdisk_flush_data_count, 0);
        spin_lock_init(&ctd->vdisk_flush_data_list_lock);

        INIT_LIST_HEAD(&ctd->alloc_vdisk_flush_data_list);
        spin_lock_init(&ctd->alloc_vdisk_flush_data_list_lock);

        // recliam vdisk flush data about
        INIT_LIST_HEAD(&ctd->reclaim_vfds_list);
        atomic_set(&ctd->reclaim_vfds_count, 0);
        spin_lock_init(&ctd->reclaim_vfds_list_lock);

        // bio read cache about
        INIT_LIST_HEAD(&ctd->bio_read_cache_list);
        atomic_set(&ctd->bio_read_cache_count, 0);
        spin_lock_init(&ctd->bio_read_cache_list_lock);

        INIT_LIST_HEAD(&ctd->alloc_bio_read_cache_list);
        spin_lock_init(&ctd->alloc_bio_read_cache_list_lock);

        // reading list about
        INIT_LIST_HEAD(&ctd->reading_list);
        atomic_set(&ctd->reading_count, 0);
        spin_lock_init(&ctd->reading_list_lock);

        // add read page list about
        INIT_LIST_HEAD(&ctd->add_read_page_list);
        atomic_set(&ctd->add_read_page_count, 0);
        spin_lock_init(&ctd->add_read_page_list_lock);

        // radix tree about
        spin_lock_init(&ctd->radix_tree_lock_data);
        ctd->data_cache_tree_root = kmalloc(sizeof(struct data_cache_radix_tree_root), GFP_KERNEL);
        memset(ctd->data_cache_tree_root, 0, sizeof(struct data_cache_radix_tree_root));
        INIT_DATA_CACHE_RADIX_TREE(ctd->data_cache_tree_root, GFP_ATOMIC); 
        ctd->data_cache_tree_root = data_cache_radix_tree_init(
                                    ctd->data_cache_tree_root, devs);

        // flush all about
        ctd->will_free = 0;
        ctd->in_flush_all = 0;
        INIT_LIST_HEAD(&ctd->flush_all_vfds_list);
        spin_lock_init(&ctd->flush_all_vfds_list_lock);
        atomic_set(&ctd->flush_all_vfds_count, 0);
        atomic_set(&ctd->flush_all_vfds_pages, 0);
        init_waitqueue_head(&ctd->wait_for_flush_io_queue);

        init_waitqueue_head(&ctd->wait_for_bt_read_page_queue);
        mddev->ctd = ctd;
        ctd->mdd = mddev;
#ifdef USE_RECOMBINE_STRIPE
        if (NULL == ctd->cache_r5meta)
        {
            mdc_info("setup shmeta!!!");
            setup_shmeta(ctd, 2048);
        }
#endif
    }
    else 
        mdc_info("alread_init");
}
EXPORT_SYMBOL_GPL(md_cache_init);



static struct md_cache mcache =
{
    .name       = "cache",
    .init_cache = md_cache_init,
    .size       = MAX_COUNT_OF_CACHE_DATA,
    // .cache_allwrite = md_cache_allwrite,
    // .replace_vdisk_cache_data_all = blockio_exec_replace_vdisk_cache_data_all,
    // .writer_free = md_writer_free,
    .free = cache_free,
    .cache_request  = mdc_make_request,
};


static int __init cache_init(void)
{
    md_register_cache(&mcache);
    return 0;
}


static void __exit cache_exit(void)
{
    mdc_info("start!\n");
    md_unregister_cache(&mcache);
}


module_init(cache_init);
module_exit(cache_exit);
MODULE_LICENSE("GPL");

