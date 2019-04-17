/*************************************************************************
	> File Name: metadata.c
	> Author: YMS 
	> Mail: 
	> Created Time: Mon 18 Sep 2017 04:31:45 PM CST
 ************************************************************************/

#include "metadata.h"
#include "flag.h"
#include <linux/kthread.h>
#include <linux/delay.h>

#define mtd_fmt(fmt)             "MTD: [%d %s] " fmt
#define mtd_fmt_err(fmt)         "MTD ERROR: [%d %s] " fmt
#define mtd_info(fmt,...)   \
            // printk(KERN_ERR mtd_fmt(fmt),__LINE__, __func__, ##__VA_ARGS__)
#define mtd_err(fmt,...)    \
            printk(KERN_ERR mtd_fmt_err(fmt),__LINE__, __func__, ##__VA_ARGS__)

#define META_PAGES_HASH     128
#define MTD_HASH_MAX_SIZE   128  // 8
// #define                  PRINT_PAGE_CONTENT

#define MB_SHMETA_SHIFT         7 // 3
#define FLUSH_THREAD_HASH       8

#define META_HASH(sector)        ((sector >> SM_SHIFT) & (META_PAGES_HASH - 1))
#define META_PAGE_HASH(sector)   ((sector >> 3) &(META_PAGES_HASH - 1))

static inline void mtd_set_bi_stripes(struct bio *bio, unsigned int cnt)
{
    atomic_t *segments = (atomic_t *)&bio->bi_phys_segments;
    atomic_set(segments, cnt);
}


static void flush_mtd_bio_endio(struct bio *bi)
{
    struct metadata_page* mbp = bi->bi_private;
    struct meta_data *mtd = mbp->mtd;
    mbp->bio_finished = true;    
    wake_up(&mtd->wait_for_raid5_bio_finish);
    return;
}


void print_shmeta_test(struct shmeta* sm)
{
    int i;
    if(sm == NULL)
        return;
    mtd_info("sector: %lu\n", sm->sector);
    for(i = 0; i < 3; i++)
        mtd_info("dev%d: lba: %ld, lso: %ld, psn: %d\n",
                i, sm->dmeta[i].lba, 
                sm->dmeta[i].lso, sm->dmeta[i].psn);
    return;
}


void print_metadata_conf(struct meta_data* mtd)
{
    mtd_info("\n--------------------------------------------------\n");
    mtd_info("shmetas: %lu\n", mtd->shmetas);
    mtd_info("devnum: %d, metadata_size: %d, meta_data_per_page: %d\n",
            mtd->devnum, mtd->metadata_size, mtd->metadata_per_page);
    mtd_info("metadata_begin_sector: %lu, metadata_page_each_hash %d\n",
             mtd->metadata_begin_sector, mtd->metadata_page_each_hash);
    mtd_info("metadata_begin_sector: %lu, metadata_end_sector: %lu\n",
             mtd->metadata_begin_sector, 
             mtd->metadata_end_sector);
    mtd_info("--------------------------------------------------\n\n");
    return;
}



bool substitution_page(struct meta_data* mtd, struct metadata_page* mdp, 
                        sector_t bio_sector)
{
    struct bio* bi, *rbi;
    unsigned int* cache;
    sector_t old_sector;
    int i = 0;
    bool re = false;
    struct mddev *mddev = mtd->mddev;

    if(mtd == NULL || mdp == NULL || mdp->page == NULL/* || 
       mtd->bd == NULL*/)
    {
        mtd_err("mtd is NULL OR mdp is NULL\n");
        return false;
    }

    bi = bio_alloc(GFP_NOIO, 2);
    rbi = bio_alloc(GFP_NOIO, 2);
    if(bi == NULL || rbi == NULL)
    {
        mtd_err("bi create failed\n");
        return false;
    }


    // lock 
    if(spin_is_locked(&mdp->read_lock))
    {
        wait_event(mtd->wait_for_read_finish, !spin_is_locked(&mdp->read_lock));
    }
    spin_lock(&mdp->read_lock);
    if(spin_is_locked(&mdp->write_lock))
    {
        wait_event(mtd->wait_for_write_finish, !spin_is_locked(&mdp->write_lock));
    }
    spin_lock(&mdp->write_lock);

    if(mdp->sector != -1)
    {
        mtd_info("submit bio sector: %lu, WRITE, page: %p\n", 
                mdp->sector, mdp->page);
        old_sector = bi->bi_iter.bi_sector = mdp->sector;
        
        bi->bi_rw = WRITE;
        bio_add_page(bi, mdp->page, PAGE_SIZE, 0);

#ifdef MTD_BIO_USE_MDDEV
        bi->bi_end_io = flush_mtd_bio_endio;
        mdp->bio_finished = false;
        bi->bi_private = mdp;
        mtd_set_bi_stripes(bi, 1);
        mddev->pers->make_request(mddev, bi);
        wait_event(mtd->wait_for_raid5_bio_finish, mdp->bio_finished == true);
#else
        bi->bi_bdev = mtd->bd;
        if(bi->bi_bdev == NULL)
        {
            mtd_err("bi->bi_bdev is NULL(%p)\n", bi->bi_bdev);
            goto substitution_page_end;
        }
        submit_bio_wait(bi->bi_rw, bi);
#endif
        __free_page(mdp->page);
        if((mdp->page = alloc_page(GFP_KERNEL)) == NULL)
            mtd_err("alloc page wrong!\n");
    }
    if(mdp->page)
    {
        mdp->sector = rbi->bi_iter.bi_sector = bio_sector;
        mtd_info("submit bio sector: %lu, READ, page: %p\n", 
                mdp->sector, mdp->page);
        rbi->bi_rw = READ;
        bio_add_page(rbi, mdp->page, PAGE_SIZE, 0);
#ifdef MTD_BIO_USE_MDDEV
        rbi->bi_end_io = flush_mtd_bio_endio;
        rbi->bi_private = mdp;
        mdp->bio_finished = false;
        mtd_set_bi_stripes(bi, 1);
        mddev->pers->make_request(mddev, bi);
        wait_event(mtd->wait_for_raid5_bio_finish, mdp->bio_finished == true);
#else
        rbi->bi_bdev = mtd->bd;
        if(rbi->bi_bdev == NULL)
        {
            mtd_err("bi->bi_bdev is NULL(%p)\n", bi->bi_bdev);
            goto substitution_page_end;
        }
        submit_bio_wait(rbi->bi_rw, rbi);
#endif
    }
substitution_page_end:
    spin_unlock(&mdp->write_lock);
    spin_unlock(&mdp->read_lock);
    atomic_set(&mdp->handling, 0);
    wake_up(&mtd->wait_for_read_finish);
    wake_up(&mtd->wait_for_write_finish);
    mtd_info("down %lu up %lu mdp->sector: %lu, page %p finished\n", 
            old_sector, bio_sector, mdp->sector, mdp->page);
    return true; 
}


bool flush_metadata_bio(struct meta_data* mtd, struct metadata_page* mdp, 
                        sector_t bio_sector, int read)
{
    struct bio* bi;
    unsigned int* cache;
    int i = 0;
    bool re = false;
    struct mddev *mddev = mtd->mddev;

    if(mtd == NULL || mdp == NULL || mdp->page == NULL ||
       (bi = bio_alloc(GFP_NOIO, 2)) == NULL)
    {
        mtd_err("mtd is NULL OR mdp is NULL\n");
        return false;
    }

    mtd_info("submit bio sector: %lu, type: %d, page: %p\n",
            bio_sector, read, mdp->page);
    bi->bi_iter.bi_sector = bio_sector;
    
    if(spin_is_locked(&mdp->read_lock)/* && read == MTD_WRITE */)
    {
        wait_event(mtd->wait_for_read_finish, !spin_is_locked(&mdp->read_lock));
        // mtd_info("lock read lock %lu, %x\n", 
        //        mdp->sector, page_address(mdp->page));
    }

    if(!spin_is_locked(&mdp->write_lock))
    {
        spin_lock(&mdp->write_lock);
        mtd_info("lock write lock %lu, page: %p\n", 
                mdp->sector, mdp->page);
    }

    if(read == MTD_READ)
        bi->bi_rw = READ;
    else if(read == MTD_WRITE)
    {
        bi->bi_rw = WRITE;
#ifdef PRINT_PAGE_CONTENT
        mtd_info("written content: \n");
        cache = page_address(mdp->page);
        for(i = 0; i < 1024; i++)
            mtd_info("page sector %lu:%d cache = %u\n", 
                     bio_sector, i, cache[i]);
#endif
    }
    else
    {
        mtd_err("strange read/write state: %d\n", read);
        re = false;
        goto flush_metadata_bio_finish;
    }

    bio_add_page(bi, mdp->page, PAGE_SIZE, 0);
#ifdef MTD_BIO_USE_MDDEV
    bi->bi_end_io = flush_mtd_bio_endio;
    bi->bi_private = mdp;
    mdp->bio_finished = false;
    mtd_set_bi_stripes(bi, 1);
    mddev->pers->make_request(mddev, bi);
    wait_event(mtd->wait_for_raid5_bio_finish, mdp->bio_finished == true);
#else
    bi->bi_bdev = mtd->bd;
    if(bi->bi_bdev == NULL)
    {
        mtd_err("bi->bi_bdev is NULL(%p)\n", bi->bi_bdev);
        re = false;
        goto flush_metadata_bio_finish;
    }
    submit_bio_wait(bi->bi_rw, bi);
#endif
    re = true;
flush_metadata_bio_finish:   
    spin_unlock(&mdp->write_lock);
    spin_unlock(&mdp->read_lock);
    atomic_set(&mdp->handling, 0);
    wake_up(&mtd->wait_for_read_finish);
    wake_up(&mtd->wait_for_write_finish);
    if(read == MTD_WRITE)
        mtd_info("write page %lu ok and unlock read & write lock page %p\n", 
                 bio_sector, mdp->page);
    else
    {
        mtd_info("read page %lu ok and unlock read & write lock page %p\n", 
                 bio_sector, mdp->page);
#ifdef PRINT_PAGE_CONTENT
        mtd_info("read content: \n");
        cache = page_address(mdp->page);
        for(i = 0; i < 1024; i++)
            mtd_info("page sector %lu:%d cache = %u\n", 
                         bio_sector, i, cache[i]);
#endif
    }
    return re; 
}




struct metadata_page* load_page(struct meta_data* mtd, sector_t sector)
{
    struct metadata_page *mdp = NULL, *temp = NULL;
    struct page* page = NULL;
    unsigned int min_times = 999999;
    struct hlist_head* list = NULL;
    spinlock_t *lock = NULL;
    sector_t mdp_old_sector = 0;
    bool substitution = false;
    int hash = META_PAGE_HASH(sector);

    if(mtd == NULL)
    {
        mtd_err("no valid meta_data or task_unit\n");
        return NULL;
    }

    mtd_info("sector: %lu, hash: %d\n", 
             (unsigned long long)sector, hash);

    list = &mtd->metadata_lru[hash];
    lock = &mtd->metadata_lock;
    
    mtd_info("allocated_meta_page[%d] = %d\n", 
            hash, mtd->allocated_meta_page[hash]);
    if(mtd->allocated_meta_page[hash] < mtd->meta_max_pages)
    {
        mtd_info("alloc\n");
        mdp = kmalloc(sizeof(struct metadata_page), GFP_KERNEL);
        memset(mdp, 0, sizeof(struct metadata_page));
        if(!mdp)
            goto substitution;

        page = alloc_page(GFP_KERNEL);
        if(!page)
        {
            kfree(mdp);
            goto substitution;
        }
        
        mdp->mtd = mtd;
        mdp->bio_finished = true;
        mdp->page = page;
        mdp->sector = sector;
        mdp->mtd = mtd;
        mdp->times = 1;
        spin_lock_init(&mdp->read_lock);
        spin_lock_init(&mdp->write_lock);
        atomic_set(&mdp->handling, 0);

        spin_lock(lock);
        hlist_add_head(&mdp->lru, list);
        mtd->allocated_meta_page[hash]++;
        spin_unlock(lock);

        // spin_lock(&mdp->read_lock); 
        // spin_lock(&mdp->write_lock);
        // mtd_info("lock read lock %lu, %x\n", 
        //          mdp->sector, page_address(mdp->page));
        // mtd_info("lock write lock %lu, %x\n", 
        //          mdp->sector, page_address(mdp->page));
        // mtd_info("hash: %d, allocated_meta_pages: %d\n", 
        //         hash, mtd->allocated_meta_page[hash]);
        if(NULL == mdp || NULL == page)
        {
            mtd_err("no mdp or page to load page\n");
            return NULL;
        }
        /*
         * load page we need.
         */
        if(flush_metadata_bio(mtd, mdp, sector, MTD_READ) == false)
        {
            mtd_err("flush_metadata_bio %lu failed\n", sector);
            goto substitution;
        }
        mtd_info("load page %lu over\n", (unsigned long long)sector);
    }
    else
    {
substitution:
        spin_lock(lock);
        if(NULL == page && !hlist_empty(list))
        {
            mtd_info("find a substitution\n");
            min_times = 999999;
            hlist_for_each_entry(temp, list, lru)
            {
                mtd_info("sector: %lu page: %p, hash: %d, temp->times: %u, handling: %d, readlock: %d, writelock: %d\n",
                     mdp->sector, mdp->page, hash, mdp->times, 
                     atomic_read(&mdp->handling),
                     spin_is_locked(&mdp->read_lock), 
                     spin_is_locked(&mdp->write_lock));
                /*
                 * only happens when find shmeta in disk 
                 * other is preparing to load this page
                 * so just wait patiently.
                 * write lock will be unlocked after load page bio completated.
                 */
                if(temp->sector == sector)
                {
                    spin_unlock(lock);
                    // mtd_info("sector: %lu is being handling now, wait\n");
                    // if(!spin_is_locked(&temp->write_lock))
                    //    spin_lock(&temp->write_lock);
                    // atomic_inc(&temp->handling);
                    return temp;
                }
                if(temp->sector == -1)
                {
                    spin_unlock(&temp->read_lock);
                    spin_unlock(&temp->write_lock);
                    atomic_set(&mdp->handling, 0);
                    break;
                }
                if(temp->times < min_times && 
                   !spin_is_locked(&temp->write_lock) &&
                   !spin_is_locked(&temp->read_lock))
                {
                    mdp = temp;
                    min_times = temp->times;
                    mtd_info("%lu can be used\n", temp->sector);
                }
            }
            spin_unlock(lock);
        
            if(mdp == NULL || mdp->page == NULL || min_times == 999999)
            {
                mtd_info("find a page for %lu but all page can't be used\n", 
                         sector);
                return  NULL;
                mdelay(10);
                goto substitution;
            }
    
            substitution = true;
            atomic_set(&mdp->handling, 0);
            mdp_old_sector = mdp->sector;
    
            mtd_info("substitution: down page %lu, load page %lu, page %p\n", 
                    mdp_old_sector, sector, mdp->page);
            /*
             * flush old page down first.
             */
            if(substitution_page(mtd, mdp, sector) == false)
            {
                mtd_err("substitution %lu to %lu page %p failed\n", 
                        mdp_old_sector, sector, mdp->page);
                goto substitution;
            }
        }
        else
        {
            spin_unlock(lock);
            return NULL;
        }
    }
    mtd_info("load page %lu over\n", sector);
    return mdp;
}

/*
struct metadata_page* find_mtd_page(struct meta_data* mtd, sector_t sector, 
                                    struct hlist_head* list, spinlock_t *lock)
{
    struct metadata_page* mdp;
    
    mtd_info("sector: %lu", sector);
    if(mtd == NULL || list == NULL || lock == NULL)
    {
        mtd_err("mtd/list/lock is NULL");
        return NULL;
    }
    if(!hlist_empty(list))
    {
        spin_lock(lock);
        // mtd_info("begin to find");
        // mtd_info("%p, %p, %p", mtd, list, lock);
        hlist_for_each_entry(mdp, list, lru)
        {
            // mtd_info("sector: %lu, temp->times: %u, handling: %d",
            //         mdp->sector, mdp->times, atomic_read(&mdp->handling));
            if(mdp->sector == sector)
            {
                // move to the tail
                mdp->times++;
                atomic_inc(&mdp->handling);
                if(!spin_is_locked(&mdp->read_lock))
                    spin_lock(&mdp->read_lock);
                spin_unlock(lock);
                mtd_info("find mdp in cache");
                return mdp;
            }
        }
        spin_unlock(lock);
    }
    mtd_info("NO find mdp in cache");
    return NULL;
}
*/

struct metadata_page* find_mtd_page(struct meta_data* mtd, sector_t sector)
{
    struct metadata_page* mdp = NULL;
    bool at_head = true;
    int hash = META_PAGE_HASH(sector);
    mtd_info("sector: %lu, hash: %d\n", sector, hash);
    if(mtd == NULL)
    {
        mtd_err("mtd/list/lock is NULL\n");
        return NULL;
    }

    spin_lock(&mtd->metadata_lock);
    if(!hlist_empty(&mtd->metadata_lru[hash]))
    {
        hlist_for_each_entry(mdp, &mtd->metadata_lru[hash], lru)
        {
            // mtd_err("sector: %lu(%p), hash: %d, temp->times: %u, handling: %d, readlock: %d, writelock: %d\n",
            //          mdp->sector, mdp, hash, mdp->times, atomic_read(&mdp->handling),
            //         spin_is_locked(&mdp->read_lock), spin_is_locked(&mdp->write_lock));
            if(mdp->sector == sector)
            {
                // move to the tail
                mdp->times++;
                mtd_info("find mdp %lu hash %d in cache\n", sector, hash);
                if(!at_head)
                {
                    hlist_del_init(&mdp->lru);
                    hlist_add_head(&mdp->lru, &mtd->metadata_lru[hash]);
                }
                break;
            }
            at_head = false;
        }
    }
    spin_unlock(&mtd->metadata_lock);
    return mdp;
}



bool load_shmeta_metadata(struct r5meta *meta, struct meta_data *mtd, void *data)
{
    struct metadata_page* mdp = NULL;
    struct shmeta* sm = (struct shmeta*)data;
    sector_t load_sector;
    int meta_th, meta_th_in_page, page_th, flush_pos, i, hash;
    unsigned int *cache;
    bool retryed = false;
    spinlock_t lock;
    spin_lock_init(&lock);
    unsigned long sector_test;
    
    if(meta == NULL || mtd == NULL)
    {
        mtd_err("no valid mtd or hm\n");
        return false;
    }

    struct shmeta *sm_new;
    spin_lock(&mtd->loading_sm_lock);
    if(atomic_read(&mtd->loading_sm_count) != 0)
    {
        list_for_each_entry(sm_new, &mtd->loading_sm, lru)
        {
            if(sm_new->sector == sm->sector)
            {
                set_bit(SM_OTHER_LOADING_META_NOW, &sm->flags);
                spin_unlock(&mtd->loading_sm_lock);
                return false;
            }
        }
    }
    

    
    INIT_LIST_HEAD(&sm->lru);
    list_add(&sm->lru, &mtd->loading_sm);
    atomic_inc(&mtd->loading_sm_count);
    spin_unlock(&mtd->loading_sm_lock);

    hash = META_HASH(sm->sector);
    meta_th = sm->lba_align / META_PAGES_HASH;
    meta_th_in_page = meta_th % mtd->metadata_per_page;
    page_th = meta_th / mtd->metadata_per_page;

    load_sector = (hash * mtd->metadata_page_each_hash << PAGE_2_SECTOR_SHIFT)
                    + mtd->metadata_begin_sector 
                    + (page_th << PAGE_2_SECTOR_SHIFT);
    mtd_info("sm->sector: %lu, load_sector: %lu, hash: %d\n", 
            sm->sector, load_sector, hash);

retry_load_meta:
    if((mdp = find_mtd_page(mtd, load_sector)) == NULL)
    {
        // load page first.
        mtd_info("hash %d I need to handle this by myself\n", hash);
        mdp = load_page(mtd, load_sector);
        if(mdp == NULL && !retryed) 
        {
            if(!retryed)
            {
                mtd_err("hash %d no valid page to use, retry2\n", hash);
                mdelay(10);
                retryed = true;
                goto retry_load_meta;
            }
            else
            {
                mtd_err("load metadata failed twice!\n");
                

                spin_lock(&mtd->loading_sm_lock);
                atomic_dec(&mtd->loading_sm_count);
                list_del_init(&sm->lru);
                spin_unlock(&mtd->loading_sm_lock);

                return false;
            }
        }
    }

    if(mdp == NULL || mdp->page == NULL)
    {
        mtd_err("oooops2\n");
        return false;
        goto retry_load_meta;
    }
    if(spin_is_locked(&mdp->write_lock))
    {
        /*
         * is handled by others, wait
        */
        mtd_info("wait for handling, %lu\n", load_sector);
        wait_event(mtd->wait_for_write_finish, !spin_is_locked(&mdp->write_lock));
        mtd_info("wake_up\n");
        // goto retry_load_meta;
    }
    if(mdp->sector != load_sector)
        goto retry_load_meta;

    if(!spin_is_locked(&mdp->read_lock))
    {
        spin_lock(&mdp->read_lock);
        atomic_set(&mdp->handling, 0);
        mtd_info("lock read_lock for mdp %lu, page %p", mdp->sector, mdp->page);
    }
    atomic_inc(&mdp->handling);

    flush_pos = mtd->metadata_size * meta_th_in_page;
    mtd_info("meta_th: %d, meta_th_in_page: %d, page_th: %d, load_sector: %lu, flush_pos: %d\n", meta_th, meta_th_in_page, page_th, load_sector, flush_pos);
    memcpy(&sector_test, page_address(mdp->page) + flush_pos, 
            sizeof(unsigned long));
    flush_pos += sizeof(unsigned long);
    i = 0;
    while(i < mtd->devnum)
    {
        spin_lock(&lock);
        memcpy(&sm->dmeta[i].lba, page_address(mdp->page) + flush_pos,
                sizeof(sector_t));
        flush_pos += sizeof(sector_t);

        memcpy(&sm->dmeta[i].lso, page_address(mdp->page) + flush_pos,
                sizeof(unsigned long));
        flush_pos += sizeof(unsigned long);

        memcpy(&sm->dmeta[i].psn, page_address(mdp->page) + flush_pos,
                sizeof(unsigned int));
        flush_pos += sizeof(unsigned int);

        sm->dmeta[i].bi_sector = DEV_META_BLANK;
        i++;
        spin_unlock(&lock);
    }
    mtd_info("after load shmeta\n");
    print_shmeta_test(sm);
    if(sector_test != sm->sector)
    {
#ifdef PRINT_PAGE_CONTENT
        cache = page_address(mdp->page);
        for(i = 0; i < 1024; i++)
            mtd_info("page sector %lu:%d cache = %u\n", 
                    mdp->sector, i, cache[i]);
#endif
        /*
        if(retryed == false)
        {
            mtd_err("page content wrong sm: %lu, loaded: %lu, mdp->sector: %lu, %p\n", 
                    sm->sector, sector_test, mdp->sector, mdp);
            spin_unlock(&mdp->read_lock);
            spin_unlock(&mdp->write_lock);
            atomic_dec(&mdp->handling);
            wake_up(&mtd->wait_for_read_finish);
            wake_up(&mtd->wait_for_write_finish);
            mdp->sector = -1;
            / *
            hlist_del_init(&mdp->lru);
            __free_page(mdp->page);
            kfree(mdp);
            mdp = NULL;
            mtd->allocated_meta_page[hash]--;
            * /
            retryed = true;
            mtd_info("allocated_meta_page[%d] = %d\n", 
                     hash, mtd->allocated_meta_page[hash]);
            goto retry_load_meta;
        }
        else
        {
        */
            if(sector_test != sm->sector && sector_test != 0)
                mtd_err("page destoryed! when load sm %lu, loaded: %lu, mdp->sector: %lu, page %p\n", 
                    sm->sector, sector_test, mdp->sector, mdp->page);
            atomic_set(&mdp->handling, 0);
            spin_unlock(&mdp->read_lock);
            spin_unlock(&mdp->write_lock);
            wake_up(&mtd->wait_for_read_finish);
            wake_up(&mtd->wait_for_write_finish);
            mtd_info("unlock read lock page %p\n", mdp->page);
        
        
            spin_lock(&mtd->loading_sm_lock);
            atomic_dec(&mtd->loading_sm_count);
            list_del_init(&sm->lru);
            spin_unlock(&mtd->loading_sm_lock);

            return false;
        // }
    }
    atomic_dec(&mdp->handling);
    if(atomic_read(&mdp->handling) == 0)
    {
        spin_unlock(&mdp->read_lock);
        wake_up(&mtd->wait_for_read_finish);
        mtd_info("unlock read lock page %p\n", mdp->page);
    }
    set_bit(SM_WRITTEN, &sm->flags);
    set_bit(SM_DYNAMIC, &sm->flags);
    
    spin_lock(&mtd->loading_sm_lock);
    atomic_dec(&mtd->loading_sm_count);
    list_del_init(&sm->lru);
    INSERT_SHMETA_HASH(meta, sm, HASH(sm->sector))
    spin_unlock(&mtd->loading_sm_lock);

    return true;
}

void reset_metadata_zero(struct meta_data *mtd, sector_t sector, sector_t lba_align)
{
    struct metadata_page* mdp = NULL;
    sector_t load_sector;
    int page_th = 0, meta_th = 0, meta_th_in_page = 0, flush_pos, i;
    int *cache;
    spinlock_t lock;
    bool retryed = false;
    unsigned long sector_test;

    if(mtd == NULL)
    {
        mtd_err("no valid mtd or hm\n");
        return;
    }
    mtd_info("sector: %lu, hash %d\n", sector, hash);

    int hash = META_HASH(sector);
    meta_th = lba_align / META_PAGES_HASH;
    meta_th_in_page = meta_th % mtd->metadata_per_page;
    page_th = meta_th / mtd->metadata_per_page;
    load_sector = (hash * mtd->metadata_page_each_hash << PAGE_2_SECTOR_SHIFT)
                    + mtd->metadata_begin_sector 
                    + (page_th << PAGE_2_SECTOR_SHIFT);

    mtd_info("hash: %d, lba_align: %lu\n", hash, lba_align);
    if(hash != (lba_align % META_PAGES_HASH))
    {
        mtd_err("hash != lba_align div %d, hash = %d, lba_align = %lu\n",
                META_PAGES_HASH, hash, lba_align);
    }

retry_load_meta:
    if((mdp = find_mtd_page(mtd, load_sector)) == NULL)
    {
        // load page first.
        mtd_info("hash %d I need to handle this by myself\n", hash);
        if((mdp = load_page(mtd, load_sector)) == NULL) 
        {
            if(!retryed)
            {
                retryed = true;
                mtd_err("hash %d no page to use, retry2\n", hash);
                mdelay(10);
                goto retry_load_meta;
            }
            else
            {
                mtd_err("page: %lu retryed twice failed both\n",
                       load_sector);
                return;
            }
        }
    }

    if(mdp == NULL || mdp->page == NULL)
    {
        mtd_err("oooops2\n");
        goto retry_load_meta;
            return;
    }

    if(spin_is_locked(&mdp->read_lock))
        wait_event(mtd->wait_for_read_finish, !spin_is_locked(&mdp->read_lock));

    if(spin_is_locked(&mdp->write_lock))
    {
        /*
         * is handled by others, wait
        */
        mtd_info("wait for handling\n");
        wait_event(mtd->wait_for_write_finish, !spin_is_locked(&mdp->write_lock));
        mtd_info("wake_up\n");
        goto retry_load_meta;
    }
    if(mdp->sector != load_sector)
        goto retry_load_meta;

    spin_lock(&mdp->write_lock);
    mtd_info("lock mdp write_lock, %lu, page %p\n", 
            mdp->sector, mdp->page);
    
    flush_pos = mtd->metadata_size * meta_th_in_page;
    mtd_info("meta_th: %d, meta_th_in_page: %d, page_th: %d, \ 
             load_sector: %lu, flush_pos: %d\n", 
             meta_th, meta_th_in_page, page_th, load_sector, flush_pos);
    
    // write begin
    memset(page_address(mdp->page) + flush_pos, 0,  mtd->metadata_size);
   
    spin_unlock(&mdp->write_lock);
    spin_unlock(&mdp->read_lock);
    atomic_set(&mdp->handling, 0);
    mtd_info("unlock write_lock for mdp %lu, page %p\n", 
            mdp->sector, mdp->page);
    wake_up(&mtd->wait_for_write_finish);
    return;
}


void change_metadata(struct meta_data* mtd, struct shmeta* sm, int hash)
{
    struct metadata_page* mdp = NULL;
    sector_t load_sector;
    int page_th = 0, meta_th = 0, meta_th_in_page = 0, flush_pos, i;
    struct shmeta* sm_new;
    int *cache;
    spinlock_t lock;
    bool retryed = false;
    unsigned long sector_test;

    spin_lock_init(&lock);
    
    if(sm == NULL || mtd == NULL)
    {
        mtd_err("no valid mtd or hm\n");
        return;
    }
    mtd_info("sector: %lu, hash %d\n", sm->sector, hash);

    /*
    sm_new = kmalloc(sizeof(struct shmeta), GFP_KERNEL);
    sm_new->dmeta = kmalloc(sizeof(struct devmeta) * 3, GFP_KERNEL);
    */
    hash = META_HASH(sm->sector);
    meta_th = sm->lba_align / META_PAGES_HASH;
    meta_th_in_page = meta_th % mtd->metadata_per_page;
    page_th = meta_th / mtd->metadata_per_page;
    // meta_th = sm->sector / SM_FLUSH_HASH; 
    /*
    meta_th = sm->lba_align / META_PAGES_HASH;
    meta_th_in_page = meta_th % mtd->metadata_per_page;
    page_th = meta_th / mtd->metadata_per_page;
    */
    /*
    meta_th = sm->lba_align / 8;
    meta_th_in_page = meta_th % mtd->metadata_per_page;
    page_th = meta_th / mtd->metadata_per_page;
    */

    load_sector = (hash * mtd->metadata_page_each_hash << PAGE_2_SECTOR_SHIFT)
                    + mtd->metadata_begin_sector 
                    + (page_th << PAGE_2_SECTOR_SHIFT);

    mtd_info("hash: %d, lba_align: %lu\n", hash, sm->lba_align);
    if(hash != (sm->lba_align % META_PAGES_HASH))
    {
        mtd_err("hash != sm->lba_align div %d, hash = %d, lba_align = %lu\n",
                META_PAGES_HASH, hash, sm->lba_align);
        print_shmeta_test(sm);
    }

retry_load_meta:
    if((mdp = find_mtd_page(mtd, load_sector)) == NULL)
    {
        // load page first.
        mtd_info("hash %d I need to handle this by myself\n", hash);
        if((mdp = load_page(mtd, load_sector)) == NULL) 
        {
            if(!retryed)
            {
                retryed = true;
                mtd_err("hash %d no page to use, retry2\n", hash);
                mdelay(10);
                goto retry_load_meta;
            }
            else
            {
                mtd_err("page: %lu retryed twice failed both\n",
                       load_sector);
                return;
            }
        }
    }

    if(mdp == NULL || mdp->page == NULL)
    {
        mtd_err("oooops2\n");
        goto retry_load_meta;
            return;
    }

    if(spin_is_locked(&mdp->read_lock))
        wait_event(mtd->wait_for_read_finish, !spin_is_locked(&mdp->read_lock));

    if(spin_is_locked(&mdp->write_lock))
    {
        /*
         * is handled by others, wait
        */
        mtd_info("wait for handling\n");
        wait_event(mtd->wait_for_write_finish, !spin_is_locked(&mdp->write_lock));
        mtd_info("wake_up\n");
        goto retry_load_meta;
    }
    if(mdp->sector != load_sector)
        goto retry_load_meta;

    spin_lock(&mdp->write_lock);
    mtd_info("lock mdp write_lock, %lu, page %p\n", 
            mdp->sector, mdp->page);
    
    flush_pos = mtd->metadata_size * meta_th_in_page;
    mtd_info("meta_th: %d, meta_th_in_page: %d, page_th: %d, \ 
             load_sector: %lu, flush_pos: %d\n", 
             meta_th, meta_th_in_page, page_th, load_sector, flush_pos);
    print_shmeta_test(sm);
    
    // check position
    /*
    memcpy(&sector_test, page_address(mdp->page) + flush_pos, 
           sizeof(unsigned long));
    if(sector_test != -1 && sector_test != 0 && sector_test != sm->sector)
        mtd_err("change wrong! sector_test: %lu, sm->sector: %lu, mdp->sector: %lu, %p\n", sector_test, sm->sector, mdp->sector, mdp);
    */
    // write begin
    memcpy(page_address(mdp->page) + flush_pos, &sm->sector, 
           sizeof(unsigned long));
    flush_pos += sizeof(unsigned long);
    i = 0;
    while(i < mtd->devnum)
    {
        spin_lock(&lock);
        memcpy(page_address(mdp->page) + flush_pos, 
               &sm->dmeta[i].lba, sizeof(sector_t));
        flush_pos += sizeof(sector_t);

        memcpy(page_address(mdp->page) + flush_pos, 
               &sm->dmeta[i].lso, sizeof(unsigned long));
        flush_pos += sizeof(unsigned long);

        memcpy(page_address(mdp->page) + flush_pos, 
               &sm->dmeta[i].psn, sizeof(unsigned int));
        flush_pos += sizeof(unsigned int);
        i++;
        spin_unlock(&lock);
    }
    
#ifdef PRINT_PAGE_CONTENT
    /*
    flush_pos = mtd->metadata_size * meta_th_in_page;
    mtd_info("meta_th: %d, meta_th_in_page: %d, page_th: %d, load_sector: %lu, flush_pos: %d\n", meta_th, meta_th_in_page, page_th, load_sector, flush_pos);
    memcpy(&sm_new->sector, page_address(mdp->page) + flush_pos, 
            sizeof(unsigned long));
    flush_pos += sizeof(unsigned long);
    i = 0;
    while(i < mtd->devnum)
    {
        spin_lock(&lock);
        memcpy(&sm_new->dmeta[i].lba, page_address(mdp->page) + flush_pos,
                sizeof(sector_t));
        flush_pos += sizeof(sector_t);

        memcpy(&sm_new->dmeta[i].lso, page_address(mdp->page) + flush_pos,
                sizeof(unsigned long));
        flush_pos += sizeof(unsigned long);

        memcpy(&sm_new->dmeta[i].psn, page_address(mdp->page) + flush_pos,
                sizeof(int));
        flush_pos += sizeof(int);
        i++;
        spin_unlock(&lock);
    }
    
    mtd_info("after change:\n");
    print_shmeta_test(sm_new);
    flush_pos = mtd->metadata_size * meta_th_in_page;
    mtd_info("change content: \n");
    cache = page_address(mdp->page);
    for(i = flush_pos / 4; i < (flush_pos + mtd->metadata_size) / 4; i++)
        mtd_info("page sector %lu:%d cache = %u\n", 
                     mdp->sector, i, cache[i]);
    */
#endif

    spin_unlock(&mdp->write_lock);
    spin_unlock(&mdp->read_lock);
    atomic_set(&mdp->handling, 0);
    mtd_info("unlock write_lock for mdp %lu, page %p\n", 
            mdp->sector, mdp->page);
    wake_up(&mtd->wait_for_write_finish);
    /*
    atomic_dec(&mdp->handling);
    if(atomic_read(&mdp->handling) == 0)
    {
        spin_unlock(&mdp->read_lock);
        wake_up(&mtd->wait_for_read_finish);
        mtd_info("unlock read lock %x\n", page_address(mdp->page));
    }
    */
    /*
    kfree(sm_new->dmeta);
    kfree(sm_new);
    */
    return;
}



//////////////////////////////////////////////////
//  flush metadata
int flush_hash_bio_thread(void *data)
{
    struct flush_task_unit* ftu = (struct flush_task_unit*)data;
    struct meta_data* mtd;
    struct shmeta* sm;
    int metadata_per_page, hash;
    int total_shmetas, size, handle_hash_now;
    struct list_head* list;

    if(ftu == NULL || (mtd = ftu->mtd) == NULL)
    {
        mtd_err("no valid ftu\n");
        goto flush_hash_bio_thread_end;
    }
   
    hash = ftu->hash;
    metadata_per_page = mtd->metadata_per_page;

    /*
     * handle second written metadata
     */
    handle_hash_now = hash;
    while(handle_hash_now < SM_FLUSH_HASH)
    {
        list = &ftu->list[handle_hash_now];
        total_shmetas = ftu->list_size[handle_hash_now];
        sm = NULL;
        if(total_shmetas != 0)
        {
            list_for_each_entry(sm, list, lru)
            {
                mtd_info("hash %d, total_shmetas: %d\n", hash, total_shmetas);
                if(total_shmetas == 0 || sm == NULL ||
                   !test_bit(SM_IN_FLUSH, &sm->flags))
                    break;
                total_shmetas--;
                change_metadata(mtd, sm, handle_hash_now); 
            }
        }
        handle_hash_now += FLUSH_THREAD_HASH;
    }
flush_hash_bio_thread_end:
    atomic_dec(&mtd->flush_flags);

    mtd_info("handle hash %d end\n", hash);
    mtd_info("flush flag: %d\n", atomic_read(&mtd->flush_flags));
    wake_up(&mtd->wait_for_pre_flush);
    // do_exit(0);
    return 0;
}




int flush_metadata_by_others(struct meta_data* mtd)
{
    struct r5meta * meta;
    int i, *hash_list_size;
    struct task_struct * bio_task;
    struct flush_task_unit ftu[FLUSH_THREAD_HASH];

    if(NULL == mtd || (meta = mtd->r5meta) == NULL)
    {
        mtd_err("no valid meta_data\n");
        return -1;
    }

    hash_list_size = meta->hash_list_size; 
    for(i = 0; i < FLUSH_THREAD_HASH; i++)
    {
        ftu[i].hash = i;
        ftu[i].mtd = mtd; 
        ftu[i].list_size = hash_list_size;
        ftu[i].list = meta->flush_list;

        // setup a thread to handle flush
        bio_task = kthread_create(flush_hash_bio_thread, &ftu[i], "task");
        if(IS_ERR(bio_task))
        {
            mtd_err("Unable to start submit_metadata_bio thread. \n");
            bio_task = NULL;
            /*
             * so ?
             */
            return -1;
        }

        mtd_info("tgid: %lu, pid: %lu\n", task_pid(bio_task), task_tgid(bio_task));
        atomic_inc(&mtd->flush_flags);
        mtd_info("flag: %d\n", atomic_read(&mtd->flush_flags));
        wake_up_process(bio_task);
    }

    mtd_info("begin wait\n");
    if(atomic_read(&mtd->flush_flags) != 0)
        wait_event(mtd->wait_for_pre_flush, atomic_read(&mtd->flush_flags) == 0);
    mtd_info("all hash handled already\n");
    return 0;
}


// int handle_blank_sectors(struct meta_data* mtd, int read);

void exit_metadata(struct meta_data* mtd)
{
    struct metadata_page* mdp = NULL;
    sector_t last_sec = -1;
    int i = 0;

    if(!mtd)
        return;

    set_flag(MTD_STOP, &mtd->flags);
    /*
    if(mtd->meta_page != NULL)
    {
        mtd_info("flush meta_page\n");
        handle_blank_sectors(mtd, MTD_WRITE);
    }
    */

    spin_lock(&mtd->metadata_lock);
    for(i = 0; i < META_PAGES_HASH; i++)
    {
        while(!hlist_empty(&mtd->metadata_lru[i]))
        {
            mdp = hlist_entry((mtd->metadata_lru[i].first), 
                              struct metadata_page, lru);
            if(!mdp || mdp->sector == last_sec)
                break;
            hlist_del_init(&mdp->lru);
            mtd_info("handle metapage %lu\n", mdp->sector);   
            last_sec = mdp->sector;
            if(NULL != mdp->page)
            {
                mtd_info("flush metapage %lu\n", mdp->sector);
                flush_metadata_bio(mtd, mdp, mdp->sector, MTD_WRITE);
                // put_page(mtd->meta_page);
                __free_page(mdp->page);
            }
            kfree(mdp);
        }
    }
    spin_unlock(&mtd->metadata_lock);
    kfree(mtd);
    mtd_info("stop meta data over\n");
    return;
}


/*
int load_blank_sectors_thread(void *data)
{
    struct meta_data* mtd = (struct meta_data*)data;
    struct page* page = mtd->meta_page;
    struct bio* bi;
    // int i;
    if(mtd == NULL)
    {
        mtd_info("no valid task_unit or mtd\n");
        return -1;
    }

    if(page == NULL)
        page = alloc_page(GFP_KERNEL);
    if(NULL == page)
    {
        mtd_err("Create page failed\n");
        return -1;
    }
    
    bi = bio_alloc(GFP_NOIO, 2);
    if(NULL == bi)
    {
        mtd_err("create bio failed\n");
        return -1;
    }

    bi->bi_iter.bi_sector = mtd->metadata_begin_sector - 8;
    mtd_info("load_blank_sectors sector: %lu\n", 
             (unsigned long long)bi->bi_iter.bi_sector);

    bi->bi_rw = READ;
   

    mtd_set_bi_stripes(rbi, 1);
    mddev->pers->make_request(mddev, bi);
    wait_event(mtd->wait_for_raid5_bio_finish, mdp->bio_finished == true);

    clear_flag(MTD_WAIT_HANDLE_BLANK_PAGE, &mtd->flags);
    wake_up(&mtd->wait_for_load_blank_page);
    // do_exit(0);
    return 0;
}

int flush_blank_sectors_thread(void *data)
{
    struct meta_data* mtd = (struct meta_data*)data;
    struct page* page = mtd->meta_page;
    struct bio* bi;
    // int i;

    if(mtd == NULL)
    {
        mtd_info("no valid task_unit or mtd\n");
        return -1;
    }

    if(page == NULL)
    {
        mtd_err("page is NUL\nL");
        return -1;
    }
    
    bi = bio_alloc(GFP_NOIO, 2);
    if(NULL == bi)
    {
        mtd_err("create bio failed\n");
        return -1;
    }

    bi->bi_iter.bi_sector = mtd->metadata_begin_sector - 8;
   	bio_add_page(bi, page, PAGE_SIZE, 0);
    mtd_info("flush_blank_sectors sector: %lu\n", 
            (unsigned long long)bi->bi_iter.bi_sector);
    // bio_set_op_attrs(bi, REQ_OP_WRITE, 0);
    bi->bi_rw = WRITE;
    bi->bi_bdev = mtd->bd;
    if(bi->bi_bdev == NULL)
    {
        mtd_err("bi->bi_bdev is NULL(%p)\n", bi->bi_bdev);
        return 0;
    }
    submit_bio_wait(bi->bi_rw, bi);
   
    if(check_flag(MTD_STOP, &mtd->flags))
    {
        // put_page(mtd->meta_page);
        __free_page(mtd->meta_page);
    }
    
    clear_flag(MTD_WAIT_HANDLE_BLANK_PAGE, &mtd->flags);
    wake_up(&mtd->wait_for_load_blank_page);
    / *
    if(check_flag(MTD_STOP, &mtd->flags))
    {
        bi->bi_bdev = mtd->bd;
        if(bi->bi_bdev == NULL)
        {
            mtd_err("bi->bi_bdev is NULL(%p)", bi->bi_bdev);
            return false;
        }
        submit_bio_wait(bi);
        // put_page(mtd->meta_page);
        //__free_page(mtd->meta_page);
    }
    else
    {
        bi->bi_bdev = mtd->rdev->bdev;
        if(bi->bi_bdev == NULL)
        {
            mtd_err("bi->bi_bdev is NULL(%p)", bi->bi_bdev);
            return false;
        }
        submit_bio(bi);
    }
    * /
    return 0;
}

int handle_blank_sectors(struct meta_data* mtd, int read)
{
    struct task_struct * bio_task;

    mtd_info("\n");
    // load hash metadata. 
    / *
    if(read == MTD_READ)
        set_flag(MTD_LOADING_BLANK_SECTORS, &mtd->flags);
    else
        set_flag(MTD_FLUSHING_BLANK_SECTORS, &mtd->flags);
    * / 
    if(read == MTD_READ)
        bio_task = kthread_create(load_blank_sectors_thread,
                                  mtd, "load_blank_sectors");
    else
        bio_task = kthread_create(flush_blank_sectors_thread, 
                                 mtd, "flush_blank_sectors");
    if(IS_ERR(bio_task))
    {
        mtd_err("Unable to start kernel submit_bio thread. \n");
        bio_task = NULL;
        / *
         * so ?
         * /
        return -1;
    }

    set_flag(MTD_WAIT_HANDLE_BLANK_PAGE, &mtd->flags);
    wake_up_process(bio_task);
    wait_event(mtd->wait_for_load_blank_page, 
               !check_flag(MTD_WAIT_HANDLE_BLANK_PAGE, &mtd->flags));
    mtd_info("wake up\n");
    return 0;
}
*/



struct meta_data* setup_metadata(struct r5meta* meta, 
                                 sector_t begin_sector,
                                 int rec_sm_radio,
                                 struct block_device* bd)
{
    struct meta_data* mtd = meta->mtd;
    sector_t *blanks;
    struct cache_tree_data* ctd;
    int i, devnum;
    struct mddev* mdd;
    struct md_rdev* rdev;
    
    if( meta == NULL || 
        (mtd = meta->mtd) != NULL ||
        (ctd = meta->ctd) == NULL ||
        (mdd = ctd->mdd) == NULL ||
        ((mtd = kmalloc(sizeof(struct meta_data),GFP_KERNEL))
              == NULL))
        return mtd;

    memset(mtd, 0, sizeof(struct meta_data));
    mtd->r5meta = meta; 
    mtd_info("%lu\n", begin_sector);

#ifndef MTD_BIO_USE_MDDEV
    if((mtd->bd = bd) == NULL)
    {
        mtd->bd = blkdev_get_by_path("/dev/sdb9", 
                 FMODE_READ | FMODE_WRITE, NULL);
        if(NULL == mtd->bd || IS_ERR(mtd->bd))
        {
            mtd_err("mb->bd err\n");
            kfree(mtd);
            return NULL;
        }
    }
#endif

    if ((mtd->metadata_lru = kmalloc(PAGE_SIZE, GFP_KERNEL)) == NULL ||
        (mtd->allocated_meta_page = kmalloc(PAGE_SIZE, GFP_KERNEL)) == NULL)
    {
        mtd_err("alloc lru or meta_pages_counter failed\n");
        kfree(mtd);
        return NULL;
    }
    memset(mtd->metadata_lru, 0, PAGE_SIZE);
    memset(mtd->allocated_meta_page, 0, PAGE_SIZE);
    devnum = mtd->devnum = meta->devnum;
    mtd->mddev = mdd;
    if(begin_sector != -1)
        mtd->metadata_begin_sector = begin_sector + 8;
    else
        mtd->metadata_begin_sector = SNAP_BEGIN_SECTOR;
   
    printk(KERN_INFO "meta begin_sector: %lu\n", mtd->metadata_begin_sector);
    if(rec_sm_radio > 0 && rec_sm_radio < 100)
        mtd->rec_sm_radio = rec_sm_radio;
    else
        mtd->rec_sm_radio = REC_SM_RADIO;

    mtd->meta_max_pages = MTD_HASH_MAX_SIZE;

    // meta_data_per_page
    mtd->metadata_size = sizeof(unsigned long) + 
        (sizeof(sector_t) + sizeof(unsigned long) + sizeof(unsigned int)) * devnum;

    mtd->metadata_per_page = MTD_PAGE_SIZE / mtd->metadata_size; 
    mtd->shmetas = mdd->dev_sectors >> 3/*MB_SHMETA_SHIFT */;
    // mtd->dynamic_shmetas = mtd->shmetas * REC_SM_RADIO / 100;
 
    mtd_info("metadata_size: %d, metadata_per_page: %d\n",
            mtd->metadata_size, mtd->metadata_per_page);
    // about sectors
    mtd->metadata_page_each_hash = (mtd->shmetas >> MTD_HASH_SHIFT) / 
                                mtd->metadata_per_page + 1; 

    mtd->metadata_end_sector = mtd->metadata_begin_sector + 
            (mtd->metadata_page_each_hash << MTD_HASH_SHIFT) << PAGE_2_SECTOR_SHIFT;
    // wait queue
    init_waitqueue_head(&mtd->wait_for_pre_flush);
    init_waitqueue_head(&mtd->wait_for_load_blank_page);
    init_waitqueue_head(&mtd->wait_for_read_finish);
    init_waitqueue_head(&mtd->wait_for_write_finish);
    init_waitqueue_head(&mtd->wait_for_raid5_bio_finish);

    // spin lock
    spin_lock_init(&mtd->metadata_lock);
    spin_lock_init(&mtd->meta_page_lock);

    // list head
    for(i = 0; i < META_PAGES_HASH; i++)
    {
        INIT_HLIST_HEAD(&mtd->metadata_lru[i]);
        mtd->allocated_meta_page[i] = 0;
    }

    atomic_set(&mtd->flush_flags, 0);
    
    mtd->meta_page = NULL;
    mtd->meta_page = alloc_page(GFP_KERNEL);
    blanks = page_address(mtd->meta_page);
    blanks[0] = blanks[1] = blanks[2] = blanks[3] = 0;

    print_metadata_conf(mtd);
    meta->mtd = mtd;
    mtd->load_blank_page = false;
    // handle_blank_sectors(mtd, MTD_READ);
    

    spin_lock_init(&mtd->loading_sm_lock);
    atomic_set(&mtd->loading_sm_count, 0);
    INIT_LIST_HEAD(&mtd->loading_sm); 

    return mtd;
}


