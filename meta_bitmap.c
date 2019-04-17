/*************************************************************************
	> File Name: meta_bitmap.c
	> Author: yms 
	> Mail: meow@meow.com
	> Created Time: Tue 18 Jul 2017 10:37:54 AM CST
 ************************************************************************/


#include "meta_bitmap.h"
#include "flag.h"

#include <linux/wait.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/blkdev.h>
#define mb_fmt(fmt) "mb: [%d %s] " fmt
#define mb_fmt_err(fmt) "mb ERROR: [%d %s] " fmt
#define mb_info(fmt,...)// printk(KERN_INFO mb_fmt(fmt), __LINE__, __func__, ##__VA_ARGS__)
#define mb_err(fmt,...) printk(KERN_INFO mb_fmt_err(fmt),__LINE__, __func__, ##__VA_ARGS__)


#define MB_HASH_TABLE_HASH_NUM          8
#define MB_HASH(sector)        ((sector >> 3) & (MB_HASH_TABLE_HASH_NUM - 1))


#define MB_MAX_PAGES        32 // 8



static int dynamics = 0;


static inline void mb_set_bi_stripes(struct bio *bio, unsigned int cnt)
{
    atomic_t *segments = (atomic_t *)&bio->bi_phys_segments;
    atomic_set(segments, cnt);
}


static void flush_mb_bio_endio(struct bio *bi)
{
    struct meta_bitmap_page* mbp = bi->bi_private;
    struct meta_bitmap *mb = mbp->mb;
    mbp->bio_finished = true;    
    wake_up(&mb->wait_for_raid5_bio_finish);
    // put_bio(bi);
    return;
}

bool mb_substitution_page(struct meta_bitmap *mb, struct meta_bitmap_page *mbp,
                      sector_t bio_sector)
{
    struct bio *bi, *rbi;
    unsigned int *cache;
    sector_t old_sector;
    struct mddev *mddev;
    int i = 0;
    bool re = false;

    if(!mb || !mbp || mbp->page == NULL ||
       ((mddev = (mb->mddev)) == NULL))
    {
        mb_err("para NULL\n");
        return false;
    }

    bi = bio_alloc(GFP_NOIO, 2);
    rbi = bio_alloc(GFP_NOIO, 2);
    if(!bi || !rbi) 
    {
        mb_err("bi Create failed\n");
        return false;
    }
    
    if(spin_is_locked(&mbp->read_lock))
    {
        wait_event(mb->wait_for_read_finish, !spin_is_locked(&mbp->read_lock));
    }
    spin_lock(&mbp->read_lock);
    if(spin_is_locked(&mbp->write_lock))
    {
        wait_event(mb->wait_for_write_finish, !spin_is_locked(&mbp->write_lock));
    }
    spin_lock(&mbp->write_lock);

    // write first.
    old_sector = bi->bi_iter.bi_sector = mbp->sector;
    if(mbp->sector != -1)
    {
        mb_info("submit bio sector: %lu, WRITE, mbp: %p, page: %p\n", 
                mbp->sector, mbp, mbp->page);
        bi->bi_rw = WRITE;
        bio_add_page(bi, mbp->page, PAGE_SIZE, 0);

#ifdef MB_BIO_USE_MDDEV
        bi->bi_private = mbp;
        bi->bi_end_io = flush_mb_bio_endio;
        mbp->bio_finished = false;

        mb_set_bi_stripes(bi, 1);
        mddev->pers->make_request(mddev, bi);
        wait_event(mb->wait_for_raid5_bio_finish, mbp->bio_finished == true);
#else
        bi->bi_bdev = mb->bd;
        submit_bio_wait(bi->bi_rw, rbi);
#endif
        __free_page(mbp->page);
        if((mbp->page = alloc_page(GFP_KERNEL)) == NULL)
            mb_err("alloc page wrong!\n");
    }
    // read 
    if(mbp->page)
    {
        mbp->sector = rbi->bi_iter.bi_sector = bio_sector;
        mb_info("submit bio sector: %lu, READ, mbp: %p, page: %p\n", 
                mbp->sector, mbp, mbp->page);
        rbi->bi_rw = READ;
        bio_add_page(rbi, mbp->page, PAGE_SIZE, 0);
        
#ifdef MB_BIO_USE_MDDEV
        rbi->bi_private = mbp;
        rbi->bi_end_io = flush_mb_bio_endio;
        mbp->bio_finished = false;

        mb_set_bi_stripes(rbi, 1);
        mddev->pers->make_request(mddev, rbi);
        wait_event(mb->wait_for_raid5_bio_finish, mbp->bio_finished == true);
#else        
        rbi->bi_bdev = mb->bd;
        submit_bio_wait(rbi->bi_rw, rbi);
#endif
    }
    // end
    spin_unlock(&mbp->write_lock);
    spin_unlock(&mbp->read_lock);
    atomic_set(&mbp->handling, 0);
    wake_up(&mb->wait_for_read_finish);
    wake_up(&mb->wait_for_write_finish);
    mb_info("down %lu up %lu mbp->sector: %lu, %p, page: %p finished\n", 
            old_sector, bio_sector, mbp->sector, mbp, mbp->page);
    return true; 
}



bool flush_mb_bio(struct meta_bitmap* mb, struct meta_bitmap_page* mbp, 
                  sector_t bio_sector, int read)
{
    struct bio* bi;
    struct mddev *mddev;
    unsigned int *cache;
    int i;
    bool re;

    if(mb == NULL || mbp == NULL || mbp->page == NULL ||
       ((mddev = mb->mddev) == NULL) ||
       (bi = bio_alloc(GFP_NOIO, 2)) == NULL)
    {
        mb_info("NULL SHOWS UP\n");
        return false;
    }

    mb_info("submit bio sector: %lu, type: %d, mbp: %p, page: %p\n", 
            bio_sector, read, mbp, mbp->page);
	bi->bi_iter.bi_sector = bio_sector;

    if(spin_is_locked(&mbp->read_lock)/* && read == MB_WRITE */)
    {
        //mb_err("read is locked %lu %p\n", mb->sector, page_address(mb->page));
        wait_event(mb->wait_for_read_finish, !spin_is_locked(&mbp->read_lock));
    }

    if(!spin_is_locked(&mbp->write_lock))
    {
        spin_lock(&mbp->write_lock);
        mb_info("lock write_lock %lu, mbp: %p, page: %p\n", 
                mbp->sector, mbp, mbp->page);
    }

    if(read == MB_READ){
        mb_info("read_request\n");
        bi->bi_rw = READ;
    }
    else if(read == MB_WRITE)
    {
        bi->bi_rw = WRITE;
#ifdef MB_PRINT_PAGES
        mb_info("before flush_mb_bio:\n");
        mb_info("bio sector: %lu, page address: %p\n", 
                bi->bi_iter.bi_sector, page_address(mbp->page));
        cache = page_address(mbp->page);
        for(i = 0; i < 1024; i++)
            mb_info("i = %d,(%p) cache: %u\n", i, &cache[i], cache[i]);
#endif
    }
    else
    {
        mb_err("strange read/write state %d\n", read);
        re = false;
        goto flush_mb_bio_finish;
    }

    bio_add_page(bi, mbp->page, PAGE_SIZE, 0);
#ifdef MB_BIO_USE_MDDEV
    bi->bi_private = mbp;
    bi->bi_end_io = flush_mb_bio_endio;
    mbp->bio_finished = false;
        mb_set_bi_stripes(bi, 1);
        mddev->pers->make_request(mddev, bi);
    mb_info("before_to_wait\n");
    wait_event(mb->wait_for_raid5_bio_finish, mbp->bio_finished == true);
    mb_info("after_to_wait\n");
#else
    bi->bi_bdev = mb->bd;
    if(bi->bi_bdev == NULL)
    {
        mb_err("bi->bi_bdev is NULL(%p)\n", bi->bi_bdev);
        re = false;
        goto flush_mb_bio_finish;
    }
    submit_bio_wait(bi->bi_rw, bi);
#endif
    re = true;
flush_mb_bio_finish:
    spin_unlock(&mbp->read_lock);
    spin_unlock(&mbp->write_lock);
    atomic_set(&mbp->handling, 0);
    wake_up(&mb->wait_for_read_finish);
    wake_up(&mb->wait_for_write_finish);
    if(read == MB_WRITE)
        mb_info("write mbp %lu %p page %p ok and unlock read & write lock\n", 
                 bio_sector, mbp, mbp->page);
    else
    {
        mb_info("read mbp %lu %p page %p ok and unlock read & write lock\n", 
                 bio_sector, mbp, mbp->page);
#ifdef MB_PRINT_PAGES
        mb_info("read conten:\n");
        cache = page_address(mbp->page);
        for(i = 0; i < 1024; i++)
            mb_info("i = %d,(%p) cache: %u\n", i, &cache[i], cache[i]);
#endif
    }
    return re;
}



struct meta_bitmap_page* load_mb_page(struct meta_bitmap* mb, 
                                     sector_t sector)
{
    struct meta_bitmap_page* mbp = NULL, *temp = NULL;
    struct page* page = NULL;
    int hash;
    unsigned int min_times = -1;
    sector_t mb_old_sector;
    
    if(mb == NULL)
    {
        mb_err("No valid meta_bitmap or handling_page\n");
        return NULL;
    }

    hash = MB_HASH(sector);
    mb_info("sector: %lu, hash: %d\n", sector, hash);

    if (mb->allocated_pages[hash] < mb->max_pages)
    {
        mbp = kmalloc(sizeof(struct meta_bitmap_page), GFP_KERNEL);
        memset(mbp, 0, (sizeof(struct meta_bitmap_page)));
        if(!mbp)
            goto substitution;

        page = alloc_page(GFP_KERNEL);
        if(!page)
        {
            mb_info("alloc page failed\n");
            kfree(mbp);
            goto substitution;
        }

        // add page to lru list
        mbp->page = page;
        mbp->sector = sector;
        mbp->mb = mb;
        mbp->times = 1;
        spin_lock_init(&mbp->read_lock);
        spin_lock_init(&mbp->write_lock);
        atomic_set(&mbp->handling, 0);

        spin_lock(&mb->lru_lock);
        hlist_add_head(&mbp->lru, &mb->hash_list[hash]);
        mb->allocated_pages[hash]++;
        spin_unlock(&mb->lru_lock);
        mb_info("hash %d has page num: %d\n", 
                hash, mb->allocated_pages[hash]);

        if(flush_mb_bio(mb, mbp, sector, MB_READ) == false)
        {
            mb_err("flush_mb_bio %lu failed\n", sector);
            goto substitution;
        }
        mb_info("load bitmap page sector: mbp: %lu %p page: %p over\n", 
                sector, mbp, mbp->page);
    }
    else
    {
substitution:
        spin_lock(&mb->lru_lock);
        if(NULL == page && !hlist_empty(&mb->hash_list[hash]))
        {
            hlist_for_each_entry(temp, &mb->hash_list[hash], lru)
            {
                if(temp->sector == sector)
                {
                    spin_unlock(&mb->lru_lock);
                    return temp;
                }
                if(temp->times < min_times && 
                   !spin_is_locked(&temp->write_lock) && 
                   !spin_is_locked(&temp->read_lock))
                {
                    mbp = temp;
                    min_times = temp->times;
                }
            }
            spin_unlock(&mb->lru_lock);

            if(mbp == NULL || mbp->page == NULL || min_times == -1)
            {
                mb_info("find a page for %lu, all page locked! \
                        wait for one can be used!\n", sector);
                return NULL;
                mdelay(10);
                goto substitution;
            }

            atomic_set(&mbp->handling, 0);
            mb_old_sector = mbp->sector;
            mb_info("substitution: download page: %lu, load page %lu, %p, page: %p\n", 
                    mb_old_sector, sector, mbp, mbp->page);

            if(mb_substitution_page(mb, mbp, sector) == false)
            {
                mb_err("substitution %lu to %lu %p page: %p failed\n", 
                       mb_old_sector, sector, mbp, mbp->page);
                goto substitution;
            }
            page = mbp->page;
        }
        else
        {
            spin_unlock(&mb->lru_lock);
            return NULL;
        }
    }
    mb_info("load bitmap page sector: %lu mbp: %p, page: %p over\n", sector, mbp, mbp->page);
    return mbp;
}


struct meta_bitmap_page* find_mb_page(struct meta_bitmap* mb, sector_t sector)
{
    struct meta_bitmap_page* mbp = NULL;
    bool at_head = true;

    // find page in cache
    mb_info("find page in cache sector: %lu, hash: %d\n", 
            sector, MB_HASH(sector));
    spin_lock(&mb->lru_lock);
    hlist_for_each_entry(mbp, &mb->hash_list[MB_HASH(sector)], lru)
    {
        if(mbp->sector == sector)
        {
            mbp->times++;
            if(!at_head)
            {
                hlist_del_init(&mbp->lru);
                hlist_add_head(&mbp->lru, &mb->hash_list[MB_HASH(sector)]);
            }
            break;
        }
        at_head = false;
    }
    spin_unlock(&mb->lru_lock);
    return mbp;
}



void change_bitmap_func(struct meta_bitmap *mb, sector_t sector, 
                        int bitmap_type, int change)
{
    struct meta_bitmap_page *mbp = NULL;
    sector_t th, page_th, page_sector, offset;
    unsigned int *bitmap_cache;
    bool re, retryed;
    
    // 1. find page the sector belongs to
    if(bitmap_type == WRITTEN_BITMAP) 
    {
        th = sector >> BLOCK_TH_SHIFT; 
        page_th = th >> BIT_PER_PAGE_SHIFT;
        page_sector = mb->written_begin_sector + 
                      (page_th << PAGE_SECTOR_SHIFT);
        offset = th & BM_PAGE_SHIFT;
    }
    else if(bitmap_type == DYNAMIC_BITMAP)
    {
        th = sector >> SHMETA_TH_SHIFT;
        page_th = th >> BIT_PER_PAGE_SHIFT;
        page_sector = mb->dynamic_begin_sector + 
                      (page_th << PAGE_SECTOR_SHIFT);
        offset = th & BM_PAGE_SHIFT;   
    }
    ////////meggie
    else if(bitmap_type == DEV_BITMAP)
    {
        th = sector >> SHMETA_TH_SHIFT;
        page_th = th >> BIT_PER_PAGE_SHIFT;
        page_sector = mb->dev_begin_sector + 
                      (page_th << PAGE_SECTOR_SHIFT);
        offset = th & BM_PAGE_SHIFT;   
    }
    ////////meggie
    else
    {
        mb_err("a strange type shows\n");
        return;
    }

    if(bitmap_type == DYNAMIC_BITMAP)
        mb_info("sector:%lu, page_sector: %lu, offset: %d, \
                DYNAMIC, change: %d", 
                    (unsigned long long)sector, 
                    (unsigned long long)page_sector, 
                    offset, 
                    change);
    ////////meggie
    else if(bitmap_type == DEV_BITMAP)
        mb_info("sector:%lu, page_sector: %lu, offset: %d, \
                    DEV, change: %d", 
                    (unsigned long long)sector, 
                    (unsigned long long)page_sector, 
                    offset, 
                    change);
    ////////meggie
    else
        mb_info("sector:%lu, page_sector: %lu, offset: %d, \
                    WRITTEN, change: %d", 
                    (unsigned long long)sector, 
                    (unsigned long long)page_sector, 
                    offset, 
                    change);
        
    retryed = false;
retry_change_bitmap:  
    if((mbp = find_mb_page(mb, page_sector)) == NULL) 
    {
        if((mbp = load_mb_page(mb, page_sector)) == NULL)
        {
            if(!retryed)
            {
                mb_err("page %lu load failed and retry\n",
                      page_sector);
                mdelay(10);
                goto retry_change_bitmap;
            }
            else
            {
                mb_err("page %lu retryed twice failed both\n",
                        page_sector);
                return;
            }
        }
    }

    if(mbp == NULL || mbp->page == NULL)
    {
        mb_err("mbp(page_sector: %lu) NULL\n", page_sector);
        goto retry_change_bitmap;
    }
   
    if(spin_is_locked(&mbp->read_lock))
    {
        mb_info("wait read finish mbp: %lu, %p, page: %p\n", 
                mbp->sector, mbp, mbp->page);
        wait_event(mb->wait_for_read_finish, 
                   !spin_is_locked(&mbp->read_lock));
    }
    if(spin_is_locked(&mbp->write_lock))
    {
        mb_info("wait for write handling, mbp: %lu, %p, page: %p\n", 
                mbp->sector, mbp, mbp->page);
        wait_event(mb->wait_for_write_finish, 
                   !spin_is_locked(&mbp->write_lock));
        mb_info("wake up, mbp: %lu, %p, page: %lu\n", 
                mbp->sector, mbp, mbp->page);
        goto retry_change_bitmap;
    }
    if(mbp->sector != page_sector)
        goto retry_change_bitmap;

    spin_lock(&mbp->write_lock);
    mb_info("lock write_lock mbp: %lu, %p, page: %p\n", 
            mbp->sector, mbp, mbp->page);
    bitmap_cache = page_address(mbp->page);
    re = bitmap_cache[offset >> INT_SHIFT] & (1<<(offset & INT_MASK));
    if(change == CLEAR)
    {
        if(!re)
            mb_info("bit is 0 and will clear(%lu): bitmap: %d, mbp: %lu, %p, page: %p\n", 
                    sector, bitmap_type, mbp->sector, mbp, mbp->page);
        bitmap_cache[offset >> INT_SHIFT] &= ~(1<<(offset & INT_MASK)); 
    }
    else if(change == SET)
    {
        if(re)
            mb_info("bit is 1 and will set(%lu): bitmap: %d, mbp: %lu, %p, page: %p\n", 
                    sector, bitmap_type, mbp->sector, mbp, mbp->page);
        bitmap_cache[offset >> INT_SHIFT] |= (1<<(offset & INT_MASK));
    }
    spin_unlock(&mbp->write_lock);
    spin_unlock(&mbp->read_lock);
    atomic_set(&mbp->handling, 0);
		
    wake_up(&mb->wait_for_write_finish);
    wake_up(&mb->wait_for_changing_queue);
    return;
}


static void change_bitmap_thread(struct md_thread* thread)
{
    struct mddev* mddev;
    struct r5meta* meta;
    struct cache_tree_data* ctd;
    struct modify_bitmap_meta* mbm;
    struct meta_bitmap* mb;
    struct handling_page* hp;
    sector_t sector;
    int bitmap_type, change;
    unsigned int * bitmap_cache;
    sector_t th, page_th, page_sector;
    unsigned int offset;
    struct meta_bitmap_page* mbp;
    bool retryed = false, re;

    if(!thread ||
       (mddev = thread->mddev) == NULL ||
       (ctd = mddev->ctd) == NULL ||
       (meta = ctd->cache_r5meta) == NULL ||
       (mb = meta->bitmap) == NULL)
    {
        mb_err("para NULL\n");
        return;
    }

    mb_info("start\n");
    spin_lock(&mb->mbm_lock);
    while(!list_empty_careful(&mb->mbm_list))
    {
        mbm = list_last_entry(&mb->mbm_list, 
                               struct modify_bitmap_meta, lru); 
        spin_unlock(&mb->mbm_lock);
        
        offset = 0;    
        sector = mbm->sector;
        bitmap_type = mbm->bitmap_type;
        change = mbm->change;

        if(bitmap_type == WRITTEN_BITMAP && change == SET)
            mb_info("set WRITTEN_BITMAP sector: %lu\n", sector);
        else if(bitmap_type == DYNAMIC_BITMAP && change == SET)
            mb_info("set DYNAMIC_BITMAP sector: %lu\n", sector);
        else if(bitmap_type == WRITTEN_BITMAP && change == CLEAR)
            mb_info("clear WRITTEN_BITMAP sector: %lu\n", sector);
        ///////meggie
        else if(bitmap_type==DEV_BITMAP && change == SET)
            mb_info("set DEV_BITMAP sector: %lu\n", sector);
        ////////meggie
        else if(bitmap_type == DYNAMIC_BITMAP && change == CLEAR)
            mb_info("clear DYNAMIC_BITMAP sector: %lu\n", sector);
        ///////meggie
        else if(bitmap_type==DEV_BITMAP && change == CLEAR)
            mb_info("clear DEV_BITMAP sector: %lu\n", sector);
        //////meggie

        // 1. find page the sector belongs to
        if(bitmap_type == WRITTEN_BITMAP)
        {
            th = sector >> BLOCK_TH_SHIFT; 
            page_th = th >> BIT_PER_PAGE_SHIFT;
            page_sector = mb->written_begin_sector + 
                          (page_th << PAGE_SECTOR_SHIFT);
            offset = th & BM_PAGE_SHIFT;
        }
        else if(bitmap_type == DYNAMIC_BITMAP)
        {
            th = sector >> SHMETA_TH_SHIFT;
            page_th = th >> BIT_PER_PAGE_SHIFT;
            page_sector = mb->dynamic_begin_sector + 
                          (page_th << PAGE_SECTOR_SHIFT);
            offset = th & BM_PAGE_SHIFT;   
        }
        ////////meggie
        else if(bitmap_type == DEV_BITMAP)
        {
            th = sector >> SHMETA_TH_SHIFT;
            page_th = th >> BIT_PER_PAGE_SHIFT;
            page_sector = mb->dev_begin_sector + 
                          (page_th << PAGE_SECTOR_SHIFT);
            offset = th & BM_PAGE_SHIFT;   
        }
        ////////meggie
        else
        {
            mb_err("a strange type shows\n");
            spin_lock(&mb->mbm_lock);
			list_del_init(&mbm->lru);
            continue;
        }

        if(bitmap_type == DYNAMIC_BITMAP)
            mb_info("sector:%lu, page_sector: %lu, offset: %d, \
                    DYNAMIC, change: %d", 
                        (unsigned long long)sector, 
                        (unsigned long long)page_sector, 
                        offset, 
                        mbm->change);
        ////////meggie
        else if(bitmap_type == DEV_BITMAP)
            mb_info("sector:%lu, page_sector: %lu, offset: %d, \
                        DEV, change: %d", 
                        (unsigned long long)sector, 
                        (unsigned long long)page_sector, 
                        offset, 
                        mbm->change);
        ////////meggie
        else
            mb_info("sector:%lu, page_sector: %lu, offset: %d, \
                        WRITTEN, change: %d", 
                        (unsigned long long)sector, 
                        (unsigned long long)page_sector, 
                        offset, 
                        mbm->change);
            
        retryed = false;
retry_change_bitmap:  
        if((mbp = find_mb_page(mb, page_sector)) == NULL) 
        {
            if((mbp = load_mb_page(mb, page_sector)) == NULL)
            {
                if(!retryed)
                {
                    mb_err("page %lu load failed and retry\n",
                          page_sector);
                    mdelay(10);
                    goto retry_change_bitmap;
                }
                else
                {
                    mb_err("page %lu retryed twice failed both\n",
                          page_sector);
                    spin_lock(&mb->mbm_lock);
					list_del_init(&mbm->lru);
                    continue;
                }
            }
        }

        if(mbp == NULL || mbp->page == NULL)
        {
            mb_err("mbp(page_sector: %lu) NULL\n", page_sector);
            goto retry_change_bitmap;
            continue;
            return false;
        }
   
        if(spin_is_locked(&mbp->read_lock))
        {
            mb_info("wait read finish mbp: %lu, %p, page: %p\n", 
                    mbp->sector, mbp, mbp->page);
            wait_event(mb->wait_for_read_finish, 
                       !spin_is_locked(&mbp->read_lock));
        }
        if(spin_is_locked(&mbp->write_lock))
        {
            mb_info("wait for write handling, mbp: %lu, %p, page: %p\n", 
                    mbp->sector, mbp, mbp->page);
            wait_event(mb->wait_for_write_finish, 
                       !spin_is_locked(&mbp->write_lock));
            mb_info("wake up, mbp: %lu, %p, page: %lu\n", 
                    mbp->sector, mbp, mbp->page);
            goto retry_change_bitmap;
        }
        if(mbp->sector != page_sector)
            goto retry_change_bitmap;

        spin_lock(&mbp->write_lock);
        mb_info("lock write_lock mbp: %lu, %p, page: %p\n", 
                mbp->sector, mbp, mbp->page);
        bitmap_cache = page_address(mbp->page);
        re = bitmap_cache[offset >> INT_SHIFT] & (1<<(offset & INT_MASK));
        if(change == CLEAR)
        {
            if(!re)
                mb_err("bit is 0 and will clear(%lu): bitmap: %d, mbp: %lu, %p, page: %p\n", 
                        sector, bitmap_type, mbp->sector, mbp, mbp->page);
            bitmap_cache[offset >> INT_SHIFT] &= ~(1<<(offset & INT_MASK)); 
        }
        else if(change == SET)
        {
            if(re)
                mb_err("bit is 1 and will set(%lu): bitmap: %d, mbp: %lu, %p, page: %p\n", 
                        sector, bitmap_type, mbp->sector, mbp, mbp->page);
            bitmap_cache[offset >> INT_SHIFT] |= (1<<(offset & INT_MASK));
        }
        spin_unlock(&mbp->write_lock);
        spin_unlock(&mbp->read_lock);
        atomic_set(&mbp->handling, 0);
		
		spin_lock(&mb->mbm_lock);
		list_del_init(&mbm->lru);
        kfree(mbm);
        wake_up(&mb->wait_for_write_finish);
        wake_up(&mb->wait_for_changing_queue);
    }
    spin_unlock(&mb->mbm_lock);
    wake_up(&mb->wait_for_write_finish);
    wake_up(&mb->wait_for_changing_queue);
    return 0;
}




void change_bitmap(struct meta_bitmap* mb, sector_t sector, 
                   int bitmap_type, int change)
{
    /*
    struct modify_bitmap_meta *mbm = kmalloc(sizeof(struct modify_bitmap_meta),
                                    GFP_KERNEL);
    memset(mbm, 0, (sizeof(struct modify_bitmap_meta)));
    */
    if(bitmap_type == WRITTEN_BITMAP && change == SET)
        mb_info("set WRITTEN_BITMAP sector: %lu\n", sector);
    else if(bitmap_type == WRITTEN_BITMAP && change == CLEAR)
        mb_info("clear WRITTEN_BITMAP sector: %lu\n", sector);
    else if(bitmap_type == DYNAMIC_BITMAP && change == SET)
    {
        dynamics++;
        mb_info("set DYNAMIC_BITMAP sector: %lu, dynamics: %d\n", 
                sector, dynamics);
    }
    else if(bitmap_type == DYNAMIC_BITMAP && change == CLEAR)
    {
        dynamics--;
        mb_info("clear DYNAMIC_BITMAP sector: %lu, dynamics: %d\n", 
                sector, dynamics);
    }
    ////////meggie
    else if(bitmap_type == DEV_BITMAP && change == SET)
        mb_info("set DEV_BITMAP sector: %lu\n", sector);
    else if(bitmap_type == DEV_BITMAP && change == CLEAR)
        mb_info("clear DEV_BITMAP sector: %lu\n", sector);
    ////////meggie
   
    /*
    mbm->mb = mb;
    mbm->sector = sector;
    mbm->bitmap_type = bitmap_type;
    mbm->change = change; 
    */

    change_bitmap_func(mb, sector, bitmap_type, change);
    /*
    spin_lock(&mb->mbm_lock);
    list_add(&mbm->lru, &mb->mbm_list);
    spin_unlock(&mb->mbm_lock);
    md_wakeup_thread(mb->change_thread);
    */
    return;
}
EXPORT_SYMBOL(change_bitmap);

bool check_and_set_bitmap(struct meta_bitmap* mb, sector_t sector,
                  int bitmap_type)
{
    sector_t th, page_th, page_sector = 0;
    unsigned int offset = 0;
    struct meta_bitmap_page* mbp;
    struct handling_page* hp;
    unsigned int * bitmap_cache;
    bool re, retryed = false;
    
    // 1. find page the sector belongs to
    if(bitmap_type == WRITTEN_BITMAP)
    {
        th = sector >> BLOCK_TH_SHIFT; 
        page_th = th >> BIT_PER_PAGE_SHIFT;
        page_sector = mb->written_begin_sector + 
                      (page_th << PAGE_SECTOR_SHIFT);
        offset = th & BM_PAGE_SHIFT;    
        
        mb_info("WRITTEN BITMAP: sector:%lu, page_sector: %lu,\
                offset: %d\n", sector, page_sector, offset);
    }
    else if(bitmap_type == DYNAMIC_BITMAP)
    {
        th = sector >> SHMETA_TH_SHIFT;
        page_th = th >> BIT_PER_PAGE_SHIFT;
        page_sector = mb->dynamic_begin_sector + 
                      (page_th << PAGE_SECTOR_SHIFT);
        offset = th & BM_PAGE_SHIFT;
        
        mb_info("DYNAMIC BITMAP: sector:%lu, page_sector: %lu,\
                offset: %d\n", sector, page_sector, offset);
    }
    ////////meggie
    else if(bitmap_type == DEV_BITMAP)
    {
        th = sector >> SHMETA_TH_SHIFT; 
        page_th = th >> BIT_PER_PAGE_SHIFT;
        page_sector = mb->dev_begin_sector + 
                      (page_th << PAGE_SECTOR_SHIFT);
        offset = th & BM_PAGE_SHIFT;    
        
        mb_info("DEV BITMAP: sector:%lu, page_sector: %lu,\
                offset: %d\n", 
                sector, 
                page_sector, 
                offset);
    }
    ////////meggie
    else
    {
        mb_err("a strange type shows\n");
        return false;
    }

    // find page or load page
retry_check_and_set_bitmap:
    if((mbp = find_mb_page(mb, page_sector)) == NULL) 
    {
        mb_info("page %lu I need handle this by myself\n", 
               page_sector);
        mbp = load_mb_page(mb, page_sector);
        if(mbp == NULL && !retryed)
        {
            if(!retryed)
            {
                mb_err("page %lu need retry\n", page_sector);
                mdelay(10);
                retryed = true;
                goto retry_check_and_set_bitmap;
            }
            else
            {
                mb_err("load page %lu failed twice\n",
                      page_sector);
                return false;
            }
        }
    }
    if(mbp == NULL)
    {
        mb_err("mbp(page_sector: %lu) NULL\n", page_sector);
        return false;
    }
    else if(mbp->page == NULL)
    {
         mb_err("mbp(page_sector: %lu)->page(p %p) NULL\n",
              page_sector, mbp->page);
        return false;
    }

    if(spin_is_locked(&mbp->write_lock))
    {
        mb_info("wait for write handling, mbp: %lu %p, page: %p\n", 
                mbp->sector, mbp, mbp->page);
        wait_event(mb->wait_for_write_finish, 
                   !spin_is_locked(&mbp->write_lock));
        mb_info("wake up, mbp: %lu %p, page: %lu\n", mbp->sector, mbp, mbp->page);
    }
    if(mbp->sector != page_sector)
        goto retry_check_and_set_bitmap;

    if(!spin_is_locked(&mbp->read_lock))
    {
        spin_lock(&mbp->read_lock);
        atomic_set(&mbp->handling, 0);
        mb_info("lock read_lock for mbp %lu, %p, page: %p\n",
               mbp->sector, mbp, mbp->page);
    }
    atomic_inc(&mbp->handling); 
    bitmap_cache = page_address(mbp->page);
    /*
    mb_info("offset >> INT_SHIFT: %d", offset >> INT_SHIFT);
    mb_info("bitmap_cache: %d", bitmap_cache[offset >> INT_SHIFT]);
    mb_info("MASK: %d", 1<<(offset & INT_MASK));
    */
    re = bitmap_cache[offset >> INT_SHIFT] & (1<<(offset & INT_MASK)); 
    bitmap_cache[offset >> INT_SHIFT] |= (1<<(offset & INT_MASK));
    /*
    mb_info("bitmap_cache: %d", bitmap_cache[offset >> INT_SHIFT]);
    mb_info("MASK: %d", 1<<(offset & INT_MASK));
    */
    mb_info("CHECK BIEMAP FINISH sector:%lu, page_sector: %lu,\
            offset: %d, dynamic: %d\n", sector, page_sector, offset, re);
    atomic_dec(&mbp->handling);
    if(atomic_read(&mbp->handling) == 0)
    {
        spin_unlock(&mbp->read_lock);
        wake_up(&mb->wait_for_read_finish);
        mb_info("unlock read lock for mbp: %lu %p, page: %p\n",
                mbp->sector, mbp, mbp->page);
    }
    return re;
}


bool check_bitmap(struct meta_bitmap* mb, sector_t sector,
                  int bitmap_type)
{
    sector_t th, page_th, page_sector = 0;
    unsigned int offset = 0;
    struct meta_bitmap_page* mbp;
    struct handling_page* hp;
    unsigned int *bitmap_cache;
    bool re, retryed = false;
    struct modify_bitmap_meta *mbm = NULL;

    /*
    spin_lock(&mb->mbm_lock);
    if(!list_empty_careful(&mb->mbm_list))
    {
        list_for_each_entry(mbm, &mb->mbm_list, lru)
        {
            if(mbm->sector == sector && mbm->bitmap_type == bitmap_type)
            {
                mb_info("meta_bitmap is waiting to handling\n");
                if(mbm->change == SET)
                {
                    spin_unlock(&mb->mbm_lock);
                    return true;
                }
                else if(mbm->change == CLEAR)
                {
                    spin_unlock(&mb->mbm_lock);
                    return false;
                }
            }
        }
    }
    spin_unlock(&mb->mbm_lock);
    */

    // 1. find page the sector belongs to
    if(bitmap_type == WRITTEN_BITMAP)
    {
        th = sector >> BLOCK_TH_SHIFT; 
        page_th = th >> BIT_PER_PAGE_SHIFT;
        page_sector = mb->written_begin_sector + 
                      (page_th << PAGE_SECTOR_SHIFT);
        offset = th & BM_PAGE_SHIFT;    
        
        mb_info("WRITTEN BITMAP: sector:%lu, page_sector: %lu,\
                offset: %d\n", sector, page_sector, offset);
    }
    else if(bitmap_type == DYNAMIC_BITMAP)
    {
        th = sector >> SHMETA_TH_SHIFT;
        page_th = th >> BIT_PER_PAGE_SHIFT;
        page_sector = mb->dynamic_begin_sector + 
                      (page_th << PAGE_SECTOR_SHIFT);
        offset = th & BM_PAGE_SHIFT;
        
        mb_info("DYNAMIC BITMAP: sector:%lu, page_sector: %lu,\
                offset: %d\n", sector, page_sector, offset);
    }
    ////////meggie
    else if(bitmap_type == DEV_BITMAP)
    {
        th = sector >> SHMETA_TH_SHIFT; 
        page_th = th >> BIT_PER_PAGE_SHIFT;
        page_sector = mb->dev_begin_sector + 
                      (page_th << PAGE_SECTOR_SHIFT);
        offset = th & BM_PAGE_SHIFT;    
        
        mb_info("DEV BITMAP: sector:%lu, page_sector: %lu,\
                offset: %d\n", 
                sector, 
                page_sector, 
                offset);
    }
    ////////meggie
    else
    {
        mb_err("a strange type shows\n");
        return false;
    }

    // find page or load page
retry_check_bitmap:
    if((mbp = find_mb_page(mb, page_sector)) == NULL) 
    {
        mb_info("page %lu I need handle this by myself\n", 
               page_sector);
        mbp = load_mb_page(mb, page_sector);
        if(mbp == NULL && !retryed)
        {
            if(!retryed)
            {
                mb_err("page %lu need retry\n", page_sector);
                mdelay(10);
                retryed = true;
                goto retry_check_bitmap;
            }
            else
            {
                mb_err("load page %lu failed twice\n",
                      page_sector);
                return false;
            }
        }
    }
    if(mbp == NULL)
    {
        mb_err("mbp(page_sector: %lu) NULL\n", page_sector);
        return false;
    }
    else if(mbp->page == NULL)
    {
         mb_err("mbp(page_sector: %lu)->page(p %p) NULL\n",
              page_sector, mbp->page);
        return false;
    }

    if(spin_is_locked(&mbp->write_lock))
    {
        mb_info("wait for write handling, mbp: %lu, %p, page: %p\n", 
                mbp->sector, mbp, mbp->page);
        wait_event(mb->wait_for_write_finish, 
                   !spin_is_locked(&mbp->write_lock));
        mb_info("wake up, mbp: %lu, %p, page: %p\n", 
                mbp->sector, mbp, mbp->page);
    }
    if(mbp->sector != page_sector)
        goto retry_check_bitmap;

    if(!spin_is_locked(&mbp->read_lock))
    {
        spin_lock(&mbp->read_lock);
        atomic_set(&mbp->handling, 0);
        mb_info("lock read_lock for mbp %lu, %p, page: %p\n",
               mbp->sector, mbp, mbp->page);
    }
    atomic_inc(&mbp->handling); 
    bitmap_cache = page_address(mbp->page);
    /*
    mb_info("offset >> INT_SHIFT: %d", offset >> INT_SHIFT);
    mb_info("bitmap_cache: %d", bitmap_cache[offset >> INT_SHIFT]);
    mb_info("MASK: %d", 1<<(offset & INT_MASK));
    */
    re = bitmap_cache[offset >> INT_SHIFT] & (1<<(offset & INT_MASK));
    //通过字节寻址，然后通过位运算改变单独bit位的值 
    /*
    mb_info("bitmap_cache: %d", bitmap_cache[offset >> INT_SHIFT]);
    mb_info("MASK: %d", 1<<(offset & INT_MASK));
    */
    mb_info("CHECK BIEMAP FINISH sector:%lu, page_sector: %lu,\
            offset: %d, dynamic: %d\n", sector, page_sector, offset, re);
    atomic_dec(&mbp->handling);
    if(atomic_read(&mbp->handling) == 0)
    {
        spin_unlock(&mbp->read_lock);
        wake_up(&mb->wait_for_read_finish);
        mb_info("unlock read lock for mbp: %lu %p, page: %p\n",
                mbp->sector, mbp, mbp->page);
    }
    return re;
}
EXPORT_SYMBOL(check_bitmap);




void print_meta_bitmap(struct meta_bitmap* mb)
{
    mb_info("************************************************\n");
    mb_info("max_pages: %d, shmetas: %u, dynamic_file_pages: %u,\
            written_file_pages: %u\n", 
            mb->max_pages, 
            mb->shmetas, 
            mb->dynamic_file_pages, 
            mb->written_file_pages);
    mb_info("dynamic_begin_sector: %lu, dynamic_end_sector: %lu,\
            written_begin_sector: %lu, written_end_sector: %lu\n", 
            mb->dynamic_begin_sector, 
            mb->dynamic_end_sector, 
            mb->written_begin_sector, 
            mb->written_end_sector);
    mb_info("************************************************\n");
    return;
}


///////////////////meggie
static void scan_dynamic_page_thread(struct md_thread *thread)
{
    struct mddev *mddev;
    struct r5meta* meta;
    struct cache_tree_data* ctd;
    struct meta_bitmap* mb;
    struct meta_bitmap_page *mbp;
    unsigned int *bitmap_cache;
    int i, page_th, th;
    bool type;
    sector_t stripe_sector, temp_sector;

    if(!thread ||
       (mddev = thread->mddev) == NULL ||
       (ctd = mddev->ctd) == NULL ||
       (meta = ctd->cache_r5meta) == NULL ||
       (mb = meta->bitmap) == NULL)
    {
        mb_err("para NULL\n");
        return;
    }

    spin_lock(&mb->dynamic_list_lock);
    while(!list_empty_careful(&mb->dynamic_page_list))
    {
        i = 0;
        mbp = list_first_entry(&mb->dynamic_page_list, struct meta_bitmap_page, dynamic_lru);
        list_del(&mbp->dynamic_lru);
        spin_unlock(&mb->dynamic_list_lock);
        mb_info("mbp->sector:%lu,mbp->page:%p\n", mbp->sector, mbp->page);
        if(mbp->page == NULL){
            mb_err("mbp->page == NULL\n");
            return;
        }
        bitmap_cache = page_address(mbp->page);
        while(i < BIT_PER_PAGE){
            struct stripe_unit *sunit;
#ifdef SUNIT_IN_POOL
            spin_lock(&mddev->stripe_unit_pool_lock);
            if(list_empty_careful(&mddev->stripe_unit_pool))
            {
                mb_info("stripe_unit_pool is empty\n");
                if(atomic_read(&mddev->allocated_stripe_units) < 4096)
                {
                    sunit = (struct stripe_unit *)kmalloc(sizeof(struct stripe_unit), GFP_KERNEL);
                    atomic_inc(&mddev->allocated_stripe_units);
                    memset(sunit, 0, sizeof(struct stripe_unit));
                    spin_unlock(&mddev->stripe_unit_pool_lock);
                    mb_info("allocated_stripe_units:%d\n", atomic_read(&mddev->allocated_stripe_units));
                }
                else{
                    mddev->wait_for_sunit_now = true;
                    spin_unlock(&mddev->stripe_unit_pool_lock);
                    mb_info("to_wakeup_thread\n");
                    md_wakeup_thread(mddev->rebuild_dynamic_thread);
                    md_wakeup_thread(mddev->rebuild_static_thread);
                    mb_info("insert_to_waitqueue\n");
                    wait_event(mddev->wait_for_stripe_unit, atomic_read(&mddev->stripe_unit_in_pool) > 16);
                    
                    mb_info("wake_up\n");

                    spin_lock(&mddev->stripe_unit_pool_lock);
                    sunit = list_first_entry(&mddev->stripe_unit_pool, struct stripe_unit, lru);
                    list_del_init(&sunit->lru);
                    atomic_dec(&mddev->stripe_unit_in_pool);
                    mb_info("now,stripe_unit_in_pool is %d\n", atomic_read(&mddev->stripe_unit_in_pool));
                    spin_unlock(&mddev->stripe_unit_pool_lock);
                    memset(sunit, 0, sizeof(struct stripe_unit));
                }
            }
            else{
                mb_info("stripe_unit_pool is_not empty\n");
                sunit = list_first_entry(&mddev->stripe_unit_pool, struct stripe_unit, lru);
                list_del_init(&sunit->lru);
                atomic_dec(&mddev->stripe_unit_in_pool);
                mb_info("now,stripe_unit_in_pool is %d\n", atomic_read(&mddev->stripe_unit_in_pool));
                spin_unlock(&mddev->stripe_unit_pool_lock);
                memset(sunit, 0, sizeof(struct stripe_unit));
            }
#else
            sunit = (struct stripe_unit *)kmalloc(sizeof(struct stripe_unit), GFP_KERNEL);
#endif

            INIT_LIST_HEAD(&sunit->lru);
            type = bitmap_cache[i >> INT_SHIFT] & (1 << (i & INT_MASK));
            temp_sector = mbp->sector - mb->dynamic_begin_sector;
            page_th = temp_sector >> PAGE_SECTOR_SHIFT;
            th = (page_th << BIT_PER_PAGE_SHIFT) + i;
            stripe_sector = th << SHMETA_TH_SHIFT;

            mb_info("check_bit:i:%d, temp_sector:%lu, page_th:%d, th: %d, stripe_sector:%lu\n",i, 
                temp_sector, page_th, th, stripe_sector);

            sunit->sector = stripe_sector;
            sunit->type = type;

            if(type){
                spin_lock(&mddev->stripe_dynamic_list_lock);
                list_add_tail(&sunit->lru, &mddev->stripe_dynamic_list);
                atomic_inc(&mddev->stripe_dynamic_count);
                spin_unlock(&mddev->stripe_dynamic_list_lock);
            }
            else{
                spin_lock(&mddev->stripe_static_list_lock);
                list_add_tail(&sunit->lru, &mddev->stripe_static_list);
                atomic_inc(&mddev->stripe_static_count);
                spin_unlock(&mddev->stripe_static_list_lock);
            }
            mb_info("stripe_dynamic_count:%d, stripe_static_count:%d, th:%d\n", 
                atomic_read(&mddev->stripe_dynamic_count), atomic_read(&mddev->stripe_static_count), th);
            mb_info("mddev->dev_sectors:%lu, mddev->dev_sectors >> 3 -1 = %d\n", 
                mddev->dev_sectors, ((mddev->dev_sectors >> 3) - 1));
            if(th >= ((mddev->dev_sectors >> 3) - 1)){
                mb_info(">=\n");
                break;
            }
            i++;
        }
        spin_unlock(&mbp->read_lock);
        wake_up(&mb->wait_for_read_finish);
        spin_lock(&mb->dynamic_list_lock);
    }
    mb_info("dynamic_page_list_is_empty_now\n");
    spin_unlock(&mb->dynamic_list_lock);
    md_wakeup_thread(mddev->rebuild_dynamic_thread);
    md_wakeup_thread(mddev->rebuild_static_thread);
    return;
}


void get_all_dynamic_pages(struct meta_bitmap *mb)
{
    int all_pages, i;
    sector_t page_sector;

    struct mddev *mddev = mb->mddev;

    
    all_pages = mb->dynamic_file_pages;

    i = 0;
    mb_info("all_pages:%d\n", all_pages);
    while(i< all_pages){
        struct meta_bitmap_page *mbp = NULL;
        page_sector = mb->dynamic_begin_sector + (i << PAGE_SECTOR_SHIFT);
        mb_info("i:%d, page_sector: %lu\n", i, page_sector);
        bool retryed = false;
retry_get_dynamic_page:
        if((mbp = find_mb_page(mb, page_sector)) == NULL)
        {
            mb_info("page %lu I need handle this by myself\n", 
                   page_sector);
            mbp = load_mb_page(mb, page_sector);
            if(mbp == NULL && !retryed)
            {
                if(!retryed)
                {
                    mb_err("page %lu need retry\n", page_sector);
                    mdelay(10);
                    retryed = true;
                }
                else
                {
                    mb_err("load_page %lu failed twice, cannot get dynamic pages\n", page_sector);
                    return;
                }  
            }
        }
        if(mbp == NULL)
        {
            mb_err("mbp(page_sector: %lu) NULL\n", page_sector);
            return;
        }
        else if(mbp->page == NULL)
        {
             mb_err("mbp(page_sector: %lu)->page(p %p) NULL\n",
                  page_sector, mbp->page);
            return;
        }
        if(mbp->sector != page_sector){
            mb_info("mbp->sector!=page_sector\n");
            goto retry_get_dynamic_page; 
        }
        if(spin_is_locked(&mbp->write_lock))
        {
            mb_info("wait for write handling, mbp: %lu, %p, page: %p\n", 
                    mbp->sector, mbp, mbp->page);
            wait_event(mb->wait_for_write_finish, 
                       !spin_is_locked(&mbp->write_lock));
            mb_info("wake up, mbp: %lu, %p, page: %p\n", 
                    mbp->sector, mbp, mbp->page);
        }
        if(!spin_is_locked(&mbp->read_lock))
        {
            spin_lock(&mbp->read_lock);
            atomic_set(&mbp->handling, 0);
            mb_info("lock read_lock for mbp %lu, %p, page: %p\n",
                   mbp->sector, mbp, mbp->page);
        }
        atomic_inc(&mbp->handling);
        spin_lock(&mb->dynamic_list_lock);
        list_add_tail(&mbp->dynamic_lru, &mb->dynamic_page_list);
        spin_unlock(&mb->dynamic_list_lock);
        i++;
    }
    md_wakeup_thread(mb->scan_dynamic_thread);
    mb_info("have_get_all_pages\n");
    return;
}
EXPORT_SYMBOL(get_all_dynamic_pages);
///////////////////meggie



// after flush all shmeta bitmap changes to bitmap pages
void meta_bitmap_stop(struct meta_bitmap* mb)
{
    struct meta_bitmap_page* mbp;
    int i;
    if(NULL == mb)
        return;
    mb_info("\n");

    if(check_flag(MB_CHANGING_BITMAP, &mb->flags))
    {
        mb_info("change_thread is running\n");
        wait_event(mb->wait_for_changing_queue,
                   !check_flag(MB_CHANGING_BITMAP, &mb->flags));
        mb_info("after change_thread finish\n");
    }

    if(NULL != mb->change_thread)
    {
        md_unregister_thread(&mb->change_thread); 
        mb_info("unregistered change_bitmap_thread\n");
    }
    // free mbps 
    spin_lock(&mb->lru_lock);
    for(i = 0; i < MB_HASH_SIZE; i++)
    {
        while(!hlist_empty(&mb->hash_list[i]))
        {
            mbp = hlist_entry((mb->hash_list[i].first), 
                              struct meta_bitmap_page, lru);
            hlist_del_init(&mbp->lru);
            if(mbp && NULL != mbp->page)
            {
                flush_mb_bio(mb, mbp, mbp->sector, MB_WRITE);
                mb_info("flush page %lu\n", mbp->sector);
                __free_page(mbp->page);
            }
            kfree(mbp);
        }
    }
    spin_unlock(&mb->lru_lock);
    kfree(mb);
    mb_info("stop meta bitmap over\n");
    return;
}


struct meta_bitmap* setup_meta_bitmap(struct r5meta* r5_meta, 
                                      int max_pages,
                                      sector_t begin_sector)
{
    struct meta_bitmap* mb = r5_meta->bitmap;
    struct mddev* mddev;
    struct cache_tree_data *ctd;
    int i, devnum;
    
    if(r5_meta == NULL ||
       (ctd = r5_meta->ctd) == NULL ||
       (mddev = ctd->mdd) == NULL ||
       (mb = r5_meta->bitmap) != NULL ||
       ((mb = kmalloc(sizeof(struct meta_bitmap), GFP_KERNEL))
            == NULL))
        return mb;

    memset(mb, 0, sizeof(struct meta_bitmap));
    mb->r5meta = r5_meta;
    mb->mddev = mddev;

#ifndef MB_BIO_USE_MDDEV
    /*mb->bd = blkdev_get_by_path("/dev/sdb9", 
             FMODE_READ | FMODE_WRITE, NULL);*/
    ////meggie
    rdev_for_each(rdev,mddev){
        if(rdev->raid_disk<0 && !test_bit(Faulty,&rdev->flags) && rdev->bdev){
              printk(KERN_INFO "now set a meta disk\n");
              mb->bd=rdev->bdev;
              set_bit(SPARE_META,&rdev->spare_flags);
              break;
        }
    }
    ///////meggie
    if(NULL == mb->bd || IS_ERR(mb->bd))
    {
        mb_err("mb->bd err\n");
        kfree(mb);
        return NULL;
    }
#endif
    devnum = r5_meta->devnum;
    mb->shmetas = mddev->dev_sectors >> MB_SHMETA_SHIFT; 
    mb_info("mddev->dev_sectors:%lu\n", mddev->dev_sectors);
    mb->dynamic_file_pages = (mb->shmetas >> BIT_PER_PAGE_SHIFT) + 1;
    mb->written_file_pages = mb->dynamic_file_pages * devnum;
    ///////meggie
    mb->dev_file_pages = mb->dynamic_file_pages; 
    ///////meggie

    mb_info("dynamic_file_pages:%d\n",mb->dynamic_file_pages);
    
    // max pages
    if(max_pages == 0)
        mb->max_pages = MB_MAX_PAGES;
    else 
        mb->max_pages = max_pages;

    // begin sector
    if(begin_sector == 0)
#ifdef MB_BIO_USE_MDDEV
        mb->dynamic_begin_sector = 0;
#else
        mb->dynamic_begin_sector = MB_BEGIN_SECTOR;
#endif
    else
        mb->dynamic_begin_sector = begin_sector;
    printk(KERN_INFO "bitmap begin_sector: %lu\n", begin_sector);

    mb->dynamic_end_sector = mb->dynamic_begin_sector + 
                             mb->dynamic_file_pages * SM_SECTORS;
    mb->written_begin_sector = mb->dynamic_end_sector;
    mb->written_end_sector = mb->written_begin_sector + 
                             mb->written_file_pages * SM_SECTORS;
    ///////meggie
    mb->dev_begin_sector =mb->written_end_sector;
    mb->dev_end_sector = mb->dev_begin_sector + mb->dev_file_pages * SM_SECTORS;
    ////////meggie
    // pages lru list
    for(i = 0; i < MB_HASH_SIZE; i++)
    {
        mb->hash_list[i].first = NULL;
        mb->allocated_pages[i] = 0;
    }

    spin_lock_init(&mb->lru_lock);

    INIT_LIST_HEAD(&mb->mbm_list);
    ////////////meggie
    INIT_LIST_HEAD(&mb->dynamic_page_list);
    ////////////meggie
    spin_lock_init(&mb->mbm_lock);

	init_waitqueue_head(&mb->wait_for_changing_queue);
	init_waitqueue_head(&mb->wait_for_read_finish);
	init_waitqueue_head(&mb->wait_for_write_finish);
	init_waitqueue_head(&mb->wait_for_raid5_bio_finish);

    mb->change_thread = md_register_thread(change_bitmap_thread, 
                                          mddev, "change_bitmap");
    ///////////////meggie
    mb->scan_dynamic_thread = md_register_thread(scan_dynamic_page_thread, mddev, "scan_thread");
    ///////////////meggie
    if(!mb->change_thread)
    {
        mb_err("change_thread alloc failed\n");
        kfree(mb);
        return NULL;
    }

    print_meta_bitmap(mb);
    r5_meta->bitmap = mb;
    return mb;
}

