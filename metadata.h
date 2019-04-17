/*************************************************************************
	> File Name: metadata.h
	> Author: 
	> Mail: 
	> Created Time: Mon 18 Sep 2017 04:31:35 PM CST
 ************************************************************************/

#ifndef _METADATA_H
#define _METADATA_H


#include "md_cache.h"
/* 
 * meta data:
 * sector + (lba + lso + lsb + psn) * data_devs
 * sector_t + (unsigned int * 3 + unsigned short) * data_devs
 * 
 * if data_devs = 3:
 * 64 + (32 * 3 + 16)*3 = 400b = 50B
 * a page can save 81 meta_data.
 *
 * for the page saves the begin stripe sectors for each meta_data page
 * a page can save (4096 / 8) = 512 pages' begin_stripe_sector
 *
 * here we just give 4 pages to save begin_stripe_sector for each hash value
 * so it can represent 2048 pages for each hash value
 * 0-3 = hash 1
 * ...
 * 28-31 = hash 7
 *
 * And we give 2048 pages for each hash 
 * 32 - 4159 = hash 1
 * ...
 * 28736 - 32832 = hash 7
 * so we can save 4096 * 81 = 331776 recombinated stripe metadata.
 *
 * the space after metadata for stripes saves the metadata for the recombinated stripe
 * which is static stripe first.
 */


#define REC_SM_RADIO            40
#define SNAP_BEGIN_SECTOR       6072
#define MTD_PAGE_SIZE           4096
#define MTD_HASH_SHIFT          7 // 3
#define SECTOR_T_SHIFT          3
#define PAGE_2_SECTOR_SHIFT     3


#define MTD_MAX_THREAD          16


#define MTD_READ 0
#define MTD_WRITE 1
#define MTD_SUBSTITUTION 2

/*
enum {
    MTD_SNAP1 = 0,
    MTD_SNAP2,
    MTD_META,
};
*/

enum {
    MTD_LOADING_HASH_META = 0,
    MTD_FLUSHING_HASH_META ,
    MTD_STOP,
    MTD_WAIT_HANDLE_BLANK_PAGE,
};

struct flush_task_unit {
    int hash;
    int *list_size;
    struct list_head* list;
    struct meta_data* mtd;
};


/*
struct stripe_metadata
{
    sector_t logic_sector;
    struct dev_data
    {
        sector_t lba;
        sector_t lso;
        sector_t lsb;
        short psn;
    }dev[1];
};
*/

/*
struct task_unit {
    bool snapshot;
    sector_t sector;
    int hash;
    struct meta_data* mtd;
    struct list_head lru;
    struct metadata_page* mdp;
};
*/


struct metadata_page{
    unsigned int times;
    bool bio_finished; 
    int hash;
    sector_t sector;
    struct hlist_node lru;
    spinlock_t read_lock;
    spinlock_t write_lock;
    atomic_t handling;
    struct meta_data* mtd;
    struct page *page;
};


/*
struct metadata_each_hash{
    int written_pages;
    int shmetas_in_last_page;
    sector_t begin_sector;
    sector_t total_shmetas;
    sector_t last_written_page_sector;
    sector_t snap1_sector;
    sector_t snap2_sector;
    int snap1s;
    sector_t snap2s;
    int snap0s;
};
*/


struct meta_data{
    void                *mddev;
    struct r5meta       *r5meta;
    struct block_device *bd;
    struct page         *meta_page;
    struct hlist_head   *metadata_lru;
    int                 *allocated_meta_page;

    bool                load_blank_page;
    unsigned short      flags;
    int                 rec_sm_radio;
    int                 meta_max_pages;
    int                 devnum;
    int                 metadata_size;
    int                 metadata_per_page;
    int                 metadata_page_each_hash;

    sector_t            shmetas;
    sector_t            dynamic_shmetas;
    sector_t            metadata_begin_sector;
    sector_t            metadata_end_sector;
    atomic_t            flush_flags;

    wait_queue_head_t   wait_for_pre_flush;
    wait_queue_head_t   wait_for_load_blank_page;
    wait_queue_head_t   wait_for_read_finish;
    wait_queue_head_t   wait_for_write_finish;
    wait_queue_head_t   wait_for_raid5_bio_finish;

    spinlock_t          metadata_lock;
    spinlock_t          meta_page_lock;


    spinlock_t          loading_sm_lock;
    atomic_t            loading_sm_count;
    struct  list_head   loading_sm;
}; 


extern struct meta_data* setup_metadata(struct r5meta* meta, 
            sector_t begin_sector,int rec_sm_radio, 
            struct block_device* bd);
extern void exit_metadata(struct meta_data* mtd);
extern bool load_shmeta_metadata(struct r5meta* meta, struct meta_data *mtd, void *data);
extern int flush_metadata_by_others(struct meta_data* mtd);
extern int handle_blank_sectors(struct meta_data* mtd, int read);
extern void change_metadata(struct meta_data* mtd, struct shmeta* sm, int hash);
extern void reset_metadata_zero(struct meta_data *mtd, sector_t sector, sector_t lba_align);
#endif
