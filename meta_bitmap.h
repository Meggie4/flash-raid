/*************************************************************************
	> File Name: meta_bitmap.h
	> Author: yms 
	> Mail: meow@meow.com
	> Created Time: Tue 18 Jul 2017 09:50:56 AM CST
 ************************************************************************/

#ifndef _META_BITMAP_H
#define _META_BITMAP_H

#include "md_cache.h"

#define BLOCK_TH_SHIFT      3
#define SHMETA_TH_SHIFT     3
#define MB_SHMETA_SHIFT     3
#define PAGE_SECTOR_SHIFT   3
#define BIT_PER_PAGE_SHIFT  (PAGE_SHIFT + 3)       // 15
#define BIT_PER_PAGE        (1 << BIT_PER_PAGE_SHIFT)  // 1 << 15

#define INT_MASK            0x1F
#define INT_SHIFT           5
#define MB_BEGIN_SECTOR     60000

#define BM_PAGE_SHIFT       0x7fff

#define SECTOR_SIZE         512
#define SECTOR_SHIFT        (PAGE_SHIFT - 3)            // 9

#define MB_HASH_SIZE        8
#define SM_SECTORS          8
enum {
    DYNAMIC_BITMAP = 0,
    WRITTEN_BITMAP,
    STATIC_2_DYNAMIC_BITMAP,
    BLANK_2_DYNAMIC_BITMAP,
    SET,
    CLEAR,
    MB_READ,
    MB_WRITE,
    /////meggie
    DEV_BITMAP,
    /////meggie
};


struct meta_bitmap_page{
    int times;
    sector_t sector;
    struct page *page;
    // struct list_head lru;
    struct hlist_node lru;
    ///////////////////meggie
    struct list_head dynamic_lru;
    /////////////////////meggie
    spinlock_t read_lock;
    spinlock_t write_lock;
    atomic_t handling; 
    struct meta_bitmap* mb;
    bool bio_finished;
};

struct modify_bitmap_meta {
    struct meta_bitmap* mb;
    sector_t sector;
    int bitmap_type;
    int change;
    struct list_head lru;
};


/*
struct handling_page {
    sector_t sector;
    struct list_head lru;
};
*/

enum {
    MB_CHANGING_BITMAP = 0,
    MB_CHANGED_BITMAP,
    MB_LOADING_BITMAP,
    MB_LOADED_BITMAP,
};


struct meta_bitmap{
    struct r5meta       *r5meta;
    void                *mddev;
    struct block_device *bd;
    struct md_thread    *change_thread;


    struct hlist_head   hash_list[MB_HASH_SIZE];
    struct list_head    mbm_list;

    unsigned short      flags;
    unsigned int        max_pages;
    unsigned int        dynamic_file_pages;
    unsigned int        written_file_pages;
    //////meggie
    unsigned int        dev_file_pages;
    struct list_head    dynamic_page_list;
    struct md_thread    *scan_dynamic_thread;
    spinlock_t          dynamic_list_lock;
    /////meggie
    unsigned int        allocated_pages[MB_HASH_SIZE];
    unsigned long long  shmetas;
    int                 *bitmap_cache;

    sector_t            written_begin_sector;
    sector_t            written_end_sector;
    sector_t            dynamic_begin_sector;
    sector_t            dynamic_end_sector;
    ///////meggie
    sector_t            dev_begin_sector;
    sector_t            dev_end_sector;
    //////meggie
    
    spinlock_t          lru_lock;
    spinlock_t          mbm_lock;

    wait_queue_head_t   wait_for_handle_queue;
    wait_queue_head_t   wait_for_changing_queue;
    wait_queue_head_t   wait_for_read_finish;
	wait_queue_head_t	wait_for_write_finish;
	wait_queue_head_t	wait_for_raid5_bio_finish;
};


extern struct meta_bitmap* setup_meta_bitmap(struct r5meta* meta, 
                            int max_pages, sector_t begin_sector);


extern void change_bitmap(struct meta_bitmap* mb, sector_t sector, 
                            int bitmap_type, int change);

extern bool check_bitmap(struct meta_bitmap* mb, sector_t sector, 
                            int bitmap_type);
extern bool check_and_set_bitmap(struct meta_bitmap* mb, sector_t sector, 
                            int bitmap_type);

extern void meta_bitmap_stop(struct meta_bitmap* mb);
extern void get_all_dynamic_pages(struct meta_bitmap *mb);
#endif
