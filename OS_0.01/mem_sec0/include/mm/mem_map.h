#ifndef _MM_MEM_MAP_H
#define _MM_MEM_MAP_H


#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/bitmap.h>


#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define PAGE_MASK (~(PAGE_SIZE - 1))


struct page {
unsigned long flags; /* page flags */
atomic_t _refcount;
unsigned long private; /* arch / allocator private */
unsigned long index; /* page index in zone */
struct page *next; /* freelist */
};


struct zone {
unsigned long start_pfn;
unsigned long size; /* in pages */
struct page *free_list;
spinlock_t lock;
unsigned long free_pages;
unsigned long *bitmap; /* optional */
};


struct meminfo {
struct zone *zones;
unsigned int nr_zones;
unsigned long totalram_pages;
};


extern struct meminfo system_meminfo;


static inline void page_ref_inc(struct page *p)
{
atomic_inc(&p->_refcount);
}


static inline void page_ref_dec(struct page *p)
{
atomic_dec(&p->_refcount);
}


#endif