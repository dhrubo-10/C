#include "include/mm/mem_map.h"
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/errno.h>


struct page *pfn_to_page_map;
struct meminfo system_meminfo;


int __init mem_init(unsigned long start_pfn, unsigned long nr_pages)
{
unsigned long i;


system_meminfo.nr_zones = 1;
system_meminfo.zones = kzalloc(sizeof(struct zone), GFP_KERNEL);
if (!system_meminfo.zones)
return -ENOMEM;


system_meminfo.totalram_pages = nr_pages;


system_meminfo.zones[0].start_pfn = start_pfn;
system_meminfo.zones[0].size = nr_pages;
spin_lock_init(&system_meminfo.zones[0].lock);
system_meminfo.zones[0].free_pages = nr_pages;


pfn_to_page_map = kzalloc(nr_pages * sizeof(struct page), GFP_KERNEL);
if (!pfn_to_page_map)
return -ENOMEM;


for (i = 0; i < nr_pages; i++) {
pfn_to_page_map[i].index = i + start_pfn;
atomic_set(&pfn_to_page_map[i]._refcount, 0);
pfn_to_page_map[i].flags = 0;
pfn_to_page_map[i].next = (i + 1 < nr_pages) ? &pfn_to_page_map[i+1] : NULL;
}


system_meminfo.zones[0].free_list = &pfn_to_page_map[0];


return 0;
}
EXPORT_SYMBOL(mem_init);


struct page *alloc_page_zone(struct zone *z)
{
struct page *p = NULL;
unsigned long flags;


spin_lock_irqsave(&z->lock, flags);
if (z->free_list) {
p = z->free_list;
z->free_list = p->next;
p->next = NULL;
z->free_pages--;
atomic_set(&p->_refcount, 1);
}
spin_unlock_irqrestore(&z->lock, flags);
return p;
}
EXPORT_SYMBOL(alloc_page_zone);


void free_page_zone(struct zone *z, struct page *p)
{
unsigned long flags;


spin_lock_irqsave(&z->lock, flags);
p->next = z->free_list;
z->free_list = p;
atomic_set(&p->_refcount, 0);
z->free_pages++;
spin_unlock_irqrestore(&z->lock, flags);
}
EXPORT_SYMBOL(free_page_zone);