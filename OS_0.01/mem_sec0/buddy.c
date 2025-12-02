#include "include/mm/mem_map.h"
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/spinlock.h>


/* 
 * Simple power of two buddy allocator for page blocks.
 */

#define BUDDY_MAX_ORDER 11 /* will support up to 2^11 pages contiguous blocks (~8MB if 4KB pages) */
/* enough for now */

struct free_area {
struct page *free_list;
unsigned long nr_free;
};


struct buddy_zone {
struct free_area free_area[BUDDY_MAX_ORDER];
spinlock_t lock;
unsigned long size_pages;
};


int buddy_init(struct buddy_zone *bz, unsigned long size_pages)
{
int i;


memset(bz, 0, sizeof(*bz));
spin_lock_init(&bz->lock);
bz->size_pages = size_pages;


/* initial single block at highest order covering entire zone if possible */
for (i = 0; i < BUDDY_MAX_ORDER; i++) {
bz->free_area[i].free_list = NULL;
bz->free_area[i].nr_free = 0;
}


/* put whole memory as order-high block if power-of-two; else split accordingly in caller */
return 0;
}
EXPORT_SYMBOL(buddy_init);


struct page *buddy_alloc(struct buddy_zone *bz, int order)
{
int i;
unsigned long flags;
struct page *p = NULL;


if (order >= BUDDY_MAX_ORDER)
return NULL;


spin_lock_irqsave(&bz->lock, flags);
for (i = order; i < BUDDY_MAX_ORDER; i++) {
if (bz->free_area[i].free_list) {
p = bz->free_area[i].free_list;
bz->free_area[i].free_list = p->next;
bz->free_area[i].nr_free--;
break;
}
}


if (!p) {
spin_unlock_irqrestore(&bz->lock, flags);
return NULL;
}


/* split until desired order */
while (i-- > order) {
struct page *buddy = p + (1UL << i);
buddy->next = bz->free_area[i].free_list;
bz->free_area[i].free_list = buddy;
bz->free_area[i].nr_free++;
}


atomic_set(&p->_refcount, 1);
spin_unlock_irqrestore(&bz->lock, flags);
return p;
}
EXPORT_SYMBOL(buddy_alloc);


void buddy_free(struct buddy_zone *bz, struct page *p, int order)
{
unsigned long flags;
	spin_lock_irqsave(&bz->lock, flags);

	p->next = bz->free_area[order].free_list;

	bz->free_area[order].free_list = p;

	bz->free_area[order].nr_free++;

	atomic_set(&p->_refcount, 0);

	spin_unlock_irqrestore(&bz->lock, flags);

}
EXPORT_SYMBOL(buddy_free);