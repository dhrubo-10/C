#include "include/mm/mem_map.h"
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/spinlock.h>


/* Minimal slab like allocator backed by page allocator. Not a full slub.
*/

#define KMEM_MIN_SIZE 8
#define KMEM_MAX_SIZE 4096
#define KMEM_BUCKETS 9 /* 8,16,32,...,4k */


struct kmem_cache {
size_t size;
struct page *page_list;
spinlock_t lock;
};


static struct kmem_cache kmem_caches[KMEM_BUCKETS];


static int kmem_bucket_for_size(size_t size)
{
size_t s = KMEM_MIN_SIZE;
int i = 0;
while (s < size && i < KMEM_BUCKETS) { s <<= 1; i++; }
return i;
}


int __init kmem_init(void)
{
int i;
size_t s = KMEM_MIN_SIZE;


for (i = 0; i < KMEM_BUCKETS; i++) {
kmem_caches[i].size = s;
kmem_caches[i].page_list = NULL;
spin_lock_init(&kmem_caches[i].lock);
s <<= 1;
}
return 0;
}
EXPORT_SYMBOL(kmem_init);


void *kmalloc(size_t size, gfp_t flags)
{
int b = kmem_bucket_for_size(size);
void *ret = NULL;
unsigned long flags;
struct page *p;


if (size == 0 || b >= KMEM_BUCKETS)
return NULL;


spin_lock_irqsave(&kmem_caches[b].lock, flags);
if (kmem_caches[b].page_list) {
p = kmem_caches[b].page_list;
kmem_caches[b].page_list = p->next;
ret = (void *)p; /* use page struct memory area */
}
spin_unlock_irqrestore(&kmem_caches[b].lock, flags);


if (!ret) {
p = alloc_page_zone(&system_meminfo.zones[0]);
if (!p)
return NULL;
ret = (void *)p;
}


return ret;
}
EXPORT_SYMBOL(kmalloc);


void kfree(const void *objp)
{
struct page *p = (struct page *)objp;
free_page_zone(&system_meminfo.zones[0], p);
}
EXPORT_SYMBOL(kfree);