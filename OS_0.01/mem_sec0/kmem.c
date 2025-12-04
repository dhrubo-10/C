#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/init.h>


#define KMEM_MIN_SIZE 8
#define KMEM_MAX_SIZE 4096
#define KMEM_BUCKETS 9 

struct kmem_cache {
	size_t size;               
	struct page *page_list;    
	spinlock_t lock;           
};

static struct kmem_cache kmem_caches[KMEM_BUCKETS];

static int kmem_bucket_for_size(size_t size)
{
	int i = 0;
	size_t s = KMEM_MIN_SIZE;

	while (s < size && i < KMEM_BUCKETS - 1) {
		s <<= 1;
		i++;
	}
	return i;
}

int __init kmem_init(void)
{
	size_t s = KMEM_MIN_SIZE;
	int i;

	for (i = 0; i < KMEM_BUCKETS; i++) {
		kmem_caches[i].size = s;
		kmem_caches[i].page_list = NULL;
		spin_lock_init(&kmem_caches[i].lock);
		s <<= 1;
	}

	pr_info("kmem: initialized %d caches (min %zu, max %zu)\n",
	        KMEM_BUCKETS, KMEM_MIN_SIZE, KMEM_MAX_SIZE);

	return 0;
}
EXPORT_SYMBOL(kmem_init);

void *kmalloc(size_t size, gfp_t flags)
{
	int bucket;
	void *ret = NULL;
	unsigned long lock_flags;
	struct page *p;

	if (!size || size > KMEM_MAX_SIZE)
		return NULL;

	bucket = kmem_bucket_for_size(size);

	/* Try to allocate from cache */
	spin_lock_irqsave(&kmem_caches[bucket].lock, lock_flags);
	if (kmem_caches[bucket].page_list) {
		p = kmem_caches[bucket].page_list;
		kmem_caches[bucket].page_list = p->next;
		ret = (void *)p; /* Use page memory directly */
	}
	spin_unlock_irqrestore(&kmem_caches[bucket].lock, lock_flags);

	/* Fallback to allocating a new page if cache is empty */
	if (!ret) {
		p = alloc_page(flags);
		if (!p)
			return NULL;
		ret = (void *)p;
	}

	return ret;
}
EXPORT_SYMBOL(kmalloc);

void kfree(const void *objp)
{
	struct page *p;

	if (!objp)
		return;

	p = (struct page *)objp;

	__free_page(p);
}
EXPORT_SYMBOL(kfree);
