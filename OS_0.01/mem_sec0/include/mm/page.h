#ifndef _MM_PAGE_H
#define _MM_PAGE_H


#include <linux/types.h>
#include <linux/atomic.h>
#include "mem_map.h"


static inline struct page *pfn_to_page(unsigned long pfn)
{
extern struct page *pfn_to_page_map; /* allocated by mem init */
return &pfn_to_page_map[pfn];
}


static inline unsigned long page_to_pfn(struct page *page)
{
return page->index;
}


#endif