#include <linux/errno.h>
#include <linux/stddef.h>
#include <linux/slab.h>
#include <linux/export.h>
#include <linux/string.h>
#include <linux/relay.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/cpu.h>
#include <linux/splice.h>


static DEFINE_MUTEX(relay_channels_mutex);
static LIST_HEAD(relay_channels);

static vm_fault_t relay_buf_fault(struct vm_fault *vmf)
{
	struct page *page;
	struct rchan_buf *buf = vmf->vma->vm_private_data;
	pgoff_t pgoff = vmf->pgoff;

	if (!buf)
		return VM_FAULT_OOM;

	page = vmalloc_to_page(buf->start + (pgoff << PAGE_SHIFT));
	if (!page)
		return VM_FAULT_SIGBUS;
	get_page(page);
	vmf->page = page;

	return 0;
}

static void *relay_alloc_buf(struct rchan_buf *buf, size_t *size)
{
	void *mem;
	unsigned int i, j, n_pages;

	*size = PAGE_ALIGN(*size);
	n_pages = *size >> PAGE_SHIFT;

	buf->page_array = relay_alloc_page_array(n_pages);
	if (!buf->page_array)
		return NULL;

	for (i = 0; i < n_pages; i++) {
		buf->page_array[i] = alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (unlikely(!buf->page_array[i]))
			goto depopulate;
		set_page_private(buf->page_array[i], (unsigned long)buf);
	}
	mem = vmap(buf->page_array, n_pages, VM_MAP, PAGE_KERNEL);
	if (!mem)
		goto depopulate;

	buf->page_count = n_pages;
	return mem;

depopulate:
	for (j = 0; j < i; j++)
		__free_page(buf->page_array[j]);
	relay_free_page_array(buf->page_array);
	return NULL;
}

static struct rchan_buf *relay_create_buf(struct rchan *chan)
{
	struct rchan_buf *buf;

	if (chan->n_subbufs > KMALLOC_MAX_SIZE / sizeof(size_t))
		return NULL;

	buf = kzalloc(sizeof(struct rchan_buf), GFP_KERNEL);
	if (!buf)
		return NULL;
	buf->padding = kmalloc_array(chan->n_subbufs, sizeof(size_t),
				     GFP_KERNEL);
	if (!buf->padding)
		goto free_buf;

	buf->start = relay_alloc_buf(buf, &chan->alloc_size);
	if (!buf->start)
		goto free_buf;

	buf->chan = chan;
	kref_get(&buf->chan->kref);
	return buf;

free_buf:
	kfree(buf->padding);
	kfree(buf);
	return NULL;
}

static void __relay_reset(struct rchan_buf *buf, unsigned int init)
{
	size_t i;

	if (init) {
		init_waitqueue_head(&buf->read_wait);
		kref_init(&buf->kref);
		init_irq_work(&buf->wakeup_work, wakeup_readers);
	} else {
		irq_work_sync(&buf->wakeup_work);
	}

	buf->subbufs_produced = 0;
	buf->subbufs_consumed = 0;
	buf->bytes_consumed = 0;
	buf->finalized = 0;
	buf->data = buf->start;
	buf->offset = 0;
	buf->stats.full_count = 0;
	buf->stats.big_count = 0;

	for (i = 0; i < buf->chan->n_subbufs; i++)
		buf->padding[i] = 0;

	relay_subbuf_start(buf, buf->data, NULL);
}

void relay_reset(struct rchan *chan)
{
	struct rchan_buf *buf;
	unsigned int i;

	if (!chan)
		return;

	if (chan->is_global && (buf = *per_cpu_ptr(chan->buf, 0))) {
		__relay_reset(buf, 0);
		return;
	}

	mutex_lock(&relay_channels_mutex);
	for_each_possible_cpu(i)
		if ((buf = *per_cpu_ptr(chan->buf, i)))
			__relay_reset(buf, 0);
	mutex_unlock(&relay_channels_mutex);
}
EXPORT_SYMBOL_GPL(relay_reset);

static inline void relay_set_buf_dentry(struct rchan_buf *buf,
					struct dentry *dentry)
{
	buf->dentry = dentry;
	d_inode(buf->dentry)->i_size = buf->early_bytes;
}

static struct dentry *relay_create_buf_file(struct rchan *chan,
					    struct rchan_buf *buf,
					    unsigned int cpu)
{
	struct dentry *dentry;
	char *tmpname;

	tmpname = kasprintf(GFP_KERNEL, "%s%d", chan->base_filename, cpu);
	if (!tmpname)
		return NULL;

	/* Create file in fs */
	dentry = chan->cb->create_buf_file(tmpname, chan->parent,
					   S_IRUSR, buf,
					   &chan->is_global);
	if (IS_ERR(dentry))
		dentry = NULL;

	kfree(tmpname);

	return dentry;
}


static struct rchan_buf *relay_open_buf(struct rchan *chan, unsigned int cpu)
{
	struct rchan_buf *buf;
	struct dentry *dentry;

 	if (chan->is_global)
		return *per_cpu_ptr(chan->buf, 0);

	buf = relay_create_buf(chan);
	if (!buf)
		return NULL;

	if (chan->has_base_filename) {
		dentry = relay_create_buf_file(chan, buf, cpu);
		if (!dentry)
			goto free_buf;
		relay_set_buf_dentry(buf, dentry);
	} else {
		
		dentry = chan->cb->create_buf_file(NULL, NULL,
						   S_IRUSR, buf,
						   &chan->is_global);
		if (IS_ERR_OR_NULL(dentry))
			goto free_buf;
	}

 	buf->cpu = cpu;
 	__relay_reset(buf, 1);

 	if(chan->is_global) {
		*per_cpu_ptr(chan->buf, 0) = buf;
 		buf->cpu = 0;
  	}

	return buf;

free_buf:
 	relay_destroy_buf(buf);
	return NULL;
}

static void relay_close_buf(struct rchan_buf *buf)
{
	buf->finalized = 1;
	irq_work_sync(&buf->wakeup_work);
	buf->chan->cb->remove_buf_file(buf->dentry);
	kref_put(&buf->kref, relay_remove_buf);
}

int relay_prepare_cpu(unsigned int cpu)
{
	struct rchan *chan;
	struct rchan_buf *buf;

	mutex_lock(&relay_channels_mutex);
	list_for_each_entry(chan, &relay_channels, list) {
		if (*per_cpu_ptr(chan->buf, cpu))
			continue;
		buf = relay_open_buf(chan, cpu);
		if (!buf) {
			pr_err("relay: cpu %d buffer creation failed\n", cpu);
			mutex_unlock(&relay_channels_mutex);
			return -ENOMEM;
		}
		*per_cpu_ptr(chan->buf, cpu) = buf;
	}
	mutex_unlock(&relay_channels_mutex);
	return 0;
}

struct rchan *relay_open(const char *base_filename,
			 struct dentry *parent,
			 size_t subbuf_size,
			 size_t n_subbufs,
			 const struct rchan_callbacks *cb,
			 void *private_data)
{
	unsigned int i;
	struct rchan *chan;
	struct rchan_buf *buf;

	if (!(subbuf_size && n_subbufs))
		return NULL;
	if (subbuf_size > UINT_MAX / n_subbufs)
		return NULL;
	if (!cb || !cb->create_buf_file || !cb->remove_buf_file)
		return NULL;

	chan = kzalloc(sizeof(struct rchan), GFP_KERNEL);
	if (!chan)
		return NULL;

	chan->buf = alloc_percpu(struct rchan_buf *);
	if (!chan->buf) {
		kfree(chan);
		return NULL;
	}

	chan->version = RELAYFS_CHANNEL_VERSION;
	chan->n_subbufs = n_subbufs;
	chan->subbuf_size = subbuf_size;
	chan->alloc_size = PAGE_ALIGN(subbuf_size * n_subbufs);
	chan->parent = parent;
	chan->private_data = private_data;
	if (base_filename) {
		chan->has_base_filename = 1;
		strscpy(chan->base_filename, base_filename, NAME_MAX);
	}
	chan->cb = cb;
	kref_init(&chan->kref);

	mutex_lock(&relay_channels_mutex);
	for_each_online_cpu(i) {
		buf = relay_open_buf(chan, i);
		if (!buf)
			goto free_bufs;
		*per_cpu_ptr(chan->buf, i) = buf;
	}
	list_add(&chan->list, &relay_channels);
	mutex_unlock(&relay_channels_mutex);

	return chan;

free_bufs:
	for_each_possible_cpu(i) {
		if ((buf = *per_cpu_ptr(chan->buf, i)))
			relay_close_buf(buf);
	}

	kref_put(&chan->kref, relay_destroy_channel);
	mutex_unlock(&relay_channels_mutex);
	return NULL;
}
EXPORT_SYMBOL_GPL(relay_open);

struct rchan_percpu_buf_dispatcher {
	struct rchan_buf *buf;
	struct dentry *dentry;
};


size_t relay_switch_subbuf(struct rchan_buf *buf, size_t length)
{
	void *old, *new;
	size_t old_subbuf, new_subbuf;

	if (unlikely(length > buf->chan->subbuf_size))
		goto toobig;

	if (buf->offset != buf->chan->subbuf_size + 1) {
		size_t prev_padding;

		prev_padding = buf->chan->subbuf_size - buf->offset;
		old_subbuf = buf->subbufs_produced % buf->chan->n_subbufs;
		buf->padding[old_subbuf] = prev_padding;
		buf->subbufs_produced++;
		if (buf->dentry)
			d_inode(buf->dentry)->i_size +=
				buf->chan->subbuf_size -
				buf->padding[old_subbuf];
		else
			buf->early_bytes += buf->chan->subbuf_size -
					    buf->padding[old_subbuf];
		smp_mb();
		if (waitqueue_active(&buf->read_wait)) {

			irq_work_queue(&buf->wakeup_work);
		}
	}

	old = buf->data;
	new_subbuf = buf->subbufs_produced % buf->chan->n_subbufs;
	new = buf->start + new_subbuf * buf->chan->subbuf_size;
	buf->offset = 0;
	if (!relay_subbuf_start(buf, new, old)) {
		buf->offset = buf->chan->subbuf_size + 1;
		return 0;
	}
	buf->data = new;
	buf->padding[new_subbuf] = 0;

	if (unlikely(length + buf->offset > buf->chan->subbuf_size))
		goto toobig;

	return length;

toobig:
	buf->stats.big_count++;
	return 0;
}
EXPORT_SYMBOL_GPL(relay_switch_subbuf);

size_t relay_stats(struct rchan *chan, int flags)
{
	unsigned int i, count = 0;
	struct rchan_buf *rbuf;

	if (!chan || flags > RELAY_STATS_LAST)
		return 0;

	if (chan->is_global) {
		rbuf = *per_cpu_ptr(chan->buf, 0);
		if (flags & RELAY_STATS_BUF_FULL)
			count = rbuf->stats.full_count;
		else if (flags & RELAY_STATS_WRT_BIG)
			count = rbuf->stats.big_count;
	} else {
		for_each_online_cpu(i) {
			rbuf = *per_cpu_ptr(chan->buf, i);
			if (rbuf) {
				if (flags & RELAY_STATS_BUF_FULL)
					count += rbuf->stats.full_count;
				else if (flags & RELAY_STATS_WRT_BIG)
					count += rbuf->stats.big_count;
			}
		}
	}

	return count;
}

static int relay_file_read_avail(struct rchan_buf *buf)
{
	size_t subbuf_size = buf->chan->subbuf_size;
	size_t n_subbufs = buf->chan->n_subbufs;
	size_t produced = buf->subbufs_produced;
	size_t consumed;

	relay_file_read_consume(buf, 0, 0);

	consumed = buf->subbufs_consumed;

	if (unlikely(buf->offset > subbuf_size)) {
		if (produced == consumed)
			return 0;
		return 1;
	}

	if (unlikely(produced - consumed >= n_subbufs)) {
		consumed = produced - n_subbufs + 1;
		buf->subbufs_consumed = consumed;
		buf->bytes_consumed = 0;
	}

	produced = (produced % n_subbufs) * subbuf_size + buf->offset;
	consumed = (consumed % n_subbufs) * subbuf_size + buf->bytes_consumed;

	if (consumed > produced)
		produced += n_subbufs * subbuf_size;

	if (consumed == produced) {
		if (buf->offset == subbuf_size &&
		    buf->subbufs_produced > buf->subbufs_consumed)
			return 1;
		return 0;
	}

	return 1;
}

static size_t relay_file_read_end_pos(struct rchan_buf *buf,
				      size_t read_pos,
				      size_t count)
{
	size_t read_subbuf, padding, end_pos;
	size_t subbuf_size = buf->chan->subbuf_size;
	size_t n_subbufs = buf->chan->n_subbufs;

	read_subbuf = read_pos / subbuf_size;
	padding = buf->padding[read_subbuf];
	if (read_pos % subbuf_size + count + padding == subbuf_size)
		end_pos = (read_subbuf + 1) * subbuf_size;
	else
		end_pos = read_pos + count;
	if (end_pos >= subbuf_size * n_subbufs)
		end_pos = 0;

	return end_pos;
}

static ssize_t relay_file_read(struct file *filp,
			       char __user *buffer,
			       size_t count,
			       loff_t *ppos)
{
	struct rchan_buf *buf = filp->private_data;
	size_t read_start, avail;
	size_t written = 0;
	int ret;

	inode_lock(file_inode(filp));
	do {
		void *from;

		if (!relay_file_read_avail(buf))
			break;

		read_start = relay_file_read_start_pos(buf);
		avail = relay_file_read_subbuf_avail(read_start, buf);
		if (!avail)
			break;

		avail = min(count, avail);
		from = buf->start + read_start;
		ret = avail;
		if (copy_to_user(buffer, from, avail))
			break;

		buffer += ret;
		written += ret;
		count -= ret;

		relay_file_read_consume(buf, read_start, ret);
		*ppos = relay_file_read_end_pos(buf, read_start, ret);
	} while (count);
	inode_unlock(file_inode(filp));

	return written;
}


const struct file_operations relay_file_operations = {
	.open		= relay_file_open,
	.poll		= relay_file_poll,
	.mmap		= relay_file_mmap,
	.read		= relay_file_read,
	.release	= relay_file_release,
};
EXPORT_SYMBOL_GPL(relay_file_operations);

static char *fwctl_devnode(const struct device *dev, umode_t *mode)
{
	return kasprintf(GFP_KERNEL, "fwctl/%s", dev_name(dev));
}

static struct class fwctl_class = {
	.name = "fwctl",
	.dev_release = fwctl_device_release,
	.devnode = fwctl_devnode,
};

static struct fwctl_device *
_alloc_device(struct device *parent, const struct fwctl_ops *ops, size_t size)
{
	struct fwctl_device *fwctl __free(kfree) = kzalloc(size, GFP_KERNEL);
	int devnum;

	if (!fwctl)
		return NULL;

	devnum = ida_alloc_max(&fwctl_ida, FWCTL_MAX_DEVICES - 1, GFP_KERNEL);
	if (devnum < 0)
		return NULL;

	fwctl->dev.devt = fwctl_dev + devnum;
	fwctl->dev.class = &fwctl_class;
	fwctl->dev.parent = parent;

	init_rwsem(&fwctl->registration_lock);
	mutex_init(&fwctl->uctx_list_lock);
	INIT_LIST_HEAD(&fwctl->uctx_list);

	device_initialize(&fwctl->dev);
	return_ptr(fwctl);
}

static void sched_core_put_cookie(unsigned long cookie)
{
	struct sched_core_cookie *ptr = (void *)cookie;

	if (ptr && refcount_dec_and_test(&ptr->refcnt)) {
		kfree(ptr);
		sched_core_put();
	}
}

static unsigned long sched_core_get_cookie(unsigned long cookie)
{
	struct sched_core_cookie *ptr = (void *)cookie;

	if (ptr)
		refcount_inc(&ptr->refcnt);

	return cookie;
}