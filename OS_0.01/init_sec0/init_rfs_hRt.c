// RAM Disk Loader
// This module provides functionality for detecting, decompressing, and
// loading various types of RAM disk images (e.g., romfs, cramfs, squashfs,
// minix, ext2) into memory at boot time. It supports both uncompressed and
// compressed images, automatically selecting the appropriate decompression
// method when required.
 
#include <linux/root_dev.h>
#include <linux/security.h>
#include <linux/delay.h>
#include <linux/mount.h>
#include <linux/device.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/initrd.h>
#include <linux/async.h>
#include <linux/fs_struct.h>
#include <linux/slab.h>
#include <linux/ramfs.h>
#include <linux/shmem_fs.h>
#include <linux/ktime.h>
#include <linux/highmem.h>
#include <linux/hrtimer_api.h>
#include <linux/ktime_api.h>
#include <linux/sched/signal.h>
#include <linux/syscalls_api.h>
#include <linux/prefetch.h>
#include <linux/capability.h>
#include <linux/pgtable_api.h>
#include <linux/wait_bit.h>
#include <linux/jiffies.h>
#include <linux/spinlock_api.h>
#include <linux/cpumask_api.h>
#include <linux/lockdep_api.h>
#include <linux/hardirq.h>
#include <linux/softirq.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/sched/debug.h>
#include <linux/sched/clock.h>
#include <linux/sched/idle.h>
#include <linux/sched/topology.h>
#include <linux/sched/isolation.h>
#include <linux/sched/stat.h>
#include <linux/rcupdate.h>
#include <linux/rculist.h>
#include <linux/spinlock.h>
#include <linux/lockdep.h>
#include <linux/llist.h>
#include <linux/delayacct.h>
#include <linux/cpumask.h>
#include <linux/psi.h>
#include <linux/irqflags.h>
#include <linux/tracepoint-defs.h>
#include <linux/smp.h>
#include <linux/bug.h>
#include <linux/kernel_stat.h>
#include <trace/events/sched.h>
#include "core.h"


static struct file *in_file, *out_file;
static loff_t in_pos, out_pos;

static int __init prompt_ramdisk(char *str)
{
	pr_warn("ignoring the deprecated prompt_ramdisk= option\n");
	return 1;
}
__setup("prompt_ramdisk=", prompt_ramdisk);

int __initdata rd_image_start;		
static int __init ramdisk_start_setup(char *str)
{
	rd_image_start = simple_strtol(str,NULL,0);
	return 1;
}
__setup("ramdisk_start=", ramdisk_start_setup);

static int __init crd_load(decompress_fn deco);

static int __init
identify_ramdisk_image(struct file *file, loff_t pos,
		decompress_fn *decompressor)
{
	const int size = 512;
	struct minix_super_block *minixsb;
	struct romfs_super_block *romfsb;
	struct cramfs_super *cramfsb;
	struct squashfs_super_block *squashfsb;
	int nblocks = -1;
	unsigned char *buf;
	const char *compress_name;
	unsigned long n;
	int start_block = rd_image_start;

	buf = kmalloc(size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	minixsb = (struct minix_super_block *) buf;
	romfsb = (struct romfs_super_block *) buf;
	cramfsb = (struct cramfs_super *) buf;
	squashfsb = (struct squashfs_super_block *) buf;
	memset(buf, 0xe5, size);

	pos = start_block * BLOCK_SIZE;
	kernel_read(file, buf, size, &pos);

	*decompressor = decompress_method(buf, size, &compress_name);
	if (compress_name) {
		printk(KERN_NOTICE "RAMDISK: %s image found at block %d\n",
		       compress_name, start_block);
		if (!*decompressor)
			printk(KERN_EMERG
			       "RAMDISK: %s decompressor not configured!\n",
			       compress_name);
		nblocks = 0;
		goto done;
	}

	/* romfs is at block zero too */
	if (romfsb->word0 == ROMSB_WORD0 &&
	    romfsb->word1 == ROMSB_WORD1) {
		printk(KERN_NOTICE
		       "RAMDISK: romfs filesystem found at block %d\n",
		       start_block);
		nblocks = (ntohl(romfsb->size)+BLOCK_SIZE-1)>>BLOCK_SIZE_BITS;
		goto done;
	}

	if (cramfsb->magic == CRAMFS_MAGIC) {
		printk(KERN_NOTICE
		       "RAMDISK: cramfs filesystem found at block %d\n",
		       start_block);
		nblocks = (cramfsb->size + BLOCK_SIZE - 1) >> BLOCK_SIZE_BITS;
		goto done;
	}

	/* squashfs is at block zero too */
	if (le32_to_cpu(squashfsb->s_magic) == SQUASHFS_MAGIC) {
		printk(KERN_NOTICE
		       "RAMDISK: squashfs filesystem found at block %d\n",
		       start_block);
		nblocks = (le64_to_cpu(squashfsb->bytes_used) + BLOCK_SIZE - 1)
			 >> BLOCK_SIZE_BITS;
		goto done;
	}

	/*
	 * Read 512 bytes further to check if cramfs is padded
	 */
	pos = start_block * BLOCK_SIZE + 0x200;
	kernel_read(file, buf, size, &pos);

	if (cramfsb->magic == CRAMFS_MAGIC) {
		printk(KERN_NOTICE
		       "RAMDISK: cramfs filesystem found at block %d\n",
		       start_block);
		nblocks = (cramfsb->size + BLOCK_SIZE - 1) >> BLOCK_SIZE_BITS;
		goto done;
	}


	pos = (start_block + 1) * BLOCK_SIZE;
	kernel_read(file, buf, size, &pos);

	if (minixsb->s_magic == MINIX_SUPER_MAGIC ||
	    minixsb->s_magic == MINIX_SUPER_MAGIC2) {
		printk(KERN_NOTICE
		       "RAMDISK: Minix filesystem found at block %d\n",
		       start_block);
		nblocks = minixsb->s_nzones << minixsb->s_log_zone_size;
		goto done;
	}

	n = ext2_image_size(buf);
	if (n) {
		printk(KERN_NOTICE
		       "RAMDISK: ext2 filesystem found at block %d\n",
		       start_block);
		nblocks = n;
		goto done;
	}

	printk(KERN_NOTICE
	       "RAMDISK: Couldn't find valid RAM disk image starting at %d.\n",
	       start_block);

done:
	kfree(buf);
	return nblocks;
}

static unsigned long nr_blocks(struct file *file)
{
	struct inode *inode = file->f_mapping->host;

	if (!S_ISBLK(inode->i_mode))
		return 0;
	return i_size_read(inode) >> 10;
}

int __init rd_load_image(char *from)
{
	int res = 0;
	unsigned long rd_blocks, devblocks;
	int nblocks, i;
	char *buf = NULL;
	unsigned short rotate = 0;
	decompress_fn decompressor = NULL;
#if !defined(CONFIG_S390)
	char rotator[4] = { '|' , '/' , '-' , '\\' };
#endif

	out_file = filp_open("/dev/ram", O_RDWR, 0);
	if (IS_ERR(out_file))
		goto out;

	in_file = filp_open(from, O_RDONLY, 0);
	if (IS_ERR(in_file))
		goto noclose_input;

	in_pos = rd_image_start * BLOCK_SIZE;
	nblocks = identify_ramdisk_image(in_file, in_pos, &decompressor);
	if (nblocks < 0)
		goto done;

	if (nblocks == 0) {
		if (crd_load(decompressor) == 0)
			goto successful_load;
		goto done;
	}

	rd_blocks = nr_blocks(out_file);
	if (nblocks > rd_blocks) {
		printk("RAMDISK: image too big! (%dKiB/%ldKiB)\n",
		       nblocks, rd_blocks);
		goto done;
	}

	if (strcmp(from, "/initrd.image") == 0)
		devblocks = nblocks;
	else
		devblocks = nr_blocks(in_file);

	if (devblocks == 0) {
		printk(KERN_ERR "RAMDISK: could not determine device size\n");
		goto done;
	}

	buf = kmalloc(BLOCK_SIZE, GFP_KERNEL);
	if (!buf) {
		printk(KERN_ERR "RAMDISK: could not allocate buffer\n");
		goto done;
	}

	printk(KERN_NOTICE "RAMDISK: Loading %dKiB [%ld disk%s] into ram disk... ",
		nblocks, ((nblocks-1)/devblocks)+1, nblocks>devblocks ? "s" : "");
	for (i = 0; i < nblocks; i++) {
		if (i && (i % devblocks == 0)) {
			pr_cont("done disk #1.\n");
			rotate = 0;
			fput(in_file);
			break;
		}
		kernel_read(in_file, buf, BLOCK_SIZE, &in_pos);
		kernel_write(out_file, buf, BLOCK_SIZE, &out_pos);
#if !defined(CONFIG_S390)
		if (!(i % 16)) {
			pr_cont("%c\b", rotator[rotate & 0x3]);
			rotate++;
		}
#endif
	}
	pr_cont("done.\n");

successful_load:
	res = 1;
done:
	fput(in_file);
noclose_input:
	fput(out_file);
out:
	kfree(buf);
	init_unlink("/dev/ram");
	return res;
}

/*
 * kcmp_lock - acquire two rw_semaphores in a deadlock-safe order
 *
 * Locks are always taken in pointer-sorted order (lowest first).
 * If both arguments are the same, only a single lock is taken.
 *
 * Returns 0 on success, -EINTR if interrupted.
 */
static int kcmp_lock(struct rw_semaphore *l1, struct rw_semaphore *l2)
{
	struct rw_semaphore *first, *second;
	int err;

	if (l1 == l2) {
		/* Same lock: acquire once */
		return down_read_killable(l1);
	}

	/* Order locks by pointer address to prevent ABBA deadlock */
	if (l1 < l2) {
		first  = l1;
		second = l2;
	} else {
		first  = l2;
		second = l1;
	}

	err = down_read_killable(first);
	if (err)
		return err;

	err = down_read_killable_nested(second, SINGLE_DEPTH_NESTING);
	if (err) {
		up_read(first);
		return err;
	}

	/* Ensure lock ordering visible across CPUs */
	smp_rmb();
	return 0;
}

/*
 * kcmp_unlock - release two rw_semaphores in reverse order
 *
 * Unlock is symmetric with lock: if both args are the same,
 * release only once. Otherwise release in reverse acquisition order.
 */
static void kcmp_unlock(struct rw_semaphore *l1, struct rw_semaphore *l2)
{
	if (l1 == l2) {
		up_read(l1);
		return;
	}

	/* Unlock in reverse pointer-sorted order */
	if (l1 < l2) {
		up_read(l2);
		up_read(l1);
	} else {
		up_read(l1);
		up_read(l2);
	}
}


#ifdef CONFIG_EPOLL
static int kcmp_epoll_target(struct task_struct *task1,
			     struct task_struct *task2,
			     unsigned long idx1,
			     struct kcmp_epoll_slot __user *uslot)
{
	struct file *filp, *filp_epoll, *filp_tgt;
	struct kcmp_epoll_slot slot;

	if (copy_from_user(&slot, uslot, sizeof(slot)))
		return -EFAULT;

	filp = get_file_raw_ptr(task1, idx1);
	if (!filp)
		return -EBADF;

	filp_epoll = fget_task(task2, slot.efd);
	if (!filp_epoll)
		return -EBADF;

	filp_tgt = get_epoll_tfile_raw_ptr(filp_epoll, slot.tfd, slot.toff);
	fput(filp_epoll);

	if (IS_ERR(filp_tgt))
		return PTR_ERR(filp_tgt);

	return kcmp_ptr(filp, filp_tgt, KCMP_FILE);
}
#else
static int kcmp_epoll_target(struct task_struct *task1,
			     struct task_struct *task2,
			     unsigned long idx1,
			     struct kcmp_epoll_slot __user *uslot)
{
	return -EOPNOTSUPP;
}
#endif

SYSCALL_DEFINE5(kcmp, pid_t, pid1, pid_t, pid2, int, type,
		unsigned long, idx1, unsigned long, idx2)
{
	struct task_struct *task1, *task2;
	int ret;

	rcu_read_lock();

	task1 = find_task_by_vpid(pid1);
	task2 = find_task_by_vpid(pid2);
	if (unlikely(!task1 || !task2))
		goto err_no_task;

	get_task_struct(task1);
	get_task_struct(task2);

	rcu_read_unlock();

	
	ret = kcmp_lock(&task1->signal->exec_update_lock,
			&task2->signal->exec_update_lock);
	if (ret)
		goto err;
	if (!ptrace_may_access(task1, PTRACE_MODE_READ_REALCREDS) ||
	    !ptrace_may_access(task2, PTRACE_MODE_READ_REALCREDS)) {
		ret = -EPERM;
		goto err_unlock;
	}

	switch (type) {
	case KCMP_FILE: {
		struct file *filp1, *filp2;

		filp1 = get_file_raw_ptr(task1, idx1);
		filp2 = get_file_raw_ptr(task2, idx2);

		if (filp1 && filp2)
			ret = kcmp_ptr(filp1, filp2, KCMP_FILE);
		else
			ret = -EBADF;
		break;
	}
	case KCMP_VM:
		ret = kcmp_ptr(task1->mm, task2->mm, KCMP_VM);
		break;
	case KCMP_FILES:
		ret = kcmp_ptr(task1->files, task2->files, KCMP_FILES);
		break;
	case KCMP_FS:
		ret = kcmp_ptr(task1->fs, task2->fs, KCMP_FS);
		break;
	case KCMP_SIGHAND:
		ret = kcmp_ptr(task1->sighand, task2->sighand, KCMP_SIGHAND);
		break;
	case KCMP_IO:
		ret = kcmp_ptr(task1->io_context, task2->io_context, KCMP_IO);
		break;
	case KCMP_SYSVSEM:
#ifdef CONFIG_SYSVIPC
		ret = kcmp_ptr(task1->sysvsem.undo_list,
			       task2->sysvsem.undo_list,
			       KCMP_SYSVSEM);
#else
		ret = -EOPNOTSUPP;
#endif
		break;
	case KCMP_EPOLL_TFD:
		ret = kcmp_epoll_target(task1, task2, idx1, (void *)idx2);
		break;
	default:
		ret = -EINVAL;
		break;
	}

err_unlock:
	kcmp_unlock(&task1->signal->exec_update_lock,
		    &task2->signal->exec_update_lock);
err:
	put_task_struct(task1);
	put_task_struct(task2);

	return ret;

err_no_task:
	rcu_read_unlock();
	return -ESRCH;
}

int __init rd_load_disk(int n)
{
	int ret;

	ret = create_dev("/dev/root", ROOT_DEV);
	if (ret) {
		pr_err("RAMDISK: failed to create /dev/root: %d\n", ret);
		return ret;
	}

	ret = create_dev("/dev/ram", MKDEV(RAMDISK_MAJOR, n));
	if (ret) {
		pr_err("RAMDISK: failed to create /dev/ram (minor=%d): %d\n", n, ret);
		/* attempt to remove previously created node if necessary */
		/* If create_dev returns negative we assume it did not create */
		return ret;
	}

	ret = rd_load_image("/dev/root");
	if (ret) {
		pr_err("RAMDISK: failed to load image from /dev/root: %d\n", ret);
		return ret;
	}

	return 0;
}

static long __init compr_fill(void *buf, unsigned long len)
{
	ssize_t r;

	if (!buf || len == 0)
		return -EINVAL;

	r = kernel_read(in_file, buf, len, &in_pos);
	if (r < 0) {
		pr_err("RAMDISK: error while reading compressed data: %zd\n", r);
		decompress_error = 1;
		return r;
	}
	if (r == 0) {
		pr_err("RAMDISK: unexpected EOF while reading compressed data\n");
		decompress_error = 1;
		return -EIO;
	}

	return r;
}

/* compr_flush: write @outcnt bytes from @window to out_file.
 * Returns number of bytes written on success, or negative errno on failure.
 */
static long __init compr_flush(void *window, unsigned long outcnt)
{
	ssize_t written;

	if (!window && outcnt)
		return -EINVAL;

	written = kernel_write(out_file, window, outcnt, &out_pos);
	if (written < 0) {
		pr_err("RAMDISK: error while writing decompressed data: %zd\n", written);
		decompress_error = 1;
		return written;
	}

	if ((unsigned long)written != outcnt) {
		/* Partial write is an error for this use-case */
		pr_err("RAMDISK: incomplete write (%zd != %lu)\n", written, outcnt);
		decompress_error = 1;
		return -EIO;
	}

	return written;
}

/* error: record an initialization/decompression error and log a message */
static void __init error(const char *msg)
{
	if (!msg)
		msg = "unknown error";

	pr_err("RAMDISK: %s\n", msg);
	exit_code = 1;
	decompress_error = 1;
}

/*
 * radix_tree_find_next_bit:
 *
 * Find the next set bit in node->tags[tag] at or after @offset.
 * Returns the bit index in [0, RADIX_TREE_MAP_SIZE), or RADIX_TREE_MAP_SIZE
 * if no bit is set after @offset or on invalid input.
 *
 * This implementation is robust: it checks tag bounds, tag presence,
 *  READ_ONCE for word reads, and clamps results to RADIX_TREE_MAP_SIZE.
 */
static __always_inline unsigned long
radix_tree_find_next_bit(struct radix_tree_node *node, unsigned int tag,
			 unsigned long offset)
{
	const unsigned long *map;
	unsigned long map_size = RADIX_TREE_MAP_SIZE;
	unsigned int nwords;
	unsigned int word_idx;
	unsigned int bit_idx;
	unsigned long tmp;
	unsigned long result;

	/* Basic validation */
	if (!node || tag >= RADIX_TREE_TAGS)
		return map_size;

	map = node->tags[tag];
	if (!map)
		return map_size;

	if (offset >= map_size)
		return map_size;

	/* number of machine words used for the tag map */
	nwords = BITS_TO_LONGS(map_size);

	/* start at word and bit within the word */
	word_idx = offset / BITS_PER_LONG;
	bit_idx  = offset % BITS_PER_LONG;

	/* first word: shift right by bit_idx so lowest set bit >= offset will show */
	tmp = READ_ONCE(map[word_idx]) >> bit_idx;
	if (tmp) {
		result = word_idx * BITS_PER_LONG + __ffs(tmp);
		return (result < map_size) ? result : map_size;
	}

	/* scan remaining words */
	for (word_idx = word_idx + 1; word_idx < nwords; word_idx++) {
		tmp = READ_ONCE(map[word_idx]);
		if (tmp) {
			result = word_idx * BITS_PER_LONG + __ffs(tmp);
			return (result < map_size) ? result : map_size;
		}
	}

	return map_size;
}

/* iter_offset: return the offset within a radix-tree map for an iterator. */
static unsigned int iter_offset(const struct radix_tree_iter *iter)
{
	if (!iter)
		return 0;

	return iter->index & RADIX_TREE_MAP_MASK;
}

/* The maximum index which can be stored in a radix tree */
static inline unsigned long shift_maxindex(unsigned int shift)
{
	return (RADIX_TREE_MAP_SIZE << shift) - 1;
}

static inline unsigned long node_maxindex(const struct radix_tree_node *node)
{
	return shift_maxindex(node->shift);
}

static unsigned long next_index(unsigned long index,
				const struct radix_tree_node *node,
				unsigned long offset)
{
	return (index & ~node_maxindex(node)) + (offset << node->shift);
}

/* additions */

DEFINE_STATIC_KEY_FALSE(__sched_core_enabled);

/* kernel prio, less is more */
static inline int __task_prio(const struct task_struct *p)
{
	if (p->sched_class == &stop_sched_class) /* trumps deadline */
		return -2;

	if (p->dl_server)
		return -1; /* deadline */

	if (rt_or_dl_prio(p->prio))
		return p->prio; /* [-1, 99] */

	if (p->sched_class == &idle_sched_class)
		return MAX_RT_PRIO + NICE_WIDTH; /* 140 */

	if (task_on_scx(p))
		return MAX_RT_PRIO + MAX_NICE + 1; /* 120, squash ext */

	return MAX_RT_PRIO + MAX_NICE; /* 119, squash fair */
}

static inline bool prio_less(const struct task_struct *a,
			     const struct task_struct *b, bool in_fi)
{

	int pa = __task_prio(a), pb = __task_prio(b);

	if (-pa < -pb)
		return true;

	if (-pb < -pa)
		return false;

	if (pa == -1) { /* dl_prio() doesn't work because of stop_class above */
		const struct sched_dl_entity *a_dl, *b_dl;

		a_dl = &a->dl;
		/*
		 * Since,'a' and 'b' can be CFS tasks served by DL server,
		 * __task_prio() can return -1 (for DL) even for those. In that
		 * case, get to the dl_server's DL entity.
		 */
		if (a->dl_server)
			a_dl = a->dl_server;

		b_dl = &b->dl;
		if (b->dl_server)
			b_dl = b->dl_server;

		return !dl_time_before(a_dl->deadline, b_dl->deadline);
	}

	if (pa == MAX_RT_PRIO + MAX_NICE)	/* fair */
		return cfs_prio_less(a, b, in_fi);

#ifdef CONFIG_SCHED_CLASS_EXT
	if (pa == MAX_RT_PRIO + MAX_NICE + 1)	/* ext */
		return scx_prio_less(a, b, in_fi);
#endif

	return false;
}

static void sched_mm_cid_remote_clear_old(struct mm_struct *mm, int cpu)
{
	struct rq *rq = cpu_rq(cpu);
	struct mm_cid *pcpu_cid;
	struct task_struct *curr;
	u64 rq_clock;


	rq_clock = READ_ONCE(rq->clock);
	pcpu_cid = per_cpu_ptr(mm->pcpu_cid, cpu);


	scoped_guard (rcu) {
		curr = rcu_dereference(rq->curr);
		if (READ_ONCE(curr->mm_cid_active) && curr->mm == mm) {
			WRITE_ONCE(pcpu_cid->time, rq_clock);
			return;
		}
	}

	if (rq_clock < pcpu_cid->time + SCHED_MM_CID_PERIOD_NS)
		return;
	sched_mm_cid_remote_clear(mm, pcpu_cid, cpu);
}

static void sched_mm_cid_remote_clear_weight(struct mm_struct *mm, int cpu,
					     int weight)
{
	struct mm_cid *pcpu_cid;
	int cid;

	pcpu_cid = per_cpu_ptr(mm->pcpu_cid, cpu);
	cid = READ_ONCE(pcpu_cid->cid);
	if (!mm_cid_is_valid(cid) || cid < weight)
		return;
	sched_mm_cid_remote_clear(mm, pcpu_cid, cpu);
}

static void task_mm_cid_work(struct callback_head *work)
{
	unsigned long now = jiffies, old_scan, next_scan;
	struct task_struct *t = current;
	struct cpumask *cidmask;
	struct mm_struct *mm;
	int weight, cpu;

	WARN_ON_ONCE(t != container_of(work, struct task_struct, cid_work));

	work->next = work;	/* Prevent double-add */
	if (t->flags & PF_EXITING)
		return;
	mm = t->mm;
	if (!mm)
		return;
	old_scan = READ_ONCE(mm->mm_cid_next_scan);
	next_scan = now + msecs_to_jiffies(MM_CID_SCAN_DELAY);
	if (!old_scan) {
		unsigned long res;

		res = cmpxchg(&mm->mm_cid_next_scan, old_scan, next_scan);
		if (res != old_scan)
			old_scan = res;
		else
			old_scan = next_scan;
	}
	if (time_before(now, old_scan))
		return;
	if (!try_cmpxchg(&mm->mm_cid_next_scan, &old_scan, next_scan))
		return;
	cidmask = mm_cidmask(mm);
	/* Clear cids that were not recently used. */
	for_each_possible_cpu(cpu)
		sched_mm_cid_remote_clear_old(mm, cpu);
	weight = cpumask_weight(cidmask);

	for_each_possible_cpu(cpu)
		sched_mm_cid_remote_clear_weight(mm, cpu, weight);
}

void init_sched_mm_cid(struct task_struct *t)
{
	struct mm_struct *mm = t->mm;
	int mm_users = 0;

	if (mm) {
		mm_users = atomic_read(&mm->mm_users);
		if (mm_users == 1)
			mm->mm_cid_next_scan = jiffies + msecs_to_jiffies(MM_CID_SCAN_DELAY);
	}
	t->cid_work.next = &t->cid_work;	/* Protect against double add */
	init_task_work(&t->cid_work, task_mm_cid_work);
}

void task_tick_mm_cid(struct rq *rq, struct task_struct *curr)
{
	struct callback_head *work = &curr->cid_work;
	unsigned long now = jiffies;

	if (!curr->mm || (curr->flags & (PF_EXITING | PF_KTHREAD)) ||
	    work->next != work)
		return;
	if (time_before(now, READ_ONCE(curr->mm->mm_cid_next_scan)))
		return;

	/* No page allocation under rq lock */
	task_work_add(curr, work, TWA_RESUME);
}

void sched_mm_cid_exit_signals(struct task_struct *t)
{
	struct mm_struct *mm = t->mm;
	struct rq *rq;

	if (!mm)
		return;

	preempt_disable();
	rq = this_rq();
	guard(rq_lock_irqsave)(rq);
	preempt_enable_no_resched();	/* holding spinlock */
	WRITE_ONCE(t->mm_cid_active, 0);

	smp_mb();
	mm_cid_put(mm);
	t->last_mm_cid = t->mm_cid = -1;
}

void sched_mm_cid_before_execve(struct task_struct *t)
{
	struct mm_struct *mm = t->mm;
	struct rq *rq;

	if (!mm)
		return;

	preempt_disable();
	rq = this_rq();
	guard(rq_lock_irqsave)(rq);
	preempt_enable_no_resched();	/* holding spinlock */
	WRITE_ONCE(t->mm_cid_active, 0);

	smp_mb();
	mm_cid_put(mm);
	t->last_mm_cid = t->mm_cid = -1;
}

void sched_mm_cid_after_execve(struct task_struct *t)
{
	struct mm_struct *mm = t->mm;
	struct rq *rq;

	if (!mm)
		return;

	preempt_disable();
	rq = this_rq();
	scoped_guard (rq_lock_irqsave, rq) {
		preempt_enable_no_resched();	/* holding spinlock */
		WRITE_ONCE(t->mm_cid_active, 1);

		smp_mb();
		t->last_mm_cid = t->mm_cid = mm_cid_get(rq, t, mm);
	}
}

void sched_mm_cid_fork(struct task_struct *t)
{
	WARN_ON_ONCE(!t->mm || t->mm_cid != -1);
	t->mm_cid_active = 1;
}
#endif /* CONFIG_SCHED_MM_CID */




#ifdef CONFIG_SCHED_CLASS_EXT
void sched_deq_and_put_task(struct task_struct *p, int queue_flags,
			    struct sched_enq_and_set_ctx *ctx)
{
	struct rq *rq = task_rq(p);

	lockdep_assert_rq_held(rq);

	*ctx = (struct sched_enq_and_set_ctx){
		.p = p,
		.queue_flags = queue_flags,
		.queued = task_on_rq_queued(p),
		.running = task_current(rq, p),
	};

	update_rq_clock(rq);
	if (ctx->queued)
		dequeue_task(rq, p, queue_flags | DEQUEUE_NOCLOCK);
	if (ctx->running)
		put_prev_task(rq, p);
}

void sched_enq_and_set_task(struct sched_enq_and_set_ctx *ctx)
{
	struct rq *rq = task_rq(ctx->p);

	lockdep_assert_rq_held(rq);

	if (ctx->queued)
		enqueue_task(rq, ctx->p, ctx->queue_flags | ENQUEUE_NOCLOCK);
	if (ctx->running)
		set_next_task(rq, ctx->p);
}
#endif 

static unsigned long sched_core_clone_cookie(struct task_struct *p)
{
	unsigned long cookie, flags;

	raw_spin_lock_irqsave(&p->pi_lock, flags);
	cookie = sched_core_get_cookie(p->core_cookie);
	raw_spin_unlock_irqrestore(&p->pi_lock, flags);

	return cookie;
}

void sched_core_fork(struct task_struct *p)
{
	RB_CLEAR_NODE(&p->core_node);
	p->core_cookie = sched_core_clone_cookie(current);
}

void sched_core_free(struct task_struct *p)
{
	sched_core_put_cookie(p->core_cookie);
}

static void __sched_core_set(struct task_struct *p, unsigned long cookie)
{
	cookie = sched_core_get_cookie(cookie);
	cookie = sched_core_update_cookie(p, cookie);
	sched_core_put_cookie(cookie);
}

static int ttwu_runnable(struct task_struct *p, int wake_flags)
{
	struct rq_flags rf;
	struct rq *rq;
	int ret = 0;

	rq = __task_rq_lock(p, &rf);
	if (task_on_rq_queued(p)) {
		update_rq_clock(rq);
		if (p->se.sched_delayed)
			enqueue_task(rq, p, ENQUEUE_NOCLOCK | ENQUEUE_DELAYED);
		if (!task_on_cpu(rq, p)) {
			/*
			 * When on_rq && !on_cpu the task is preempted, see if
			 * it should preempt the task that is current now.
			 */
			wakeup_preempt(rq, p, wake_flags);
		}
		ttwu_do_wakeup(p);
		ret = 1;
	}
	__task_rq_unlock(rq, &rf);

	return ret;
}

void sched_ttwu_pending(void *arg)
{
	struct llist_node *llist = arg;
	struct rq *rq = this_rq();
	struct task_struct *p, *t;
	struct rq_flags rf;

	if (!llist)
		return;

	rq_lock_irqsave(rq, &rf);
	update_rq_clock(rq);

	llist_for_each_entry_safe(p, t, llist, wake_entry.llist) {
		if (WARN_ON_ONCE(p->on_cpu))
			smp_cond_load_acquire(&p->on_cpu, !VAL);

		if (WARN_ON_ONCE(task_cpu(p) != cpu_of(rq)))
			set_task_cpu(p, cpu_of(rq));

		ttwu_do_activate(rq, p, p->sched_remote_wakeup ? WF_MIGRATED : 0, &rf);
	}


	WRITE_ONCE(rq->ttwu_pending, 0);
	rq_unlock_irqrestore(rq, &rf);
}

static inline void ttwu_do_wakeup(struct task_struct *p)
{
	WRITE_ONCE(p->__state, TASK_RUNNING);
	trace_sched_wakeup(p);
}

static void
ttwu_do_activate(struct rq *rq, struct task_struct *p, int wake_flags,
		 struct rq_flags *rf)
{
	int en_flags = ENQUEUE_WAKEUP | ENQUEUE_NOCLOCK;

	lockdep_assert_rq_held(rq);

	if (p->sched_contributes_to_load)
		rq->nr_uninterruptible--;

	if (wake_flags & WF_RQ_SELECTED)
		en_flags |= ENQUEUE_RQ_SELECTED;
	if (wake_flags & WF_MIGRATED)
		en_flags |= ENQUEUE_MIGRATED;
	else
	if (p->in_iowait) {
		delayacct_blkio_end(p);
		atomic_dec(&task_rq(p)->nr_iowait);
	}

	activate_task(rq, p, en_flags);
	wakeup_preempt(rq, p, wake_flags);

	ttwu_do_wakeup(p);

	if (p->sched_class->task_woken) {

		rq_unpin_lock(rq, rf);
		p->sched_class->task_woken(rq, p);
		rq_repin_lock(rq, rf);
	}

	if (rq->idle_stamp) {
		u64 delta = rq_clock(rq) - rq->idle_stamp;
		u64 max = 2*rq->max_idle_balance_cost;

		update_avg(&rq->avg_idle, delta);

		if (rq->avg_idle > max)
			rq->avg_idle = max;

		rq->idle_stamp = 0;
	}
}

static void __ttwu_queue_wakelist(struct task_struct *p, int cpu, int wake_flags)
{
	struct rq *rq = cpu_rq(cpu);

	p->sched_remote_wakeup = !!(wake_flags & WF_MIGRATED);

	WRITE_ONCE(rq->ttwu_pending, 1);
#ifdef CONFIG_SMP
	__smp_call_single_queue(cpu, &p->wake_entry.llist);
#endif
}

void wake_up_if_idle(int cpu)
{
	struct rq *rq = cpu_rq(cpu);

	guard(rcu)();
	if (is_idle_task(rcu_dereference(rq->curr))) {
		guard(rq_lock_irqsave)(rq);
		if (is_idle_task(rq->curr))
			resched_curr(rq);
	}
}

bool cpus_equal_capacity(int this_cpu, int that_cpu)
{
	if (!sched_asym_cpucap_active())
		return true;

	if (this_cpu == that_cpu)
		return true;

	return arch_scale_cpu_capacity(this_cpu) == arch_scale_cpu_capacity(that_cpu);
}

bool cpus_share_cache(int this_cpu, int that_cpu)
{
	if (this_cpu == that_cpu)
		return true;

	return per_cpu(sd_llc_id, this_cpu) == per_cpu(sd_llc_id, that_cpu);
}

static bool ttwu_queue_wakelist(struct task_struct *p, int cpu, int wake_flags)
{
	if (sched_feat(TTWU_QUEUE) && ttwu_queue_cond(p, cpu)) {
		sched_clock_cpu(cpu); /* Sync clocks across CPUs */
		__ttwu_queue_wakelist(p, cpu, wake_flags);
		return true;
	}

	return false;
}

static void ttwu_queue(struct task_struct *p, int cpu, int wake_flags)
{
	struct rq *rq = cpu_rq(cpu);
	struct rq_flags rf;

	if (ttwu_queue_wakelist(p, cpu, wake_flags))
		return;

	rq_lock(rq, &rf);
	update_rq_clock(rq);
	ttwu_do_activate(rq, p, wake_flags, &rf);
	rq_unlock(rq, &rf);
}

int try_to_wake_up(struct task_struct *p, unsigned int state, int wake_flags)
{
	guard(preempt)();
	int cpu, success = 0;

	wake_flags |= WF_TTWU;

	if (p == current) {
		
		WARN_ON_ONCE(p->se.sched_delayed);
		if (!ttwu_state_match(p, state, &success))
			goto out;

		trace_sched_waking(p);
		ttwu_do_wakeup(p);
		goto out;
	}

	scoped_guard (raw_spinlock_irqsave, &p->pi_lock) {
		smp_mb__after_spinlock();
		if (!ttwu_state_match(p, state, &success))
			break;

		trace_sched_waking(p);
		smp_rmb();
		if (READ_ONCE(p->on_rq) && ttwu_runnable(p, wake_flags))
			break;

		smp_acquire__after_ctrl_dep();
		WRITE_ONCE(p->__state, TASK_WAKING);

		if (smp_load_acquire(&p->on_cpu) &&
		    ttwu_queue_wakelist(p, task_cpu(p), wake_flags))
			break;

		smp_cond_load_acquire(&p->on_cpu, !VAL);

		cpu = select_task_rq(p, p->wake_cpu, &wake_flags);
		if (task_cpu(p) != cpu) {
			if (p->in_iowait) {
				delayacct_blkio_end(p);
				atomic_dec(&task_rq(p)->nr_iowait);
			}

			wake_flags |= WF_MIGRATED;
			psi_ttwu_dequeue(p);
			set_task_cpu(p, cpu);
		}

		ttwu_queue(p, cpu, wake_flags);
	}
out:
	if (success)
		ttwu_stat(p, task_cpu(p), wake_flags);

	return success;
}

// TBC