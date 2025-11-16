#include "fs.h"
#include "ondisk.h"

#include <linux/buffer_head.h>
#include <linux/slab.h>
#include <linux/time.h>
#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/exportfs.h>
#include <linux/export.h>
#include <linux/filelock.h>
#include <linux/mm.h>
#include <linux/backing-dev.h>
#include <linux/hash.h>
#include <linux/swap.h>
#include <linux/security.h>
#include <linux/cdev.h>
#include <linux/memblock.h>
#include <linux/fsnotify.h>
#include <linux/mount.h>
#include <linux/posix_acl.h>


static unsigned int i_hash_mask __ro_after_init;
static unsigned int i_hash_shift __ro_after_init;
static struct hlist_head *inode_hashtable __ro_after_init;
static __cacheline_aligned_in_smp DEFINE_SPINLOCK(inode_hash_lock);

/*
 * Empty aops. Can be used for the cases where the user does not
 * define any of the address_space operations.
 */
const struct address_space_operations empty_aops = {
};
EXPORT_SYMBOL(empty_aops);

static DEFINE_PER_CPU(unsigned long, nr_inodes);
static DEFINE_PER_CPU(unsigned long, nr_unused);

static struct kmem_cache *inode_cachep __ro_after_init;

static long get_nr_inodes(void)
{
	int i;
	long sum = 0;
	for_each_possible_cpu(i)
		sum += per_cpu(nr_inodes, i);
	return sum < 0 ? 0 : sum;
}

static inline long get_nr_inodes_unused(void)
{
	int i;
	long sum = 0;
	for_each_possible_cpu(i)
		sum += per_cpu(nr_unused, i);
	return sum < 0 ? 0 : sum;
}

long get_nr_dirty_inodes(void)
{
	/* not actually dirty inodes, but a wild approximation */
	long nr_dirty = get_nr_inodes() - get_nr_inodes_unused();
	return nr_dirty > 0 ? nr_dirty : 0;
}

#ifdef CONFIG_DEBUG_FS
static DEFINE_PER_CPU(long, mg_ctime_updates);
static DEFINE_PER_CPU(long, mg_fine_stamps);
static DEFINE_PER_CPU(long, mg_ctime_swaps);

static unsigned long get_mg_ctime_updates(void)
{
	unsigned long sum = 0;
	int i;

	for_each_possible_cpu(i)
		sum += data_race(per_cpu(mg_ctime_updates, i));
	return sum;
}

static unsigned long get_mg_fine_stamps(void)
{
	unsigned long sum = 0;
	int i;

	for_each_possible_cpu(i)
		sum += data_race(per_cpu(mg_fine_stamps, i));
	return sum;
}

static unsigned long get_mg_ctime_swaps(void)
{
	unsigned long sum = 0;
	int i;

	for_each_possible_cpu(i)
		sum += data_race(per_cpu(mg_ctime_swaps, i));
	return sum;
}

#define mgtime_counter_inc(__var)	this_cpu_inc(__var)

static int mgts_show(struct seq_file *s, void *p)
{
	unsigned long ctime_updates = get_mg_ctime_updates();
	unsigned long ctime_swaps = get_mg_ctime_swaps();
	unsigned long fine_stamps = get_mg_fine_stamps();
	unsigned long floor_swaps = timekeeping_get_mg_floor_swaps();

	seq_printf(s, "%lu %lu %lu %lu\n",
		   ctime_updates, ctime_swaps, fine_stamps, floor_swaps);
	return 0;
}

DEFINE_SHOW_ATTRIBUTE(mgts);

static int __init mg_debugfs_init(void)
{
	debugfs_create_file("multigrain_timestamps", S_IFREG | S_IRUGO, NULL, NULL, &mgts_fops);
	return 0;
}
late_initcall(mg_debugfs_init);

#else 

#define mgtime_counter_inc(__var)	do { } while (0)

#endif 

/*
 * Handle nr_inode sysctl
 */
#ifdef CONFIG_SYSCTL
/*
 * Statistics gathering..
 */
static struct inodes_stat_t inodes_stat;

static int proc_nr_inodes(const struct ctl_table *table, int write, void *buffer,
			  size_t *lenp, loff_t *ppos)
{
	inodes_stat.nr_inodes = get_nr_inodes();
	inodes_stat.nr_unused = get_nr_inodes_unused();
	return proc_doulongvec_minmax(table, write, buffer, lenp, ppos);
}

static const struct ctl_table inodes_sysctls[] = {
	{
		.procname	= "inode-nr",
		.data		= &inodes_stat,
		.maxlen		= 2*sizeof(long),
		.mode		= 0444,
		.proc_handler	= proc_nr_inodes,
	},
	{
		.procname	= "inode-state",
		.data		= &inodes_stat,
		.maxlen		= 7*sizeof(long),
		.mode		= 0444,
		.proc_handler	= proc_nr_inodes,
	},
};

static struct inode *simplefs_iget_internal(struct super_block *sb, unsigned long ino)
{
	struct inode *inode;
	struct simplefs_inode *din;
	struct buffer_head *bh;
	struct simplefs_sb_info *sbi = SIMPLEFS_SB(sb);
	unsigned long itable_block = sbi->s_itable_block;
	unsigned long per_block = sb->s_blocksize / sizeof(struct simplefs_inode);
	unsigned long block = itable_block + (ino / per_block);
	unsigned long offset = (ino % per_block) * sizeof(struct simplefs_inode);

	inode = new_inode(sb);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	bh = sb_bread(sb, block);
	if (!bh) {
		iput(inode);
		return ERR_PTR(-EIO);
	}

	din = (struct simplefs_inode *)(bh->b_data + offset);

	inode->i_ino = ino;
	inode_init_owner(&init_user_ns, inode, NULL, le16_to_cpu(din->i_mode));
	inode->i_mode = le16_to_cpu(din->i_mode);
	i_uid_write(inode, le16_to_cpu(din->i_uid));
	i_gid_write(inode, 0); /* optional: extend structure for gid */
	inode->i_size = le32_to_cpu(din->i_size);
	inode->i_atime.tv_sec = le32_to_cpu(din->i_atime);
	inode->i_mtime.tv_sec = le32_to_cpu(din->i_mtime);
	inode->i_ctime.tv_sec = le32_to_cpu(din->i_ctime);

	SIMPLEFS_I(inode)->i_blocks = le32_to_cpu(din->i_blocks);
	for (int i = 0; i < SIMPLEFS_N_BLOCKS; i++)
		SIMPLEFS_I(inode)->i_block_ptrs[i] = le32_to_cpu(din->i_block[i]);

	if (S_ISDIR(inode->i_mode)) {
		inode->i_op = &simple_dir_inode_operations;
		inode->i_fop = &simple_dir_operations;
	} else if (S_ISREG(inode->i_mode)) {
		inode->i_op = &simple_file_inode_operations;
		inode->i_fop = &simplefs_file_ops;
	} else if (S_ISLNK(inode->i_mode)) {
		inode->i_op = &page_symlink_inode_operations;
		inode->i_mapping->a_ops = &simple_aops;
	} else {
		init_special_inode(inode, inode->i_mode, 0);
	}

	brelse(bh);
	return inode;
}

int simplefs_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	struct super_block *sb = inode->i_sb;
	struct simplefs_sb_info *sbi = SIMPLEFS_SB(sb);
	struct simplefs_inode din;
	struct buffer_head *bh;
	unsigned long ino = inode->i_ino;
	unsigned long itable_block = sbi->s_itable_block;
	unsigned long per_block = sb->s_blocksize / sizeof(struct simplefs_inode);
	unsigned long block = itable_block + (ino / per_block);
	unsigned long offset = (ino % per_block) * sizeof(struct simplefs_inode);

	memset(&din, 0, sizeof(din));
	din.i_mode = cpu_to_le16(inode->i_mode);
	din.i_uid  = cpu_to_le16(from_kuid(&init_user_ns, inode->i_uid));
	din.i_size = cpu_to_le32(inode->i_size);
	din.i_atime = cpu_to_le32((u32)inode->i_atime.tv_sec);
	din.i_mtime = cpu_to_le32((u32)inode->i_mtime.tv_sec);
	din.i_ctime = cpu_to_le32((u32)inode->i_ctime.tv_sec);
	din.i_blocks = cpu_to_le32(SIMPLEFS_I(inode)->i_blocks);

	for (int i = 0; i < SIMPLEFS_N_BLOCKS; i++)
		din.i_block[i] = cpu_to_le32(SIMPLEFS_I(inode)->i_block_ptrs[i]);

	bh = sb_bread(sb, block);
	if (!bh)
		return -EIO;

	memcpy(bh->b_data + offset, &din, sizeof(din));
	mark_buffer_dirty(bh);
	sync_dirty_buffer(bh);
	brelse(bh);

	return 0;
}

static const struct inode_operations simple_file_inode_operations = {
	.setattr = simple_setattr,
};

struct inode *simplefs_iget_export(struct super_block *sb, unsigned long ino)
{
	return simplefs_iget_internal(sb, ino);
}

struct inode *simplefs_iget(struct super_block *sb, unsigned long ino)
{
	return simplefs_iget_internal(sb, ino);
}
