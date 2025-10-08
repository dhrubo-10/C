#include "fs.h"
#include "ondisk.h"

#include <linux/buffer_head.h>
#include <linux/slab.h>
#include <linux/namei.h>
#include <linux/statfs.h>

static const struct super_operations simplefs_super_ops;

int simple_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb = dentry->d_sb;
	struct simplefs_sb_info *sbi = SIMPLEFS_SB(sb);

	buf->f_type = SIMPLEFS_MAGIC;
	buf->f_bsize = sb->s_blocksize;
	buf->f_blocks = sbi->s_blocks_count;
	buf->f_bfree = 0; /* not tracked precisely here */
	buf->f_bavail = 0;
	buf->f_files = sbi->s_inodes_count;
	buf->f_ffree = 0;
	return 0;
}

int simplefs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct buffer_head *bh;
	struct simplefs_super *ds;
	struct inode *root;
	struct simplefs_sb_info *sbi;

	sbi = kzalloc(sizeof(*sbi), GFP_KERNEL);
	if (!sbi) return -ENOMEM;

	sb->s_fs_info = sbi;
	sb->s_blocksize = SIMPLEFS_BLOCK_SIZE;
	sb->s_blocksize_bits = 10;

	/* read superblock from block 0 */
	bh = sb_bread(sb, 0);
	if (!bh) {
		kfree(sbi);
		return -EIO;
	}
	ds = (struct simplefs_super *)bh->b_data;

	if (le32_to_cpu(ds->s_magic) != SIMPLEFS_SUPER_MAGIC) {
		pr_err("simplefs: bad magic\n");
		brelse(bh);
		kfree(sbi);
		return -EINVAL;
	}

	sbi->s_sbh = bh;
	sbi->s_inodes_count = le32_to_cpu(ds->s_inodes_count);
	sbi->s_blocks_count = le32_to_cpu(ds->s_blocks_count);
	sbi->s_first_data_block = le32_to_cpu(ds->s_first_data_block);
	sbi->s_itable_block = le32_to_cpu(ds->s_inode_table_block);
	sbi->s_bmap_block = le32_to_cpu(ds->s_block_bitmap_block);

	sb->s_magic = SIMPLEFS_MAGIC;
	sb->s_op = &simplefs_super_ops;

	root = simplefs_iget(sb, 0);
	if (!root) return -EIO;

	sb->s_root = d_make_root(root);
	if (!sb->s_root) {
		iput(root);
		return -ENOMEM;
	}

	return 0;
}

static const struct super_operations simplefs_super_ops = {
	.drop_inode = generic_delete_inode,
	.statfs = simple_statfs,
};
