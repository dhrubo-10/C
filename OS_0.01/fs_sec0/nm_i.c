#include "fs.h"
#include "ondisk.h"

#include <linux/buffer_head.h>
#include <linux/slab.h>
#include <linux/namei.h>
#include <linux/statfs.h>

static const struct super_operations simplefs_super_ops;

int simplefs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb = dentry->d_sb;
	struct simplefs_sb_info *sbi = SIMPLEFS_SB(sb);

	buf->f_type = SIMPLEFS_MAGIC;
	buf->f_bsize = sb->s_blocksize;
	buf->f_blocks = sbi->s_blocks_count;
	buf->f_bfree = sbi->s_free_blocks;
	buf->f_bavail = sbi->s_free_blocks;
	buf->f_files = sbi->s_inodes_count;
	buf->f_ffree = sbi->s_free_inodes;
	buf->f_namelen = SIMPLEFS_NAME_LEN;

	return 0;
}

int simplefs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct buffer_head *bh;
	struct simplefs_super *ds;
	struct inode *root;
	struct simplefs_sb_info *sbi;

	sbi = kzalloc(sizeof(*sbi), GFP_KERNEL);
	if (!sbi)
		return -ENOMEM;

	sb->s_fs_info = sbi;
	sb->s_blocksize = SIMPLEFS_BLOCK_SIZE;
	sb->s_blocksize_bits = ilog2(SIMPLEFS_BLOCK_SIZE);
	sb->s_magic = SIMPLEFS_MAGIC;
	sb->s_op = &simplefs_super_ops;

	bh = sb_bread(sb, SIMPLEFS_SUPERBLOCK_BLOCK_NUMBER);
	if (!bh) {
		kfree(sbi);
		return -EIO;
	}

	ds = (struct simplefs_super *)bh->b_data;

	if (le32_to_cpu(ds->s_magic) != SIMPLEFS_SUPER_MAGIC) {
		brelse(bh);
		kfree(sbi);
		return -EINVAL;
	}

	sbi->s_sbh = bh;
	sbi->s_inodes_count = le32_to_cpu(ds->s_inodes_count);
	sbi->s_blocks_count = le32_to_cpu(ds->s_blocks_count);
	sbi->s_free_blocks = le32_to_cpu(ds->s_free_blocks);
	sbi->s_free_inodes = le32_to_cpu(ds->s_free_inodes);
	sbi->s_first_data_block = le32_to_cpu(ds->s_first_data_block);
	sbi->s_itable_block = le32_to_cpu(ds->s_inode_table_block);
	sbi->s_bmap_block = le32_to_cpu(ds->s_block_bitmap_block);

	root = simplefs_iget(sb, SIMPLEFS_ROOT_INODE_NUMBER);
	if (IS_ERR(root)) {
		brelse(bh);
		kfree(sbi);
		return PTR_ERR(root);
	}

	sb->s_root = d_make_root(root);
	if (!sb->s_root) {
		iput(root);
		brelse(bh);
		kfree(sbi);
		return -ENOMEM;
	}

	return 0;
}

static const struct super_operations simplefs_super_ops = {
	.drop_inode = generic_delete_inode,
	.statfs = simplefs_statfs,
};
