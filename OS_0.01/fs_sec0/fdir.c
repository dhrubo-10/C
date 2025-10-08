#include "fs.h"
#include "ondisk.h"

#include <linux/buffer_head.h>
#include <linux/slab.h>
#include <linux/string.h>

static struct dentry *simple_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags)
{
	struct super_block *sb = dir->i_sb;
	struct buffer_head *bh;
	struct simplefs_dir_entry *de;
	int i, j;
	uint32_t block;

	for (i = 0; i < SIMPLEFS_I(dir)->i_blocks; i++) {
		block = SIMPLEFS_I(dir)->i_block_ptrs[i];
		if (!block) continue;
		bh = sb_bread(sb, block);
		if (!bh) continue;
		de = (struct simplefs_dir_entry *)bh->b_data;
		for (j = 0; j < sb->s_blocksize / sizeof(*de); j++, de++) {
			if (le32_to_cpu(de->inode) && strcmp(de->name, dentry->d_name.name) == 0) {
				struct inode *inode = simplefs_iget(sb, le32_to_cpu(de->inode));
				if (inode) d_add(dentry, inode);
				brelse(bh);
				return NULL;
			}
		}
		brelse(bh);
	}
	return NULL;
}

static int simple_add_dir_entry(struct inode *dir, struct inode *inode, const char *name)
{
	struct super_block *sb = dir->i_sb;
	struct buffer_head *bh;
	struct simplefs_dir_entry *de;
	int i, j;
	uint32_t block;

	for (i = 0; i < ARRAY_SIZE(SIMPLEFS_I(dir)->i_block_ptrs); i++) {
		block = SIMPLEFS_I(dir)->i_block_ptrs[i];
		if (!block) {
			/* allocate new block */
			if (simplefs_balloc(sb, &block)) return -ENOSPC;
			SIMPLEFS_I(dir)->i_block_ptrs[i] = block;
			SIMPLEFS_I(dir)->i_blocks++;
		}
		bh = sb_bread(sb, block);
		if (!bh) return -EIO;
		de = (struct simplefs_dir_entry *)bh->b_data;
		for (j = 0; j < sb->s_blocksize / sizeof(*de); j++, de++) {
			if (!le32_to_cpu(de->inode)) {
				de->inode = cpu_to_le32(inode->i_ino);
				strncpy(de->name, name, SIMPLEFS_NAME_LEN);
				mark_buffer_dirty(bh);
				brelse(bh);
				return 0;
			}
		}
		brelse(bh);
	}
	return -ENOSPC;
}

static int simple_create(struct inode *dir, struct dentry *dentry, umode_t mode, bool excl)
{
	struct inode *inode = new_inode(dir->i_sb);
	int err = 0;

	if (!inode) return -ENOMEM;
	inode_init_owner(&init_user_ns, inode, dir, mode);
	inode->i_ino = get_next_ino();
	SIMPLEFS_I(inode)->i_blocks = 0;
	inode->i_fop = &simplefs_file_ops;
	inode->i_op = &simple_file_inode_operations;

	/* persist inode */
	simplefs_write_inode(inode, NULL);

	err = simple_add_dir_entry(dir, inode, dentry->d_name.name);
	if (err) {
		iput(inode);
		return err;
	}
	d_add(dentry, inode);
	inc_nlink(dir);
	mark_inode_dirty(dir);
	return 0;
}

static int simple_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct inode *inode = new_inode(dir->i_sb);
	int err;

	if (!inode) return -ENOMEM;
	inode_init_owner(&init_user_ns, inode, dir, S_IFDIR | mode);
	inode->i_ino = get_next_ino();
	SIMPLEFS_I(inode)->i_blocks = 0;
	inode->i_fop = &simple_dir_operations;
	inode->i_op  = &simple_dir_inode_operations;

	simplefs_write_inode(inode, NULL);
	err = simple_add_dir_entry(dir, inode, dentry->d_name.name);
	if (err) {
		iput(inode);
		return err;
	}
	d_add(dentry, inode);
	inc_nlink(dir);
	inc_nlink(inode);
	mark_inode_dirty(dir);
	return 0;
}

static int simple_unlink(struct inode *dir, struct dentry *dentry)
{
	/* Simplified: !! not fully implemented. Placeholder returning  */
	return -ENOTEMPTY;
}

const struct file_operations simple_dir_operations = {
	.llseek = noop_llseek,
};

const struct inode_operations simple_dir_inode_operations = {
	.lookup = simple_lookup,
	.create = simple_create,
	.mkdir  = simple_mkdir,
	.unlink = simple_unlink,
};
