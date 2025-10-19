#include "fs.h"
#include "ondisk.h"

#include <linux/buffer_head.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

static struct dentry *simplefs_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags)
{
	struct super_block *sb = dir->i_sb;
	struct buffer_head *bh;
	struct simplefs_dir_entry *de;
	struct inode *inode = NULL;
	uint32_t block;
	int i, j;

	for (i = 0; i < SIMPLEFS_I(dir)->i_blocks; i++) {
		block = SIMPLEFS_I(dir)->i_block_ptrs[i];
		if (!block)
			continue;

		bh = sb_bread(sb, block);
		if (!bh)
			continue;

		de = (struct simplefs_dir_entry *)bh->b_data;
		for (j = 0; j < sb->s_blocksize / sizeof(*de); j++, de++) {
			if (le32_to_cpu(de->inode) &&
			    strncmp(de->name, dentry->d_name.name, SIMPLEFS_NAME_LEN) == 0) {
				inode = simplefs_iget(sb, le32_to_cpu(de->inode));
				if (inode)
					d_add(dentry, inode);
				brelse(bh);
				return NULL;
			}
		}
		brelse(bh);
	}

	d_add(dentry, NULL);
	return NULL;
}

static int simplefs_add_dir_entry(struct inode *dir, struct inode *inode, const char *name)
{
	struct super_block *sb = dir->i_sb;
	struct buffer_head *bh;
	struct simplefs_dir_entry *de;
	uint32_t block;
	int i, j, err;

	for (i = 0; i < ARRAY_SIZE(SIMPLEFS_I(dir)->i_block_ptrs); i++) {
		block = SIMPLEFS_I(dir)->i_block_ptrs[i];

		if (!block) {
			err = simplefs_balloc(sb, &block);
			if (err)
				return err;

			SIMPLEFS_I(dir)->i_block_ptrs[i] = block;
			SIMPLEFS_I(dir)->i_blocks++;
		}

		bh = sb_bread(sb, block);
		if (!bh)
			return -EIO;

		de = (struct simplefs_dir_entry *)bh->b_data;
		for (j = 0; j < sb->s_blocksize / sizeof(*de); j++, de++) {
			if (!le32_to_cpu(de->inode)) {
				de->inode = cpu_to_le32(inode->i_ino);
				strncpy(de->name, name, SIMPLEFS_NAME_LEN - 1);
				de->name[SIMPLEFS_NAME_LEN - 1] = '\0';
				mark_buffer_dirty(bh);
				brelse(bh);
				return 0;
			}
		}

		brelse(bh);
	}

	return -ENOSPC;
}

static int simplefs_create(struct inode *dir, struct dentry *dentry, umode_t mode, bool excl)
{
	struct inode *inode;
	int err;

	inode = new_inode(dir->i_sb);
	if (!inode)
		return -ENOMEM;

	inode_init_owner(&init_user_ns, inode, dir, mode);
	inode->i_ino = get_next_ino();
	SIMPLEFS_I(inode)->i_blocks = 0;
	inode->i_fop = &simplefs_file_ops;
	inode->i_op = &simple_file_inode_operations;

	err = simplefs_write_inode(inode, NULL);
	if (err) {
		iput(inode);
		return err;
	}

	err = simplefs_add_dir_entry(dir, inode, dentry->d_name.name);
	if (err) {
		iput(inode);
		return err;
	}

	d_add(dentry, inode);
	inc_nlink(dir);
	mark_inode_dirty(dir);

	return 0;
}

static int simplefs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct inode *inode;
	int err;

	inode = new_inode(dir->i_sb);
	if (!inode)
		return -ENOMEM;

	inode_init_owner(&init_user_ns, inode, dir, S_IFDIR | mode);
	inode->i_ino = get_next_ino();
	SIMPLEFS_I(inode)->i_blocks = 0;
	inode->i_fop = &simple_dir_operations;
	inode->i_op = &simple_dir_inode_operations;

	err = simplefs_write_inode(inode, NULL);
	if (err) {
		iput(inode);
		return err;
	}

	err = simplefs_add_dir_entry(dir, inode, dentry->d_name.name);
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

static int simplefs_unlink(struct inode *dir, struct dentry *dentry)
{
	/* Future work: directory entry cleanup and inode truncation */
	return -EOPNOTSUPP;
}

const struct file_operations simple_dir_operations = {
	.llseek = noop_llseek,
};

const struct inode_operations simple_dir_inode_operations = {
	.lookup = simplefs_lookup,
	.create = simplefs_create,
	.mkdir  = simplefs_mkdir,
	.unlink = simplefs_unlink,
};
