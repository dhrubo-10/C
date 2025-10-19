#include "fs.h"
#include "ondisk.h"

#include <linux/buffer_head.h>
#include <linux/slab.h>
#include <linux/time.h>
#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/exportfs.h>

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
