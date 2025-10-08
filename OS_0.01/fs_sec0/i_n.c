#include "fs.h"
#include "ondisk.h"

#include <linux/buffer_head.h>
#include <linux/slab.h>
#include <linux/time.h>

static struct inode *simplefs_iget(struct super_block *sb, unsigned long ino)
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
	if (!inode) return NULL;

	bh = sb_bread(sb, block);
	if (!bh) {
		iput(inode);
		return NULL;
	}
	din = (struct simplefs_inode *)(bh->b_data + offset);

	inode->i_ino = ino;
	inode_init_owner(&init_user_ns, inode, NULL, le16_to_cpu(din->i_mode));
	inode->i_mode = le16_to_cpu(din->i_mode);
	inode->i_uid.val = le16_to_cpu(din->i_uid);
	inode->i_size = le32_to_cpu(din->i_size);
	inode->i_atime.tv_sec = le32_to_cpu(din->i_atime);
	inode->i_mtime.tv_sec = le32_to_cpu(din->i_mtime);
	inode->i_ctime.tv_sec = le32_to_cpu(din->i_ctime);

	SIMPLEFS_I(inode)->i_blocks = le32_to_cpu(din->i_blocks);
	for (int i = 0; i < 12; i++)
		SIMPLEFS_I(inode)->i_block_ptrs[i] = le32_to_cpu(din->i_block[i]);

	if (S_ISDIR(inode->i_mode)) {
		inode->i_fop = &simple_dir_operations;
		inode->i_op  = &simple_dir_inode_operations;
	} else {
		inode->i_fop = &simplefs_file_ops;
		inode->i_op  = &simple_file_inode_operations;
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
	din.i_uid  = cpu_to_le16((u16)inode->i_uid.val);
	din.i_size = cpu_to_le32((u32)inode->i_size);
	din.i_atime = cpu_to_le32((u32)inode->i_atime.tv_sec);
	din.i_mtime = cpu_to_le32((u32)inode->i_mtime.tv_sec);
	din.i_ctime = cpu_to_le32((u32)inode->i_ctime.tv_sec);
	din.i_blocks = cpu_to_le32(SIMPLEFS_I(inode)->i_blocks);
	for (int i = 0; i < 12; i++)
		din.i_block[i] = cpu_to_le32(SIMPLEFS_I(inode)->i_block_ptrs[i]);

	bh = sb_bread(sb, block);
	if (!bh) return -EIO;

	memcpy(bh->b_data + offset, &din, sizeof(din));
	mark_buffer_dirty(bh);
	brelse(bh);
	return 0;
}

static const struct inode_operations simple_file_inode_operations = {
	.write_inode = simplefs_write_inode,
};

struct inode *simplefs_iget_export(struct super_block *sb, unsigned long ino)
{
	return simplefs_iget(sb, ino);
}

struct inode *simplefs_iget(struct super_block *sb, unsigned long ino)
{
	return simplefs_iget(sb, ino);
}
