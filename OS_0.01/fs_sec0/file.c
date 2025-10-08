#include "fs.h"
#include "ondisk.h"

#include <linux/buffer_head.h>
#include <linux/uaccess.h>

static ssize_t simple_read_file(struct file *filp, char __user *buf, size_t len, loff_t *ppos)
{
	struct inode *inode = file_inode(filp);
	struct super_block *sb = inode->i_sb;
	loff_t pos = *ppos;
	ssize_t ret = 0;
	uint32_t block_idx = pos / sb->s_blocksize;
	uint32_t block_offset = pos % sb->s_blocksize;
	uint32_t to_read;
	struct buffer_head *bh;

	if (pos >= inode->i_size) return 0;
	if (pos + len > inode->i_size) len = inode->i_size - pos;

	while (len) {
		if (block_idx >= SIMPLEFS_I(inode)->i_blocks) break;
		bh = sb_bread(sb, SIMPLEFS_I(inode)->i_block_ptrs[block_idx]);
		if (!bh) return -EIO;
		to_read = min((size_t)(sb->s_blocksize - block_offset), len);
		if (copy_to_user(buf, bh->b_data + block_offset, to_read)) {
			brelse(bh);
			return -EFAULT;
		}
		brelse(bh);
		buf += to_read;
		len -= to_read;
		ret += to_read;
		block_offset = 0;
		block_idx++;
	}
	*ppos += ret;
	return ret;
}

static ssize_t simple_write_file(struct file *filp, const char __user *buf, size_t len, loff_t *ppos)
{
	struct inode *inode = file_inode(filp);
	struct super_block *sb = inode->i_sb;
	loff_t pos = *ppos;
	ssize_t ret = 0;
	uint32_t block_idx = pos / sb->s_blocksize;
	uint32_t block_offset = pos % sb->s_blocksize;
	uint32_t to_write;
	struct buffer_head *bh;
	int err;

	while (len) {
		if (block_idx >= ARRAY_SIZE(SIMPLEFS_I(inode)->i_block_ptrs)) return -EFBIG;
		if (block_idx >= SIMPLEFS_I(inode)->i_blocks) {
			uint32_t newblock;
			err = simplefs_balloc(sb, &newblock);
			if (err) return err;
			SIMPLEFS_I(inode)->i_block_ptrs[block_idx] = newblock;
			SIMPLEFS_I(inode)->i_blocks++;
		}
		bh = sb_bread(sb, SIMPLEFS_I(inode)->i_block_ptrs[block_idx]);
		if (!bh) return -EIO;
		to_write = min((size_t)(sb->s_blocksize - block_offset), len);
		if (copy_from_user(bh->b_data + block_offset, buf, to_write)) {
			brelse(bh);
			return -EFAULT;
		}
		mark_buffer_dirty(bh);
		brelse(bh);
		buf += to_write;
		len -= to_write;
		ret += to_write;
		block_offset = 0;
		block_idx++;
	}
	*ppos += ret;
	if (*ppos > inode->i_size) {
		inode->i_size = *ppos;
		mark_inode_dirty(inode);
	}
	return ret;
}

const struct file_operations simplefs_file_ops = {
	.read = simple_read_file,
	.write = simple_write_file,
	.llseek = generic_file_llseek,
};
