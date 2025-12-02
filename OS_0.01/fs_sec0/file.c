#include "fs.h"
#include "ondisk.h"

#include <linux/buffer_head.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/slab.h>

static ssize_t simplefs_read_file(struct file *filp, char __user *buf, size_t len, loff_t *ppos)
{
	struct inode *inode = file_inode(filp);
	struct super_block *sb = inode->i_sb;
	struct simplefs_inode_info *si = SIMPLEFS_I(inode);
	loff_t pos = *ppos;
	ssize_t ret = 0;
	uint32_t block_idx, block_offset, to_read;
	struct buffer_head *bh;

	if (pos >= inode->i_size)
		return 0;

	if (pos + len > inode->i_size)
		len = inode->i_size - pos;

	while (len > 0) {
		block_idx = pos / sb->s_blocksize;
		block_offset = pos % sb->s_blocksize;

		if (block_idx >= si->i_blocks)
			break;

		bh = sb_bread(sb, si->i_block_ptrs[block_idx]);
		if (!bh)
			return -EIO;

		to_read = min_t(size_t, sb->s_blocksize - block_offset, len);

		if (copy_to_user(buf, bh->b_data + block_offset, to_read)) {
			brelse(bh);
			return -EFAULT;
		}

		brelse(bh);
		buf += to_read;
		len -= to_read;
		ret += to_read;
		pos += to_read;
	}

	*ppos = pos;
	return ret;
}

static ssize_t simplefs_write_file(struct file *filp, const char __user *buf, size_t len, loff_t *ppos)
{
	struct inode *inode = file_inode(filp);
	struct super_block *sb = inode->i_sb;
	struct simplefs_inode_info *si = SIMPLEFS_I(inode);
	loff_t pos = *ppos;
	ssize_t ret = 0;
	uint32_t block_idx, block_offset, to_write;
	struct buffer_head *bh;
	int err;

	while (len > 0) {
		block_idx = pos / sb->s_blocksize;
		block_offset = pos % sb->s_blocksize;

		if (block_idx >= ARRAY_SIZE(si->i_block_ptrs))
			return -EFBIG;

		if (block_idx >= si->i_blocks) {
			uint32_t newblock;
			err = simplefs_balloc(sb, &newblock);
			if (err)
				return err;

			si->i_block_ptrs[block_idx] = newblock;
			si->i_blocks++;
		}

		bh = sb_bread(sb, si->i_block_ptrs[block_idx]);
		if (!bh)
			return -EIO;

		to_write = min_t(size_t, sb->s_blocksize - block_offset, len);

		if (copy_from_user(bh->b_data + block_offset, buf, to_write)) {
			brelse(bh);
			return -EFAULT;
		}

		mark_buffer_dirty(bh);
		brelse(bh);

		buf += to_write;
		len -= to_write;
		ret += to_write;
		pos += to_write;
		block_offset = 0;
	}

	*ppos = pos;

	if (pos > inode->i_size) {
		inode->i_size = pos;
		mark_inode_dirty(inode);
	}

	return ret;
}

const struct file_operations simplefs_file_ops = {
	.read = simplefs_read_file,
	.write = simplefs_write_file,
	.llseek = generic_file_llseek,
};
