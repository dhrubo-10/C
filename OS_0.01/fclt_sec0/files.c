/* Updated!! */
#include <errno.h>
#include <fcntl.h>

#include <linux/sched.h>
#include <linux/kernel.h>
#include <asm/segment.h>

#define MIN(a,b) ((a)<(b)?(a):(b))

int file_read(struct m_inode *inode, struct file *filp, char *buf, int count)
{
	int left = count;
	int block, off, n;
	struct buffer_head *bh;

	if (count <= 0)
		return 0;

	while (left > 0) {
		block = bmap(inode, filp->f_pos / BLOCK_SIZE);
		if (block > 0) {
			bh = bread(inode->i_dev, block);
			if (!bh)
				break;
		} else {
			bh = NULL;
		}

		off = filp->f_pos % BLOCK_SIZE;
		n = MIN(BLOCK_SIZE - off, left);
		filp->f_pos += n;
		left -= n;

		if (bh) {
			char *src = bh->b_data + off;
			for (int i = 0; i < n; i++)
				put_fs_byte(src[i], buf++);
			brelse(bh);
		} else {
			for (int i = 0; i < n; i++)
				put_fs_byte(0, buf++);
		}
	}

	inode->i_atime = CURRENT_TIME;
	return (count - left) > 0 ? (count - left) : -ERROR;
}


int file_write(struct m_inode *inode, struct file *filp, char *buf, int count)
{
	int written = 0;
	int block, off, n;
	struct buffer_head *bh;
	char *dst;
	off_t pos;

	pos = (filp->f_flags & O_APPEND) ? inode->i_size : filp->f_pos;

	while (written < count) {
		block = create_block(inode, pos / BLOCK_SIZE);
		if (!block)
			break;

		bh = bread(inode->i_dev, block);
		if (!bh)
			break;

		off = pos % BLOCK_SIZE;
		dst = bh->b_data + off;
		n = MIN(BLOCK_SIZE - off, count - written);

		for (int i = 0; i < n; i++)
			dst[i] = get_fs_byte(buf++);

		bh->b_dirt = 1;
		brelse(bh);

		pos += n;
		written += n;

		if (pos > inode->i_size) {
			inode->i_size = pos;
			inode->i_dirt = 1;
		}
	}

	inode->i_mtime = CURRENT_TIME;

	if (!(filp->f_flags & O_APPEND)) {
		filp->f_pos = pos;
		inode->i_ctime = CURRENT_TIME;
	}

	return written > 0 ? written : -1;
}
