#include <linux/fs.h>
#include <linux/buffer_head.h>
#include <linux/uaccess.h>
#include <linux/time.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/slab.h>

#define BLOCK_SIZE    1024  
#define BLOCK_SHIFT   10    

static inline unsigned long block_nr_from_pos(loff_t pos)
{
    return pos >> BLOCK_SHIFT;
}

ssize_t file_read(struct inode *inode, struct file *filp,
                  char __user *buf, size_t count)
{
    loff_t pos = filp->f_pos;
    size_t left = count;
    ssize_t total = 0;

    if (count == 0)
        return 0;

    inode_lock(inode);

    while (left > 0) {
        unsigned long block = bmap(inode, block_nr_from_pos(pos));
        size_t off = pos & (BLOCK_SIZE - 1);
        size_t n = min(left, (size_t)(BLOCK_SIZE - off));
        struct buffer_head *bh;

        if (block > 0) {
            bh = sb_bread(inode->i_sb, block);
            if (!bh) {
                /* I/O error while reading block */
                total = -EIO;
                break;
            }
        } else {
            bh = NULL;
        }

        /* If beyond EOF, return what we've read so far */
        if (pos >= i_size_read(inode)) {
            if (bh)
                brelse(bh);
            break;
        }

        /* Trim to EOF if necessary */
        if (pos + n > i_size_read(inode))
            n = i_size_read(inode) - pos;

        if (n == 0) {
            if (bh)
                brelse(bh);
            break;
        }

        if (bh) {
            void *kaddr = bh->b_data + off;
            if (copy_to_user(buf + total, kaddr, n)) {
                brelse(bh);
                total = -EFAULT;
                break;
            }
            brelse(bh);
        } else {
            /* a hole - return zeroes */
            void *zero_buf = kzalloc(n, GFP_KERNEL);
            if (!zero_buf) {
                total = -ENOMEM;
                break;
            }
            if (copy_to_user(buf + total, zero_buf, n)) {
                kfree(zero_buf);
                total = -EFAULT;
                break;
            }
            kfree(zero_buf);
        }

        pos += n;
        left -= n;
        total += n;
    }

    filp->f_pos = pos;

    inode->i_atime = current_time(inode);
    mark_inode_dirty(inode);

    inode_unlock(inode);

    return (total > 0) ? total : total; /* total already holds error or bytes */
}

ssize_t file_write(struct inode *inode, struct file *filp,
                   const char __user *buf, size_t count)
{
    loff_t pos;
    size_t left = count;
    ssize_t written = 0;

    if (count == 0)
        return 0;

    inode_lock(inode);

    pos = (filp->f_flags & O_APPEND) ? i_size_read(inode) : filp->f_pos;

    while (left > 0) {
        unsigned long block;
        size_t off = pos & (BLOCK_SIZE - 1);
        size_t n = min(left, (size_t)(BLOCK_SIZE - off));
        struct buffer_head *bh;

        block = create_block(inode, block_nr_from_pos(pos));
        if (!block) {
            written = -ENOSPC;
            break;
        }

        bh = sb_bread(inode->i_sb, block);
        if (!bh) {
            written = -EIO;
            break;
        }

        /* Copy user data directly into the buffer head */
        if (copy_from_user(bh->b_data + off, buf + written, n)) {
            brelse(bh);
            written = -EFAULT;
            break;
        }

        mark_buffer_dirty(bh);
        brelse(bh);

        pos += n;
        left -= n;
        written += n;

        /* update inode size if we extended the file */
        if (pos > i_size_read(inode)) {
            i_size_write(inode, pos);
            mark_inode_dirty(inode);
        }
    }

    inode->i_mtime = current_time(inode);

    if (!(filp->f_flags & O_APPEND)) {
        filp->f_pos = pos;
        inode->i_ctime = current_time(inode);
        mark_inode_dirty(inode);
    }

    inode_unlock(inode);

    return (written >= 0) ? written : written; /* return bytes written or error */
}
