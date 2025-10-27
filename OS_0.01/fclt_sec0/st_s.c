#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/stat.h>
#include <linux/time.h>
#include <linux/namei.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <asm/segment.h>

static int cp_stat(struct m_inode *inode, struct stat __user *statbuf)
{
	struct stat tmp;

	if (!inode || !statbuf)
		return -EINVAL;

	memset(&tmp, 0, sizeof(struct stat));

	
	tmp.st_dev   = inode->i_dev;
	tmp.st_ino   = inode->i_num;
	tmp.st_mode  = inode->i_mode;
	tmp.st_nlink = inode->i_nlinks;
	tmp.st_uid   = inode->i_uid;
	tmp.st_gid   = inode->i_gid;
	tmp.st_rdev  = inode->i_zone[0];
	tmp.st_size  = inode->i_size;
	tmp.st_blksize = 1024;  
	tmp.st_blocks  = (inode->i_size + 511) / 512;
	tmp.st_atime = inode->i_atime;
	tmp.st_mtime = inode->i_mtime;
	tmp.st_ctime = inode->i_ctime;

	
	if (copy_to_user(statbuf, &tmp, sizeof(struct stat)))
		return -EFAULT;

	return 0;
}

int sys_stat(const char __user *filename, struct stat __user *statbuf)
{
	struct m_inode *inode;
	int ret = 0;

	if (!filename || !statbuf)
		return -EINVAL;

	inode = namei(filename);  /* resolve path to inode */
	if (!inode)
		return -ENOENT;

	
	ret = cp_stat(inode, statbuf);

	iput(inode);  /* release inode reference */
	return ret;
}

int sys_lstat(const char __user *filename, struct stat __user *statbuf)
{
	struct m_inode *inode;
	int ret = 0;

	if (!filename || !statbuf)
		return -EINVAL;

	inode = lnamei(filename);  
	if (!inode)
		return -ENOENT;

	ret = cp_stat(inode, statbuf);
	iput(inode);

	return ret;
}

int sys_fstat(unsigned int fd, struct stat __user *statbuf)
{
	struct file *f;
	struct m_inode *inode;

	if (!statbuf)
		return -EINVAL;

	if (fd >= NR_OPEN)
		return -EBADF;

	f = current->filp[fd];
	if (!f || !(inode = f->f_inode))
		return -EBADF;

	return cp_stat(inode, statbuf);
}


int sys_statx(int dirfd, const char __user *pathname, int flags,
              unsigned int mask, struct statx __user *buffer)
{
	struct m_inode *inode;
	struct stat tmp;
	int ret;
	if (!pathname || !buffer)
		return -EINVAL;

	inode = namei(pathname);
	if (!inode)
		return -ENOENT;

	ret = cp_stat(inode, (struct stat __user *)buffer);
	iput(inode);

	return ret;
}

void debug_print_inode_stat(struct m_inode *inode)
{
	if (!inode)
		return;

	printk(KERN_INFO "Inode %lu: mode=%o, size=%lu, nlink=%u, uid=%u, gid=%u\n",
	       (unsigned long)inode->i_num,
	       inode->i_mode,
	       inode->i_size,
	       inode->i_nlinks,
	       inode->i_uid,
	       inode->i_gid);
}
EXPORT_SYMBOL(debug_print_inode_stat);
