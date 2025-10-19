/*
 *  Conversion between 31bit and 64bit native syscalls for s390
 *
 *  Updated by: Lyliana.
 *
 *  Notes:
 *  - On truncation of 64-bit fields to 32-bit compat fields this implementation
 *    returns -EOVERFLOW while still copying a truncated structure.
 */

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/file.h>
#include <linux/signal.h>
#include <linux/resource.h>
#include <linux/times.h>
#include <linux/smp.h>
#include <linux/sem.h>
#include <linux/msg.h>
#include <linux/shm.h>
#include <linux/uio.h>
#include <linux/quota.h>
#include <linux/poll.h>
#include <linux/personality.h>
#include <linux/stat.h>
#include <linux/filter.h>
#include <linux/highmem.h>
#include <linux/mman.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/icmpv6.h>
#include <linux/syscalls.h>
#include <linux/sysctl.h>
#include <linux/binfmts.h>
#include <linux/capability.h>
#include <linux/compat.h>
#include <linux/vfs.h>
#include <linux/ptrace.h>
#include <linux/fadvise.h>
#include <linux/ipc.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/rwsem.h>
#include <linux/time.h>
#include <linux/kdev_t.h>

#include <asm/types.h>

#include <net/scm.h>
#include <net/sock.h>

#include "compat_linux.h" 


/* check if 64-bit unsigned fits in 32-bit unsigned */
static inline bool fits_in_u32(u64 v)
{
	return v <= (u64)UINT_MAX;
}

static inline int timespec_to_u32_checked(const long tv_sec, __u32 *out)
{
	if (tv_sec < 0)
		return -EOVERFLOW;
	if (!fits_in_u32((u64)tv_sec))
		return -EOVERFLOW;
	*out = (__u32)tv_sec;
	return 0;
}

struct stat64_emu31 {
	__u64	st_dev;		/* Device ID */
	__u32	__pad1;

#define STAT64_HAS_BROKEN_ST_INO 1
	__u32	__st_ino;	/* Old 32-bit inode number */

	__u32	st_mode;	/* File mode */
	__u32	st_nlink;	/* Link count */
	__u32	st_uid;		/* User ID */
	__u32	st_gid;		/* Group ID */

	__u64	st_rdev;	/* Device type (if special file) */
	__u32	__pad3;

	__s64	st_size;	/* Total size, in bytes */
	__u32	st_blksize;	/* Block size for filesystem I/O */

	__u32	__pad4;
	__u32	__pad5;

	__u32	st_blocks;	/* 512B blocks allocated */

	__u32	st_atime;	/* Access time (seconds) */
	__u32	__pad6;
	__u32	st_mtime;	/* Modification time */
	__u32	__pad7;
	__u32	st_ctime;	/* Change time */
	__u32	__pad8;

	__u64	st_ino;		/* Full 64-bit inode number */
};

static int cp_stat64(struct stat64_emu31 __user *ubuf, struct kstat *stat)
{
	struct stat64_emu31 tmp;
	int ret = 0;

	memset(&tmp, 0, sizeof(tmp));

	/* Device and inode */
	tmp.st_dev   = huge_encode_dev(stat->dev);
	tmp.st_ino   = stat->ino;

	if (!fits_in_u32(stat->ino)) {
		tmp.__st_ino = (__u32)(stat->ino & 0xffffffff);
		ret = -EOVERFLOW;
	} else {
		tmp.__st_ino = (__u32)stat->ino;
	}

	tmp.st_mode  = stat->mode;
	tmp.st_nlink = (__u32)stat->nlink;
	tmp.st_uid   = from_kuid_munged(current_user_ns(), stat->uid);
	tmp.st_gid   = from_kgid_munged(current_user_ns(), stat->gid);
	tmp.st_rdev  = huge_encode_dev(stat->rdev);

	/* File size and storage */
	tmp.st_size = stat->size;

	if (!fits_in_u32(stat->blksize)) {
		tmp.st_blksize = (__u32)(stat->blksize & 0xffffffff);
		ret = -EOVERFLOW;
	} else {
		tmp.st_blksize = (__u32)stat->blksize;
	}

	if (!fits_in_u32(stat->blocks)) {
		tmp.st_blocks = (__u32)(stat->blocks & 0xffffffff);
		ret = -EOVERFLOW;
	} else {
		tmp.st_blocks = (__u32)stat->blocks;
	}

	if (timespec_to_u32_checked((long)stat->atime.tv_sec, &tmp.st_atime))
		ret = -EOVERFLOW;
	if (timespec_to_u32_checked((long)stat->mtime.tv_sec, &tmp.st_mtime))
		ret = -EOVERFLOW;
	if (timespec_to_u32_checked((long)stat->ctime.tv_sec, &tmp.st_ctime))
		ret = -EOVERFLOW;

	/* Copy out - if copy_to_user fails, return -EFAULT */
	if (copy_to_user(ubuf, &tmp, sizeof(tmp)))
		return -EFAULT;

	return ret;
}


#ifdef CONFIG_SYSVIPC
COMPAT_SYSCALL_DEFINE5(s390_ipc, uint, call, int, first, compat_ulong_t, second,
		       compat_ulong_t, third, compat_uptr_t, ptr)
{
	/* backward compatibility: old callers use call >> 16 */
	if (call >> 16)
		return -EINVAL;
	return compat_ksys_ipc(call, first, second, third, ptr, third);
}
#endif

COMPAT_SYSCALL_DEFINE3(s390_truncate64, const char __user *, path, u32, high, u32, low)
{
	loff_t len = ((loff_t)high << 32) | (u32)low;
	return ksys_truncate(path, len);
}

COMPAT_SYSCALL_DEFINE3(s390_ftruncate64, unsigned int, fd, u32, high, u32, low)
{
	loff_t len = ((loff_t)high << 32) | (u32)low;
	return ksys_ftruncate(fd, len);
}

COMPAT_SYSCALL_DEFINE5(s390_pread64, unsigned int, fd, char __user *, ubuf,
		       compat_size_t, count, u32, high, u32, low)
{
	if ((compat_ssize_t)count < 0)
		return -EINVAL;
	loff_t pos = ((loff_t)high << 32) | (u32)low;
	return ksys_pread64(fd, ubuf, count, pos);
}

COMPAT_SYSCALL_DEFINE5(s390_pwrite64, unsigned int, fd, const char __user *, ubuf,
		       compat_size_t, count, u32, high, u32, low)
{
	if ((compat_ssize_t)count < 0)
		return -EINVAL;
	loff_t pos = ((loff_t)high << 32) | (u32)low;
	return ksys_pwrite64(fd, ubuf, count, pos);
}

COMPAT_SYSCALL_DEFINE4(s390_readahead, int, fd, u32, high, u32, low, s32, count)
{
	loff_t pos = ((loff_t)high << 32) | (u32)low;
	return ksys_readahead(fd, pos, count);
}

COMPAT_SYSCALL_DEFINE2(s390_stat64, const char __user *, filename, struct stat64_emu31 __user *, statbuf)
{
	struct kstat stat;
	int ret;

	ret = vfs_stat(filename, &stat);
	if (ret)
		return ret;
	return cp_stat64(statbuf, &stat);
}

COMPAT_SYSCALL_DEFINE2(s390_lstat64, const char __user *, filename, struct stat64_emu31 __user *, statbuf)
{
	struct kstat stat;
	int ret;

	ret = vfs_lstat(filename, &stat);
	if (ret)
		return ret;
	return cp_stat64(statbuf, &stat);
}

COMPAT_SYSCALL_DEFINE2(s390_fstat64, unsigned int, fd, struct stat64_emu31 __user *, statbuf)
{
	struct kstat stat;
	int ret;

	ret = vfs_fstat(fd, &stat);
	if (ret)
		return ret;
	return cp_stat64(statbuf, &stat);
}

COMPAT_SYSCALL_DEFINE4(s390_fstatat64, unsigned int, dfd,
		       const char __user *, filename,
		       struct stat64_emu31 __user *, statbuf,
		       int, flag)
{
	struct kstat stat;
	int ret;

	ret = vfs_fstatat(dfd, filename, &stat, flag);
	if (ret)
		return ret;
	return cp_stat64(statbuf, &stat);
}

struct fwctl_uctx;
struct fwctl_ioctl_op;
struct fwctl_ucmd;
union fwctl_ucmd_buffer;

static long fwctl_fops_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct fwctl_uctx *uctx = filp->private_data;
	const struct fwctl_ioctl_op *op;
	struct fwctl_ucmd ucmd = {};
	union fwctl_ucmd_buffer buf;
	unsigned int nr;
	int ret;

	nr = _IOC_NR(cmd);
	if ((nr - FWCTL_CMD_BASE) >= ARRAY_SIZE(fwctl_ioctl_ops))
		return -ENOIOCTLCMD;

	op = &fwctl_ioctl_ops[nr - FWCTL_CMD_BASE];
	if (op->ioctl_num != cmd)
		return -ENOIOCTLCMD;

	ucmd.uctx = uctx;
	ucmd.cmd = &buf;
	ucmd.ubuffer = (void __user *)arg;

	{
		u32 user_size;
		if (get_user(user_size, (u32 __user *)ucmd.ubuffer))
			return -EFAULT;
		ucmd.user_size = user_size;
	}

	if (ucmd.user_size < op->min_size)
		return -EINVAL;

	ret = copy_struct_from_user(ucmd.cmd, op->size, ucmd.ubuffer, ucmd.user_size);
	if (ret)
		return ret;

	down_read(&uctx->fwctl->registration_lock);
	if (!uctx->fwctl->ops) {
		up_read(&uctx->fwctl->registration_lock);
		return -ENODEV;
	}

	ret = op->execute(&ucmd);
	up_read(&uctx->fwctl->registration_lock);

	return ret;
}


COMPAT_SYSCALL_DEFINE1(s390_old_mmap, struct mmap_arg_struct_emu31 __user *, arg)
{
	struct mmap_arg_struct_emu31 a;

	if (copy_from_user(&a, arg, sizeof(a)))
		return -EFAULT;
	if (a.offset & ~PAGE_MASK)
		return -EINVAL;
	return ksys_mmap_pgoff(a.addr, a.len, a.prot, a.flags, a.fd,
			       a.offset >> PAGE_SHIFT);
}

COMPAT_SYSCALL_DEFINE1(s390_mmap2, struct mmap_arg_struct_emu31 __user *, arg)
{
	struct mmap_arg_struct_emu31 a;

	if (copy_from_user(&a, arg, sizeof(a)))
		return -EFAULT;
	return ksys_mmap_pgoff(a.addr, a.len, a.prot, a.flags, a.fd, a.offset);
}

COMPAT_SYSCALL_DEFINE3(s390_read, unsigned int, fd, char __user *, buf, compat_size_t, count)
{
	if ((compat_ssize_t)count < 0)
		return -EINVAL;
	return ksys_read(fd, buf, count);
}

COMPAT_SYSCALL_DEFINE3(s390_write, unsigned int, fd, const char __user *, buf, compat_size_t, count)
{
	if ((compat_ssize_t)count < 0)
		return -EINVAL;
	return ksys_write(fd, buf, count);
}

COMPAT_SYSCALL_DEFINE5(s390_fadvise64, int, fd, u32, high, u32, low, compat_size_t, len, int, advise)
{
	long long offset = ((long long)high << 32) | (u32)low;

	if (advise == 4)
		advise = POSIX_FADV_DONTNEED;
	else if (advise == 5)
		advise = POSIX_FADV_NOREUSE;

	return ksys_fadvise64_64(fd, offset, len, advise);
}

struct fadvise64_64_args {
	int fd;
	long long offset;
	long long len;
	int advice;
};

COMPAT_SYSCALL_DEFINE1(s390_fadvise64_64, struct fadvise64_64_args __user *, args)
{
	struct fadvise64_64_args a;

	if (copy_from_user(&a, args, sizeof(a)))
		return -EFAULT;

	if (a.advice == 4)
		a.advice = POSIX_FADV_DONTNEED;
	else if (a.advice == 5)
		a.advice = POSIX_FADV_NOREUSE;

	return ksys_fadvise64_64(a.fd, a.offset, a.len, a.advice);
}

COMPAT_SYSCALL_DEFINE6(s390_sync_file_range, int, fd, u32, offhigh, u32, offlow,
		       u32, nhigh, u32, nlow, unsigned int, flags)
{
	loff_t off = ((loff_t)offhigh << 32) + (u32)offlow;
	loff_t n = ((loff_t)nhigh << 32) + (u32)nlow;
	return ksys_sync_file_range(fd, off, n, flags);
}

COMPAT_SYSCALL_DEFINE6(s390_fallocate, int, fd, int, mode, u32, offhigh, u32, offlow,
		       u32, lenhigh, u32, lenlow)
{
	loff_t off = ((loff_t)offhigh << 32) + (u32)offlow;
	loff_t len = ((loff_t)lenhigh << 32) + (u32)lenlow;
	return ksys_fallocate(fd, mode, off, len);
}
