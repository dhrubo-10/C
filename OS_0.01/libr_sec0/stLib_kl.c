/*
 *  Conversion between 31-bit and 64-bit native syscalls for s390
 *
 *  Rewritten for improved logic, security and ABI correctness.
 *
 *  Author: Lyliana (updated by SD.)
 */

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/errno.h>
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
#include <linux/limits.h>
#include <linux/bitops.h>

#include <asm/types.h>
#include <asm/page.h>

#include <net/scm.h>
#include <net/sock.h>

#include "compat_linux.h"


/* check if 64-bit unsigned fits in 32-bit unsigned */
static inline bool fits_in_u32(u64 v)
{
	return v <= (u64)UINT_MAX;
}

/* convert timespec sec -> u32 with checks */
static inline int timespec_to_u32_checked(const s64 tv_sec, __u32 *out)
{
	if (tv_sec < 0)
		return -EOVERFLOW;
	if (!fits_in_u32((u64)tv_sec))
		return -EOVERFLOW;
	*out = (__u32)tv_sec;
	return 0;
}

/* safe combine of two 32-bit halves into signed/unsigned 64-bit offset */
static inline loff_t compat_combine_u32_to_loff(u32 high, u32 low)
{
	return (loff_t)(((u64)high << 32) | (u64)low);
}

/* read a 32-bit user value safely */
static inline int get_u32_from_user(u32 __user *uaddr, u32 *out)
{
	u32 tmp;
	if (copy_from_user(&tmp, uaddr, sizeof(tmp)))
		return -EFAULT;
	*out = tmp;
	return 0;
}


/*
 * stat64_emu31 - on-disk/user structure presented to 31-bit userland.
 *
 * Always zero the entire struct before populating it to avoid leaking
 * kernel memory through padding.
 */
struct stat64_emu31 {
	__u64	st_dev;		/* Device ID */
	__u32	__pad1;

#define STAT64_HAS_BROKEN_ST_INO 1
	__u32	__st_ino;	

	__u32	st_mode;	
	__u32	st_nlink;	
	__u32	st_uid;		
	__u32	st_gid;		

	__u64	st_rdev;	
	__u32	__pad3;

	__s64	st_size;	
	__u32	st_blksize;	
	__u32	__pad4;
	__u32	__pad5;

	__u32	st_blocks;	

	__u32	st_atime;	
	__u32	__pad6;
	__u32	st_mtime;	
	__u32	__pad7;
	__u32	st_ctime;	
	__u32	__pad8;

	__u64	st_ino;		
};

static int cp_stat64(struct stat64_emu31 __user *ubuf, const struct kstat *stat)
{
	struct stat64_emu31 tmp;
	int ret = 0;
	int err;

	/* start with zeroed structure - prevents leaking padding/stack. */
	memset(&tmp, 0, sizeof(tmp));

	/* Device and inode */
	tmp.st_dev = huge_encode_dev(stat->dev);
	tmp.st_ino = stat->ino;

	if (!fits_in_u32(stat->ino)) {
		tmp.__st_ino = (__u32)(stat->ino & 0xffffffff);
		ret = -EOVERFLOW;
	} else {
		tmp.__st_ino = (__u32)stat->ino;
	}

	tmp.st_mode  = stat->mode;
	tmp.st_nlink = (u32)stat->nlink;
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

	err = timespec_to_u32_checked((s64)stat->atime.tv_sec, &tmp.st_atime);
	if (err)
		ret = -EOVERFLOW;
	err = timespec_to_u32_checked((s64)stat->mtime.tv_sec, &tmp.st_mtime);
	if (err)
		ret = -EOVERFLOW;
	err = timespec_to_u32_checked((s64)stat->ctime.tv_sec, &tmp.st_ctime);
	if (err)
		ret = -EOVERFLOW;

	/* copy to userspace, check failure */
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

	/* delegate to compat ks ipc handler */
	return compat_ksys_ipc(call, first, second, third, ptr, third);
}
#endif /* CONFIG_SYSVIPC */

COMPAT_SYSCALL_DEFINE3(s390_truncate64, const char __user *, path, u32, high, u32, low)
{
	loff_t len = compat_combine_u32_to_loff(high, low);
	return ksys_truncate(path, len);
}

COMPAT_SYSCALL_DEFINE3(s390_ftruncate64, unsigned int, fd, u32, high, u32, low)
{
	loff_t len = compat_combine_u32_to_loff(high, low);
	return ksys_ftruncate(fd, len);
}

COMPAT_SYSCALL_DEFINE5(s390_pread64, unsigned int, fd, char __user *, ubuf,
		       compat_size_t, count, u32, high, u32, low)
{
	if ((compat_ssize_t)count < 0)
		return -EINVAL;
	loff_t pos = compat_combine_u32_to_loff(high, low);
	return ksys_pread64(fd, ubuf, (size_t)count, pos);
}

COMPAT_SYSCALL_DEFINE5(s390_pwrite64, unsigned int, fd, const char __user *, ubuf,
		       compat_size_t, count, u32, high, u32, low)
{
	if ((compat_ssize_t)count < 0)
		return -EINVAL;
	loff_t pos = compat_combine_u32_to_loff(high, low);
	return ksys_pwrite64(fd, ubuf, (size_t)count, pos);
}

COMPAT_SYSCALL_DEFINE4(s390_readahead, int, fd, u32, high, u32, low, s32, count)
{
	loff_t pos = compat_combine_u32_to_loff(high, low);
	/* count can be negative in compat; validate */
	if (count < 0)
		return -EINVAL;
	return ksys_readahead(fd, pos, (size_t)count);
}

/* stat variants */
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


/* Minimal forward declarations for types referenced earlier.
 * Keep these small and explicit to avoid accidental dependency issues.
 */
struct fwctl_uctx {
	struct fwctl *fwctl;
	void *private;
	/* registration_lock assumed to be rwsem in fwctl */
};

struct fwctl_ioctl_op {
	unsigned int ioctl_num;
	size_t size;
	size_t min_size;
	int (*execute)(struct fwctl_ucmd *);
};

struct fwctl_ucmd {
	struct fwctl_uctx *uctx;
	void *cmd;
	void __user *ubuffer;
	size_t user_size;
};

COMPAT_SYSCALL_DEFINE3(s390_old_mmap, struct mmap_arg_struct_emu31 __user *, arg)
{
	struct mmap_arg_struct_emu31 a;

	if (copy_from_user(&a, arg, sizeof(a)))
		return -EFAULT;

	/* old mmap offsets must be page-aligned, validate */
	if (a.offset & ~PAGE_MASK)
		return -EINVAL;

	return ksys_mmap_pgoff(a.addr, a.len, a.prot, a.flags, a.fd, a.offset >> PAGE_SHIFT);
}

COMPAT_SYSCALL_DEFINE1(s390_mmap2, struct mmap_arg_struct_emu31 __user *, arg)
{
	struct mmap_arg_struct_emu31 a;

	if (copy_from_user(&a, arg, sizeof(a)))
		return -EFAULT;

	/* Offsets passed to mmap2 are already page-shifted on many ABIs; validate */
	return ksys_mmap_pgoff(a.addr, a.len, a.prot, a.flags, a.fd, a.offset);
}

/* simple wrappers for read/write - ensure count signedness validated */
COMPAT_SYSCALL_DEFINE3(s390_read, unsigned int, fd, char __user *, buf, compat_size_t, count)
{
	if ((compat_ssize_t)count < 0)
		return -EINVAL;
	return ksys_read(fd, buf, (size_t)count);
}

COMPAT_SYSCALL_DEFINE3(s390_write, unsigned int, fd, const char __user *, buf, compat_size_t, count)
{
	if ((compat_ssize_t)count < 0)
		return -EINVAL;
	return ksys_write(fd, buf, (size_t)count);
}

/* fadvise / fallocate / sync variants with safe combine of halves */
COMPAT_SYSCALL_DEFINE5(s390_fadvise64, int, fd, u32, high, u32, low, compat_size_t, len, int, advise)
{
	loff_t offset = compat_combine_u32_to_loff(high, low);

	if (advise == 4)
		advise = POSIX_FADV_DONTNEED;
	else if (advise == 5)
		advise = POSIX_FADV_NOREUSE;

	return ksys_fadvise64_64(fd, offset, len, advise);
}

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
	loff_t off = compat_combine_u32_to_loff(offhigh, offlow);
	loff_t n   = compat_combine_u32_to_loff(nhigh, nlow);
	return ksys_sync_file_range(fd, off, n, flags);
}

COMPAT_SYSCALL_DEFINE6(s390_fallocate, int, fd, int, mode, u32, offhigh, u32, offlow,
		       u32, lenhigh, u32, lenlow)
{
	loff_t off = compat_combine_u32_to_loff(offhigh, offlow);
	loff_t len = compat_combine_u32_to_loff(lenhigh, lenlow);
	return ksys_fallocate(fd, mode, off, len);
}


/* Example implementation — adapt op table / structures to your fwctl implementation */
static long fwctl_fops_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct fwctl_uctx *uctx = filp->private_data;
	const struct fwctl_ioctl_op *op;
	struct fwctl_ucmd ucmd;
	void *kbuf = NULL;
	u32 user_size;
	int nr, ret = 0;

	if (!uctx || !uctx->fwctl)
		return -ENODEV;

	nr = _IOC_NR(cmd);
	if ((nr - FWCTL_CMD_BASE) >= ARRAY_SIZE(fwctl_ioctl_ops))
		return -ENOIOCTLCMD;

	op = &fwctl_ioctl_ops[nr - FWCTL_CMD_BASE];
	if (op->ioctl_num != cmd)
		return -ENOIOCTLCMD;

	/* read user size from user buffer; user supplied pointer may be NULL */
	if (!arg)
		return -EINVAL;

	/* safe copy of user_size (first word at arg) */
	if (copy_from_user(&user_size, (u32 __user *)arg, sizeof(user_size)))
		return -EFAULT;

	/* basic size validations */
	if (user_size < op->min_size || user_size > op->size)
		return -EINVAL;

	/* allocate kernel buffer of op->size and zero it (avoid leaks) */
	kbuf = kzalloc(op->size, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	/* copy full user buffer into kbuf (size = user_size) */
	if (copy_from_user(kbuf, (void __user *)arg, user_size)) {
		ret = -EFAULT;
		goto out_free;
	}

	/* build ucmd and call op->execute under registration_lock */
	ucmd.uctx = uctx;
	ucmd.cmd = kbuf;
	ucmd.ubuffer = (void __user *)arg;
	ucmd.user_size = user_size;

	down_read(&uctx->fwctl->registration_lock);
	if (!uctx->fwctl->ops) {
		ret = -ENODEV;
		up_read(&uctx->fwctl->registration_lock);
		goto out_free;
	}

	ret = op->execute(&ucmd);
	up_read(&uctx->fwctl->registration_lock);

out_free:
	kfree(kbuf);
	return ret;
}

/**DONNEE */