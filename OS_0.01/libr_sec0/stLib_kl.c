/*  Conversion between 31bit and 64bit native syscalls.
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

#include <asm/types.h>
#include <linux/uaccess.h>

#include <net/scm.h>
#include <net/sock.h>

#include "compat_linux.h" /* not finished & included yet */

#ifdef CONFIG_SYSVIPC
COMPAT_SYSCALL_DEFINE5(s390_ipc, uint, call, int, first, compat_ulong_t, second,
		compat_ulong_t, third, compat_uptr_t, ptr)
{
	if (call >> 16)		/* hack for backward compatibility */
		return -EINVAL;
	return compat_ksys_ipc(call, first, second, third, ptr, third);
}
#endif

COMPAT_SYSCALL_DEFINE3(s390_truncate64, const char __user *, path, u32, high, u32, low)
{
	return ksys_truncate(path, (unsigned long)high << 32 | low);
}

COMPAT_SYSCALL_DEFINE3(s390_ftruncate64, unsigned int, fd, u32, high, u32, low)
{
	return ksys_ftruncate(fd, (unsigned long)high << 32 | low);
}

COMPAT_SYSCALL_DEFINE5(s390_pread64, unsigned int, fd, char __user *, ubuf,
		       compat_size_t, count, u32, high, u32, low)
{
	if ((compat_ssize_t) count < 0)
		return -EINVAL;
	return ksys_pread64(fd, ubuf, count, (unsigned long)high << 32 | low);
}

COMPAT_SYSCALL_DEFINE5(s390_pwrite64, unsigned int, fd, const char __user *, ubuf,
		       compat_size_t, count, u32, high, u32, low)
{
	if ((compat_ssize_t) count < 0)
		return -EINVAL;
	return ksys_pwrite64(fd, ubuf, count, (unsigned long)high << 32 | low);
}

COMPAT_SYSCALL_DEFINE4(s390_readahead, int, fd, u32, high, u32, low, s32, count)
{
	return ksys_readahead(fd, (unsigned long)high << 32 | low, count);
}

/*
 * stat64_emu31: A 32-bit emulation of struct stat64
 * - Provides compatibility for 32-bit userland on 64-bit kernels
 * - Fields match old Linux ABI requirements
 */
struct stat64_emu31 {
    __u64   st_dev;        /* Device ID */
    __u32   __pad1;        /* Padding (ABI alignment) */

#define STAT64_HAS_BROKEN_ST_INO  1
    __u32   __st_ino;      /* Old 32-bit inode number */

    __u32   st_mode;       /* File mode */
    __u32   st_nlink;      /* Link count */
    __u32   st_uid;        /* User ID */
    __u32   st_gid;        /* Group ID */

    __u64   st_rdev;       /* Device type (if special file) */
    __u32   __pad3;        /* Padding */

    __s64   st_size;       /* Total size, in bytes */
    __u32   st_blksize;    /* Block size for filesystem I/O */

    __u32   __pad4;        /* Padding */
    __u32   __pad5;        /* Future st_blocks high bits */

    __u32   st_blocks;     /* 512B blocks allocated */

    __u32   st_atime;      /* Access time (seconds) */
    __u32   __pad6;        /* High 32 bits of atime (future use) */
    __u32   st_mtime;      /* Modification time */
    __u32   __pad7;        /* High 32 bits of mtime (future use) */
    __u32   st_ctime;      /* Change time */
    __u32   __pad8;        /* High 32 bits of ctime (future use) */

    __u64   st_ino;        /* Full 64-bit inode number */
};

static int cp_stat64(struct stat64_emu31 __user *ubuf, struct kstat *stat)
{
	struct stat64_emu31 tmp;

	memset(&tmp, 0, sizeof(tmp));

	tmp.st_dev = huge_encode_dev(stat->dev);
	tmp.st_ino = stat->ino;
	tmp.__st_ino = (u32)stat->ino;
	tmp.st_mode = stat->mode;
	tmp.st_nlink = (unsigned int)stat->nlink;
	tmp.st_uid = from_kuid_munged(current_user_ns(), stat->uid);
	tmp.st_gid = from_kgid_munged(current_user_ns(), stat->gid);
	tmp.st_rdev = huge_encode_dev(stat->rdev);
	tmp.st_size = stat->size;
	tmp.st_blksize = (u32)stat->blksize;
	tmp.st_blocks = (u32)stat->blocks;
	tmp.st_atime = (u32)stat->atime.tv_sec;
	tmp.st_mtime = (u32)stat->mtime.tv_sec;
	tmp.st_ctime = (u32)stat->ctime.tv_sec;

	return copy_to_user(ubuf,&tmp,sizeof(tmp)) ? -EFAULT : 0; 
}

COMPAT_SYSCALL_DEFINE2(s390_stat64, const char __user *, filename, struct stat64_emu31 __user *, statbuf)
{
	struct kstat stat;
	int ret = vfs_stat(filename, &stat);
	if (!ret)
		ret = cp_stat64(statbuf, &stat);
	return ret;
}

COMPAT_SYSCALL_DEFINE2(s390_lstat64, const char __user *, filename, struct stat64_emu31 __user *, statbuf)
{
	struct kstat stat;
	int ret = vfs_lstat(filename, &stat);
	if (!ret)
		ret = cp_stat64(statbuf, &stat);
	return ret;
}

COMPAT_SYSCALL_DEFINE2(s390_fstat64, unsigned int, fd, struct stat64_emu31 __user *, statbuf)
{
	struct kstat stat;
	int ret = vfs_fstat(fd, &stat);
	if (!ret)
		ret = cp_stat64(statbuf, &stat);
	return ret;
}

COMPAT_SYSCALL_DEFINE4(s390_fstatat64, unsigned int, dfd, const char __user *, filename,
		       struct stat64_emu31 __user *, statbuf, int, flag)
{
	struct kstat stat;
	int error;

	error = vfs_fstatat(dfd, filename, &stat, flag);
	if (error)
		return error;
	return cp_stat64(statbuf, &stat);
}



static long fwctl_fops_ioctl(struct file *filp, unsigned int cmd,
			       unsigned long arg)
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
	ret = get_user(ucmd.user_size, (u32 __user *)ucmd.ubuffer);
	if (ret)
		return ret;

	if (ucmd.user_size < op->min_size)
		return -EINVAL;

	ret = copy_struct_from_user(ucmd.cmd, op->size, ucmd.ubuffer,
				    ucmd.user_size);
	if (ret)
		return ret;

	guard(rwsem_read)(&uctx->fwctl->registration_lock);
	if (!uctx->fwctl->ops)
		return -ENODEV;
	return op->execute(&ucmd);
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
	if ((compat_ssize_t) count < 0)
		return -EINVAL; 

	return ksys_read(fd, buf, count);
}

COMPAT_SYSCALL_DEFINE3(s390_write, unsigned int, fd, const char __user *, buf, compat_size_t, count)
{
	if ((compat_ssize_t) count < 0)
		return -EINVAL; 

	return ksys_write(fd, buf, count);
}


COMPAT_SYSCALL_DEFINE5(s390_fadvise64, int, fd, u32, high, u32, low, compat_size_t, len, int, advise)
{
	if (advise == 4)
		advise = POSIX_FADV_DONTNEED;
	else if (advise == 5)
		advise = POSIX_FADV_NOREUSE;
	return ksys_fadvise64_64(fd, (unsigned long)high << 32 | low, len,
				 advise);
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

	if ( copy_from_user(&a, args, sizeof(a)) )
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
	return ksys_sync_file_range(fd, ((loff_t)offhigh << 32) + offlow,
				   ((u64)nhigh << 32) + nlow, flags);
}

COMPAT_SYSCALL_DEFINE6(s390_fallocate, int, fd, int, mode, u32, offhigh, u32, offlow,
		       u32, lenhigh, u32, lenlow)
{
	return ksys_fallocate(fd, mode, ((loff_t)offhigh << 32) + offlow,
			      ((u64)lenhigh << 32) + lenlow);
}
