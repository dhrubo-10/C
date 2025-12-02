/*
 * compat_linux.h - Compatibility layer for 31-bit userland on 64-bit kernel
 * 32-bit to 64-bit syscall translation on s390 (and similar) ports.
 */

#ifndef _COMPAT_LINUX_H
#define _COMPAT_LINUX_H

#include <linux/types.h>
#include <linux/compat.h>
#include <linux/mm.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/errno.h>

typedef u32	compat_uptr_t;      
typedef u32	compat_size_t; 
typedef s32	compat_ssize_t; 
typedef u32	compat_ulong_t;     

struct mmap_arg_struct_emu31 {
	compat_ulong_t addr;    /* Address hint */
	compat_ulong_t len;     /* Length of mapping */
	compat_ulong_t prot;    /* Protection flags */
	compat_ulong_t flags;   /* Mapping flags */
	compat_ulong_t fd;      /* File descriptor */
	compat_ulong_t offset;  /* File offset (in bytes or pages) */
};

#ifdef CONFIG_SYSVIPC
extern long compat_ksys_ipc(uint call, int first, compat_ulong_t second,
			    compat_ulong_t third, compat_uptr_t ptr,
			    compat_ulong_t fifth);
#endif

#ifndef HAVE_COPY_STRUCT_FROM_USER
static inline int copy_struct_from_user(void *dst, size_t ksize,
					const void __user *src, size_t usize)
{
	if (usize > ksize)
		return -E2BIG;
	if (copy_from_user(dst, src, usize))
		return -EFAULT;
	if (usize < ksize)
		memset(dst + usize, 0, ksize - usize);
	return 0;
}
#endif /* HAVE_COPY_STRUCT_FROM_USER */

#define compat_ptr(ptr)		((void __user *)(uintptr_t)(ptr))

#endif /* _COMPAT_LINUX_H */
