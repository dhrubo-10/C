#include <linux/module.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/fcntl.h>
#include <linux/init.h>
#include <linux/poll.h>
#include <linux/smp.h>
#include <linux/major.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/cpu.h>
#include <linux/notifier.h>
#include <linux/uaccess.h>
#include <linux/gfp.h>
#include <linux/completion.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include <linux/highuid.h>
#include <linux/sysctl.h>
#include <linux/slab.h>

static enum cpuhp_state cpuhp_cpuid_state;

struct cpuid_regs_done {
	struct cpuid_regs regs;
	struct completion done;
};

static void cpuid_smp_cpuid(void *cmd_block)
{
	struct cpuid_regs_done *cmd = cmd_block;

	cpuid_count(cmd->regs.eax, cmd->regs.ecx,
		    &cmd->regs.eax, &cmd->regs.ebx,
		    &cmd->regs.ecx, &cmd->regs.edx);

	complete(&cmd->done);
}

static ssize_t cpuid_read(struct file *file, char __user *buf,
			  size_t count, loff_t *ppos)
{
	char __user *tmp = buf;
	struct cpuid_regs_done cmd;
	int cpu = iminor(file_inode(file));
	u64 pos = *ppos;
	ssize_t bytes = 0;
	int err = 0;

	if (count % 16)
		return -EINVAL;	/* Invalid chunk size */

	init_completion(&cmd.done);
	for (; count; count -= 16) {
		call_single_data_t csd;

		INIT_CSD(&csd, cpuid_smp_cpuid, &cmd);

		cmd.regs.eax = pos;
		cmd.regs.ecx = pos >> 32;

		err = smp_call_function_single_async(cpu, &csd);
		if (err)
			break;
		wait_for_completion(&cmd.done);
		if (copy_to_user(tmp, &cmd.regs, 16)) {
			err = -EFAULT;
			break;
		}
		tmp += 16;
		bytes += 16;
		*ppos = ++pos;
		reinit_completion(&cmd.done);
	}

	return bytes ? bytes : err;
}

static int cpuid_open(struct inode *inode, struct file *file)
{
	unsigned int cpu;
	struct cpuinfo_x86 *c;

	cpu = iminor(file_inode(file));
	if (cpu >= nr_cpu_ids || !cpu_online(cpu))
		return -ENXIO;	/* No such CPU */

	c = &cpu_data(cpu);
	if (c->cpuid_level < 0)
		return -EIO;	/* CPUID not supported */

	return 0;
}

/*
 * File operations we support
 */
static const struct file_operations cpuid_fops = {
	.owner = THIS_MODULE,
	.llseek = no_seek_end_llseek,
	.read = cpuid_read,
	.open = cpuid_open,
};

static char *cpuid_devnode(const struct device *dev, umode_t *mode)
{
	return kasprintf(GFP_KERNEL, "cpu/%u/cpuid", MINOR(dev->devt));
}

static const struct class cpuid_class = {
	.name		= "cpuid",
	.devnode	= cpuid_devnode,
};

static int cpuid_device_create(unsigned int cpu)
{
	struct device *dev;

	dev = device_create(&cpuid_class, NULL, MKDEV(CPUID_MAJOR, cpu), NULL,
			    "cpu%d", cpu);
	return PTR_ERR_OR_ZERO(dev);
}

static int cpuid_device_destroy(unsigned int cpu)
{
	device_destroy(&cpuid_class, MKDEV(CPUID_MAJOR, cpu));
	return 0;
}

static int __init cpuid_init(void)
{
	int err;

	if (__register_chrdev(CPUID_MAJOR, 0, NR_CPUS,
			      "cpu/cpuid", &cpuid_fops)) {
		printk(KERN_ERR "cpuid: unable to get major %d for cpuid\n",
		       CPUID_MAJOR);
		return -EBUSY;
	}
	err = class_register(&cpuid_class);
	if (err)
		goto out_chrdev;

	err = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "x86/cpuid:online",
				cpuid_device_create, cpuid_device_destroy);
	if (err < 0)
		goto out_class;

	cpuhp_cpuid_state = err;
	return 0;

out_class:
	class_unregister(&cpuid_class);
out_chrdev:
	__unregister_chrdev(CPUID_MAJOR, 0, NR_CPUS, "cpu/cpuid");
	return err;
}
module_init(cpuid_init);

static void __exit cpuid_exit(void)
{
	cpuhp_remove_state(cpuhp_cpuid_state);
	class_unregister(&cpuid_class);
	__unregister_chrdev(CPUID_MAJOR, 0, NR_CPUS, "cpu/cpuid");
}
module_exit(cpuid_exit);

MODULE_AUTHOR("H. Peter Anvin <hpa@zytor.com>");
MODULE_DESCRIPTION("x86 generic CPUID driver");
MODULE_LICENSE("GPL");

/* check */

unsigned long
arch_get_unmapped_area_topdown(struct file *filp, unsigned long addr0,
			  unsigned long len, unsigned long pgoff,
			  unsigned long flags, vm_flags_t vm_flags)
{
	struct vm_area_struct *vma;
	struct mm_struct *mm = current->mm;
	unsigned long addr = addr0;
	struct vm_unmapped_area_info info = {};

	/* requested length too big for entire address space */
	if (len > TASK_SIZE)
		return -ENOMEM;

	/* No address checking. See comment at mmap_address_hint_valid() */
	if (flags & MAP_FIXED)
		return addr;

	/* for MAP_32BIT mappings we force the legacy mmap base */
	if (!in_32bit_syscall() && (flags & MAP_32BIT))
		goto bottomup;

	/* requesting a specific address */
	if (addr) {
		addr &= PAGE_MASK;
		if (!mmap_address_hint_valid(addr, len))
			goto get_unmapped_area;

		vma = find_vma(mm, addr);
		if (!vma || addr + len <= vm_start_gap(vma))
			return addr;
	}
get_unmapped_area:

	info.flags = VM_UNMAPPED_AREA_TOPDOWN;
	info.length = len;
	if (!in_32bit_syscall() && (flags & MAP_ABOVE4G))
		info.low_limit = SZ_4G;
	else
		info.low_limit = PAGE_SIZE;

	info.high_limit = get_mmap_base(0);
	if (!(filp && is_file_hugepages(filp))) {
		info.start_gap = stack_guard_placement(vm_flags);
		info.align_offset = pgoff << PAGE_SHIFT;
	}

	/*
	 * If hint address is above DEFAULT_MAP_WINDOW, look for unmapped area
	 * in the full address space.
	 *
	 * !in_32bit_syscall() check to avoid high addresses for x32
	 * (and make it no op on native i386).
	 */
	if (addr > DEFAULT_MAP_WINDOW && !in_32bit_syscall())
		info.high_limit += TASK_SIZE_MAX - DEFAULT_MAP_WINDOW;

	if (filp) {
		info.align_mask = get_align_mask(filp);
		info.align_offset += get_align_bits();
	}
	addr = vm_unmapped_area(&info);
	if (!(addr & ~PAGE_MASK))
		return addr;
	VM_BUG_ON(addr != -ENOMEM);

bottomup:
	/*
	 * A failed mmap() very likely causes application failure,
	 * so fall back to the bottom-up function here. This scenario
	 * can happen with large stack limits and large mmap()
	 * allocations.
	 */
	return arch_get_unmapped_area(filp, addr0, len, pgoff, flags, 0);
}


/* Added this segman it will correctly handle 64-bit arguments by combining high/low
  parts into full 64-bit offsets/lengths. Check if it works in an x86 emulator */


SYSCALL_DEFINE6(ia32_fadvise64_64, int, fd, __u32, offset_low,
		__u32, offset_high, __u32, len_low, __u32, len_high,
		int, advice)
{
	return ksys_fadvise64_64(fd,
				 (((u64)offset_high)<<32) | offset_low,
				 (((u64)len_high)<<32) | len_low,
				 advice);
}

SYSCALL_DEFINE4(ia32_readahead, int, fd, unsigned int, off_lo,
		unsigned int, off_hi, size_t, count)
{
	return ksys_readahead(fd, ((u64)off_hi << 32) | off_lo, count);
}

SYSCALL_DEFINE6(ia32_sync_file_range, int, fd, unsigned int, off_low,
		unsigned int, off_hi, unsigned int, n_low,
		unsigned int, n_hi, int, flags)
{
	return ksys_sync_file_range(fd,
				    ((u64)off_hi << 32) | off_low,
				    ((u64)n_hi << 32) | n_low, flags);
}

SYSCALL_DEFINE5(ia32_fadvise64, int, fd, unsigned int, offset_lo,
		unsigned int, offset_hi, size_t, len, int, advice)
{
	return ksys_fadvise64_64(fd, ((u64)offset_hi << 32) | offset_lo,
				 len, advice);
}

SYSCALL_DEFINE6(ia32_fallocate, int, fd, int, mode,
		unsigned int, offset_lo, unsigned int, offset_hi,
		unsigned int, len_lo, unsigned int, len_hi)
{
	return ksys_fallocate(fd, mode, ((u64)offset_hi << 32) | offset_lo,
			      ((u64)len_hi << 32) | len_lo);
}

#ifdef CONFIG_IA32_EMULATION

static int cp_stat64(struct stat64 __user *ubuf, struct kstat *stat)
{
	typeof(ubuf->st_uid) uid = 0;
	typeof(ubuf->st_gid) gid = 0;
	SET_UID(uid, from_kuid_munged(current_user_ns(), stat->uid));
	SET_GID(gid, from_kgid_munged(current_user_ns(), stat->gid));
	if (!user_write_access_begin(ubuf, sizeof(struct stat64)))
		return -EFAULT;
	unsafe_put_user(huge_encode_dev(stat->dev), &ubuf->st_dev, Efault);
	unsafe_put_user(stat->ino, &ubuf->__st_ino, Efault);
	unsafe_put_user(stat->ino, &ubuf->st_ino, Efault);
	unsafe_put_user(stat->mode, &ubuf->st_mode, Efault);
	unsafe_put_user(stat->nlink, &ubuf->st_nlink, Efault);
	unsafe_put_user(uid, &ubuf->st_uid, Efault);
	unsafe_put_user(gid, &ubuf->st_gid, Efault);
	unsafe_put_user(huge_encode_dev(stat->rdev), &ubuf->st_rdev, Efault);
	unsafe_put_user(stat->size, &ubuf->st_size, Efault);
	unsafe_put_user(stat->atime.tv_sec, &ubuf->st_atime, Efault);
	unsafe_put_user(stat->atime.tv_nsec, &ubuf->st_atime_nsec, Efault);
	unsafe_put_user(stat->mtime.tv_sec, &ubuf->st_mtime, Efault);
	unsafe_put_user(stat->mtime.tv_nsec, &ubuf->st_mtime_nsec, Efault);
	unsafe_put_user(stat->ctime.tv_sec, &ubuf->st_ctime, Efault);
	unsafe_put_user(stat->ctime.tv_nsec, &ubuf->st_ctime_nsec, Efault);
	unsafe_put_user(stat->blksize, &ubuf->st_blksize, Efault);
	unsafe_put_user(stat->blocks, &ubuf->st_blocks, Efault);
	user_access_end();
	return 0;
Efault:
	user_write_access_end();
	return -EFAULT;
}