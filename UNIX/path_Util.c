#include <linux/fcntl.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init_syscalls.h>
#include <linux/init.h>
#include <linux/async.h>
#include <linux/export.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/init_syscalls.h>
#include <linux/umh.h>
#include <linux/security.h>
#include <linux/ctype.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/minmax.h>
#include <linux/unaligned.h>
#include <linux/cpu.h>
#include <linux/err.h>
#include <linux/smp.h>
#include <linux/delay.h>

// main
// This section is still under progress
//......//

const char hex_asc[] = "0123456789abcdef";
EXPORT_SYMBOL(hex_asc);
const char hex_asc_upper[] = "0123456789ABCDEF";
EXPORT_SYMBOL(hex_asc_upper);

static void __init do_ctors(void)
{

#if defined(CONFIG_CONSTRUCTORS) && !defined(CONFIG_UML)
	ctor_fn_t *fn = (ctor_fn_t *) __ctors_start;

	for (; fn < (ctor_fn_t *) __ctors_end; fn++)
		(*fn)();
#endif
}

#ifdef CONFIG_KALLSYMS
struct blacklist_entry {
	struct list_head next;
	char *buf;
};

static __initdata_or_module LIST_HEAD(blacklisted_initcalls);

static int __init initcall_blacklist(char *str)
{
	char *str_entry;
	struct blacklist_entry *entry;


	do {
		str_entry = strsep(&str, ",");
		if (str_entry) {
			pr_debug("blacklisting initcall %s\n", str_entry);
			entry = memblock_alloc_or_panic(sizeof(*entry),
					       SMP_CACHE_BYTES);
			entry->buf = memblock_alloc_or_panic(strlen(str_entry) + 1,
						    SMP_CACHE_BYTES);
			strcpy(entry->buf, str_entry);
			list_add(&entry->next, &blacklisted_initcalls);
		}
	} while (str_entry);

	return 1;
}

static DEFINE_PER_CPU(struct task_struct *, idle_threads);

struct task_struct *idle_thread_get(unsigned int cpu)
{
	struct task_struct *tsk = per_cpu(idle_threads, cpu);

	if (!tsk)
		return ERR_PTR(-ENOMEM);
	return tsk;
}

void __init idle_thread_set_boot_cpu(void)
{
	per_cpu(idle_threads, smp_processor_id()) = current;
}

static bool __init_or_module initcall_blacklisted(initcall_t fn)
{
	struct blacklist_entry *entry;
	char fn_name[KSYM_SYMBOL_LEN];
	unsigned long addr;

	if (list_empty(&blacklisted_initcalls))
		return false;

	addr = (unsigned long) dereference_function_descriptor(fn);
	sprint_symbol_no_offset(fn_name, addr);

	
	strreplace(fn_name, ' ', '\0');

	list_for_each_entry(entry, &blacklisted_initcalls, next) {
		if (!strcmp(fn_name, entry->buf)) {
			pr_debug("initcall %s blacklisted\n", fn_name);
			return true;
		}
	}

#ifdef CONFIG_BLK_DEV_INITRD
	if (initrd_start && !initrd_below_start_ok &&
	    page_to_pfn(virt_to_page((void *)initrd_start)) < min_low_pfn) {
		pr_crit("initrd overwritten (0x%08lx < 0x%08lx) - disabling it.\n",
		    page_to_pfn(virt_to_page((void *)initrd_start)),
		    min_low_pfn);
		initrd_start = 0;
	}
#endif
	static void __init initramfs_test_fname_overrun(struct kunit *test)
{
	char *err, *cpio_srcbuf;
	size_t len, suffix_off;
	struct initramfs_test_cpio c[] = { {
		.magic = "070701",
		.ino = 1,
		.mode = S_IFREG | 0777,
		.uid = 0,
		.gid = 0,
		.nlink = 1,
		.mtime = 1,
		.filesize = 0,
		.devmajor = 0,
		.devminor = 1,
		.rdevmajor = 0,
		.rdevminor = 0,
		.namesize = sizeof("initramfs_test_fname_overrun"),
		.csum = 0,
		.fname = "initramfs_test_fname_overrun",
	} };

	
	
	cpio_srcbuf = kmalloc(CPIO_HDRLEN + PATH_MAX + 3, GFP_KERNEL);
	memset(cpio_srcbuf, 'B', CPIO_HDRLEN + PATH_MAX + 3);
	/* limit overrun to avoid crashes / filp_open() ENAMETOOLONG */
	cpio_srcbuf[CPIO_HDRLEN + strlen(c[0].fname) + 20] = '\0';

	len = fill_cpio(c, ARRAY_SIZE(c), cpio_srcbuf);
	/* overwrite trailing fname terminator and padding */
	suffix_off = len - 1;
	while (cpio_srcbuf[suffix_off] == '\0') {
		cpio_srcbuf[suffix_off] = 'P';
		suffix_off--;
	}

	err = unpack_to_rootfs(cpio_srcbuf, len);
	KUNIT_EXPECT_NOT_NULL(test, err);

	kfree(cpio_srcbuf);
}

static void __init initramfs_test_data(struct kunit *test)
{
	char *err, *cpio_srcbuf;
	size_t len;
	struct file *file;
	struct initramfs_test_cpio c[] = { {
		.magic = "070701",
		.ino = 1,
		.mode = S_IFREG | 0777,
		.uid = 0,
		.gid = 0,
		.nlink = 1,
		.mtime = 1,
		.filesize = sizeof("ASDF") - 1,
		.devmajor = 0,
		.devminor = 1,
		.rdevmajor = 0,
		.rdevminor = 0,
		.namesize = sizeof("initramfs_test_data"),
		.csum = 0,
		.fname = "initramfs_test_data",
		.data = "ASDF",
	} };

	/* +6 for max name and data 4-byte padding */
	cpio_srcbuf = kmalloc(CPIO_HDRLEN + c[0].namesize + c[0].filesize + 6,
			      GFP_KERNEL);

	len = fill_cpio(c, ARRAY_SIZE(c), cpio_srcbuf);

	err = unpack_to_rootfs(cpio_srcbuf, len);
	KUNIT_EXPECT_NULL(test, err);

	file = filp_open(c[0].fname, O_RDONLY, 0);
	if (IS_ERR(file)) {
		KUNIT_FAIL(test, "open failed");
		goto out;
	}

	/* read back file contents into @cpio_srcbuf and confirm match */
	len = kernel_read(file, cpio_srcbuf, c[0].filesize, NULL);
	KUNIT_EXPECT_EQ(test, len, c[0].filesize);
	KUNIT_EXPECT_MEMEQ(test, cpio_srcbuf, c[0].data, len);

	fput(file);
	KUNIT_EXPECT_EQ(test, init_unlink(c[0].fname), 0);
out:
	kfree(cpio_srcbuf);
}

#ifdef CONFIG_CRASH_DUMP
static void __init setup_zfcpdump(void)
{
	if (!is_ipl_type_dump())
		return;
	if (oldmem_data.start)
		return;
	strlcat(boot_command_line, " cio_ignore=all,!ipldev,!condev", COMMAND_LINE_SIZE);
	console_loglevel = 2;
}
#else
static inline void setup_zfcpdump(void) {}
#endif /

unsigned long initrd_start, initrd_end;
int initrd_below_start_ok;
static unsigned int real_root_dev;	/* do_proc_dointvec cannot handle kdev_t */
static int __initdata mount_initrd = 1;

phys_addr_t phys_initrd_start __initdata;
unsigned long phys_initrd_size __initdata;

#ifdef CONFIG_SYSCTL
static const struct ctl_table kern_do_mounts_initrd_table[] = {
	{
		.procname       = "real-root-dev",
		.data           = &real_root_dev,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec,
	},
	struct lowcore *lc, *abs_lc;

	/*
	 * Setup lowcore for boot cpu
	 */
	BUILD_BUG_ON(sizeof(struct lowcore) != LC_PAGES * PAGE_SIZE);
	lc = memblock_alloc_low(sizeof(*lc), sizeof(*lc));
	if (!lc)
		panic("%s: Failed to allocate %zu bytes align=%zx\n",
		      __func__, sizeof(*lc), sizeof(*lc));

	lc->pcpu = (unsigned long)per_cpu_ptr(&pcpu_devices, 0);
	lc->restart_psw.mask = PSW_KERNEL_BITS & ~PSW_MASK_DAT;
	lc->restart_psw.addr = __pa(restart_int_handler);
	lc->external_new_psw.mask = PSW_KERNEL_BITS;
	lc->external_new_psw.addr = (unsigned long) ext_int_handler;
	lc->svc_new_psw.mask = PSW_KERNEL_BITS;
	lc->svc_new_psw.addr = (unsigned long) system_call;
	lc->program_new_psw.mask = PSW_KERNEL_BITS;
	lc->program_new_psw.addr = (unsigned long) pgm_check_handler;
	lc->mcck_new_psw.mask = PSW_KERNEL_BITS;
	lc->mcck_new_psw.addr = (unsigned long) mcck_int_handler;
	lc->io_new_psw.mask = PSW_KERNEL_BITS;
	lc->io_new_psw.addr = (unsigned long) io_int_handler;
	lc->clock_comparator = clock_comparator_max;
	lc->current_task = (unsigned long)&init_task;
	lc->lpp = LPP_MAGIC;
	lc->preempt_count = get_lowcore()->preempt_count;
	nmi_alloc_mcesa_early(&lc->mcesad);
	lc->sys_enter_timer = get_lowcore()->sys_enter_timer;
	lc->exit_timer = get_lowcore()->exit_timer;
	lc->user_timer = get_lowcore()->user_timer;
	lc->system_timer = get_lowcore()->system_timer;
	lc->steal_timer = get_lowcore()->steal_timer;
	lc->last_update_timer = get_lowcore()->last_update_timer;
	lc->last_update_clock = get_lowcore()->last_update_clock;
	/*
	  Allocate the global restart stack which is the same for
	  all CPUs in case *one* of them does a PSW restart.
	 */
	restart_stack = (void *)(stack_alloc_early() + STACK_INIT_OFFSET);
	lc->mcck_stack = stack_alloc_early() + STACK_INIT_OFFSET;
	lc->async_stack = stack_alloc_early() + STACK_INIT_OFFSET;
	lc->nodat_stack = stack_alloc_early() + STACK_INIT_OFFSET;
	lc->kernel_stack = get_lowcore()->kernel_stack;
	/*
	  Set up PSW restart to call ipl.c:do_restart(). Copy the relevant
	 restart data to the absolute zero lowcore. This is necessary if
	  PSW restart is done on an offline CPU that has lowcore zero.
	 */
	lc->restart_stack = (unsigned long) restart_stack;
	lc->restart_fn = (unsigned long) do_restart;
	lc->restart_data = 0;
	lc->restart_source = -1U;
	lc->spinlock_lockval = arch_spin_lockval(0);
	lc->spinlock_index = 0;
	arch_spin_lock_setup(0);
	lc->return_lpswe = gen_lpswe(__LC_RETURN_PSW);
	lc->return_mcck_lpswe = gen_lpswe(__LC_RETURN_MCCK_PSW);
	lc->preempt_count = PREEMPT_DISABLED;
	lc->kernel_asce = get_lowcore()->kernel_asce;
	lc->user_asce = get_lowcore()->user_asce;

	system_ctlreg_init_save_area(lc);
	abs_lc = get_abs_lowcore();
	abs_lc->restart_stack = lc->restart_stack;
	abs_lc->restart_fn = lc->restart_fn;
	abs_lc->restart_data = lc->restart_data;
	abs_lc->restart_source = lc->restart_source;
	abs_lc->restart_psw = lc->restart_psw;
	abs_lc->restart_flags = RESTART_FLAG_CTLREGS;
	abs_lc->program_new_psw = lc->program_new_psw;
	abs_lc->mcesad = lc->mcesad;
	put_abs_lowcore(abs_lc);

	set_prefix(__pa(lc));
	lowcore_ptr[0] = lc;
	if (abs_lowcore_map(0, lowcore_ptr[0], false))
		panic("Couldn't setup absolute lowcore");
};

static __init int kernel_do_mounts_initrd_sysctls_init(void)
{
	register_sysctl_init("kernel", kern_do_mounts_initrd_table);
	return 0;
}
late_initcall(kernel_do_mounts_initrd_sysctls_init);
#endif /* CONFIG_SYSCTL */

static __always_inline void idle_init(unsigned int cpu)
{
	struct task_struct *tsk = per_cpu(idle_threads, cpu);

	if (!tsk) {
		tsk = fork_idle(cpu);
		if (IS_ERR(tsk))
			pr_err("SMP: fork_idle() failed for CPU %u\n", cpu);
		else
			per_cpu(idle_threads, cpu) = tsk;
	}
}

__setup("noinitrd", no_initrd);

static int __init early_initrdmem(char *p)
{
	phys_addr_t start;
	unsigned long size;
	char *endp;

	start = memparse(p, &endp);
	if (*endp == ',') {
		size = memparse(endp + 1, NULL);

		phys_initrd_start = start;
		phys_initrd_size = size;
	}
	return 0;
}
early_param("initrdmem", early_initrdmem);

static int __init early_initrd(char *p)
{
	return early_initrdmem(p);
}
early_param("initrd", early_initrd);

static int __init init_linuxrc(struct subprocess_info *info, struct cred *new)
{
	ksys_unshare(CLONE_FS | CLONE_FILES);
	console_on_rootfs();
	/* move initrd over / and chdir/chroot in initrd root */
	init_chdir("/root");
	init_mount(".", "/", NULL, MS_MOVE, NULL);
	init_chroot(".");
	ksys_setsid();
	return 0;
}

static void __init handle_initrd(char *root_device_name)
{
	struct subprocess_info *info;
	static char *argv[] = { "linuxrc", NULL, };
	extern char *envp_init[];
	int error;

	pr_warn("using deprecated initrd support, will be removed soon.\n");

	real_root_dev = new_encode_dev(ROOT_DEV);
	create_dev("/dev/root.old", Root_RAM0);
	/* mount initrd on rootfs' /root */
	mount_root_generic("/dev/root.old", root_device_name,
			   root_mountflags & ~MS_RDONLY);
	init_mkdir("/old", 0700);
	init_chdir("/old");

	info = call_usermodehelper_setup("/linuxrc", argv, envp_init,
					 GFP_KERNEL, init_linuxrc, NULL, NULL);
	if (!info)
		return;
	call_usermodehelper_exec(info, UMH_WAIT_PROC|UMH_FREEZABLE);

	/* move initrd to rootfs' /old */
	init_mount("..", ".", NULL, MS_MOVE, NULL);
	/* switch root and cwd back to / of rootfs */
	init_chroot("..");

	if (new_decode_dev(real_root_dev) == Root_RAM0) {
		init_chdir("/old");
		return;
	}

	init_chdir("/");
	ROOT_DEV = new_decode_dev(real_root_dev);
	mount_root(root_device_name);

	printk(KERN_NOTICE "Trying to move old root to /initrd ... ");
	error = init_mount("/old", "/root/initrd", NULL, MS_MOVE, NULL);
	if (!error)
		printk("okay\n");
	else {
		if (error == -ENOENT)
			printk("/initrd does not exist. Ignored.\n");
		else
			printk("failed\n");
		printk(KERN_NOTICE "Unmounting old root\n");
		init_umount("/old", MNT_DETACH);
	}
}

bool __init initrd_load(char *root_device_name)
{
	if (mount_initrd) {
		create_dev("/dev/ram", Root_RAM0);

		if (rd_load_image("/initrd.image") && ROOT_DEV != Root_RAM0) {
			init_unlink("/initrd.image");
			handle_initrd(root_device_name);
			return true;
		}
	}
	init_unlink("/initrd.image");
	return false;
}

static LIST_HEAD(hotplug_threads);
static DEFINE_MUTEX(smpboot_threads_lock);

struct smpboot_thread_data {
	unsigned int			cpu;
	unsigned int			status;
	struct smp_hotplug_thread	*ht;
};

enum {
	HP_THREAD_NONE = 0,
	HP_THREAD_ACTIVE,
	HP_THREAD_PARKED,
};

static void __init initramfs_test_csum(struct kunit *test)
{
	char *err, *cpio_srcbuf;
	size_t len;
	struct initramfs_test_cpio c[] = { {
		/* 070702 magic indicates a valid csum is present */
		.magic = "070702",
		.ino = 1,
		.mode = S_IFREG | 0777,
		.nlink = 1,
		.filesize = sizeof("ASDF") - 1,
		.devminor = 1,
		.namesize = sizeof("initramfs_test_csum"),
		.csum = 'A' + 'S' + 'D' + 'F',
		.fname = "initramfs_test_csum",
		.data = "ASDF",
	}, {
		/* mix csum entry above with no-csum entry below */
		.magic = "070701",
		.ino = 2,
		.mode = S_IFREG | 0777,
		.nlink = 1,
		.filesize = sizeof("ASDF") - 1,
		.devminor = 1,
		.namesize = sizeof("initramfs_test_csum_not_here"),
		/* csum ignored */
		.csum = 5555,
		.fname = "initramfs_test_csum_not_here",
		.data = "ASDF",
	} };

	cpio_srcbuf = kmalloc(8192, GFP_KERNEL);

	len = fill_cpio(c, ARRAY_SIZE(c), cpio_srcbuf);

	err = unpack_to_rootfs(cpio_srcbuf, len);
	KUNIT_EXPECT_NULL(test, err);

	KUNIT_EXPECT_EQ(test, init_unlink(c[0].fname), 0);
	KUNIT_EXPECT_EQ(test, init_unlink(c[1].fname), 0);

	/* mess up the csum and confirm that unpack fails */
	c[0].csum--;
	len = fill_cpio(c, ARRAY_SIZE(c), cpio_srcbuf);

	err = unpack_to_rootfs(cpio_srcbuf, len);
	KUNIT_EXPECT_NOT_NULL(test, err);

	/*
	 * file (with content) is still retained in case of bad-csum abort.
	 * Perhaps we should change this.
	 */
	KUNIT_EXPECT_EQ(test, init_unlink(c[0].fname), 0);
	KUNIT_EXPECT_EQ(test, init_unlink(c[1].fname), -ENOENT);
	kfree(cpio_srcbuf);
}

/*
 * hardlink hashtable may leak when the archive omits a trailer:
 * https://lore.kernel.org/r/20241107002044.16477-10-ddiss@suse.de/
 */
static void __init initramfs_test_hardlink(struct kunit *test)
{
	char *err, *cpio_srcbuf;
	size_t len;
	struct kstat st0, st1;
	struct initramfs_test_cpio c[] = { {
		.magic = "070701",
		.ino = 1,
		.mode = S_IFREG | 0777,
		.nlink = 2,
		.devminor = 1,
		.namesize = sizeof("initramfs_test_hardlink"),
		.fname = "initramfs_test_hardlink",
	}, {
		/* hardlink data is present in last archive entry */
		.magic = "070701",
		.ino = 1,
		.mode = S_IFREG | 0777,
		.nlink = 2,
		.filesize = sizeof("ASDF") - 1,
		.devminor = 1,
		.namesize = sizeof("initramfs_test_hardlink_link"),
		.fname = "initramfs_test_hardlink_link",
		.data = "ASDF",
	} };

	cpio_srcbuf = kmalloc(8192, GFP_KERNEL);

	len = fill_cpio(c, ARRAY_SIZE(c), cpio_srcbuf);

	err = unpack_to_rootfs(cpio_srcbuf, len);
	KUNIT_EXPECT_NULL(test, err);

	KUNIT_EXPECT_EQ(test, init_stat(c[0].fname, &st0, 0), 0);
	KUNIT_EXPECT_EQ(test, init_stat(c[1].fname, &st1, 0), 0);
	KUNIT_EXPECT_EQ(test, st0.ino, st1.ino);
	KUNIT_EXPECT_EQ(test, st0.nlink, 2);
	KUNIT_EXPECT_EQ(test, st1.nlink, 2);

	KUNIT_EXPECT_EQ(test, init_unlink(c[0].fname), 0);
	KUNIT_EXPECT_EQ(test, init_unlink(c[1].fname), 0);

	kfree(cpio_srcbuf);
}

#define INITRAMFS_TEST_MANY_LIMIT 1000
#define INITRAMFS_TEST_MANY_PATH_MAX (sizeof("initramfs_test_many-") \
			+ sizeof(__stringify(INITRAMFS_TEST_MANY_LIMIT)))
static void __init initramfs_test_many(struct kunit *test)
{
	char *err, *cpio_srcbuf, *p;
	size_t len = INITRAMFS_TEST_MANY_LIMIT *
		     (CPIO_HDRLEN + INITRAMFS_TEST_MANY_PATH_MAX + 3);
	char thispath[INITRAMFS_TEST_MANY_PATH_MAX];
	int i;

	p = cpio_srcbuf = kmalloc(len, GFP_KERNEL);

	for (i = 0; i < INITRAMFS_TEST_MANY_LIMIT; i++) {
		struct initramfs_test_cpio c = {
			.magic = "070701",
			.ino = i,
			.mode = S_IFREG | 0777,
			.nlink = 1,
			.devminor = 1,
			.fname = thispath,
		};

		c.namesize = 1 + sprintf(thispath, "initramfs_test_many-%d", i);
		p += fill_cpio(&c, 1, p);
	}

	len = p - cpio_srcbuf;
	err = unpack_to_rootfs(cpio_srcbuf, len);
	KUNIT_EXPECT_NULL(test, err);

	for (i = 0; i < INITRAMFS_TEST_MANY_LIMIT; i++) {
		sprintf(thispath, "initramfs_test_many-%d", i);
		KUNIT_EXPECT_EQ(test, init_unlink(thispath), 0);
	}

	kfree(cpio_srcbuf);
}

#if !__has_attribute(__no_stack_protector__)
	prevent_tail_call_optimization();
#endif


	return false;
}
#else
static int __init initcall_blacklist(char *str)
{
	pr_warn("initcall_blacklist requires CONFIG_KALLSYMS\n");
	return 0;
}

static bool __init_or_module initcall_blacklisted(initcall_t fn)
{
	return false;
}
#endif
__setup("initcall_blacklist=", initcall_blacklist);

static __init_or_module void
trace_initcall_start_cb(void *data, initcall_t fn)
{
	ktime_t *calltime = data;

	printk(KERN_DEBUG "calling  %pS @ %i\n", fn, task_pid_nr(current));
	*calltime = ktime_get();
}

static __init_or_module void
trace_initcall_finish_cb(void *data, initcall_t fn, int ret)
{
	ktime_t rettime, *calltime = data;

	rettime = ktime_get();
	printk(KERN_DEBUG "initcall %pS returned %d after %lld usecs\n",
		 fn, ret, (unsigned long long)ktime_us_delta(rettime, *calltime));
}

static __init_or_module void
trace_initcall_level_cb(void *data, const char *level)
{
	printk(KERN_DEBUG "entering initcall level: %s\n", level);

	while (1) {
		set_current_state(TASK_INTERRUPTIBLE);
		preempt_disable();
		if (kthread_should_stop()) {
			__set_current_state(TASK_RUNNING);
			preempt_enable();
			/* cleanup must mirror setup */
			if (ht->cleanup && td->status != HP_THREAD_NONE)
				ht->cleanup(td->cpu, cpu_online(td->cpu));
			kfree(td);
			return 0;
		}

		if (kthread_should_park()) {
			__set_current_state(TASK_RUNNING);
			preempt_enable();
			if (ht->park && td->status == HP_THREAD_ACTIVE) {
				BUG_ON(td->cpu != smp_processor_id());
				ht->park(td->cpu);
				td->status = HP_THREAD_PARKED;
			}
			kthread_parkme();
			continue;
		}
}

static ktime_t initcall_calltime;

#ifdef TRACEPOINTS_ENABLED
static void __init initcall_debug_enable(void)
{
	int ret;

	ret = register_trace_initcall_start(trace_initcall_start_cb,
					    &initcall_calltime);
	ret |= register_trace_initcall_finish(trace_initcall_finish_cb,
					      &initcall_calltime);
	ret |= register_trace_initcall_level(trace_initcall_level_cb, NULL);
	WARN(ret, "Failed to register initcall tracepoints\n");
}
# define do_trace_initcall_start	trace_initcall_start
# define do_trace_initcall_finish	trace_initcall_finish
# define do_trace_initcall_level	trace_initcall_level
#else
static inline void do_trace_initcall_start(initcall_t fn)
{
	if (!initcall_debug)
		return;
	trace_initcall_start_cb(&initcall_calltime, fn);
}

static __initdata bool csum_present;
static __initdata u32 io_csum;

static ssize_t __init xwrite(struct file *file, const unsigned char *p,
		size_t count, loff_t *pos)
{
	ssize_t out = 0;

	/* sys_write only can write MAX_RW_COUNT aka 2G-4K bytes at most */
	while (count) {
		ssize_t rv = kernel_write(file, p, count, pos);

		if (rv < 0) {
			if (rv == -EINTR || rv == -EAGAIN)
				continue;
			return out ? out : rv;
		} else if (rv == 0)
			break;

		if (csum_present) {
			ssize_t i;

			for (i = 0; i < rv; i++)
				io_csum += p[i];
		}

		p += rv;
		out += rv;
		count -= rv;
	}

	return out;
}

static __initdata char *message;
static void __init error(char *x)
{
	if (!message)
		message = x;
}

#define panic_show_mem(fmt, ...) \
	({ show_mem(); panic(fmt, ##__VA_ARGS__); })

/* link hash */

#define N_ALIGN(len) ((((len) + 1) & ~3) + 2)

static __initdata struct hash {
	int ino, minor, major;
	umode_t mode;
	struct hash *next;
	char name[N_ALIGN(PATH_MAX)];
} *head[32];
static __initdata bool hardlink_seen;

static inline int hash(int major, int minor, int ino)
{
	unsigned long tmp = ino + minor + (major << 3);
	tmp += tmp >> 5;
	return tmp & 31;
}

static char __init *find_link(int major, int minor, int ino,
			      umode_t mode, char *name)
{
	struct hash **p, *q;
	for (p = head + hash(major, minor, ino); *p; p = &(*p)->next) {
		if ((*p)->ino != ino)
			continue;
		if ((*p)->minor != minor)
			continue;
		if ((*p)->major != major)
			continue;
		if (((*p)->mode ^ mode) & S_IFMT)
			continue;
		return (*p)->name;
	}
	q = kmalloc(sizeof(struct hash), GFP_KERNEL);
	if (!q)
		panic_show_mem("can't allocate link hash entry");
	q->major = major;
	q->minor = minor;
	q->ino = ino;
	q->mode = mode;
	strcpy(q->name, name);
	q->next = NULL;
	*p = q;
	hardlink_seen = true;
	return NULL;
}

__setup("rootwait", rootwait_setup);

static int __init rootwait_timeout_setup(char *str)
{
	int sec;

	if (kstrtoint(str, 0, &sec) || sec < 0) {
		pr_warn("ignoring invalid rootwait value\n");
		goto ignore;
	}

	if (check_mul_overflow(sec, MSEC_PER_SEC, &root_wait)) {
		pr_warn("ignoring excessive rootwait value\n");
		goto ignore;
	}

	return 1;

ignore:
	/* Fallback to indefinite wait */
	root_wait = -1;

	return 1;
}

__setup("rootwait=", rootwait_timeout_setup);

static char * __initdata root_mount_data;
static int __init root_data_setup(char *str)
{
	root_mount_data = str;
	return 1;
}
int smpboot_create_threads(unsigned int cpu)
{
	struct smp_hotplug_thread *cur;
	int ret = 0;

	mutex_lock(&smpboot_threads_lock);
	list_for_each_entry(cur, &hotplug_threads, list) {
		ret = __smpboot_create_thread(cur, cpu);
		if (ret)
			break;
	}
	mutex_unlock(&smpboot_threads_lock);
	return ret;
}
static char * __initdata root_fs_names;
static int __init fs_names_setup(char *str)
{
	root_fs_names = str;
	return 1;
}

static unsigned int __initdata root_delay;
static int __init root_delay_setup(char *str)
{
	root_delay = simple_strtoul(str, NULL, 0);
	return 1;
}

__setup("rootflags=", root_data_setup);
__setup("rootfstype=", fs_names_setup);
__setup("rootdelay=", root_delay_setup);

/* This can return zero length strings. Caller should check */
static int __init split_fs_names(char *page, size_t size)
{
	int count = 1;
	char *p = page;

	strscpy(p, root_fs_names, size);
	while (*p++) {
		if (p[-1] == ',') {
			p[-1] = '\0';
			count++;
		}
	}

	return count;
}

static int __init do_mount_root(const char *name, const char *fs,
				 const int flags, const void *data)
{
	struct super_block *s;
	struct page *p = NULL;
	char *data_page = NULL;
	int ret;

	if (data) {
		/* init_mount() requires a full page as fifth argument */
		p = alloc_page(GFP_KERNEL);
		if (!p)
			return -ENOMEM;
		data_page = page_address(p);
		strscpy_pad(data_page, data, PAGE_SIZE);
	}

	ret = init_mount(name, "/root", fs, flags, data_page);
	if (ret)
		goto out;

	init_chdir("/root");
	s = current->fs->pwd.dentry->d_sb;
	ROOT_DEV = s->s_dev;
	printk(KERN_INFO
	       "VFS: Mounted root (%s filesystem)%s on device %u:%u.\n",
	       s->s_type->name,
	       sb_rdonly(s) ? " readonly" : "",
	       MAJOR(ROOT_DEV), MINOR(ROOT_DEV));

out:
	if (p)
		put_page(p);
	return ret;
}

void __init mount_root_generic(char *name, char *pretty_name, int flags)
{
	struct page *page = alloc_page(GFP_KERNEL);
	char *fs_names = page_address(page);
	char *p;
	char b[BDEVNAME_SIZE];
	int num_fs, i;

	scnprintf(b, BDEVNAME_SIZE, "unknown-block(%u,%u)",
		  MAJOR(ROOT_DEV), MINOR(ROOT_DEV));
	if (root_fs_names)
		num_fs = split_fs_names(fs_names, PAGE_SIZE);
	else
		num_fs = list_bdev_fs_names(fs_names, PAGE_SIZE);
retry:
	for (i = 0, p = fs_names; i < num_fs; i++, p += strlen(p)+1) {
		int err;

		if (!*p)
			continue;
		err = do_mount_root(name, p, flags, root_mount_data);
		switch (err) {
			case 0:
				goto out;
			case -EACCES:
			case -EINVAL:
#ifdef CONFIG_BLOCK
				init_flush_fput();
#endif
				continue;
		}
	        /*
		 * Allow the user to distinguish between failed sys_open
		 * and bad superblock on root device.
		 * and give them a list of the available devices
		 */
		printk("VFS: Cannot open root device \"%s\" or %s: error %d\n",
				pretty_name, b, err);
		printk("Please append a correct \"root=\" boot option; here are the available partitions:\n");
		printk_all_partitions();

		if (root_fs_names)
			num_fs = list_bdev_fs_names(fs_names, PAGE_SIZE);
		if (!num_fs)
			pr_err("Can't find any bdev filesystem to be used for mount!\n");
		else {
			pr_err("List of all bdev filesystems:\n");
			for (i = 0, p = fs_names; i < num_fs; i++, p += strlen(p)+1)
				pr_err(" %s", p);
			pr_err("\n");
		}

		panic("VFS: Unable to mount root fs on %s", b);
	}
	if (!(flags & SB_RDONLY)) {
		flags |= SB_RDONLY;
		goto retry;
	}

	printk("List of all partitions:\n");
	printk_all_partitions();
	printk("No filesystem could mount root, tried: ");
	for (i = 0, p = fs_names; i < num_fs; i++, p += strlen(p)+1)
		printk(" %s", p);
	printk("\n");
	panic("VFS: Unable to mount root fs on \"%s\" or %s", pretty_name, b);
out:
	put_page(page);
}


#ifdef CONFIG_INITRAMFS_PRESERVE_MTIME
static void __init do_utime(char *filename, time64_t mtime)
{
	struct timespec64 t[2] = { { .tv_sec = mtime }, { .tv_sec = mtime } };
	init_utimes(filename, t);
}

static void __init do_utime_path(const struct path *path, time64_t mtime)
{
	struct timespec64 t[2] = { { .tv_sec = mtime }, { .tv_sec = mtime } };
	vfs_utimes(path, t);
}

static __initdata LIST_HEAD(dir_list);
struct dir_entry {
	struct list_head list;
	time64_t mtime;
	char name[];
};

static void __init dir_add(const char *name, size_t nlen, time64_t mtime)
{
	struct dir_entry *de;

	de = kmalloc(sizeof(struct dir_entry) + nlen, GFP_KERNEL);
	if (!de)
		panic_show_mem("can't allocate dir_entry buffer");
	INIT_LIST_HEAD(&de->list);
	strscpy(de->name, name, nlen);
	de->mtime = mtime;
	list_add(&de->list, &dir_list);
}

static void __init dir_utime(void)
{
	struct dir_entry *de, *tmp;
	list_for_each_entry_safe(de, tmp, &dir_list, list) {
		list_del(&de->list);
		do_utime(de->name, de->mtime);
		kfree(de);
	}
}
#else
static void __init do_utime(char *filename, time64_t mtime) {}
static void __init do_utime_path(const struct path *path, time64_t mtime) {}
static void __init dir_add(const char *name, size_t nlen, time64_t mtime) {}
static void __init dir_utime(void) {}
#endif

static __initdata time64_t mtime;



static __initdata unsigned long ino, major, minor, nlink;
static __initdata umode_t mode;
static __initdata unsigned long body_len, name_len;
static __initdata uid_t uid;
static __initdata gid_t gid;
static __initdata unsigned rdev;
static __initdata u32 hdr_csum;

static void __init parse_header(char *s)
{
	unsigned long parsed[13];
	int i;

	for (i = 0, s += 6; i < 13; i++, s += 8)
		parsed[i] = simple_strntoul(s, NULL, 16, 8);

	ino = parsed[0];
	mode = parsed[1];
	uid = parsed[2];
	gid = parsed[3];
	nlink = parsed[4];
	mtime = parsed[5]; /* breaks in y2106 */
	body_len = parsed[6];
	major = parsed[7];
	minor = parsed[8];
	rdev = new_encode_dev(MKDEV(parsed[9], parsed[10]));
	name_len = parsed[11];
	hdr_csum = parsed[12];
}

/* FSM */

static __initdata enum state {
	Start,
	Collect,
	GotHeader,
	SkipIt,
	GotName,
	CopyFile,
	GotSymlink,
	Reset
} state, next_state;

static __initdata char *victim;
static unsigned long byte_count __initdata;
static __initdata loff_t this_header, next_header;

static inline void __init eat(unsigned n)
{
	victim += n;
	this_header += n;
	byte_count -= n;
}

static __initdata char *collected;
static long remains __initdata;
static __initdata char *collect;

static void __init read_into(char *buf, unsigned size, enum state next)
{
	if (byte_count >= size) {
		collected = victim;
		eat(size);
		state = next;
	} else {
		collect = collected = buf;
		remains = size;
		next_state = next;
		state = Collect;
	}
}

static __initdata char *header_buf, *symlink_buf, *name_buf;

static int __init do_start(void)
{
	read_into(header_buf, CPIO_HDRLEN, GotHeader);
	return 0;
}

static int __init do_collect(void)
{
	unsigned long n = remains;
	if (byte_count < n)
		n = byte_count;
	memcpy(collect, victim, n);
	eat(n);
	collect += n;
	if ((remains -= n) != 0)
		return 1;
	state = next_state;
	return 0;
}

static int __init do_header(void)
{
	if (!memcmp(collected, "070701", 6)) {
		csum_present = false;
	} else if (!memcmp(collected, "070702", 6)) {
		csum_present = true;
	} else {
		if (memcmp(collected, "070707", 6) == 0)
			error("incorrect cpio method used: use -H newc option");
		else
			error("no cpio magic");
		return 1;
	}
	parse_header(collected);
	next_header = this_header + N_ALIGN(name_len) + body_len;
	next_header = (next_header + 3) & ~3;
	state = SkipIt;
	if (name_len <= 0 || name_len > PATH_MAX)
		return 0;
	if (S_ISLNK(mode)) {
		if (body_len > PATH_MAX)
			return 0;
		collect = collected = symlink_buf;
		remains = N_ALIGN(name_len) + body_len;
		next_state = GotSymlink;
		state = Collect;
		return 0;
	}
	if (S_ISREG(mode) || !body_len)
		read_into(name_buf, N_ALIGN(name_len), GotName);
	return 0;
}

static int __init do_skip(void)
{
	if (this_header + byte_count < next_header) {
		eat(byte_count);
		return 1;
	} else {
		eat(next_header - this_header);
		state = next_state;
		return 0;
	}
}

static int __init do_reset(void)
{
	while (byte_count && *victim == '\0')
		eat(1);
	if (byte_count && (this_header & 3))
		error("broken padding");
	return 1;
}

static void __init clean_path(char *path, umode_t fmode)
{
	struct kstat st;

	if (!init_stat(path, &st, AT_SYMLINK_NOFOLLOW) &&
	    (st.mode ^ fmode) & S_IFMT) {
		if (S_ISDIR(st.mode))
			init_rmdir(path);
		else
			init_unlink(path);
	}
}

static int __init maybe_link(void)
{
	if (nlink >= 2) {
		char *old = find_link(major, minor, ino, mode, collected);
		if (old) {
			return 0; // WW.T.B.C //
		}
	}
	return 0;
}

static inline void do_trace_initcall_finish(initcall_t fn, int ret)
{
	if (!initcall_debug)
		return;
	trace_initcall_finish_cb(&initcall_calltime, fn, ret);
}
static inline void do_trace_initcall_level(const char *level)
{
	if (!initcall_debug)
		return;
	trace_initcall_level_cb(NULL, level);
}
#endif /* !TRACEPOINTS_ENABLED */


static __initdata int (*actions[])(void) = {
	[Start]		= do_start,
	[Collect]	= do_collect,
	[GotHeader]	= do_header,
	[SkipIt]	= do_skip,
	[GotName]	= do_name,
	[CopyFile]	= do_copy,
	[GotSymlink]	= do_symlink,
	[Reset]		= do_reset,
};

static long __init write_buffer(char *buf, unsigned long len)
{
	byte_count = len;
	victim = buf;

	while (!actions[state]())
		;
	return len - byte_count;
}

static long __init flush_buffer(void *bufv, unsigned long len)
{
	char *buf = bufv;
	long written;
	long origLen = len;
	if (message)
		return -1;
	while ((written = write_buffer(buf, len)) < len && !message) {
		char c = buf[written];
		if (c == '0') {
			buf += written;
			len -= written;
			state = Start;
		} else if (c == 0) {
			buf += written;
			len -= written;
			state = Reset;
		} else
			error("junk within compressed archive");
	}
	return origLen;
}


int hex_to_bin(unsigned char ch)
{
	unsigned char cu = ch & 0xdf;
	return -1 +
		((ch - '0' +  1) & (unsigned)((ch - '9' - 1) & ('0' - 1 - ch)) >> 8) +
		((cu - 'A' + 11) & (unsigned)((cu - 'F' - 1) & ('A' - 1 - cu)) >> 8);
}
EXPORT_SYMBOL(hex_to_bin);


 // hex2bin - convert an ascii hexadecimal string to its binary representation
 // @dst: binary result
 // @src: ascii hexadecimal string
 // @count: result length

 // Return 0 on success, -EINVAL in case of bad input.
 
int hex2bin(u8 *dst, const char *src, size_t count)
{
	while (count--) {
		int hi, lo;

		hi = hex_to_bin(*src++);
		if (unlikely(hi < 0))
			return -EINVAL;
		lo = hex_to_bin(*src++);
		if (unlikely(lo < 0))
			return -EINVAL;

		*dst++ = (hi << 4) | lo;
	}
	return 0;
}
EXPORT_SYMBOL(hex2bin);


char *bin2hex(char *dst, const void *src, size_t count)
{
	const unsigned char *_src = src;

	while (count--)
		dst = hex_byte_pack(dst, *_src++);
	return dst;
}
EXPORT_SYMBOL(bin2hex);

int hex_dump_to_buffer(const void *buf, size_t len, int rowsize, int groupsize,
		       char *linebuf, size_t linebuflen, bool ascii)
{
	const u8 *ptr = buf;
	int ngroups;
	u8 ch;
	int j, lx = 0;
	int ascii_column;
	int ret;

	if (rowsize != 16 && rowsize != 32)
		rowsize = 16;

	if (len > rowsize)		/* limit to one line at a time */
		len = rowsize;
	if (!is_power_of_2(groupsize) || groupsize > 8)
		groupsize = 1;
	if ((len % groupsize) != 0)	/* no mixed size output */
		groupsize = 1;

	ngroups = len / groupsize;
	ascii_column = rowsize * 2 + rowsize / groupsize + 1;

	if (!linebuflen)
		goto overflow1;

	if (!len)
		goto nil;

	if (groupsize == 8) {
		const u64 *ptr8 = buf;

		for (j = 0; j < ngroups; j++) {
			ret = snprintf(linebuf + lx, linebuflen - lx,
				       "%s%16.16llx", j ? " " : "",
				       get_unaligned(ptr8 + j));
			if (ret >= linebuflen - lx)
				goto overflow1;
			lx += ret;
		}
	} else if (groupsize == 4) {
		const u32 *ptr4 = buf;

		for (j = 0; j < ngroups; j++) {
			ret = snprintf(linebuf + lx, linebuflen - lx,
				       "%s%8.8x", j ? " " : "",
				       get_unaligned(ptr4 + j));
			if (ret >= linebuflen - lx)
				goto overflow1;
			lx += ret;
		}
	} else if (groupsize == 2) {
		const u16 *ptr2 = buf;

		for (j = 0; j < ngroups; j++) {
			ret = snprintf(linebuf + lx, linebuflen - lx,
				       "%s%4.4x", j ? " " : "",
				       get_unaligned(ptr2 + j));
			if (ret >= linebuflen - lx)
				goto overflow1;
			lx += ret;
		}
	} else {
		for (j = 0; j < len; j++) {
			if (linebuflen < lx + 2)
				goto overflow2;
			ch = ptr[j];
			linebuf[lx++] = hex_asc_hi(ch);
			if (linebuflen < lx + 2)
				goto overflow2;
			linebuf[lx++] = hex_asc_lo(ch);
			if (linebuflen < lx + 2)
				goto overflow2;
			linebuf[lx++] = ' ';
		}
		if (j)
			lx--;
	}
	if (!ascii)
		goto nil;

	while (lx < ascii_column) {
		if (linebuflen < lx + 2)
			goto overflow2;
		linebuf[lx++] = ' ';
	}
	for (j = 0; j < len; j++) {
		if (linebuflen < lx + 2)
			goto overflow2;
		ch = ptr[j];
		linebuf[lx++] = (isascii(ch) && isprint(ch)) ? ch : '.';
	}
nil:
	linebuf[lx] = '\0';
	return lx;
overflow2:
	linebuf[lx++] = '\0';
overflow1:
	return ascii ? ascii_column + len : (groupsize * 2 + 1) * ngroups - 1;
}
EXPORT_SYMBOL(hex_dump_to_buffer);

#ifdef CONFIG_PRINTK

void print_hex_dump(const char *level, const char *prefix_str, int prefix_type,
		    int rowsize, int groupsize,
		    const void *buf, size_t len, bool ascii)
{
	const u8 *ptr = buf;
	int i, linelen, remaining = len;
	unsigned char linebuf[32 * 3 + 2 + 32 + 1];

	if (rowsize != 16 && rowsize != 32)
		rowsize = 16;

	for (i = 0; i < len; i += rowsize) {
		linelen = min(remaining, rowsize);
		remaining -= rowsize;

		hex_dump_to_buffer(ptr + i, linelen, rowsize, groupsize,
				   linebuf, sizeof(linebuf), ascii);

		switch (prefix_type) {
		case DUMP_PREFIX_ADDRESS:
			printk("%s%s%p: %s\n",
			       level, prefix_str, ptr + i, linebuf);
			break;
		case DUMP_PREFIX_OFFSET:
			printk("%s%s%.8x: %s\n", level, prefix_str, i, linebuf);
			break;
		default:
			printk("%s%s%s\n", level, prefix_str, linebuf);
			break;
		}
	}
}
EXPORT_SYMBOL(print_hex_dump);

#endif // defined(CONFIG_PRINTK) 

static void reset_idle_masks(struct sched_ext_ops *ops)
{
	int node;

	if (!(ops->flags & SCX_OPS_BUILTIN_IDLE_PER_NODE)) {
		cpumask_copy(idle_cpumask(NUMA_NO_NODE)->cpu, cpu_online_mask);
		cpumask_copy(idle_cpumask(NUMA_NO_NODE)->smt, cpu_online_mask);
		return;
	}

	for_each_node(node) {
		const struct cpumask *node_mask = cpumask_of_node(node);

		cpumask_and(idle_cpumask(node)->cpu, cpu_online_mask, node_mask);
		cpumask_and(idle_cpumask(node)->smt, cpu_online_mask, node_mask);
	}
}

void scx_idle_enable(struct sched_ext_ops *ops)
{
	if (!ops->update_idle || (ops->flags & SCX_OPS_KEEP_BUILTIN_IDLE))
		static_branch_enable_cpuslocked(&scx_builtin_idle_enabled);
	else
		static_branch_disable_cpuslocked(&scx_builtin_idle_enabled);

	if (ops->flags & SCX_OPS_BUILTIN_IDLE_PER_NODE)
		static_branch_enable_cpuslocked(&scx_builtin_idle_per_node);
	else
		static_branch_disable_cpuslocked(&scx_builtin_idle_per_node);

	reset_idle_masks(ops);
}

void scx_idle_disable(void)
{
	static_branch_disable(&scx_builtin_idle_enabled);
	static_branch_disable(&scx_builtin_idle_per_node);
}


static int validate_node(int node)
{
	if (!static_branch_likely(&scx_builtin_idle_per_node)) {
		scx_kf_error("per-node idle tracking is disabled");
		return -EOPNOTSUPP;
	}

	if (node == NUMA_NO_NODE)
		return -ENOENT;

	if (node < 0 || node >= nr_node_ids) {
		scx_kf_error("invalid node %d", node);
		return -EINVAL;
	}

	if (!node_possible(node)) {
		scx_kf_error("unavailable node %d", node);
		return -EINVAL;
	}

	return node;
}

__bpf_kfunc_start_defs();

static bool check_builtin_idle_enabled(void)
{
	if (static_branch_likely(&scx_builtin_idle_enabled))
		return true;

	scx_kf_error("built-in idle tracking is disabled");
	return false;
}

static s32 select_cpu_from_kfunc(struct task_struct *p, s32 prev_cpu, u64 wake_flags,
				 const struct cpumask *allowed, u64 flags)
{
	struct rq *rq;
	struct rq_flags rf;
	s32 cpu;

	if (!kf_cpu_valid(prev_cpu, NULL))
		return -EINVAL;

	if (!check_builtin_idle_enabled())
		return -EBUSY;


	if (scx_kf_allowed_if_unlocked()) {
		rq = task_rq_lock(p, &rf);
	} else {
		if (!scx_kf_allowed(SCX_KF_SELECT_CPU | SCX_KF_ENQUEUE))
			return -EPERM;
		rq = scx_locked_rq();
	}


	if (!rq)
		lockdep_assert_held(&p->pi_lock);


	if (p->nr_cpus_allowed == 1 || is_migration_disabled(p)) {
		if (cpumask_test_cpu(prev_cpu, allowed ?: p->cpus_ptr) &&
		    scx_idle_test_and_clear_cpu(prev_cpu))
			cpu = prev_cpu;
		else
			cpu = -EBUSY;
	} else {
		cpu = scx_select_cpu_dfl(p, prev_cpu, wake_flags,
					 allowed ?: p->cpus_ptr, flags);
	}

	if (scx_kf_allowed_if_unlocked())
		task_rq_unlock(rq, p, &rf);

	return cpu;
}


__bpf_kfunc int scx_bpf_cpu_node(s32 cpu)
{
	if (!kf_cpu_valid(cpu, NULL))
		return NUMA_NO_NODE;

	return cpu_to_node(cpu);
}


static struct resource code_resource = {
	.name  = "Kernel code",
	.flags = IORESOURCE_BUSY | IORESOURCE_SYSTEM_RAM,
};

static struct resource data_resource = {
	.name = "Kernel data",
	.flags = IORESOURCE_BUSY | IORESOURCE_SYSTEM_RAM,
};

static struct resource bss_resource = {
	.name = "Kernel bss",
	.flags = IORESOURCE_BUSY | IORESOURCE_SYSTEM_RAM,
};

static struct resource __initdata *standard_resources[] = {
	&code_resource,
	&data_resource,
	&bss_resource,
};

static void __init setup_resources(void)
{
	struct resource *res, *std_res, *sub_res;
	phys_addr_t start, end;
	int j;
	u64 i;

	code_resource.start = __pa_symbol(_text);
	code_resource.end = __pa_symbol(_etext) - 1;
	data_resource.start = __pa_symbol(_etext);
	data_resource.end = __pa_symbol(_edata) - 1;
	bss_resource.start = __pa_symbol(__bss_start);
	bss_resource.end = __pa_symbol(__bss_stop) - 1;

	for_each_mem_range(i, &start, &end) {
		res = memblock_alloc_or_panic(sizeof(*res), 8);
		res->flags = IORESOURCE_BUSY | IORESOURCE_SYSTEM_RAM;

		res->name = "System RAM";
		res->start = start;

		res->end = end - 1;
		request_resource(&iomem_resource, res);

		for (j = 0; j < ARRAY_SIZE(standard_resources); j++) {
			std_res = standard_resources[j];
			if (std_res->start < res->start ||
			    std_res->start > res->end)
				continue;
			if (std_res->end > res->end) {
				sub_res = memblock_alloc_or_panic(sizeof(*sub_res), 8);
				*sub_res = *std_res;
				sub_res->end = res->end;
				std_res->start = res->end + 1;
				request_resource(res, sub_res);
			} else {
				request_resource(res, std_res);
			}
		}
	}
#ifdef CONFIG_CRASH_DUMP

	if (crashk_res.end) {
		memblock_add_node(crashk_res.start, resource_size(&crashk_res),
				  0, MEMBLOCK_NONE);
		memblock_reserve(crashk_res.start, resource_size(&crashk_res));
		insert_resource(&iomem_resource, &crashk_res);
	}
#endif
}

static void __init setup_memory_end(void)
{
	max_pfn = max_low_pfn = PFN_DOWN(ident_map_size);
	pr_notice("The maximum memory size is %luMB\n", ident_map_size >> 20);
}

#ifdef CONFIG_CRASH_DUMP


static int kdump_mem_notifier(struct notifier_block *nb,
			      unsigned long action, void *data)
{
	struct memory_notify *arg = data;

	if (action != MEM_GOING_OFFLINE)
		return NOTIFY_OK;
	if (arg->start_pfn < PFN_DOWN(resource_size(&crashk_res)))
		return NOTIFY_BAD;
	return NOTIFY_OK;
}

static struct notifier_block kdump_mem_nb = {
	.notifier_call = kdump_mem_notifier,
};

#endif

/*
 Reserve page tables created by decompressor
 */
static void __init reserve_pgtables(void)
{
	unsigned long start, end;
	struct reserved_range *range;

	for_each_physmem_reserved_type_range(RR_VMEM, range, &start, &end)
		memblock_reserve(start, end - start);
}

/*
 Reserve memory for kdump kernel to be loaded with kexec
 */
static void __init reserve_crashkernel(void)
{
#ifdef CONFIG_CRASH_DUMP
	unsigned long long crash_base, crash_size;
	phys_addr_t low, high;
	int rc;

	rc = parse_crashkernel(boot_command_line, ident_map_size,
			       &crash_size, &crash_base, NULL, NULL, NULL);

	crash_base = ALIGN(crash_base, KEXEC_CRASH_MEM_ALIGN);
	crash_size = ALIGN(crash_size, KEXEC_CRASH_MEM_ALIGN);
	if (rc || crash_size == 0)
		return;

	if (memblock.memory.regions[0].size < crash_size) {
		pr_info("crashkernel reservation failed: %s\n",
			"first memory chunk must be at least crashkernel size");
		return;
	}

	low = crash_base ?: oldmem_data.start;
	high = low + crash_size;
	if (low >= oldmem_data.start && high <= oldmem_data.start + oldmem_data.size) {
		/* The crashkernel fits into OLDMEM, reuse OLDMEM */
		crash_base = low;
	} else {
		/* Find suitable area in free memory */
		low = max_t(unsigned long, crash_size, sclp.hsa_size);
		high = crash_base ? crash_base + crash_size : ULONG_MAX;

		if (crash_base && crash_base < low) {
			pr_info("crashkernel reservation failed: %s\n",
				"crash_base too low");
			return;
		}
		low = crash_base ?: low;
		crash_base = memblock_phys_alloc_range(crash_size,
						       KEXEC_CRASH_MEM_ALIGN,
						       low, high);
	}

	if (!crash_base) {
		pr_info("crashkernel reservation failed: %s\n",
			"no suitable area found");
		return;
	}

	if (register_memory_notifier(&kdump_mem_nb)) {
		memblock_phys_free(crash_base, crash_size);
		return;
	}

	if (!oldmem_data.start && machine_is_vm())
		diag10_range(PFN_DOWN(crash_base), PFN_DOWN(crash_size));
	crashk_res.start = crash_base;
	crashk_res.end = crash_base + crash_size - 1;
	memblock_remove(crash_base, crash_size);
	pr_info("Reserving %lluMB of memory at %lluMB "
		"for crashkernel (System RAM: %luMB)\n",
		crash_size >> 20, crash_base >> 20,
		(unsigned long)memblock.memory.total_size >> 20);
	os_info_crashkernel_add(crash_base, crash_size);
#endif
}

/*
 Reserve the initrd from being used by memblock
 */
static void __init reserve_initrd(void)
{
	unsigned long addr, size;

	if (!IS_ENABLED(CONFIG_BLK_DEV_INITRD) || !get_physmem_reserved(RR_INITRD, &addr, &size))
		return;
	initrd_start = (unsigned long)__va(addr);
	initrd_end = initrd_start + size;
	memblock_reserve(addr, size);
}

/*
 Reserve the memory area used to pass the certificate lists
 */
static void __init reserve_certificate_list(void)
{
	if (ipl_cert_list_addr)
		memblock_reserve(ipl_cert_list_addr, ipl_cert_list_size);
}

static void __init reserve_physmem_info(void)
{
	unsigned long addr, size;

	if (get_physmem_reserved(RR_MEM_DETECT_EXT, &addr, &size))
		memblock_reserve(addr, size);
}

static void __init free_physmem_info(void)
{
	unsigned long addr, size;

	if (get_physmem_reserved(RR_MEM_DETECT_EXT, &addr, &size))
		memblock_phys_free(addr, size);

	unsigned int cpu;
	int ret = 0;

	cpus_read_lock();
	mutex_lock(&smpboot_threads_lock);
	for_each_online_cpu(cpu) {
		ret = __smpboot_create_thread(plug_thread, cpu);
		if (ret) {
			smpboot_destroy_threads(plug_thread);
			goto out;
		}
		smpboot_unpark_thread(plug_thread, cpu);
	}
	list_add(&plug_thread->list, &hotplug_threads);
	out:
		mutex_unlock(&smpboot_threads_lock);
		cpus_read_unlock();
		return ret;
}

EXPORT_SYMBOL_GPL(smpboot_register_percpu_thread);

static void __init memblock_add_physmem_info(void)
{
	unsigned long start, end;
	int i;

	pr_debug("physmem info source: %s (%hhd)\n",
		 get_physmem_info_source(), physmem_info.info_source);
	/* keep memblock lists close to the kernel */
	memblock_set_bottom_up(true);
	for_each_physmem_usable_range(i, &start, &end)
		memblock_add(start, end - start);
	for_each_physmem_online_range(i, &start, &end)
		memblock_physmem_add(start, end - start);
	memblock_set_bottom_up(false);
	memblock_set_node(0, ULONG_MAX, &memblock.memory, 0);
}

/*
  Reserve memory used for lowcore.
 */
static void __init reserve_lowcore(void)
{
	void *lowcore_start = get_lowcore();
	void *lowcore_end = lowcore_start + sizeof(struct lowcore);
	void *start, *end;

	if (absolute_pointer(__identity_base) < lowcore_end) {
		start = max(lowcore_start, (void *)__identity_base);
		end = min(lowcore_end, (void *)(__identity_base + ident_map_size));
		memblock_reserve(__pa(start), __pa(end));
	}
}

/*
 Reserve memory used for absolute lowcore/command line/kernel image.
 */
static void __init reserve_kernel(void)
{
	memblock_reserve(0, STARTUP_NORMAL_OFFSET);
	memblock_reserve(OLDMEM_BASE, sizeof(unsigned long));
	memblock_reserve(OLDMEM_SIZE, sizeof(unsigned long));
	memblock_reserve(physmem_info.reserved[RR_AMODE31].start, __eamode31 - __samode31);
	memblock_reserve(__pa(sclp_early_sccb), EXT_SCCB_READ_SCP);
	memblock_reserve(__pa(_stext), _end - _stext);
}

static void __init setup_memory(void)
{
	phys_addr_t start, end;
	u64 i;


	for_each_mem_range(i, &start, &end)
		storage_key_init_range(start, end);

	psw_set_key(PAGE_DEFAULT_KEY);
}

static void __init relocate_amode31_section(void)
{
	unsigned long amode31_size = __eamode31 - __samode31;
	long amode31_offset, *ptr;

	amode31_offset = AMODE31_START - (unsigned long)__samode31;
	pr_info("Relocating AMODE31 section of size 0x%08lx\n", amode31_size);

	
	memmove((void *)physmem_info.reserved[RR_AMODE31].start, __samode31, amode31_size);

	memset(__samode31, 0, amode31_size);


	for (ptr = _start_amode31_refs; ptr != _end_amode31_refs; ptr++)
		*ptr += amode31_offset;
}

static void __init setup_cr(void)
{
	union ctlreg2 cr2;
	union ctlreg5 cr5;
	union ctlreg15 cr15;

	__ctl_duct[1] = (unsigned long)__ctl_aste;
	__ctl_duct[2] = (unsigned long)__ctl_aste;
	__ctl_duct[4] = (unsigned long)__ctl_duald;

	
	local_ctl_store(2, &cr2.reg);
	local_ctl_store(5, &cr5.reg);
	local_ctl_store(15, &cr15.reg);
	cr2.ducto = (unsigned long)__ctl_duct >> 6;
	cr5.pasteo = (unsigned long)__ctl_duct >> 6;
	cr15.lsea = (unsigned long)__ctl_linkage_stack >> 3;
	system_ctl_load(2, &cr2.reg);
	system_ctl_load(5, &cr5.reg);
	system_ctl_load(15, &cr15.reg);
}


static void __init setup_randomness(void)
{
	struct sysinfo_3_2_2 *vmms;

	vmms = memblock_alloc_or_panic(PAGE_SIZE, PAGE_SIZE);
	if (stsi(vmms, 3, 2, 2) == 0 && vmms->count)
		add_device_randomness(&vmms->vm, sizeof(vmms->vm[0]) * vmms->count);
	memblock_free(vmms, PAGE_SIZE);

	if (cpacf_query_func(CPACF_PRNO, CPACF_PRNO_TRNG))
		static_branch_enable(&s390_arch_random_available);
}

/
static void __init setup_control_program_code(void)
{
	union diag318_info diag318_info = {
		.cpnc = CPNC_LINUX,
		.cpvc = 0,
	};

	if (!sclp.has_diag318)
		return;

	diag_stat_inc(DIAG_STAT_X318);
	asm volatile("diag %0,0,0x318\n" : : "d" (diag318_info.val));
}


static void __init log_component_list(void)
{
	struct ipl_rb_component_entry *ptr, *end;
	char *str;

	if (!early_ipl_comp_list_addr)
		return;
	if (ipl_block.hdr.flags & IPL_PL_FLAG_SIPL)
		pr_info("Linux is running with Secure-IPL enabled\n");
	else
		pr_info("Linux is running with Secure-IPL disabled\n");
	ptr = __va(early_ipl_comp_list_addr);
	end = (void *) ptr + early_ipl_comp_list_size;
	pr_info("The IPL report contains the following components:\n");
	while (ptr < end) {
		if (ptr->flags & IPL_RB_COMPONENT_FLAG_SIGNED) {
			if (ptr->flags & IPL_RB_COMPONENT_FLAG_VERIFIED)
				str = "signed, verified";
			else
				str = "signed, verification failed";
		} else {
			str = "not signed";
		}
		pr_info("%016llx - %016llx (%s)\n",
			ptr->addr, ptr->addr + ptr->len, str);
		ptr++;
	}
}


static void __init print_rb_entry(const char *buf)
{
	char fmt[] = KERN_SOH "0boot: %s";
	int level = printk_get_level(buf);

	buf = skip_timestamp(printk_skip_level(buf));
	if (level == KERN_DEBUG[1] && (!bootdebug || !bootdebug_filter_match(buf)))
		return;

	fmt[1] = level;
	printk(fmt, buf);
}



void __init setup_arch(char **cmdline_p)
{

	if (machine_is_vm())
		pr_info("Linux is running as a z/VM "
			"guest operating system in 64-bit mode\n");
	else if (machine_is_kvm())
		pr_info("Linux is running under KVM in 64-bit mode\n");
	else if (machine_is_lpar())
		pr_info("Linux is running natively in 64-bit mode\n");
	else
		pr_info("Linux is running as a guest in 64-bit mode\n");
	/* Print decompressor messages if not already printed */
	if (!boot_earlyprintk)
		boot_rb_foreach(print_rb_entry);

	if (machine_has_relocated_lowcore())
		pr_info("Lowcore relocated to 0x%px\n", get_lowcore());

	log_component_list();

	/* Have one command line that is parsed and saved in /proc/cmdline */
	/* boot_command_line has been already set up in early.c */
	*cmdline_p = boot_command_line;

        ROOT_DEV = Root_RAM0;

	setup_initial_init_mm(_text, _etext, _edata, _end);

	if (IS_ENABLED(CONFIG_EXPOLINE_AUTO))
		nospec_auto_detect();

	jump_label_init();
	parse_early_param();
#ifdef CONFIG_CRASH_DUMP
	/* Deactivate elfcorehdr= kernel parameter */
	elfcorehdr_addr = ELFCORE_ADDR_MAX;
#endif

	os_info_init();
	setup_ipl();
	setup_control_program_code();

	reserve_lowcore();
	reserve_kernel();
	reserve_initrd();
	reserve_certificate_list();
	reserve_physmem_info();
	memblock_set_current_limit(ident_map_size);
	memblock_allow_resize();


	memblock_add_physmem_info();

	free_physmem_info();
	setup_memory_end();
	memblock_dump_all();
	setup_memory();

	relocate_amode31_section();
	setup_cr();
	setup_uv();
	dma_contiguous_reserve(ident_map_size);
	vmcp_cma_reserve();
	if (cpu_has_edat2())
		hugetlb_cma_reserve(PUD_SHIFT - PAGE_SHIFT);

	reserve_crashkernel();
#ifdef CONFIG_CRASH_DUMP

	smp_save_dump_secondary_cpus();
#endif

	setup_resources();
	setup_lowcore();
	smp_fill_possible_mask();
	cpu_detect_mhz_feature();
        cpu_init();
	numa_setup();
	smp_detect_cpus();
	topology_init_early();
	setup_protection_map();

        paging_init();


#ifdef CONFIG_CRASH_DUMP
	smp_save_dump_ipl_cpu();
#endif


	conmode_default();
	set_preferred_console();

	apply_alternative_instructions();
	if (IS_ENABLED(CONFIG_EXPOLINE))
		nospec_init_branches();


	setup_zfcpdump();


	setup_randomness();
}

void __init arch_cpu_finalize_init(void)
{
	sclp_init();
}

int __init_or_module do_one_initcall(initcall_t fn)
{
	int count = preempt_count();
	char msgbuf[64];
	int ret;

	if (initcall_blacklisted(fn))
		return -EPERM;

	do_trace_initcall_start(fn);
	ret = fn();
	do_trace_initcall_finish(fn, ret);

	msgbuf[0] = 0;

	if (preempt_count() != count) {
		sprintf(msgbuf, "preemption imbalance ");
		preempt_count_set(count);
	}
	if (irqs_disabled()) {
		strlcat(msgbuf, "disabled interrupts ", sizeof(msgbuf));
		local_irq_enable();
	}
	WARN(msgbuf[0], "initcall %pS returned with %s\n", fn, msgbuf);

	add_latent_entropy();
	return ret;
}


static initcall_entry_t *initcall_levels[] __initdata = {
	__initcall0_start,
	__initcall1_start,
	__initcall2_start,
	__initcall3_start,
	__initcall4_start,
	__initcall5_start,
	__initcall6_start,
	__initcall7_start,
	__initcall_end,
};

static const char *initcall_level_names[] __initdata = {
	"pure",
	"core",
	"postcore",
	"arch",
	"subsys",
	"fs",
	"device",
	"late",
};

static int __init ignore_unknown_bootoption(char *param, char *val,
			       const char *unused, void *arg)
{
	return 0;
}

static void __init do_initcall_level(int level, char *command_line)
{
	initcall_entry_t *fn;

	parse_args(initcall_level_names[level],
		   command_line, __start___param,
		   __stop___param - __start___param,
		   level, level,
		   NULL, ignore_unknown_bootoption);

	do_trace_initcall_level(initcall_level_names[level]);
	for (fn = initcall_levels[level]; fn < initcall_levels[level+1]; fn++)
		do_one_initcall(initcall_from_entry(fn));
}

static void __init do_initcalls(void)
{
	int level;
	size_t len = saved_command_line_len + 1;
	char *command_line;

	command_line = kzalloc(len, GFP_KERNEL);
	if (!command_line)
		panic("%s: Failed to allocate %zu bytes\n", __func__, len);

	for (level = 0; level < ARRAY_SIZE(initcall_levels) - 1; level++) {
		/* Parser modifies command_line, restore it each time */
		strcpy(command_line, saved_command_line);
		do_initcall_level(level, command_line);
	}

	kfree(command_line);
}

/*
 Ok, the machine is now initialized. None of the devices
 have been touched yet, but the CPU subsystem is up and
 running, and memory and process management works.
 
 Now we can finally start doing some real work..
 */
static void __init do_basic_setup(void)
{
	cpuset_init_smp();
	driver_init();
	init_irq_proc();
	do_ctors();
	do_initcalls();
}

static void __init do_pre_smp_initcalls(void)
{
	initcall_entry_t *fn;

	do_trace_initcall_level("early");
	for (fn = __initcall_start; fn < __initcall0_start; fn++)
		do_one_initcall(initcall_from_entry(fn));
}

static int run_init_process(const char *init_filename)
{
	const char *const *p;

	argv_init[0] = init_filename;
	pr_info("Run %s as init process\n", init_filename);
	pr_debug("  with arguments:\n");
	for (p = argv_init; *p; p++)
		pr_debug("    %s\n", *p);
	pr_debug("  with environment:\n");
	for (p = envp_init; *p; p++)
		pr_debug("    %s\n", *p);
	return kernel_execve(init_filename, argv_init, envp_init);
}

static int try_to_run_init_process(const char *init_filename)
{
	int ret;

	ret = run_init_process(init_filename);

	if (ret && ret != -ENOENT) {
		pr_err("Starting init: %s exists but couldn't execute it (error %d)\n",
		       init_filename, ret);
	}

	return ret;
}

static noinline void __init kernel_init_freeable(void);

#if defined(CONFIG_STRICT_KERNEL_RWX) || defined(CONFIG_STRICT_MODULE_RWX)
bool rodata_enabled __ro_after_init = true;

#ifndef arch_parse_debug_rodata
static inline bool arch_parse_debug_rodata(char *str) { return false; }
#endif

static int __init set_debug_rodata(char *str)
{
	if (arch_parse_debug_rodata(str))
		return 0;

	if (str && !strcmp(str, "on"))
		rodata_enabled = true;
	else if (str && !strcmp(str, "off"))
		rodata_enabled = false;
	else
		pr_warn("Invalid option string for rodata: '%s'\n", str);
	return 0;
}
early_param("rodata", set_debug_rodata);
#endif

static void mark_readonly(void)
{
	if (IS_ENABLED(CONFIG_STRICT_KERNEL_RWX) && rodata_enabled) {

		flush_module_init_free_work();
		jump_label_init_ro();
		mark_rodata_ro();
		debug_checkwx();
		rodata_test();
	} else if (IS_ENABLED(CONFIG_STRICT_KERNEL_RWX)) {
		pr_info("Kernel memory protection disabled.\n");
	} else if (IS_ENABLED(CONFIG_ARCH_HAS_STRICT_KERNEL_RWX)) {
		pr_warn("Kernel memory protection not selected by kernel config.\n");
	} else {
		pr_warn("This architecture does not have kernel memory protection.\n");
	}
}

void smpboot_unregister_percpu_thread(struct smp_hotplug_thread *plug_thread)
{
	cpus_read_lock();
	mutex_lock(&smpboot_threads_lock);
	list_del(&plug_thread->list);
	smpboot_destroy_threads(plug_thread);
	mutex_unlock(&smpboot_threads_lock);
	cpus_read_unlock();
}
EXPORT_SYMBOL_GPL(smpboot_unregister_percpu_thread);


//WTBD////
/* Soon */