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

	/*
	 * poison cpio source buffer, so we can detect overrun. source
	 * buffer is used by read_into() when hdr or fname
	 * are already available (e.g. no compression).
	 */
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

static void __init free_hash(void)
{
	struct hash **p, *q;
	for (p = head; hardlink_seen && p < head + 32; p++) {
		while (*p) {
			q = *p;
			*p = q->next;
			kfree(q);
		}
	}
	hardlink_seen = false;
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

/* cpio header parsing */

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

//WTBD////
/* Soon */