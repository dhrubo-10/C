#include <linux/anon_inodes.h>
#include <linux/exportfs.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/cgroup.h>
#include <linux/magic.h>
#include <linux/mount.h>
#include <linux/pid.h>
#include <linux/pidfs.h>
#include <linux/pid_namespace.h>
#include <linux/poll.h>
#include <linux/proc_fs.h>
#include <linux/proc_ns.h>
#include <linux/pseudo_fs.h>
#include <linux/ptrace.h>
#include <linux/seq_file.h>
#include <uapi/linux/pidfd.h>
#include <linux/ipc_namespace.h>
#include <linux/time_namespace.h>
#include <linux/utsname.h>
#include <net/net_namespace.h>
#include <linux/coredump.h>
#include <linux/xattr.h>

#define PIDFS_PID_DEAD ERR_PTR(-ESRCH)
/* needs check */

static struct kmem_cache *pidfs_attr_cachep __ro_after_init;
static struct kmem_cache *pidfs_xattr_cachep __ro_after_init;

static struct path pidfs_root_path = {};

void pidfs_get_root(struct path *path)
{
	*path = pidfs_root_path;
	path_get(path);
}

struct pidfs_exit_info {
	__u64 cgroupid;
	__s32 exit_code;
	__u32 coredump_mask;
};

struct pidfs_attr {
	struct simple_xattrs *xattrs;
	struct pidfs_exit_info __pei;
	struct pidfs_exit_info *exit_info;
};

static struct rb_root pidfs_ino_tree = RB_ROOT;

#if BITS_PER_LONG == 32
static inline unsigned long pidfs_ino(u64 ino)
{
	return lower_32_bits(ino);
}

/* On 32 bit the generation number are the upper 32 bits. */
static inline u32 pidfs_gen(u64 ino)
{
	return upper_32_bits(ino);
}

#else

/* On 64 bit simply return ino. */
static inline unsigned long pidfs_ino(u64 ino)
{
	return ino;
}

/* On 64 bit the generation number is 0. */
static inline u32 pidfs_gen(u64 ino)
{
	return 0;
}
#endif

static int pidfs_ino_cmp(struct rb_node *a, const struct rb_node *b)
{
	struct pid *pid_a = rb_entry(a, struct pid, pidfs_node);
	struct pid *pid_b = rb_entry(b, struct pid, pidfs_node);
	u64 pid_ino_a = pid_a->ino;
	u64 pid_ino_b = pid_b->ino;

	if (pid_ino_a < pid_ino_b)
		return -1;
	if (pid_ino_a > pid_ino_b)
		return 1;
	return 0;
}

void pidfs_add_pid(struct pid *pid)
{
	static u64 pidfs_ino_nr = 2;
	if (pidfs_ino(pidfs_ino_nr) == 0)
		pidfs_ino_nr += 2;

	pid->ino = pidfs_ino_nr;
	pid->stashed = NULL;
	pid->attr = NULL;
	pidfs_ino_nr++;

	write_seqcount_begin(&pidmap_lock_seq);
	rb_find_add_rcu(&pid->pidfs_node, &pidfs_ino_tree, pidfs_ino_cmp);
	write_seqcount_end(&pidmap_lock_seq);
}


void pidfs_remove_pid(struct pid *pid)
{
	write_seqcount_begin(&pidmap_lock_seq);
	rb_erase(&pid->pidfs_node, &pidfs_ino_tree);
	write_seqcount_end(&pidmap_lock_seq);
}
