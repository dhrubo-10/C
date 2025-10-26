#include <linux/export.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/slab.h>
#include <linux/fs_struct.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include "strct.h"

void set_fs_root(struct fs_struct *fs, const struct path *path)
{
	struct path old;

	path_get(path);
	write_seqlock(&fs->seq);
	old = fs->root;
	fs->root = *path;
	write_sequnlock(&fs->seq);
	if (old.dentry)
		path_put(&old);
}
EXPORT_SYMBOL(set_fs_root);

void set_fs_pwd(struct fs_struct *fs, const struct path *path)
{
	struct path old;

	path_get(path);
	write_seqlock(&fs->seq);
	old = fs->pwd;
	fs->pwd = *path;
	write_sequnlock(&fs->seq);
	if (old.dentry)
		path_put(&old);
}
EXPORT_SYMBOL(set_fs_pwd);

static inline bool path_equal(const struct path *a, const struct path *b)
{
	return a->dentry == b->dentry && a->mnt == b->mnt;
}

void chroot_fs_refs(const struct path *old_root, const struct path *new_root)
{
	struct task_struct *g, *p;
	struct fs_struct *fs;
	int refs_added = 0;

	rcu_read_lock();
	for_each_process_thread(g, p) {
		task_lock(p);
		fs = p->fs;
		if (fs) {
			write_seqlock(&fs->seq);
			if (path_equal(&fs->root, old_root)) {
				struct path prev = fs->root;
				fs->root = *new_root;
				path_get(new_root);
				path_put(&prev);
				refs_added++;
			}
			if (path_equal(&fs->pwd, old_root)) {
				struct path prev = fs->pwd;
				fs->pwd = *new_root;
				path_get(new_root);
				path_put(&prev);
				refs_added++;
			}
			write_sequnlock(&fs->seq);
		}
		task_unlock(p);
	}
	rcu_read_unlock();

	while (refs_added--)
		path_put(new_root);
}
EXPORT_SYMBOL(chroot_fs_refs);

void free_fs_struct(struct fs_struct *fs)
{
	if (!fs)
		return;
	path_put(&fs->root);
	path_put(&fs->pwd);
	kmem_cache_free(fs_cachep, fs);
}
EXPORT_SYMBOL(free_fs_struct);

void exit_fs(struct task_struct *tsk)
{
	struct fs_struct *fs = tsk->fs;
	bool kill = false;

	if (!fs)
		return;

	task_lock(tsk);
	write_seqlock(&fs->seq);
	tsk->fs = NULL;
	if (--fs->users == 0)
		kill = true;
	write_sequnlock(&fs->seq);
	task_unlock(tsk);

	if (kill)
		free_fs_struct(fs);
}
EXPORT_SYMBOL(exit_fs);

struct fs_struct *copy_fs_struct(struct fs_struct *old)
{
	struct fs_struct *fs;

	fs = kmem_cache_alloc(fs_cachep, GFP_KERNEL);
	if (!fs)
		return NULL;

	fs->users = 1;
	fs->in_exec = 0;
	seqlock_init(&fs->seq);
	fs->umask = old->umask;

	read_seqlock(&old->seq);
	fs->root = old->root;
	path_get(&fs->root);
	fs->pwd = old->pwd;
	path_get(&fs->pwd);
	read_sequnlock(&old->seq);

	return fs;
}
EXPORT_SYMBOL(copy_fs_struct);

int unshare_fs_struct(void)
{
	struct fs_struct *old_fs = current->fs;
	struct fs_struct *new_fs;

	if (!old_fs)
		return -EINVAL;

	new_fs = copy_fs_struct(old_fs);
	if (!new_fs)
		return -ENOMEM;

	task_lock(current);
	write_seqlock(&old_fs->seq);
	if (--old_fs->users == 0) {
		current->fs = new_fs;
		write_sequnlock(&old_fs->seq);
		task_unlock(current);
		free_fs_struct(old_fs);
	} else {
		current->fs = new_fs;
		write_sequnlock(&old_fs->seq);
		task_unlock(current);
	}
	return 0;
}
EXPORT_SYMBOL_GPL(unshare_fs_struct);

int current_umask(void)
{
	struct fs_struct *fs = current->fs;
	if (!fs)
		return 0;
	return fs->umask;
}
EXPORT_SYMBOL(current_umask);

struct fs_struct init_fs = {
	.users		= 1,
	.seq		= __SEQLOCK_UNLOCKED(init_fs.seq),
	.umask		= 0022,
};

int set_fs_user_ns(struct fs_struct *fs, const struct user_namespace *ns)
{
	if (!fs || !ns)
		return -EINVAL;
	write_seqlock(&fs->seq);
	fs->user_ns = ns;
	write_sequnlock(&fs->seq);
	return 0;
}
EXPORT_SYMBOL(set_fs_user_ns);

const struct path *get_task_root(struct task_struct *task)
{
	const struct path *p = NULL;
	struct fs_struct *fs;

	rcu_read_lock();
	task = rcu_dereference(task);
	if (!task) {
		rcu_read_unlock();
		return NULL;
	}
	read_seqlock(&task->fs->seq);
	p = &task->fs->root;
	rcu_read_unlock();
	return p;
}
EXPORT_SYMBOL(get_task_root);
