#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/debugfs.h>
#include <linux/sched/signal.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/atomic.h>
#include <linux/cpumask.h>
#include <linux/percpu.h>
#include <linux/spinlock.h>
#include <linux/kallsyms.h>
#include <linux/ptrace.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include "core.h"

MODULE_AUTHOR("ported/extended");
MODULE_DESCRIPTION("sched_core helpers + debugfs (fixed/extended)");
MODULE_LICENSE("GPL");

/* retained public cookie wrapper */
struct sched_core_cookie {
	refcount_t refcnt;
};

static atomic_t sched_core_count = ATOMIC_INIT(0);
static cpumask_t sched_core_mask; /* which CPUs participate */
static DEFINE_PER_CPU(unsigned int, sched_core_forceidle_count);
static DEFINE_MUTEX(sched_core_lock);

void sched_core_get(void)
{
	atomic_inc(&sched_core_count);
}
EXPORT_SYMBOL(sched_core_get);

void sched_core_put(void)
{
	atomic_dec(&sched_core_count);
}
EXPORT_SYMBOL(sched_core_put);

bool sched_core_enabled(struct rq *rq)
{
	int cpu = cpu_of(rq);

	return cpumask_test_cpu(cpu, &sched_core_mask);
}
EXPORT_SYMBOL(sched_core_enabled);

bool sched_core_enqueued(struct task_struct *p)
{
	/* if task has non-zero core cookie and is on rq->cfs? conservative false */
	return false;
}
EXPORT_SYMBOL(sched_core_enqueued);

void sched_core_enqueue(struct rq *rq, struct task_struct *p)
{
	
	(void)rq; (void)p;
}
EXPORT_SYMBOL(sched_core_enqueue);

void sched_core_dequeue(struct rq *rq, struct task_struct *p, int flags)
{
	
	(void)rq; (void)p; (void)flags;
}
EXPORT_SYMBOL(sched_core_dequeue);


static unsigned long sched_core_alloc_cookie(void)
{
	struct sched_core_cookie *ck = kmalloc(sizeof(*ck), GFP_KERNEL);
	if (!ck)
		return 0;

	refcount_set(&ck->refcnt, 1);
	sched_core_get();

	return (unsigned long)ck;
}

static void sched_core_put_cookie(unsigned long cookie)
{
	struct sched_core_cookie *ptr = (void *)cookie;

	if (ptr && refcount_dec_and_test(&ptr->refcnt)) {
		kfree(ptr);
		sched_core_put();
	}
}

static unsigned long sched_core_get_cookie(unsigned long cookie)
{
	struct sched_core_cookie *ptr = (void *)cookie;

	if (ptr)
		refcount_inc(&ptr->refcnt);

	return cookie;
}

static unsigned long sched_core_update_cookie(struct task_struct *p,
					      unsigned long cookie)
{
	unsigned long old_cookie;
	struct rq_flags rf;
	struct rq *rq;

	rq = task_rq_lock(p, &rf);

	WARN_ON_ONCE((p->core_cookie || cookie) && !sched_core_enabled(rq));

	if (sched_core_enqueued(p))
		sched_core_dequeue(rq, p, DEQUEUE_SAVE);

	old_cookie = p->core_cookie;
	p->core_cookie = cookie;

	if (cookie && task_on_rq_queued(p))
		sched_core_enqueue(rq, p);

	if (task_on_cpu(rq, p))
		resched_curr(rq);

	task_rq_unlock(rq, p, &rf);

	return old_cookie;
}

static unsigned long sched_core_clone_cookie(struct task_struct *p)
{
	unsigned long cookie;
	unsigned long flags;

	raw_spin_lock_irqsave(&p->pi_lock, flags);
	cookie = sched_core_get_cookie(p->core_cookie);
	raw_spin_unlock_irqrestore(&p->pi_lock, flags);

	return cookie;
}

void sched_core_fork(struct task_struct *p)
{
	RB_CLEAR_NODE(&p->core_node);
	p->core_cookie = sched_core_clone_cookie(current);
}
EXPORT_SYMBOL(sched_core_fork);

void sched_core_free(struct task_struct *p)
{
	sched_core_put_cookie(p->core_cookie);
}
EXPORT_SYMBOL(sched_core_free);

static void __sched_core_set(struct task_struct *p, unsigned long cookie)
{
	cookie = sched_core_get_cookie(cookie);
	cookie = sched_core_update_cookie(p, cookie);
	sched_core_put_cookie(cookie);
}

/* Called from prctl interface: PR_SCHED_CORE */
int sched_core_share_pid(unsigned int cmd, pid_t pid, enum pid_type type,
			 unsigned long uaddr)
{
	unsigned long cookie = 0, id = 0;
	struct task_struct *task = NULL, *p;
	struct pid *grp;
	int err = 0;

	if (!static_branch_likely(&sched_smt_present))
		return -ENODEV;

	BUILD_BUG_ON(PR_SCHED_CORE_SCOPE_THREAD != PIDTYPE_PID);
	BUILD_BUG_ON(PR_SCHED_CORE_SCOPE_THREAD_GROUP != PIDTYPE_TGID);
	BUILD_BUG_ON(PR_SCHED_CORE_SCOPE_PROCESS_GROUP != PIDTYPE_PGID);

	if (type > PIDTYPE_PGID || cmd >= PR_SCHED_CORE_MAX || pid < 0 ||
	    (cmd != PR_SCHED_CORE_GET && uaddr))
		return -EINVAL;

	rcu_read_lock();
	if (pid == 0) {
		task = current;
	} else {
		task = find_task_by_vpid(pid);
		if (!task) {
			rcu_read_unlock();
			return -ESRCH;
		}
	}
	get_task_struct(task);
	rcu_read_unlock();

	if (!ptrace_may_access(task, PTRACE_MODE_READ_REALCREDS)) {
		err = -EPERM;
		goto out;
	}

	switch (cmd) {
	case PR_SCHED_CORE_GET:
		if (type != PIDTYPE_PID || (uaddr & 7)) {
			err = -EINVAL;
			goto out;
		}
		cookie = sched_core_clone_cookie(task);
		if (cookie)
			ptr_to_hashval((void *)cookie, &id);
		if (put_user(id, (u64 __user *)uaddr))
			err = -EFAULT;
		goto out;

	case PR_SCHED_CORE_CREATE:
		cookie = sched_core_alloc_cookie();
		if (!cookie) {
			err = -ENOMEM;
			goto out;
		}
		break;

	case PR_SCHED_CORE_SHARE_TO:
		cookie = sched_core_clone_cookie(current);
		break;

	case PR_SCHED_CORE_SHARE_FROM:
		if (type != PIDTYPE_PID) {
			err = -EINVAL;
			goto out;
		}
		cookie = sched_core_clone_cookie(task);
		__sched_core_set(current, cookie);
		goto out;

	default:
		err = -EINVAL;
		goto out;
	}

	if (type == PIDTYPE_PID) {
		__sched_core_set(task, cookie);
		goto out;
	}

	read_lock(&tasklist_lock);
	grp = task_pid_type(task, type);

	do_each_pid_thread(grp, type, p) {
		if (!ptrace_may_access(p, PTRACE_MODE_READ_REALCREDS)) {
			err = -EPERM;
			goto out_tasklist;
		}
	} while_each_pid_thread(grp, type, p);

	do_each_pid_thread(grp, type, p) {
		__sched_core_set(p, cookie);
	} while_each_pid_thread(grp, type, p);
out_tasklist:
	read_unlock(&tasklist_lock);

out:
	sched_core_put_cookie(cookie);
	put_task_struct(task);
	return err;
}
EXPORT_SYMBOL(sched_core_share_pid);

#ifdef CONFIG_SCHEDSTATS

void __sched_core_account_forceidle(struct rq *rq)
{
	const struct cpumask *smt_mask = cpu_smt_mask(cpu_of(rq));
	u64 delta, now = rq_clock(rq->core);
	struct rq *rq_i;
	struct task_struct *p;
	int i;

	lockdep_assert_rq_held(rq);

	WARN_ON_ONCE(!rq->core->core_forceidle_count);

	if (rq->core->core_forceidle_start == 0)
		return;

	delta = now - rq->core->core_forceidle_start;
	if (unlikely((s64)delta <= 0))
		return;

	rq->core->core_forceidle_start = now;

	if (WARN_ON_ONCE(!rq->core->core_forceidle_occupation)) {
		/* can't be forced idle without a running task */
	} else if (rq->core->core_forceidle_count > 1 ||
		   rq->core->core_forceidle_occupation > 1) {
		delta *= rq->core->core_forceidle_count;
		delta = div_u64(delta, rq->core->core_forceidle_occupation);
	}

	for_each_cpu(i, smt_mask) {
		rq_i = cpu_rq(i);
		p = rq_i->core_pick ?: rq_i->curr;

		if (p == rq_i->idle)
			continue;

		__account_forceidle_time(p, delta);
	}
}
EXPORT_SYMBOL(__sched_core_account_forceidle);

void __sched_core_tick(struct rq *rq)
{
	if (!rq->core->core_forceidle_count)
		return;

	if (rq != rq->core)
		update_rq_clock(rq->core);

	__sched_core_account_forceidle(rq);
}
EXPORT_SYMBOL(__sched_core_tick);

#endif

static struct dentry *sched_core_debugfs_dir;

unsigned long sched_core_cookie_to_id(unsigned long cookie)
{
	unsigned long id = 0;

	if (!cookie)
		return 0;

	ptr_to_hashval((void *)cookie, &id);
	return id;
}
EXPORT_SYMBOL(sched_core_cookie_to_id);

static int sched_core_debug_show(struct seq_file *m, void *v)
{
	int cpu;

	seq_printf(m, "sched_core_count: %d\n", atomic_read(&sched_core_count));
	seq_printf(m, "sched_core_mask: ");

	for_each_possible_cpu(cpu) {
		seq_printf(m, cpu ? "%d" : "%d", cpumask_test_cpu(cpu, &sched_core_mask));
		if (cpu != nr_cpu_ids - 1)
			seq_putc(m, cpu % 8 == 7 ? '\n' : ' ');
	}
	seq_putc(m, '\n');

	seq_printf(m, "sched_core_forceidle_counts (per CPU core):\n");
	for_each_possible_cpu(cpu) {
		struct rq *rq = cpu_rq(cpu);
		if (!rq || !rq->core)
			seq_printf(m, " CPU%2d: <no-rq>\n", cpu);
		else
			seq_printf(m, " CPU%2d: core_forceidle_count=%u\n", cpu,
				   rq->core->core_forceidle_count);
	}

	return 0;
}

static int sched_core_debug_open(struct inode *inode, struct file *file)
{
	return single_open(file, sched_core_debug_show, NULL);
}

static const struct file_operations sched_core_debug_fops = {
	.owner   = THIS_MODULE,
	.open    = sched_core_debug_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
};

static int __init sched_core_debugfs_init(void)
{
	sched_core_debugfs_dir = debugfs_create_dir("sched_core", NULL);
	if (!sched_core_debugfs_dir)
		return -ENOMEM;

	if (!debugfs_create_file("status", 0444, sched_core_debugfs_dir,
				 NULL, &sched_core_debug_fops)) {
		debugfs_remove_recursive(sched_core_debugfs_dir);
		return -ENOMEM;
	}

	
	cpumask_copy(&sched_core_mask, cpu_possible_mask);
	return 0;
}
core_initcall(sched_core_debugfs_init);

EXPORT_TRACEPOINT_SYMBOL(sched_core_debug_show);

static int sched_core_tasks_show(struct seq_file *m, void *v)
{
	struct task_struct *p;

	seq_printf(m, " PID\tTGID\tCOMM\t\tCOOKIE_ID\n");
	seq_printf(m, "----\t----\t------------\t--------\n");

	rcu_read_lock();
	for_each_process(p) {
		unsigned long cookie = 0;
		unsigned long id = 0;

		cookie = sched_core_clone_cookie(p);
		if (!cookie)
			continue;

		id = sched_core_cookie_to_id(cookie);

		seq_printf(m, "%5d\t%5d\t%-12s\t%#lx\n",
			   task_pid_nr(p), task_tgid_nr(p), p->comm, id);

		sched_core_put_cookie(cookie);
	}
	rcu_read_unlock();

	return 0;
}

static int sched_core_tasks_open(struct inode *inode, struct file *file)
{
	return single_open(file, sched_core_tasks_show, NULL);
}

static const struct file_operations sched_core_tasks_fops = {
	.owner   = THIS_MODULE,
	.open    = sched_core_tasks_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
};

static int __init sched_core_tasks_debugfs_init(void)
{
	if (!sched_core_debugfs_dir)
		return -ENODEV;

	if (!debugfs_create_file("tasks", 0444, sched_core_debugfs_dir, NULL,
				 &sched_core_tasks_fops)) {
		pr_warn("sched_core: failed to create debugfs tasks file\n");
		return -ENOMEM;
	}

	return 0;
}
core_initcall(sched_core_tasks_debugfs_init);


int sched_core_set_mask(const struct cpumask *mask)
{
	if (!mask)
		return -EINVAL;

	cpumask_copy(&sched_core_mask, mask);
	return 0;
}
EXPORT_SYMBOL(sched_core_set_mask);

void sched_core_enable_cpu(unsigned int cpu)
{
	cpumask_set_cpu(cpu, &sched_core_mask);
}
EXPORT_SYMBOL(sched_core_enable_cpu);

void sched_core_disable_cpu(unsigned int cpu)
{
	cpumask_clear_cpu(cpu, &sched_core_mask);
}
EXPORT_SYMBOL(sched_core_disable_cpu);

MODULE_LICENSE("GPL");
