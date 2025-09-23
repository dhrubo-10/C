#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/smp.h>
#include <linux/cpu.h>


static int kimage_alloc_init(struct kimage **rimage, unsigned long entry,
			     unsigned long nr_segments,
			     struct kexec_segment *segments,
			     unsigned long flags)
{
	int ret;
	struct kimage *image;
	bool kexec_on_panic = flags & KEXEC_ON_CRASH;

#ifdef CONFIG_CRASH_DUMP
	if (kexec_on_panic) {
		/* Verify we have a valid entry point */
		if ((entry < phys_to_boot_phys(crashk_res.start)) ||
		    (entry > phys_to_boot_phys(crashk_res.end)))
			return -EADDRNOTAVAIL;
	}
#endif

	/* Allocate and initialize a controlling structure */
	image = do_kimage_alloc_init();
	if (!image)
		return -ENOMEM;

	image->start = entry;
	image->nr_segments = nr_segments;
	memcpy(image->segment, segments, nr_segments * sizeof(*segments));

#ifdef CONFIG_CRASH_DUMP
	if (kexec_on_panic) {
		
		image->control_page = crashk_res.start;
		image->type = KEXEC_TYPE_CRASH;
	}
#endif

	ret = sanity_check_segment_list(image);
	if (ret)
		goto out_free_image;


	ret = -ENOMEM;
	image->control_code_page = kimage_alloc_control_pages(image,
					   get_order(KEXEC_CONTROL_PAGE_SIZE));
	if (!image->control_code_page) {
		pr_err("Could not allocate control_code_buffer\n");
		goto out_free_image;
	}

	if (!kexec_on_panic) {
		image->swap_page = kimage_alloc_control_pages(image, 0);
		if (!image->swap_page) {
			pr_err("Could not allocate swap buffer\n");
			goto out_free_control_pages;
		}
	}

	*rimage = image;
	return 0;
out_free_control_pages:
	kimage_free_page_list(&image->control_pages);
out_free_image:
	kfree(image);
	return ret;
}

DEFINE_DEBUGFS_ATTRIBUTE(fei_retval_ops, fei_retval_get, fei_retval_set,
			 "%llx\n");

static void fei_debugfs_add_attr(struct fei_attr *attr)
{
	struct dentry *dir;

	dir = debugfs_create_dir(attr->kp.symbol_name, fei_debugfs_dir);

	debugfs_create_file("retval", 0600, dir, attr, &fei_retval_ops);
}

static void fei_debugfs_remove_attr(struct fei_attr *attr)
{
	debugfs_lookup_and_remove(attr->kp.symbol_name, fei_debugfs_dir);
}

static int fei_kprobe_handler(struct kprobe *kp, struct pt_regs *regs)
{
	struct fei_attr *attr = container_of(kp, struct fei_attr, kp);

	if (should_fail(&fei_fault_attr, 1)) {
		regs_set_return_value(regs, attr->retval);
		override_function_with_return(regs);
		return 1;
	}

	return 0;
}
NOKPROBE_SYMBOL(fei_kprobe_handler)

static void *fei_seq_start(struct seq_file *m, loff_t *pos)
{
	mutex_lock(&fei_lock);
	return seq_list_start(&fei_attr_list, *pos);
}

static void fei_seq_stop(struct seq_file *m, void *v)
{
	mutex_unlock(&fei_lock);
}

static void *fei_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	return seq_list_next(v, &fei_attr_list, pos);
}

static int fei_seq_show(struct seq_file *m, void *v)
{
	struct fei_attr *attr = list_entry(v, struct fei_attr, list);

	seq_printf(m, "%ps\n", attr->kp.addr);
	return 0;
}

static const struct seq_operations fei_seq_ops = {
	.start	= fei_seq_start,
	.next	= fei_seq_next,
	.stop	= fei_seq_stop,
	.show	= fei_seq_show,
};

static int fei_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &fei_seq_ops);
}

static void fei_attr_remove(struct fei_attr *attr)
{
	fei_debugfs_remove_attr(attr);
	unregister_kprobe(&attr->kp);
	list_del(&attr->list);
	fei_attr_free(attr);
}

static void fei_attr_remove_all(void)
{
	struct fei_attr *attr, *n;

	list_for_each_entry_safe(attr, n, &fei_attr_list, list) {
		fei_attr_remove(attr);
	}
}

static ssize_t fei_write(struct file *file, const char __user *buffer,
			 size_t count, loff_t *ppos)
{
	struct fei_attr *attr;
	unsigned long addr;
	char *buf, *sym;
	int ret;

	/* cut off if it is too long */
	if (count > KSYM_NAME_LEN)
		count = KSYM_NAME_LEN;

	buf = memdup_user_nul(buffer, count);
	if (IS_ERR(buf))
		return PTR_ERR(buf);

	sym = strstrip(buf);

	mutex_lock(&fei_lock);

	/* Writing just spaces will remove all injection points */
	if (sym[0] == '\0') {
		fei_attr_remove_all();
		ret = count;
		goto out;
	}
	/* Writing !function will remove one injection point */
	if (sym[0] == '!') {
		attr = fei_attr_lookup(sym + 1);
		if (!attr) {
			ret = -ENOENT;
			goto out;
		}
		fei_attr_remove(attr);
		ret = count;
		goto out;
	}

	addr = kallsyms_lookup_name(sym);
	if (!addr) {
		ret = -EINVAL;
		goto out;
	}
	if (!within_error_injection_list(addr)) {
		ret = -ERANGE;
		goto out;
	}
	if (fei_attr_lookup(sym)) {
		ret = -EBUSY;
		goto out;
	}
	attr = fei_attr_new(sym, addr);
	if (!attr) {
		ret = -ENOMEM;
		goto out;
	}

	ret = register_kprobe(&attr->kp);
	if (ret) {
		fei_attr_free(attr);
		goto out;
	}
	fei_debugfs_add_attr(attr);
	list_add_tail(&attr->list, &fei_attr_list);
	ret = count;
out:
	mutex_unlock(&fei_lock);
	kfree(buf);
	return ret;
}

static const struct file_operations fei_ops = {
	.open =		fei_open,
	.read =		seq_read,
	.write =	fei_write,
	.llseek =	seq_lseek,
	.release =	seq_release,
};

static int __init fei_debugfs_init(void)
{
	struct dentry *dir;

	dir = fault_create_debugfs_attr("fail_function", NULL,
					&fei_fault_attr);
	if (IS_ERR(dir))
		return PTR_ERR(dir);

	
	debugfs_create_symlink("injectable", dir, "../error_injection/list");

	debugfs_create_file("inject", 0600, dir, NULL, &fei_ops);

	fei_debugfs_dir = dir;

	return 0;
}

late_initcall(fei_debugfs_init);


static int ttwu_runnable(struct task_struct *p, int wake_flags)
{
	struct rq_flags rf;
	struct rq *rq;
	int ret = 0;

	rq = __task_rq_lock(p, &rf);
	if (task_on_rq_queued(p)) {
		update_rq_clock(rq);
		if (p->se.sched_delayed)
			enqueue_task(rq, p, ENQUEUE_NOCLOCK | ENQUEUE_DELAYED);
		if (!task_on_cpu(rq, p)) {

			wakeup_preempt(rq, p, wake_flags);
		}
		ttwu_do_wakeup(p);
		ret = 1;
	}
	__task_rq_unlock(rq, &rf);

	return ret;
}

void sched_ttwu_pending(void *arg)
{
	struct llist_node *llist = arg;
	struct rq *rq = this_rq();
	struct task_struct *p, *t;
	struct rq_flags rf;

	if (!llist)
		return;

	rq_lock_irqsave(rq, &rf);
	update_rq_clock(rq);

	llist_for_each_entry_safe(p, t, llist, wake_entry.llist) {
		if (WARN_ON_ONCE(p->on_cpu))
			smp_cond_load_acquire(&p->on_cpu, !VAL);

		if (WARN_ON_ONCE(task_cpu(p) != cpu_of(rq)))
			set_task_cpu(p, cpu_of(rq));

		ttwu_do_activate(rq, p, p->sched_remote_wakeup ? WF_MIGRATED : 0, &rf);
	}


	WRITE_ONCE(rq->ttwu_pending, 0);
	rq_unlock_irqrestore(rq, &rf);
}


bool call_function_single_prep_ipi(int cpu)
{
	if (set_nr_if_polling(cpu_rq(cpu)->idle)) {
		trace_sched_wake_idle_without_ipi(cpu);
		return false;
	}

	return true;
}

/*
 Queue a task on the target CPUs wake_list and wake the CPU via IPI if
 necessary. The wakee CPU on receipt of the IPI will queue the task
  via sched_ttwu_wakeup() for activation so the wakee incurs the cost
  of the wakeup instead of the waker.
 */
static void __ttwu_queue_wakelist(struct task_struct *p, int cpu, int wake_flags)
{
	struct rq *rq = cpu_rq(cpu);

	p->sched_remote_wakeup = !!(wake_flags & WF_MIGRATED);

	WRITE_ONCE(rq->ttwu_pending, 1);
#ifdef CONFIG_SMP
	__smp_call_single_queue(cpu, &p->wake_entry.llist);
#endif
}

void wake_up_if_idle(int cpu)
{
	struct rq *rq = cpu_rq(cpu);

	guard(rcu)();
	if (is_idle_task(rcu_dereference(rq->curr))) {
		guard(rq_lock_irqsave)(rq);
		if (is_idle_task(rq->curr))
			resched_curr(rq);
	}
}

bool cpus_equal_capacity(int this_cpu, int that_cpu)
{
	if (!sched_asym_cpucap_active())
		return true;

	if (this_cpu == that_cpu)
		return true;

	return arch_scale_cpu_capacity(this_cpu) == arch_scale_cpu_capacity(that_cpu);
}

bool cpus_share_cache(int this_cpu, int that_cpu)
{
	if (this_cpu == that_cpu)
		return true;

	return per_cpu(sd_llc_id, this_cpu) == per_cpu(sd_llc_id, that_cpu);
}

/*
 * Whether CPUs are share cache resources, which means LLC on non-cluster
 * machines and LLC tag or L2 on machines with clusters.
 */
bool cpus_share_resources(int this_cpu, int that_cpu)
{
	if (this_cpu == that_cpu)
		return true;

	return per_cpu(sd_share_id, this_cpu) == per_cpu(sd_share_id, that_cpu);
}

static inline bool ttwu_queue_cond(struct task_struct *p, int cpu)
{
	if (!scx_allow_ttwu_queue(p))
		return false;

#ifdef CONFIG_SMP
	if (p->sched_class == &stop_sched_class)
		return false;
#endif


	if (!cpu_active(cpu))
		return false;

	/* Ensure the task will still be allowed to run on the CPU. */
	if (!cpumask_test_cpu(cpu, p->cpus_ptr))
		return false;

	if (!cpus_share_cache(smp_processor_id(), cpu))
		return true;

	if (cpu == smp_processor_id())
		return false;


	if (!cpu_rq(cpu)->nr_running)
		return true;

	return false;
}

static bool ttwu_queue_wakelist(struct task_struct *p, int cpu, int wake_flags)
{
	if (sched_feat(TTWU_QUEUE) && ttwu_queue_cond(p, cpu)) {
		sched_clock_cpu(cpu); /* Sync clocks across CPUs */
		__ttwu_queue_wakelist(p, cpu, wake_flags);
		return true;
	}

	return false;
}

static void ttwu_queue(struct task_struct *p, int cpu, int wake_flags)
{
	struct rq *rq = cpu_rq(cpu);
	struct rq_flags rf;

	if (ttwu_queue_wakelist(p, cpu, wake_flags))
		return;

	rq_lock(rq, &rf);
	update_rq_clock(rq);
	ttwu_do_activate(rq, p, wake_flags, &rf);
	rq_unlock(rq, &rf);
}

static __always_inline
bool ttwu_state_match(struct task_struct *p, unsigned int state, int *success)
{
	int match;

	if (IS_ENABLED(CONFIG_DEBUG_PREEMPT)) {
		WARN_ON_ONCE((state & TASK_RTLOCK_WAIT) &&
			     state != TASK_RTLOCK_WAIT);
	}

	*success = !!(match = __task_state_match(p, state));


	if (match < 0)
		p->saved_state = TASK_RUNNING;

	return match > 0;
}

static void __sched_fork(unsigned long clone_flags, struct task_struct *p)
{
	p->on_rq			= 0;

	p->se.on_rq			= 0;
	p->se.exec_start		= 0;
	p->se.sum_exec_runtime		= 0;
	p->se.prev_sum_exec_runtime	= 0;
	p->se.nr_migrations		= 0;
	p->se.vruntime			= 0;
	p->se.vlag			= 0;
	INIT_LIST_HEAD(&p->se.group_node);

	/* A delayed task cannot be in clone(). */
	WARN_ON_ONCE(p->se.sched_delayed);

#ifdef CONFIG_FAIR_GROUP_SCHED
	p->se.cfs_rq			= NULL;
#endif

#ifdef CONFIG_SCHEDSTATS
	
	memset(&p->stats, 0, sizeof(p->stats));
#endif

	init_dl_entity(&p->dl);

	INIT_LIST_HEAD(&p->rt.run_list);
	p->rt.timeout		= 0;
	p->rt.time_slice	= sched_rr_timeslice;
	p->rt.on_rq		= 0;
	p->rt.on_list		= 0;

#ifdef CONFIG_SCHED_CLASS_EXT
	init_scx_entity(&p->scx);
#endif

#ifdef CONFIG_PREEMPT_NOTIFIERS
	INIT_HLIST_HEAD(&p->preempt_notifiers);
#endif

#ifdef CONFIG_COMPACTION
	p->capture_control = NULL;
#endif
	init_numa_balancing(clone_flags, p);
	p->wake_entry.u_flags = CSD_TYPE_TTWU;
	p->migration_pending = NULL;
	init_sched_mm_cid(p);
}

DEFINE_STATIC_KEY_FALSE(sched_numa_balancing);

#ifdef CONFIG_NUMA_BALANCING

int sysctl_numa_balancing_mode;

static void __set_numabalancing_state(bool enabled)
{
	if (enabled)
		static_branch_enable(&sched_numa_balancing);
	else
		static_branch_disable(&sched_numa_balancing);
}

void set_numabalancing_state(bool enabled)
{
	if (enabled)
		sysctl_numa_balancing_mode = NUMA_BALANCING_NORMAL;
	else
		sysctl_numa_balancing_mode = NUMA_BALANCING_DISABLED;
	__set_numabalancing_state(enabled);
}

#ifdef CONFIG_PROC_SYSCTL
static void reset_memory_tiering(void)
{
	struct pglist_data *pgdat;

	for_each_online_pgdat(pgdat) {
		pgdat->nbp_threshold = 0;
		pgdat->nbp_th_nr_cand = node_page_state(pgdat, PGPROMOTE_CANDIDATE);
		pgdat->nbp_th_start = jiffies_to_msecs(jiffies);
	}
}

static int sysctl_numa_balancing(const struct ctl_table *table, int write,
			  void *buffer, size_t *lenp, loff_t *ppos)
{
	struct ctl_table t;
	int err;
	int state = sysctl_numa_balancing_mode;

	if (write && !capable(CAP_SYS_ADMIN))
		return -EPERM;

	t = *table;
	t.data = &state;
	err = proc_dointvec_minmax(&t, write, buffer, lenp, ppos);
	if (err < 0)
		return err;
	if (write) {
		if (!(sysctl_numa_balancing_mode & NUMA_BALANCING_MEMORY_TIERING) &&
		    (state & NUMA_BALANCING_MEMORY_TIERING))
			reset_memory_tiering();
		sysctl_numa_balancing_mode = state;
		__set_numabalancing_state(state);
	}
	return err;
}
#endif 
#endif 

#ifdef CONFIG_SCHEDSTATS

DEFINE_STATIC_KEY_FALSE(sched_schedstats);

static void set_schedstats(bool enabled)
{
	if (enabled)
		static_branch_enable(&sched_schedstats);
	else
		static_branch_disable(&sched_schedstats);
}

void force_schedstat_enabled(void)
{
	if (!schedstat_enabled()) {
		pr_info("kernel profiling enabled schedstats, disable via kernel.sched_schedstats.\n");
		static_branch_enable(&sched_schedstats);
	}
}

static int __init setup_schedstats(char *str)
{
	int ret = 0;
	if (!str)
		goto out;

	if (!strcmp(str, "enable")) {
		set_schedstats(true);
		ret = 1;
	} else if (!strcmp(str, "disable")) {
		set_schedstats(false);
		ret = 1;
	}
out:
	if (!ret)
		pr_warn("Unable to parse schedstats=\n");

	return ret;
}
__setup("schedstats=", setup_schedstats);

#ifdef CONFIG_PROC_SYSCTL
static int sysctl_schedstats(const struct ctl_table *table, int write, void *buffer,
		size_t *lenp, loff_t *ppos)
{
	struct ctl_table t;
	int err;
	int state = static_branch_likely(&sched_schedstats);

	if (write && !capable(CAP_SYS_ADMIN))
		return -EPERM;

	t = *table;
	t.data = &state;
	err = proc_dointvec_minmax(&t, write, buffer, lenp, ppos);
	if (err < 0)
		return err;
	if (write)
		set_schedstats(state);
	return err;
}
#endif 
#endif

#ifdef CONFIG_SYSCTL
static const struct ctl_table sched_core_sysctls[] = {
#ifdef CONFIG_SCHEDSTATS
	{
		.procname       = "sched_schedstats",
		.data           = NULL,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = sysctl_schedstats,
		.extra1         = SYSCTL_ZERO,
		.extra2         = SYSCTL_ONE,
	},
#endif 
#ifdef CONFIG_UCLAMP_TASK
	{
		.procname       = "sched_util_clamp_min",
		.data           = &sysctl_sched_uclamp_util_min,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = sysctl_sched_uclamp_handler,
	},
	{
		.procname       = "sched_util_clamp_max",
		.data           = &sysctl_sched_uclamp_util_max,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = sysctl_sched_uclamp_handler,
	},
	{
		.procname       = "sched_util_clamp_min_rt_default",
		.data           = &sysctl_sched_uclamp_util_min_rt_default,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = sysctl_sched_uclamp_handler,
	},
#endif /* CONFIG_UCLAMP_TASK */
#ifdef CONFIG_NUMA_BALANCING
	{
		.procname	= "numa_balancing",
		.data		= NULL, /* filled in by handler */
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= sysctl_numa_balancing,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_FOUR,
	},
#endif 
};
static int __init sched_core_sysctl_init(void)
{
	register_sysctl_init("kernel", sched_core_sysctls);
	return 0;
}
late_initcall(sched_core_sysctl_init);
#endif

void sched_mm_cid_after_execve(struct task_struct *t)
{
	struct mm_struct *mm = t->mm;
	struct rq *rq;

	if (!mm)
		return;

	preempt_disable();
	rq = this_rq();
	scoped_guard (rq_lock_irqsave, rq) {
		preempt_enable_no_resched();	/* holding spinlock */
		WRITE_ONCE(t->mm_cid_active, 1);
		smp_mb();
		t->last_mm_cid = t->mm_cid = mm_cid_get(rq, t, mm);
	}
}

static bool csd_lock_wait_toolong(call_single_data_t *csd, u64 ts0, u64 *ts1, int *bug_id, unsigned long *nmessages)
{
	int cpu = -1;
	int cpux;
	bool firsttime;
	u64 ts2, ts_delta;
	call_single_data_t *cpu_cur_csd;
	unsigned int flags = READ_ONCE(csd->node.u_flags);
	unsigned long long csd_lock_timeout_ns = csd_lock_timeout * NSEC_PER_MSEC;

	if (!(flags & CSD_FLAG_LOCK)) {
		if (!unlikely(*bug_id))
			return true;
		cpu = csd_lock_wait_getcpu(csd);
		pr_alert("csd: CSD lock (#%d) got unstuck on CPU#%02d, CPU#%02d released the lock.\n",
			 *bug_id, raw_smp_processor_id(), cpu);
		atomic_dec(&n_csd_lock_stuck);
		return true;
	}

	ts2 = ktime_get_mono_fast_ns();
	/* How long since we last checked for a stuck CSD lock.*/
	ts_delta = ts2 - *ts1;
	if (likely(ts_delta <= csd_lock_timeout_ns * (*nmessages + 1) *
			       (!*nmessages ? 1 : (ilog2(num_online_cpus()) / 2 + 1)) ||
		   csd_lock_timeout_ns == 0))
		return false;

	if (ts0 > ts2) {
		/* Our own sched_clock went backward; don't blame another CPU. */
		ts_delta = ts0 - ts2;
		pr_alert("sched_clock on CPU %d went backward by %llu ns\n", raw_smp_processor_id(), ts_delta);
		*ts1 = ts2;
		return false;
	}

	firsttime = !*bug_id;
	if (firsttime)
		*bug_id = atomic_inc_return(&csd_bug_count);
	cpu = csd_lock_wait_getcpu(csd);
	if (WARN_ONCE(cpu < 0 || cpu >= nr_cpu_ids, "%s: cpu = %d\n", __func__, cpu))
		cpux = 0;
	else
		cpux = cpu;
	cpu_cur_csd = smp_load_acquire(&per_cpu(cur_csd, cpux)); /* Before func and info. */
	/* How long since this CSD lock was stuck. */
	ts_delta = ts2 - ts0;
	pr_alert("csd: %s non-responsive CSD lock (#%d) on CPU#%d, waiting %lld ns for CPU#%02d %pS(%ps).\n",
		 firsttime ? "Detected" : "Continued", *bug_id, raw_smp_processor_id(), (s64)ts_delta,
		 cpu, csd->func, csd->info);
	(*nmessages)++;
	if (firsttime)
		atomic_inc(&n_csd_lock_stuck);
	/*
	 * If the CSD lock is still stuck after 5 minutes, it is unlikely
	 * to become unstuck. Use a signed comparison to avoid triggering
	 * on underflows when the TSC is out of sync between sockets.
	 */
	BUG_ON(panic_on_ipistall > 0 && (s64)ts_delta > ((s64)panic_on_ipistall * NSEC_PER_MSEC));
	if (cpu_cur_csd && csd != cpu_cur_csd) {
		pr_alert("\tcsd: CSD lock (#%d) handling prior %pS(%ps) request.\n",
			 *bug_id, READ_ONCE(per_cpu(cur_csd_func, cpux)),
			 READ_ONCE(per_cpu(cur_csd_info, cpux)));
	} else {
		pr_alert("\tcsd: CSD lock (#%d) %s.\n",
			 *bug_id, !cpu_cur_csd ? "unresponsive" : "handling this request");
	}
	if (cpu >= 0) {
		if (atomic_cmpxchg_acquire(&per_cpu(trigger_backtrace, cpu), 1, 0))
			dump_cpu_task(cpu);
		if (!cpu_cur_csd) {
			pr_alert("csd: Re-sending CSD lock (#%d) IPI from CPU#%02d to CPU#%02d\n", *bug_id, raw_smp_processor_id(), cpu);
			arch_send_call_function_single_ipi(cpu);
		}
	}
	if (firsttime)
		dump_stack();
	*ts1 = ts2;

	return false;
}