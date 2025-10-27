#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/workqueue.h>
#include <linux/jiffies.h>
#include <linux/sched/signal.h>
#include <linux/sched.h>
#include <linux/sched/sched.h>
#include <linux/sched/task_stack.h>
#include <linux/smp.h>
#include <linux/cpumask.h>
#include <linux/errno.h>
#include <linux/atomic.h>
#include <linux/rtc.h>
#include <linux/bitops.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/sysctl.h>
#include <linux/proc_fs.h>
#include <linux/ktime.h>
#include <linux/time.h>
#include <linux/cache.h>
#include <linux/printk.h>
#include <linux/uaccess.h>
#include <linux/percpu.h>
#include <linux/static_key.h>
#include <linux/workqueue.h>
#include <linux/tracepoint.h>
#include <linux/export.h>

static ssize_t __init xwrite(struct file *file, const unsigned char *p,
			     size_t count, loff_t *pos)
{
	ssize_t out = 0;

	while (count) {
		ssize_t rv = kernel_write(file, p, count, pos);

		if (rv < 0) {
			if (rv == -EINTR || rv == -EAGAIN)
				continue;
			return out ? out : rv;
		} else if (rv == 0) {
			break;
		}

#ifdef CONFIG_CSUM
		{
			ssize_t i;
			for (i = 0; i < rv; i++)
				/* io_csum is assumed global in this context */
				; /* placeholder for checksum update */
		}
#endif

		p += rv;
		out += rv;
		count -= rv;
	}

	return out;
}

struct sched_clock_data {
	u64 tick_raw;
	u64 tick_gtod;
	u64 tick_gtod_prev;
	s64 tick_diff;
	u64 clock;
};

static DEFINE_PER_CPU(struct sched_clock_data, sched_clock_data);
static s64 __gtod_offset;
static s64 __sched_clock_offset;
static DEFINE_STATIC_KEY_TRUE(sched_clock_running);
static int __sched_clock_stable_early = 1;
static atomic_t __sched_clock_stable = ATOMIC_INIT(1);

static struct sched_clock_data *this_scd(void)
{
	return this_cpu_ptr(&sched_clock_data);
}

static void __scd_stamp(struct sched_clock_data *scd)
{
	scd->tick_gtod_prev = scd->tick_gtod;
	scd->tick_gtod = jiffies;
	scd->tick_raw = jiffies;
}

static void __sched_clock_work(struct work_struct *work)
{
	struct sched_clock_data *scd;
	int cpu;

	preempt_disable();
	scd = this_scd();
	__scd_stamp(scd);
	scd->clock = scd->tick_gtod + __gtod_offset;
	preempt_enable();

	for_each_possible_cpu(cpu)
		per_cpu(sched_clock_data, cpu) = *scd;

	pr_warn("sched_clock: TSC found unstable after boot. Use 'tsc=unstable'.\n");
	pr_info("sched_clock: Marking unstable (%lld, %lld)<-(%lld, %lld)\n",
		(long long)scd->tick_gtod, (long long)__gtod_offset,
		(long long)scd->tick_raw, (long long)__sched_clock_offset);

	static_branch_disable(&sched_clock_running);
	atomic_set(&__sched_clock_stable, 0);
}

static DECLARE_WORK(sched_clock_work, __sched_clock_work);

static void __clear_sched_clock_stable(void)
{
	if (!atomic_read(&__sched_clock_stable))
		return;

	tick_dep_set(TICK_DEP_BIT_CLOCK_UNSTABLE);
	schedule_work(&sched_clock_work);
}

void clear_sched_clock_stable(void)
{
	__sched_clock_stable_early = 0;
	smp_mb();
	if (static_key_count(&sched_clock_running.key) == 2)
		__clear_sched_clock_stable();
}
EXPORT_SYMBOL(clear_sched_clock_stable);

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
		;
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

static void __sched_fork(unsigned long clone_flags, struct task_struct *p)
{
	p->on_rq = 0;

	p->se.on_rq = 0;
	p->se.exec_start = 0;
	p->se.sum_exec_runtime = 0;
	p->se.prev_sum_exec_runtime = 0;
	p->se.nr_migrations = 0;
	p->se.vruntime = 0;
	p->se.vflag = 0;
	INIT_LIST_HEAD(&p->se.group_node);

	WARN_ON_ONCE(p->se.sched_delayed);

#ifdef CONFIG_FAIR_GROUP_SCHED
	p->se.cfs_rq = NULL;
#endif

#ifdef CONFIG_SCHEDSTATS
	memset(&p->stats, 0, sizeof(p->stats));
#endif

	init_dl_entity(&p->dl);

	INIT_LIST_HEAD(&p->rt.run_list);
	p->rt.timeout = 0;
	p->rt.time_slice = sched_rr_timeslice;
	p->rt.on_rq = 0;
	p->rt.on_list = 0;

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

int sched_fork(unsigned long clone_flags, struct task_struct *p)
{
	__sched_fork(clone_flags, p);
	p->__state = TASK_NEW;
	p->prio = current->normal_prio;
	uclamp_fork(p);

	if (unlikely(p->sched_reset_on_fork)) {
		if (task_has_dl_policy(p) || task_has_rt_policy(p)) {
			p->policy = SCHED_NORMAL;
			p->static_prio = NICE_TO_PRIO(0);
			p->rt_priority = 0;
		} else if (PRIO_TO_NICE(p->static_prio) < 0)
			p->static_prio = NICE_TO_PRIO(0);

		p->prio = p->normal_prio = p->static_prio;
		set_load_weight(p, false);
		p->se.custom_slice = 0;
		p->se.slice = sysctl_sched_base_slice;
		p->sched_reset_on_fork = 0;
	}

	if (dl_prio(p->prio))
		return -EAGAIN;

	scx_pre_fork(p);

	if (rt_prio(p->prio)) {
		p->sched_class = &rt_sched_class;
#ifdef CONFIG_SCHED_CLASS_EXT
	} else if (task_should_scx(p->policy)) {
		p->sched_class = &ext_sched_class;
#endif
	} else {
		p->sched_class = &fair_sched_class;
	}

	init_entity_runnable_average(&p->se);

#ifdef CONFIG_SCHED_INFO
	if (likely(sched_info_on()))
		memset(&p->sched_info, 0, sizeof(p->sched_info));
#endif

	p->on_cpu = 0;
	init_task_preempt_count(p);
	plist_node_init(&p->pushable_tasks, MAX_PRIO);
	RB_CLEAR_NODE(&p->pushable_dl_tasks);

	return 0;
}
EXPORT_SYMBOL(sched_fork);

int sched_cgroup_fork(struct task_struct *p, struct kernel_clone_args *kargs)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&p->pi_lock, flags);
#ifdef CONFIG_CGROUP_SCHED
	{
		struct task_group *tg;
		tg = container_of(kargs->cset->subsys[cpu_cgrp_id],
				  struct task_group, css);
		tg = autogroup_task_group(p, tg);
		p->sched_task_group = tg;
	}
#endif
	rseq_migrate(p);
	__set_task_cpu(p, smp_processor_id());
	if (p->sched_class->task_fork)
		p->sched_class->task_fork(p);
	raw_spin_unlock_irqrestore(&p->pi_lock, flags);

	return scx_fork(p);
}
EXPORT_SYMBOL(sched_cgroup_fork);

void sched_cancel_fork(struct task_struct *p)
{
	scx_cancel_fork(p);
}
EXPORT_SYMBOL(sched_cancel_fork);

void sched_post_fork(struct task_struct *p)
{
	uclamp_post_fork(p);
	scx_post_fork(p);
}
EXPORT_SYMBOL(sched_post_fork);

unsigned long to_ratio(u64 period, u64 runtime)
{
	if (runtime == RUNTIME_INF)
		return BW_UNIT;

	if (period == 0)
		return 0;

	return div64_u64(runtime << BW_SHIFT, period);
}
EXPORT_SYMBOL(to_ratio);

void wake_up_new_task(struct task_struct *p)
{
	struct rq_flags rf;
	struct rq *rq;
	int wake_flags = WF_FORK;

	raw_spin_lock_irqsave(&p->pi_lock, rf.flags);
	WRITE_ONCE(p->__state, TASK_RUNNING);
	p->recent_used_cpu = task_cpu(p);
	rseq_migrate(p);
	__set_task_cpu(p, select_task_rq(p, task_cpu(p), &wake_flags));
	rq = __task_rq_lock(p, &rf);
	update_rq_clock(rq);
	post_init_entity_util_avg(p);

	activate_task(rq, p, ENQUEUE_NOCLOCK | ENQUEUE_INITIAL);
	trace_sched_wakeup_new(p);
	wakeup_preempt(rq, p, wake_flags);
	if (p->sched_class->task_woken) {
		rq_unpin_lock(rq, &rf);
		p->sched_class->task_woken(rq, p);
		rq_repin_lock(rq, &rf);
	}
	task_rq_unlock(rq, p, &rf);
}
EXPORT_SYMBOL(wake_up_new_task);

#ifdef CONFIG_PREEMPT_NOTIFIERS
static DEFINE_STATIC_KEY_FALSE(preempt_notifier_key);

void preempt_notifier_inc(void)
{
	static_branch_inc(&preempt_notifier_key);
}
EXPORT_SYMBOL_GPL(preempt_notifier_inc);

void preempt_notifier_dec(void)
{
	static_branch_dec(&preempt_notifier_key);
}
EXPORT_SYMBOL_GPL(preempt_notifier_dec);

void preempt_notifier_register(struct preempt_notifier *notifier)
{
	if (!static_branch_unlikely(&preempt_notifier_key))
		WARN(1, "registering preempt_notifier while notifiers disabled\n");

	hlist_add_head(&notifier->link, &current->preempt_notifiers);
}
EXPORT_SYMBOL_GPL(preempt_notifier_register);

void preempt_notifier_unregister(struct preempt_notifier *notifier)
{
	hlist_del(&notifier->link);
}
EXPORT_SYMBOL_GPL(preempt_notifier_unregister);

static void __fire_sched_in_preempt_notifiers(struct task_struct *curr)
{
	struct preempt_notifier *notifier;

	hlist_for_each_entry(notifier, &curr->preempt_notifiers, link)
		notifier->ops->sched_in(notifier, raw_smp_processor_id());
}

static __always_inline void fire_sched_in_preempt_notifiers(struct task_struct *curr)
{
	if (static_branch_unlikely(&preempt_notifier_key))
		__fire_sched_in_preempt_notifiers(curr);
}

static void __fire_sched_out_preempt_notifiers(struct task_struct *curr,
					       struct task_struct *next)
{
	struct preempt_notifier *notifier;

	hlist_for_each_entry(notifier, &curr->preempt_notifiers, link)
		notifier->ops->sched_out(notifier, next);
}

static __always_inline void fire_sched_out_preempt_notifiers(struct task_struct *curr,
							     struct task_struct *next)
{
	if (static_branch_unlikely(&preempt_notifier_key))
		__fire_sched_out_preempt_notifiers(curr, next);
}
#else
static inline void fire_sched_in_preempt_notifiers(struct task_struct *curr) { }
static inline void fire_sched_out_preempt_notifiers(struct task_struct *curr, struct task_struct *next) { }
#endif

static inline void prepare_task(struct task_struct *next)
{
	WRITE_ONCE(next->on_cpu, 1);
}

static inline void finish_task(struct task_struct *prev)
{
	smp_store_release(&prev->on_cpu, 0);
}

static void do_balance_callbacks(struct rq *rq, struct balance_callback *head)
{
	struct balance_callback *next;

	lockdep_assert_rq_held(rq);

	while (head) {
		next = head->next;
		head->next = NULL;
		head->func(rq);
		head = next;
	}
}

static inline struct balance_callback *
__splice_balance_callbacks(struct rq *rq, bool split)
{
	struct balance_callback *head = rq->balance_callback;

	if (likely(!head))
		return NULL;

	lockdep_assert_rq_held(rq);
	if (split && head == &balance_push_callback)
		head = NULL;
	else
		rq->balance_callback = NULL;

	return head;
}

struct balance_callback *splice_balance_callbacks(struct rq *rq)
{
	return __splice_balance_callbacks(rq, true);
}
EXPORT_SYMBOL(splice_balance_callbacks);

static void __balance_callbacks(struct rq *rq)
{
	do_balance_callbacks(rq, __splice_balance_callbacks(rq, false));
}

void balance_callbacks(struct rq *rq, struct balance_callback *head)
{
	unsigned long flags;

	if (unlikely(head)) {
		raw_spin_rq_lock_irqsave(rq, flags);
		do_balance_callbacks(rq, head);
		raw_spin_rq_unlock_irqrestore(rq, flags);
	}
}
EXPORT_SYMBOL(balance_callbacks);

static inline void prepare_lock_switch(struct rq *rq, struct task_struct *next, struct rq_flags *rf)
{
	rq_unpin_lock(rq, rf);
	spin_release(&__rq_lockp(rq)->dep_map, _THIS_IP_);
#ifdef CONFIG_DEBUG_SPINLOCK
	rq_lockp(rq)->owner = next;
#endif
}

static inline void finish_lock_switch(struct rq *rq)
{
	spin_acquire(&__rq_lockp(rq)->dep_map, 0, 0, _THIS_IP_);
	__balance_callbacks(rq);
	raw_spin_rq_unlock_irq(rq);
}

#ifndef prepare_arch_switch
# define prepare_arch_switch(next)	do { } while (0)
#endif

#ifndef finish_arch_post_lock_switch
# define finish_arch_post_lock_switch()	do { } while (0)
#endif

static inline void kmap_local_sched_out(void)
{
#ifdef CONFIG_KMAP_LOCAL
	if (unlikely(current->kmap_ctrl.idx))
		__kmap_local_sched_out();
#endif
}

static inline void kmap_local_sched_in(void)
{
#ifdef CONFIG_KMAP_LOCAL
	if (unlikely(current->kmap_ctrl.idx))
		__kmap_local_sched_in();
#endif
}

static inline void prepare_task_switch(struct rq *rq, struct task_struct *prev,
				       struct task_struct *next)
{
	kcov_prepare_switch(prev);
	sched_info_switch(rq, prev, next);
	perf_event_task_sched_out(prev, next);
	rseq_preempt(prev);
	fire_sched_out_preempt_notifiers(prev, next);
	kmap_local_sched_out();
	prepare_task(next);
	prepare_arch_switch(next);
}

static struct rq *finish_task_switch(struct task_struct *prev)
	__releases(rq->lock)
{
	struct rq *rq = this_rq();
	struct mm_struct *mm = rq->prev_mm;
	unsigned int prev_state;

	if (WARN_ON_ONCE(preempt_count() != 2*PREEMPT_DISABLE_OFFSET,
			 "corrupted preempt_count"))
		preempt_count_set(FORK_PREEMPT_COUNT);

	rq->prev_mm = NULL;

	prev_state = READ_ONCE(prev->__state);
	vtime_task_switch(prev);
	perf_event_task_sched_in(prev, current);
	finish_task(prev);
	tick_nohz_task_switch();
	finish_lock_switch(rq);
	finish_arch_post_lock_switch();
	kcov_finish_switch(current);
	kmap_local_sched_in();
	fire_sched_in_preempt_notifiers(current);

	if (mm) {
		membarrier_mm_sync_core_before_usermode(mm);
		mmdrop_lazy_tlb_sched(mm);
	}

	if (unlikely(prev_state == TASK_DEAD)) {
		if (prev->sched_class->task_dead)
			prev->sched_class->task_dead(prev);

		put_task_stack(prev);
		put_task_struct_rcu_user(prev);
	}

	return rq;
}

asmlinkage __visible void schedule_tail(struct task_struct *prev)
	__releases(rq->lock)
{
	finish_task_switch(prev);
	trace_sched_exit_tp(true);
	preempt_enable();

	if (current->set_child_tid)
		put_user(task_pid_vnr(current), current->set_child_tid);

	calculate_sigpending();
}
EXPORT_SYMBOL(schedule_tail);

static __always_inline struct rq *
context_switch(struct rq *rq, struct task_struct *prev,
	       struct task_struct *next, struct rq_flags *rf)
{
	prepare_task_switch(rq, prev, next);
	arch_start_context_switch(prev);

	if (!next->mm) {
		enter_lazy_tlb(prev->active_mm, next);
		next->active_mm = prev->active_mm;
		if (prev->mm)
			mmgrab_lazy_tlb(prev->active_mm);
		else
			prev->active_mm = NULL;
	} else {
		membarrier_switch_mm(rq, prev->active_mm, next->mm);
		switch_mm_irqs_off(prev->active_mm, next->mm, next);
		lru_gen_use_mm(next->mm);

		if (!prev->mm) {
			rq->prev_mm = prev->active_mm;
			prev->active_mm = NULL;
		}
	}

	switch_mm_cid(rq, prev, next);
	prepare_lock_switch(rq, next, rf);
	switch_to(prev, next, prev);
	barrier();
	return finish_task_switch(prev);
}
EXPORT_SYMBOL(context_switch);

unsigned int nr_running(void)
{
	unsigned int i, sum = 0;
	for_each_online_cpu(i)
		sum += cpu_rq(i)->nr_running;
	return sum;
}
EXPORT_SYMBOL(nr_running);

bool single_task_running(void)
{
	return raw_rq()->nr_running == 1;
}
EXPORT_SYMBOL(single_task_running);

unsigned long long nr_context_switches_cpu(int cpu)
{
	return cpu_rq(cpu)->nr_switches;
}
EXPORT_SYMBOL(nr_context_switches_cpu);

unsigned long long nr_context_switches(void)
{
	int i;
	unsigned long long sum = 0;
	for_each_possible_cpu(i)
		sum += cpu_rq(i)->nr_switches;
	return sum;
}
EXPORT_SYMBOL(nr_context_switches);

unsigned int nr_iowait_cpu(int major, int minor, int ino)
{
	unsigned long tmp = ino + minor + (major << 3);
	tmp += tmp >> 5;
	return tmp & 31;
}
EXPORT_SYMBOL(nr_iowait_cpu);

static int sysctl_numa_balancing_mode;
static int sysctl_sched_uclamp_util_min;
static int sysctl_sched_uclamp_util_max;
static int sysctl_sched_uclamp_util_min_rt_default;
static int sysctl_sched_base_slice;
static int sysctl_numa_balancing_hot_threshold_val;

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
EXPORT_SYMBOL(set_numabalancing_state);

#ifdef CONFIG_PROC_SYSCTL
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
			; /* reset memory tiering handled elsewhere */
		sysctl_numa_balancing_mode = state;
		__set_numabalancing_state(state);
	}
	return err;
}
#endif

#ifdef CONFIG_SCHEDSTATS
static DEFINE_STATIC_KEY_FALSE(sched_schedstats);

static void set_schedstats(bool enabled)
{
	if (enabled)
		static_branch_enable(&sched_schedstats);
	else
		static_branch_disable(&sched_schedstats);
}

void force_schedstat_enabled(void)
{
	if (!static_branch_likely(&sched_schedstats))
		static_branch_enable(&sched_schedstats);
}
EXPORT_SYMBOL(force_schedstat_enabled);

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
		.proc_handler   = sysctl_numa_balancing,
	},
	{
		.procname       = "sched_util_clamp_max",
		.data           = &sysctl_sched_uclamp_util_max,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = sysctl_numa_balancing,
	},
	{
		.procname       = "sched_util_clamp_min_rt_default",
		.data           = &sysctl_sched_uclamp_util_min_rt_default,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = sysctl_numa_balancing,
	},
#endif
#ifdef CONFIG_NUMA_BALANCING
	{
		.procname	= "numa_balancing",
		.data		= NULL,
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
static void balance_push(struct rq *rq)
{
	/* Placeholder implementation: flush any pending balancing work for rq */
	if (!rq)
		return;
	__balance_callbacks(rq);
}
static struct balance_callback balance_push_callback = {
	.next = NULL,
	.func = balance_push,
};

static int __init sched_core_init(void)
{
	/* Initialize any required static keys or per-cpu data */
	static_branch_enable(&sched_clock_running);
#ifdef CONFIG_SCHEDSTATS
	static_branch_disable(&sched_schedstats);
#endif
	return 0;
}
late_initcall(sched_core_init);

#ifdef CONFIG_DEBUG_LOCKS
void __init sched_core_debug_init(void)
{
	/* ensure basic invariants hold early */
	WARN_ON(!static_key_enabled(&sched_clock_running));
}
early_initcall(sched_core_debug_init);
#endif

EXPORT_SYMBOL_GPL(wake_up_new_task);
EXPORT_SYMBOL_GPL(sched_fork);
EXPORT_SYMBOL_GPL(sched_cgroup_fork);
EXPORT_SYMBOL_GPL(sched_cancel_fork);
EXPORT_SYMBOL_GPL(sched_post_fork);
EXPORT_SYMBOL_GPL(balance_callbacks);
EXPORT_SYMBOL_GPL(splice_balance_callbacks);
EXPORT_SYMBOL(nr_running);
EXPORT_SYMBOL(single_task_running);
EXPORT_SYMBOL(nr_context_switches);
EXPORT_SYMBOL(nr_context_switches_cpu);
EXPORT_SYMBOL(nr_iowait_cpu);
EXPORT_SYMBOL(clear_sched_clock_stable);
EXPORT_SYMBOL(__sched_core_account_forceidle);
EXPORT_SYMBOL(__sched_core_tick);
