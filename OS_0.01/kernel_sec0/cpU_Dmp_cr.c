// Note: This module currently operates with partial CPU core utilization. 
// The implementation is under active development and will receive iterative updates as i work on it. 
// Further enhancements for CPU core access and optimization are planned in subsequent revisions.
// Feel free to check it and suggest improvements.. 

#include <linux/highmem.h>
#include <linux/hrtimer_api.h>
#include <linux/ktime_api.h>
#include <linux/syscalls_api.h>
#include <linux/debug_locks.h>
#include <linux/prefetch.h>
#include <linux/capability.h>
#include <linux/blkdev.h>
#include <linux/context_tracking.h>
#include <linux/cpuset.h>
#include <linux/delayacct.h>
#include <linux/init_task.h>
#include <linux/interrupt.h>
#include <linux/ioprio.h>
#include <linux/kallsyms.h>
#include <linux/jiffies.h>
#include <linux/spinlock_api.h>
#include <linux/cpumask_api.h>
#include <linux/lockdep_api.h>
#include <linux/hardirq.h>
#include <linux/sched.h>
#include <linux/lockdep.h>
#include <linux/configfs.h>
#include <linux/irq.h>
#include <linux/cpu_rmap.h>
#include <linux/slab.h>
#include <linux/tracepoint.h>
#include <linux/ktime.h>

EXPORT_TRACEPOINT_SYMBOL_GPL(ipi_send_cpu);
EXPORT_TRACEPOINT_SYMBOL_GPL(ipi_send_cpumask);

EXPORT_TRACEPOINT_SYMBOL_GPL(sched_util_est_se_tp);
EXPORT_TRACEPOINT_SYMBOL_GPL(sched_update_nr_running_tp);
EXPORT_TRACEPOINT_SYMBOL_GPL(sched_compute_energy_tp);

DEFINE_PER_CPU_SHARED_ALIGNED(struct rq, runqueues);

#ifdef CONFIG_SCHED_PROXY_EXEC
DEFINE_STATIC_KEY_TRUE(__sched_proxy_exec);
static int __init setup_proxy_exec(char *str)
{
	bool proxy_enable = true;

	if (*str && kstrtobool(str + 1, &proxy_enable)) {
		pr_warn("Unable to parse sched_proxy_exec=\n");
		return 0;
	}

	if (proxy_enable) {
		pr_info("sched_proxy_exec enabled via boot arg\n");
		static_branch_enable(&__sched_proxy_exec);
	} else {
		pr_info("sched_proxy_exec disabled via boot arg\n");
		static_branch_disable(&__sched_proxy_exec);
	}
	return 1;
}
#else
static int __init setup_proxy_exec(char *str)
{
	pr_warn("CONFIG_SCHED_PROXY_EXEC=n, so it cannot be enabled or disabled at boot time\n");
	return 0;
}
#endif
__setup("sched_proxy_exec", setup_proxy_exec);

#define SCHED_FEAT(name, enabled)	\
	(1UL << __SCHED_FEAT_##name) * enabled |
__read_mostly unsigned int sysctl_sched_features =
#include "features.h"
	0;
#undef SCHED_FEAT

__read_mostly int sysctl_resched_latency_warn_ms = 100;
__read_mostly int sysctl_resched_latency_warn_once = 1;

__read_mostly unsigned int sysctl_sched_nr_migrate = SCHED_NR_MIGRATE_BREAK;

__read_mostly int scheduler_running;

#ifdef CONFIG_SCHED_CORE

DEFINE_STATIC_KEY_FALSE(__sched_core_enabled);

static inline int __task_prio(const struct task_struct *p)
{
	if (p->sched_class == &stop_sched_class) 
		return -2;

	if (p->dl_server)
		return -1;

	if (rt_or_dl_prio(p->prio))
		return p->prio;

	if (p->sched_class == &idle_sched_class)
		return MAX_RT_PRIO + NICE_WIDTH;

	if (task_on_scx(p))
		return MAX_RT_PRIO + MAX_NICE + 1;

	return MAX_RT_PRIO + MAX_NICE;
}

static inline bool prio_less(const struct task_struct *a,
			     const struct task_struct *b, bool in_fi)
{
	int pa = __task_prio(a), pb = __task_prio(b);

	if (-pa < -pb)
		return true;

	if (-pb < -pa)
		return false;

	if (pa == -1) {
		const struct sched_dl_entity *a_dl, *b_dl;

		a_dl = &a->dl;
		if (a->dl_server)
			a_dl = a->dl_server;

		b_dl = &b->dl;
		if (b->dl_server)
			b_dl = b->dl_server;

		return !dl_time_before(a_dl->deadline, b_dl->deadline);
	}

	if (pa == MAX_RT_PRIO + MAX_NICE)
		return cfs_prio_less(a, b, in_fi);

#ifdef CONFIG_SCHED_CLASS_EXT
	if (pa == MAX_RT_PRIO + MAX_NICE + 1)
		return scx_prio_less(a, b, in_fi);
#endif

	return false;
}

static inline bool __sched_core_less(const struct task_struct *a,
				     const struct task_struct *b)
{
	if (a->core_cookie < b->core_cookie)
		return true;

	if (a->core_cookie > b->core_cookie)
		return false;

	if (prio_less(b, a, !!task_rq(a)->core->core_forceidle_count))
		return true;

	return false;
}

#define __node_2_sc(node) rb_entry((node), struct task_struct, core_node)

static inline bool rb_sched_core_less(struct rb_node *a, const struct rb_node *b)
{
	return __sched_core_less(__node_2_sc(a), __node_2_sc(b));
}

static inline int rb_sched_core_cmp(const void *key, const struct rb_node *node)
{
	const struct task_struct *p = __node_2_sc(node);
	unsigned long cookie = (unsigned long)key;

	if (cookie < p->core_cookie)
		return -1;

	if (cookie > p->core_cookie)
		return 1;

	return 0;
}

void sched_core_enqueue(struct rq *rq, struct task_struct *p)
{
	if (p->se.sched_delayed)
		return;

	rq->core->core_task_seq++;

	if (!p->core_cookie)
		return;

	rb_add(&p->core_node, &rq->core_tree, rb_sched_core_less);
}

void sched_core_dequeue(struct rq *rq, struct task_struct *p, int flags)
{
	if (p->se.sched_delayed)
		return;

	rq->core->core_task_seq++;

	if (sched_core_enqueued(p)) {
		rb_erase(&p->core_node, &rq->core_tree);
		RB_CLEAR_NODE(&p->core_node);
	}

	if (!(flags & DEQUEUE_SAVE) && rq->nr_running == 1 &&
	    rq->core->core_forceidle_count && rq->curr == rq->idle)
		resched_curr(rq);
}

static int sched_task_is_throttled(struct task_struct *p, int cpu)
{
	if (p->sched_class->task_is_throttled)
		return p->sched_class->task_is_throttled(p, cpu);

	return 0;
}

static struct task_struct *sched_core_next(struct task_struct *p, unsigned long cookie)
{
	struct rb_node *node = &p->core_node;
	int cpu = task_cpu(p);

	do {
		node = rb_next(node);
		if (!node)
			return NULL;

		p = __node_2_sc(node);
		if (p->core_cookie != cookie)
			return NULL;

	} while (sched_task_is_throttled(p, cpu));

	return p;
}

static struct task_struct *sched_core_find(struct rq *rq, unsigned long cookie)
{
	struct task_struct *p;
	struct rb_node *node;

	node = rb_find_first((void *)cookie, &rq->core_tree, rb_sched_core_cmp);
	if (!node)
		return NULL;

	p = __node_2_sc(node);
	if (!sched_task_is_throttled(p, rq->cpu))
		return p;

	return sched_core_next(p, cookie);
}

static DEFINE_MUTEX(sched_core_mutex);
static atomic_t sched_core_count;
static struct cpumask sched_core_mask;

static inline void wait_for_ap_thread(struct cpuhp_cpu_state *st, bool bringup)
{
	struct completion *done = bringup ? &st->done_up : &st->done_down;
	wait_for_completion(done);
}

static inline void complete_ap_thread(struct cpuhp_cpu_state *st, bool bringup)
{
	struct completion *done = bringup ? &st->done_up : &st->done_down;
	complete(done);
}


static int __set_cpus_allowed_ptr_locked(struct task_struct *p,
					 struct affinity_context *ctx,
					 struct rq *rq,
					 struct rq_flags *rf)
	__releases(rq->lock)
	__releases(p->pi_lock)
{
	const struct cpumask *cpu_allowed_mask = task_cpu_possible_mask(p);
	const struct cpumask *cpu_valid_mask = cpu_active_mask;
	bool kthread = p->flags & PF_KTHREAD;
	unsigned int dest_cpu;
	int ret = 0;

	update_rq_clock(rq);

	if (kthread || is_migration_disabled(p)) {

		cpu_valid_mask = cpu_online_mask;
	}

	if (!kthread && !cpumask_subset(ctx->new_mask, cpu_allowed_mask)) {
		ret = -EINVAL;
		goto out;
	}

	if ((ctx->flags & SCA_CHECK) && (p->flags & PF_NO_SETAFFINITY)) {
		ret = -EINVAL;
		goto out;
	}

	if (!(ctx->flags & SCA_MIGRATE_ENABLE)) {
		if (cpumask_equal(&p->cpus_mask, ctx->new_mask)) {
			if (ctx->flags & SCA_USER)
				swap(p->user_cpus_ptr, ctx->user_mask);
			goto out;
		}

		if (WARN_ON_ONCE(p == current &&
				 is_migration_disabled(p) &&
				 !cpumask_test_cpu(task_cpu(p), ctx->new_mask))) {
			ret = -EBUSY;
			goto out;
		}
	}


	dest_cpu = cpumask_any_and_distribute(cpu_valid_mask, ctx->new_mask);
	if (dest_cpu >= nr_cpu_ids) {
		ret = -EINVAL;
		goto out;
	}

	__do_set_cpus_allowed(p, ctx);

	return affine_move_task(rq, p, rf, dest_cpu, ctx->flags);

out:
	task_rq_unlock(rq, p, rf);

	return ret;
}

int cpu_rmap_update(struct cpu_rmap *rmap, u16 index,
		    const struct cpumask *affinity)
{
	cpumask_var_t update_mask;
	unsigned int cpu;

	if (unlikely(!zalloc_cpumask_var(&update_mask, GFP_KERNEL)))
		return -ENOMEM;


	for_each_online_cpu(cpu) {
		if (rmap->near[cpu].index == index) {
			rmap->near[cpu].dist = CPU_RMAP_DIST_INF;
			cpumask_set_cpu(cpu, update_mask);
		}
	}

	debug_print_rmap(rmap, "after invalidating old distances");


	for_each_cpu(cpu, affinity) {
		rmap->near[cpu].index = index;
		rmap->near[cpu].dist = 0;
		cpumask_or(update_mask, update_mask,
			   cpumask_of_node(cpu_to_node(cpu)));
	}

	debug_print_rmap(rmap, "after updating neighbours");

	/* Update distances based on topology */
	for_each_cpu(cpu, update_mask) {
		if (cpu_rmap_copy_neigh(rmap, cpu,
					topology_sibling_cpumask(cpu), 1))
			continue;
		if (cpu_rmap_copy_neigh(rmap, cpu,
					topology_core_cpumask(cpu), 2))
			continue;
		if (cpu_rmap_copy_neigh(rmap, cpu,
					cpumask_of_node(cpu_to_node(cpu)), 3))
			continue;

	}

	debug_print_rmap(rmap, "after copying neighbours");

	free_cpumask_var(update_mask);
	return 0;
}
EXPORT_SYMBOL(cpu_rmap_update);

static void sched_core_unlock(int cpu, unsigned long *flags)
{
	const struct cpumask *smt_mask = cpu_smt_mask(cpu);
	int t;

	for_each_cpu(t, smt_mask)
		raw_spin_unlock(&cpu_rq(t)->__lock);
	local_irq_restore(*flags);
}

static void __sched_core_flip(bool enabled)
{
	unsigned long flags;
	int cpu, t;

	cpus_read_lock();

	cpumask_copy(&sched_core_mask, cpu_online_mask);
	for_each_cpu(cpu, &sched_core_mask) {
		const struct cpumask *smt_mask = cpu_smt_mask(cpu);

		sched_core_lock(cpu, &flags);

		for_each_cpu(t, smt_mask)
			cpu_rq(t)->core_enabled = enabled;

		cpu_rq(cpu)->core->core_forceidle_start = 0;

		sched_core_unlock(cpu, &flags);

		cpumask_andnot(&sched_core_mask, &sched_core_mask, smt_mask);
	}

	for_each_cpu_andnot(cpu, cpu_possible_mask, cpu_online_mask)
		cpu_rq(cpu)->core_enabled = enabled;

	cpus_read_unlock();
}

static void sched_core_assert_empty(void)
{
	int cpu;

	for_each_possible_cpu(cpu)
		WARN_ON_ONCE(!RB_EMPTY_ROOT(&cpu_rq(cpu)->core_tree));
}

static void __sched_core_enable(void)
{
	static_branch_enable(&__sched_core_enabled);
	synchronize_rcu();
	__sched_core_flip(true);
	sched_core_assert_empty();
}

static void __sched_core_disable(void)
{
	sched_core_assert_empty();
	__sched_core_flip(false);
	static_branch_disable(&__sched_core_enabled);
}

void sched_core_get(void)
{
	if (atomic_inc_not_zero(&sched_core_count))
		return;

	mutex_lock(&sched_core_mutex);
	if (!atomic_read(&sched_core_count))
		__sched_core_enable();

	smp_mb__before_atomic();
	atomic_inc(&sched_core_count);
	mutex_unlock(&sched_core_mutex);
}

static void __sched_core_put(struct work_struct *work)
{
	if (atomic_dec_and_mutex_lock(&sched_core_count, &sched_core_mutex)) {
		__sched_core_disable();
		mutex_unlock(&sched_core_mutex);
	}
}

void sched_core_put(void)
{
	static DECLARE_WORK(_work, __sched_core_put);

	if (!atomic_add_unless(&sched_core_count, -1, 1))
		schedule_work(&_work);
}

#else

static inline void sched_core_enqueue(struct rq *rq, struct task_struct *p) { }
static inline void
sched_core_dequeue(struct rq *rq, struct task_struct *p, int flags) { }

#endif

EXPORT_TRACEPOINT_SYMBOL(sched_set_state_tp);

void __trace_set_current_state(int state_value)
{
	trace_sched_set_state_tp(current, state_value);
}
EXPORT_SYMBOL(__trace_set_current_state);

void raw_spin_rq_lock_nested(struct rq *rq, int subclass)
{
	raw_spinlock_t *lock;

	preempt_disable();
	if (sched_core_disabled()) {
		raw_spin_lock_nested(&rq->__lock, subclass);
		preempt_enable_no_resched();
		return;
	}

	for (;;) {
		lock = __rq_lockp(rq);
		raw_spin_lock_nested(lock, subclass);
		if (likely(lock == __rq_lockp(rq))) {
			preempt_enable_no_resched();
			return;
		}
		raw_spin_unlock(lock);
	}
}

bool raw_spin_rq_trylock(struct rq *rq)
{
	raw_spinlock_t *lock;
	bool ret;

	preempt_disable();
	if (sched_core_disabled()) {
		ret = raw_spin_trylock(&rq->__lock);
		preempt_enable();
		return ret;
	}

	for (;;) {
		lock = __rq_lockp(rq);
		ret = raw_spin_trylock(lock);
		if (!ret || (likely(lock == __rq_lockp(rq)))) {
			preempt_enable();
			return ret;
		}
		raw_spin_unlock(lock);
	}
}

void raw_spin_rq_unlock(struct rq *rq)
{
	raw_spin_unlock(rq_lockp(rq));
}

void double_rq_lock(struct rq *rq1, struct rq *rq2)
{
	lockdep_assert_irqs_disabled();

	if (rq_order_less(rq2, rq1))
		swap(rq1, rq2);

	raw_spin_rq_lock(rq1);
	if (__rq_lockp(rq1) != __rq_lockp(rq2))
		raw_spin_rq_lock_nested(rq2, SINGLE_DEPTH_NESTING);

	double_rq_clock_clear_update(rq1, rq2);
}

struct rq *__task_rq_lock(struct task_struct *p, struct rq_flags *rf)
	__acquires(rq->lock)
{
	struct rq *rq;

	lockdep_assert_held(&p->pi_lock);

	for (;;) {
		rq = task_rq(p);
		raw_spin_rq_lock(rq);
		if (likely(rq == task_rq(p) && !task_on_rq_migrating(p))) {
			rq_pin_lock(rq, rf);
			return rq;
		}
		raw_spin_rq_unlock(rq);

		while (unlikely(task_on_rq_migrating(p)))
			cpu_relax();
	}
}

struct rq *task_rq_lock(struct task_struct *p, struct rq_flags *rf)
	__acquires(p->pi_lock)
	__acquires(rq->lock)
{
	struct rq *rq;

	for (;;) {
		raw_spin_lock_irqsave(&p->pi_lock, rf->flags);
		rq = task_rq(p);
		raw_spin_rq_lock(rq);
		if (likely(rq == task_rq(p) && !task_on_rq_migrating(p))) {
			rq_pin_lock(rq, rf);
			return rq;
		}
		raw_spin_rq_unlock(rq);
		raw_spin_unlock_irqrestore(&p->pi_lock, rf->flags);

		while (unlikely(task_on_rq_migrating(p)))
			cpu_relax();
	}
}

static void update_rq_clock_task(struct rq *rq, s64 delta)
{
	s64 __maybe_unused steal = 0, irq_delta = 0;

#ifdef CONFIG_IRQ_TIME_ACCOUNTING
	switch (mode) {
	case preempt_dynamic_none:
		preempt_dynamic_enable(cond_resched);
		preempt_dynamic_disable(might_resched);
		preempt_dynamic_disable(preempt_schedule);
		preempt_dynamic_disable(preempt_schedule_notrace);
		preempt_dynamic_disable(irqentry_exit_cond_resched);
		preempt_dynamic_key_disable(preempt_lazy);
		if (mode != preempt_dynamic_mode)
			pr_info("Dynamic Preempt: none\n");
		break;

	case preempt_dynamic_voluntary:
		preempt_dynamic_enable(cond_resched);
		preempt_dynamic_enable(might_resched);
		preempt_dynamic_disable(preempt_schedule);
		preempt_dynamic_disable(preempt_schedule_notrace);
		preempt_dynamic_disable(irqentry_exit_cond_resched);
		preempt_dynamic_key_disable(preempt_lazy);
		if (mode != preempt_dynamic_mode)
			pr_info("Dynamic Preempt: voluntary\n");
		break;

	case preempt_dynamic_full:
		preempt_dynamic_disable(cond_resched);
		preempt_dynamic_disable(might_resched);
		preempt_dynamic_enable(preempt_schedule);
		preempt_dynamic_enable(preempt_schedule_notrace);
		preempt_dynamic_enable(irqentry_exit_cond_resched);
		preempt_dynamic_key_disable(preempt_lazy);
		if (mode != preempt_dynamic_mode)
			pr_info("Dynamic Preempt: full\n");
		break;

	case preempt_dynamic_lazy:
		preempt_dynamic_disable(cond_resched);
		preempt_dynamic_disable(might_resched);
		preempt_dynamic_enable(preempt_schedule);
		preempt_dynamic_enable(preempt_schedule_notrace);
		preempt_dynamic_enable(irqentry_exit_cond_resched);
		preempt_dynamic_key_enable(preempt_lazy);
		if (mode != preempt_dynamic_mode)
			pr_info("Dynamic Preempt: lazy\n");
		break;
	}
	}
#endif
#ifdef CONFIG_PARAVIRT_TIME_ACCOUNTING
	if (static_key_false((&paravirt_steal_rq_enabled))) {
		u64 prev_steal;

		steal = prev_steal = paravirt_steal_clock(cpu_of(rq));
		steal -= rq->prev_steal_time_rq;

		if (unlikely(steal > delta))
			steal = delta;

		rq->prev_steal_time_rq = prev_steal;
		delta -= steal;
	}
#endif

	rq->clock_task += delta;

#ifdef CONFIG_HAVE_SCHED_AVG_IRQ
	if ((irq_delta + steal) && sched_feat(NONTASK_CAPACITY))
		update_irq_load_avg(rq, irq_delta + steal);
#endif
	update_rq_clock_pelt(rq, delta);
}

void update_rq_clock(struct rq *rq)
{
	s64 delta;
	u64 clock;

	lockdep_assert_rq_held(rq);

	if (rq->clock_update_flags & RQCF_ACT_SKIP)
		return;

	if (sched_feat(WARN_DOUBLE_CLOCK))
		WARN_ON_ONCE(rq->clock_update_flags & RQCF_UPDATED);
	rq->clock_update_flags |= RQCF_UPDATED;

	clock = sched_clock_cpu(cpu_of(rq));
	scx_rq_clock_update(rq, clock);

	delta = clock - rq->clock;
	if (delta < 0)
		return;
	rq->clock += delta;

	update_rq_clock_task(rq, delta);
}

/* updated section */

int io_schedule_prepare(void)
{
	int old_iowait = current->in_iowait;

#ifdef CONFIG_IO_SCHED_DEBUG
	u64 start_ns = ktime_get_ns();
#endif

	current->in_iowait = 1;

	/* Flush any pending I/O plugs if they exist */
	if (current->plug)
		blk_flush_plug(current->plug, true);

#ifdef CONFIG_IO_SCHED_DEBUG
	u64 end_ns = ktime_get_ns();
	pr_debug("[io_sched] %s[%d] entered io_schedule_prepare(), took %llu ns\n",
	         current->comm, current->pid,
	         (unsigned long long)(end_ns - start_ns));
#endif

#ifdef CONFIG_SCHED_TRACING
	trace_io_schedule_prepare(current);
#endif

	return old_iowait;
}
EXPORT_SYMBOL(io_schedule_prepare);

#ifdef CONFIG_SCHED_HRTICK
/*
 * hrtick_clear - cancel an active high-resolution tick timer
 */
static void hrtick_clear(struct rq *rq)
{
	if (hrtimer_active(&rq->hrtick_timer)) {
		int ret = hrtimer_cancel(&rq->hrtick_timer);
#ifdef CONFIG_SCHED_DEBUG
		if (ret)
			pr_debug("[hrtick] Cleared active hrtick on CPU %d\n", cpu_of(rq));
#endif
	}
}

/*
 * hrtick - high-resolution scheduler tick
 * Drives fine-grained task preemption and time-slice accounting.
 */
static enum hrtimer_restart hrtick(struct hrtimer *timer)
{
	struct rq *rq = container_of(timer, struct rq, hrtick_timer);
	struct rq_flags rf;

	WARN_ON_ONCE(cpu_of(rq) != smp_processor_id());

	rq_lock(rq, &rf);
	update_rq_clock(rq);

#ifdef CONFIG_SCHED_HRTICK_DEBUG
	pr_debug("[hrtick] tick on CPU %d for %s[%d]\n",
	         cpu_of(rq), rq->curr->comm, rq->curr->pid);
#endif

	if (likely(rq->curr->sched_class && rq->curr->sched_class->task_tick))
		rq->curr->sched_class->task_tick(rq, rq->curr, 1);
	else
		pr_warn_once("[hrtick] Missing task_tick() handler on CPU %d\n",
		             cpu_of(rq));

	rq_unlock(rq, &rf);

#ifdef CONFIG_SCHED_TRACING
	trace_sched_hrtick(cpu_of(rq), rq->curr);
#endif

	return HRTIMER_NORESTART;
}
#endif /* CONFIG_SCHED_HRTICK */

/*
 * __cond_resched_rwlock_read - conditional reschedule for read locks
 */
int __cond_resched_rwlock_read(rwlock_t *lock)
{
	int resched = should_resched(PREEMPT_LOCK_OFFSET);
	int ret = 0;

	lockdep_assert_held_read(lock);

	if (rwlock_needbreak(lock) || resched) {
		read_unlock(lock);
		if (!_cond_resched())
			cpu_relax();
		ret = 1;
		read_lock(lock);
	}
	return ret;
}
EXPORT_SYMBOL(__cond_resched_rwlock_read);

/*
 * in_sched_functions - check whether @addr lies inside scheduler functions
 */
int in_sched_functions(unsigned long addr)
{
	return in_lock_functions(addr) ||
	       (addr >= (unsigned long)__sched_text_start &&
	        addr < (unsigned long)__sched_text_end);
}

/* --------------------------------------------------------------------------
 * config_key support helpers
 * -------------------------------------------------------------------------- */

static struct configfs_attribute *config_key_attrs[] = {
	&config_key_attr_description,
	NULL,
};

static void config_key_release(struct config_item *item)
{
	/*
	 * Ensure release order: decrement counter before freeing.
	 * If key_count is shared across CPUs, use atomic operations.
	 */
#ifdef CONFIG_SMP
	atomic_dec(&key_count);
#else
	key_count--;
#endif
	kfree(to_config_key(item));
}


int irq_cpu_rmap_add(struct cpu_rmap *rmap, int irq)
{
	struct irq_glue *glue = kzalloc(sizeof(*glue), GFP_KERNEL);
	int rc;

	if (!glue)
		return -ENOMEM;

	glue->notify.notify  = irq_cpu_rmap_notify;
	glue->notify.release = irq_cpu_rmap_release;
	glue->rmap = rmap;

	cpu_rmap_get(rmap);

	rc = cpu_rmap_add(rmap, glue);
	if (rc < 0)
		goto err_add;

	glue->index = rc;
	rc = irq_set_affinity_notifier(irq, &glue->notify);
	if (rc)
		goto err_set;

	return rc;

err_set:
	rmap->obj[glue->index] = NULL;
err_add:
	cpu_rmap_put(glue->rmap);
	kfree(glue);
	return rc;
}
EXPORT_SYMBOL(irq_cpu_rmap_add);

static void irq_cpu_rmap_notify(struct irq_affinity_notify *notify,
				const struct cpumask *mask)
{
	struct irq_glue *glue = container_of(notify, struct irq_glue, notify);

	if (!glue || !glue->rmap)
		return;

	cpu_rmap_update(glue->rmap, glue->index, mask);
}
EXPORT_SYMBOL(irq_cpu_rmap_notify);

static void irq_cpu_rmap_release(struct irq_affinity_notify *notify)
{
	struct irq_glue *glue = container_of(notify, struct irq_glue, notify);

	if (!glue)
		return;

	cpu_rmap_put(glue->rmap);
	glue->rmap = NULL;
	kfree(glue);
}
EXPORT_SYMBOL(irq_cpu_rmap_release);


int cpu_rmap_init(struct cpu_rmap *rmap)
{
	int cpu;

	if (!rmap)
		return -EINVAL;

	for_each_possible_cpu(cpu) {
		rmap->near[cpu].index = U16_MAX;
		rmap->near[cpu].dist  = CPU_RMAP_DIST_INF;
	}

	return 0;
}
EXPORT_SYMBOL(cpu_rmap_init);

int irq_cpu_rmap_unregister(struct cpu_rmap *rmap, unsigned int index)
{
	struct irq_glue *glue;

	if (!rmap || index >= nr_cpu_ids)
		return -EINVAL;

	glue = rmap->obj ? rmap->obj[index] : NULL;
	if (!glue)
		return -ENOENT;

	rmap->obj[index] = NULL;
	irq_cpu_rmap_release(&glue->notify);

	return 0;
}
EXPORT_SYMBOL(irq_cpu_rmap_unregister);

static inline void sched_diag_record_io_wait(u64 delta)
{
	struct sched_diag *diag = this_cpu_ptr(&cpu_sched_diag);
	raw_spin_lock(&diag->lock);
	diag->total_io_wait_ns += delta;
	diag->io_wait_count++;
	raw_spin_unlock(&diag->lock);
}


void io_schedule_complete(int old_iowait)
{
#ifdef CONFIG_SCHED_DEBUG
	static DEFINE_PER_CPU(u64, io_wait_start_ns);
	u64 now = ktime_get_ns();
	u64 delta = now - this_cpu_read(io_wait_start_ns);

	sched_diag_record_io_wait(delta);

	pr_debug("[io_sched] PID:%d (%s) waited %llu ns for I/O\n",
		 current->pid, current->comm,
		 (unsigned long long)delta);
#endif

	current->in_iowait = old_iowait;
}
EXPORT_SYMBOL(io_schedule_complete);

#ifdef CONFIG_NUMA

int numa_cpu_rmap_balance(struct cpu_rmap *rmap)
{
	int cpu, node;
	int count = 0;

	if (!rmap)
		return -EINVAL;

	for_each_online_cpu(cpu) {
		node = cpu_to_node(cpu);
		rmap->near[cpu].dist = node_distance(node, numa_node_id());
		count++;
	}

	pr_debug("[rmap] NUMA rebalance updated %d CPUs\n", count);
	return 0;
}
EXPORT_SYMBOL(numa_cpu_rmap_balance);
#endif /* CONFIG_NUMA */


#ifdef CONFIG_LOCK_STAT

struct lockstat_info {
	u64 acquire_count;
	u64 contention_count;
	u64 total_wait_ns;
};

static DEFINE_PER_CPU(struct lockstat_info, cpu_lockstat);

void sched_lockstat_acquire_start(void)
{
	struct lockstat_info *info = this_cpu_ptr(&cpu_lockstat);
	info->acquire_count++;
}

void sched_lockstat_contention(u64 wait_ns)
{
	struct lockstat_info *info = this_cpu_ptr(&cpu_lockstat);
	info->contention_count++;
	info->total_wait_ns += wait_ns;
}
#endif /* CONFIG_LOCK_STAT */

#ifdef CONFIG_PROC_FS

static int sched_diag_show(struct seq_file *m, void *v)
{
	int cpu;

	seq_puts(m, "=== Scheduler Diagnostics ===\n");
	for_each_online_cpu(cpu) {
		struct sched_diag *d = &per_cpu(cpu_sched_diag, cpu);
		u64 avg_wait = 0;

		if (d->io_wait_count)
			avg_wait = div64_u64(d->total_io_wait_ns, d->io_wait_count);

		seq_printf(m,
			"CPU %d: I/O waits=%llu, total=%llu ns, avg=%llu ns, switches=%llu\n",
			cpu,
			(unsigned long long)d->io_wait_count,
			(unsigned long long)d->total_io_wait_ns,
			(unsigned long long)avg_wait,
			(unsigned long long)d->rq_switch_count);
	}

#ifdef CONFIG_LOCK_STAT
	for_each_online_cpu(cpu) {
		struct lockstat_info *l = &per_cpu(cpu_lockstat, cpu);
		seq_printf(m,
			"CPU %d: locks=%llu, contended=%llu, total_wait=%llu ns\n",
			cpu,
			(unsigned long long)l->acquire_count,
			(unsigned long long)l->contention_count,
			(unsigned long long)l->total_wait_ns);
	}
#endif

	return 0;
}

static int sched_diag_open(struct inode *inode, struct file *file)
{
	return single_open(file, sched_diag_show, NULL);
}

static const struct proc_ops sched_diag_fops = {
	.proc_open	= sched_diag_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

static int __init sched_diag_init(void)
{
	struct sched_diag *d;
	int cpu;

	for_each_possible_cpu(cpu) {
		d = &per_cpu(cpu_sched_diag, cpu);
		raw_spin_lock_init(&d->lock);
	}

	proc_create("sched_diag", 0444, NULL, &sched_diag_fops);
	pr_info("sched_diag: /proc/sched_diag registered\n");
	return 0;
}
fs_initcall(sched_diag_init);


// TBC