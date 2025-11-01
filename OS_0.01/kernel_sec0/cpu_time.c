/* 
 * Review Req.! in here..
 * Ex: This enhances the kernels virtual time management by accurately tracking 
 * user, system, idle, and guest CPU times per task. 
 */

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/seqcount.h>
#include <linux/rcupdate.h>
#include <linux/smp.h>
#include <linux/ktime.h>
#include <linux/jiffies.h>
#include <linux/sched.h>
#include <linux/sched/cputime.h>
#include <linux/tsacct_kern.h>
#include <linux/printk.h>
#include <linux/export.h>
#ifdef CONFIG_VIRT_CPU_ACCOUNTING_NATIVE
 #include <asm/cputime.h>
#endif

DEFINE_PER_CPU(struct irqtime, cpu_irqtime);

int sched_clock_irqtime;

void enable_sched_clock_irqtime(void)
{
	sched_clock_irqtime = 1;
}

void disable_sched_clock_irqtime(void)
{
	sched_clock_irqtime = 0;
}

static void irqtime_account_delta(struct irqtime *irqtime, u64 delta,
				  enum cpu_usage_stat idx)
{
	u64 *cpustat = kcpustat_this_cpu->cpustat;

	u64_stats_update_begin(&irqtime->sync);
	cpustat[idx] += delta;
	irqtime->total += delta;
	irqtime->tick_delta += delta;
	u64_stats_update_end(&irqtime->sync);
}

void vtime_user_exit(struct task_struct *tsk)
{
	struct vtime *vtime = &tsk->vtime;

	write_seqcount_begin(&vtime->seqcount);
	vtime->utime += get_vtime_delta(vtime);
	if (vtime->utime >= TICK_NSEC) {
		account_user_time(tsk, vtime->utime);
		vtime->utime = 0;
	}
	vtime->state = VTIME_SYS;
	write_seqcount_end(&vtime->seqcount);
}

void vtime_guest_enter(struct task_struct *tsk)
{
	struct vtime *vtime = &tsk->vtime;
	write_seqcount_begin(&vtime->seqcount);
	vtime_account_system(tsk, vtime);
	tsk->flags |= PF_VCPU;
	vtime->state = VTIME_GUEST;
	write_seqcount_end(&vtime->seqcount);
}
EXPORT_SYMBOL_GPL(vtime_guest_enter);

void vtime_guest_exit(struct task_struct *tsk)
{
	struct vtime *vtime = &tsk->vtime;

	write_seqcount_begin(&vtime->seqcount);
	vtime_account_guest(tsk, vtime);
	tsk->flags &= ~PF_VCPU;
	vtime->state = VTIME_SYS;
	write_seqcount_end(&vtime->seqcount);
}
EXPORT_SYMBOL_GPL(vtime_guest_exit);

void vtime_account_idle(struct task_struct *tsk)
{
	account_idle_time(get_vtime_delta(&tsk->vtime));
}

void vtime_task_switch_generic(struct task_struct *prev)
{
	struct vtime *vtime = &prev->vtime;

	write_seqcount_begin(&vtime->seqcount);
	if (vtime->state == VTIME_IDLE)
		vtime_account_idle(prev);
	else
		__vtime_account_kernel(prev, vtime);
	vtime->state = VTIME_INACTIVE;
	vtime->cpu = -1;
	write_seqcount_end(&vtime->seqcount);

	vtime = &current->vtime;

	write_seqcount_begin(&vtime->seqcount);
	if (is_idle_task(current))
		vtime->state = VTIME_IDLE;
	else if (current->flags & PF_VCPU)
		vtime->state = VTIME_GUEST;
	else
		vtime->state = VTIME_SYS;
	vtime->starttime = sched_clock();
	vtime->cpu = smp_processor_id();
	write_seqcount_end(&vtime->seqcount);
}

void vtime_init_idle(struct task_struct *t, int cpu)
{
	struct vtime *vtime = &t->vtime;
	unsigned long flags;

	local_irq_save(flags);
	write_seqcount_begin(&vtime->seqcount);
	vtime->state = VTIME_IDLE;
	vtime->starttime = sched_clock();
	vtime->cpu = cpu;
	write_seqcount_end(&vtime->seqcount);
	local_irq_restore(flags);
}

u64 task_gtime(struct task_struct *t)
{
	struct vtime *vtime = &t->vtime;
	unsigned int seq;
	u64 gtime;

	if (!vtime_accounting_enabled())
		return t->gtime;

	do {
		seq = read_seqcount_begin(&vtime->seqcount);

		gtime = t->gtime;
		if (vtime->state == VTIME_GUEST)
			gtime += vtime->gtime + vtime_delta(vtime);

	} while (read_seqcount_retry(&vtime->seqcount, seq));

	return gtime;
}

static int kcpustat_field_vtime(u64 *cpustat,
				struct task_struct *tsk,
				enum cpu_usage_stat usage,
				int cpu, u64 *val)
{
	struct vtime *vtime = &tsk->vtime;
	unsigned int seq;

	do {
		int state;

		seq = read_seqcount_begin(&vtime->seqcount);

		state = vtime_state_fetch(vtime, cpu);
		if (state < 0)
			return state;

		*val = cpustat[usage];

		switch (usage) {
		case CPUTIME_SYSTEM:
			if (state == VTIME_SYS)
				*val += vtime->stime + vtime_delta(vtime);
			break;
		case CPUTIME_USER:
			if (task_nice(tsk) <= 0)
				*val += kcpustat_user_vtime(vtime);
			break;
		case CPUTIME_NICE:
			if (task_nice(tsk) > 0)
				*val += kcpustat_user_vtime(vtime);
			break;
		case CPUTIME_GUEST:
			if (state == VTIME_GUEST && task_nice(tsk) <= 0)
				*val += vtime->gtime + vtime_delta(vtime);
			break;
		case CPUTIME_GUEST_NICE:
			if (state == VTIME_GUEST && task_nice(tsk) > 0)
				*val += vtime->gtime + vtime_delta(vtime);
			break;
		default:
			break;
		}
	} while (read_seqcount_retry(&vtime->seqcount, seq));

	return 0;
}

u64 kcpustat_field(struct kernel_cpustat *kcpustat,
		   enum cpu_usage_stat usage, int cpu)
{
	u64 *cpustat = kcpustat->cpustat;
	u64 val = cpustat[usage];
	struct rq *rq;
	int err;

	if (!vtime_accounting_enabled_cpu(cpu))
		return val;

	rq = cpu_rq(cpu);

	for (;;) {
		struct task_struct *curr;

		rcu_read_lock();
		curr = rcu_dereference(rq->curr);
		if (WARN_ON_ONCE(!curr)) {
			rcu_read_unlock();
			return cpustat[usage];
		}

		err = kcpustat_field_vtime(cpustat, curr, usage, cpu, &val);
		rcu_read_unlock();

		if (!err)
			return val;

		cpu_relax();
	}
}
EXPORT_SYMBOL_GPL(kcpustat_field);

static int kcpustat_cpu_fetch_vtime(struct kernel_cpustat *dst,
				    const struct kernel_cpustat *src,
				    struct task_struct *tsk, int cpu)
{
	struct vtime *vtime = &tsk->vtime;
	unsigned int seq;

	do {
		u64 *cpustat;
		u64 delta;
		int state;

		seq = read_seqcount_begin(&vtime->seqcount);

		state = vtime_state_fetch(vtime, cpu);
		if (state < 0)
			return state;

		*dst = *src;
		cpustat = dst->cpustat;

		if (state < VTIME_SYS)
			continue;

		delta = vtime_delta(vtime);

		if (state == VTIME_SYS) {
			cpustat[CPUTIME_SYSTEM] += vtime->stime + delta;
		} else if (state == VTIME_USER) {
			if (task_nice(tsk) > 0)
				cpustat[CPUTIME_NICE] += vtime->utime + delta;
			else
				cpustat[CPUTIME_USER] += vtime->utime + delta;
		} else {
			WARN_ON_ONCE(state != VTIME_GUEST);
			if (task_nice(tsk) > 0) {
				cpustat[CPUTIME_GUEST_NICE] += vtime->gtime + delta;
				cpustat[CPUTIME_NICE] += vtime->gtime + delta;
			} else {
				cpustat[CPUTIME_GUEST] += vtime->gtime + delta;
				cpustat[CPUTIME_USER] += vtime->gtime + delta;
			}
		}
	} while (read_seqcount_retry(&vtime->seqcount, seq));

	return 0;
}

void kcpustat_cpu_fetch(struct kernel_cpustat *dst, int cpu)
{
	const struct kernel_cpustat *src = &kcpustat_cpu(cpu);
	struct rq *rq;
	int err;

	if (!vtime_accounting_enabled_cpu(cpu)) {
		*dst = *src;
		return;
	}

	rq = cpu_rq(cpu);

	for (;;) {
		struct task_struct *curr;

		rcu_read_lock();
		curr = rcu_dereference(rq->curr);
		if (WARN_ON_ONCE(!curr)) {
			rcu_read_unlock();
			*dst = *src;
			return;
		}

		err = kcpustat_cpu_fetch_vtime(dst, src, curr, cpu);
		rcu_read_unlock();

		if (!err)
			return;

		cpu_relax();
	}
}
EXPORT_SYMBOL_GPL(kcpustat_cpu_fetch);
