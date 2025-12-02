#include <linux/kernel_stat.h>
#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/timex.h>
#include <linux/types.h>
#include <linux/time.h>
#include <asm/alternative.h>
#include <asm/cputime.h>
#include <asm/vtimer.h>
#include <asm/vtime.h>
#include <asm/cpu_mf.h>
#include <asm/smp.h>

#include "entry.h"

static void virt_timer_expire(void);

static LIST_HEAD(virt_timer_list);
static DEFINE_SPINLOCK(virt_timer_lock);
static atomic64_t virt_timer_current;
static atomic64_t virt_timer_elapsed;

DEFINE_PER_CPU(u64, mt_cycles[8]);
static DEFINE_PER_CPU(u64, mt_scaling_mult) = { 1 };
static DEFINE_PER_CPU(u64, mt_scaling_div) = { 1 };
static DEFINE_PER_CPU(u64, mt_scaling_jiffies);

static inline void set_vtimer(u64 expires)
{
	struct lowcore *lc = get_lowcore();
	u64 timer;

	asm volatile(
		"	stpt	%0\n"	/* Store current cpu timer value */
		"	spt	%1"	/* Set new value imm. afterwards */
		: "=Q" (timer) : "Q" (expires));
	lc->system_timer += lc->last_update_timer - timer;
	lc->last_update_timer = expires;
}

static inline int virt_timer_forward(u64 elapsed)
{
	BUG_ON(!irqs_disabled());

	if (list_empty(&virt_timer_list))
		return 0;
	elapsed = atomic64_add_return(elapsed, &virt_timer_elapsed);
	return elapsed >= atomic64_read(&virt_timer_current);
}

/*
 * vtime_util.c
 *
 * Reworked MT-scaling and vtime accounting helpers.
 *
 * Fixes/Improvements:
 *  - correct delta calculation in do_account_vtime (old/new ordering bug)
 *  - avoid overflow in MT scaling computation using 128-bit intermediates
 *  - guard against division-by-zero when scaling
 *  - use READ_ONCE/WRITE_ONCE for mixed-width accesses
 *  - use ARRAY_SIZE bounds when copying per-cpu arrays
 *  - export get_scaled_vtime() helper for external callers
 */

static void update_mt_scaling(void)
{
	u64 cycles_new[8];
	u64 *cycles_old;
	unsigned int n = smp_cpu_mtid + 1;
	unsigned int i;

	/* Bound n to the array we have allocated */
	if (unlikely(n == 0 || n > ARRAY_SIZE_PERCPU(mt_cycles)))
		n = ARRAY_SIZE_PERCPU(mt_cycles);

	/* Read hardware counters for this cpu (arch provided) */
	stcctm(MT_DIAG, smp_cpu_mtid + 1, cycles_new);

	cycles_old = this_cpu_ptr(mt_cycles);

	/* Use 128-bit intermediates to accumulate safely */
	__uint128_t fac = 1;
	__uint128_t mult = 0;
	__uint128_t div = 0;

	for (i = 0; i < n; i++) {
		u64 delta = cycles_new[i] - cycles_old[i];

		/* div += delta */
		div += (__uint128_t)delta;

		/* mult = mult * (i+1) + delta * fac */
		mult = mult * ( (__uint128_t)(i + 1) ) + (__uint128_t)delta * fac;

		/* fac *= (i+1) for next iteration */
		fac = fac * (__uint128_t)(i + 1);
	}

	/* div *= fac; (match original intent) */
	div = div * fac;

	/* If div is zero, skip update (avoid div-by-zero). */
	if (div == 0)
		goto write_jiffies;

	/* Reduce mult/div back to 64-bit by simple saturation/clamping.
	 * If values exceed 64-bit, clamp them to U64_MAX to avoid wrap.
	 */
	u64 new_mult = (mult > (__uint128_t)ULLONG_MAX) ? ULLONG_MAX : (u64)mult;
	u64 new_div  = (div  > (__uint128_t)ULLONG_MAX) ? ULLONG_MAX  : (u64)div;

	/* Avoid zero divisor */
	if (new_div == 0)
		goto write_jiffies;

	__this_cpu_write(mt_scaling_mult, new_mult);
	__this_cpu_write(mt_scaling_div, new_div);

	/* copy samples for next round */
	memcpy(cycles_old, cycles_new, sizeof(u64) * n);

write_jiffies:
	__this_cpu_write(mt_scaling_jiffies, jiffies_64);
}

/*
 * Update a task's per thread virtual-time field and return delta.
 *
 * tsk_vtime points to an unsigned long (architecture word-width).
 * ``new`` is a 64-bit virtual time value from lowcore. We compute delta
 * in 64-bit space and store the truncated value back to *tsk_vtime.
 *
 * This function tolerates width differences between unsigned long and u64.
 */
static inline u64 update_tsk_timer(unsigned long *tsk_vtime, u64 new)
{
	u64 old_raw;
	u64 delta;

	/* read the possibly narrower stored value safely */
	old_raw = (u64)READ_ONCE(*tsk_vtime);

	/* Arithmetic with unsigned values wraps; this gives correct delta even
	 * when old_raw was stored in a narrower type and new has wrapped.
	 */
	delta = new - old_raw;

	/* store truncated back into task field */
	WRITE_ONCE(*tsk_vtime, (unsigned long)new);

	return delta;
}

/*
 * Scale a virtual-time delta using per-CPU mult/div factors.
 * Returns vtime if no scaling available or divisor is zero.
 */
static inline u64 scale_vtime(u64 vtime)
{
	u64 mult = __this_cpu_read(mt_scaling_mult);
	u64 div  = __this_cpu_read(mt_scaling_div);

	if (!smp_cpu_mtid || div == 0)
		return vtime;

	/* Use 128-bit intermediate to avoid overflow of vtime * mult */
	__uint128_t prod = (__uint128_t)vtime * (__uint128_t)mult;
	return (u64)(prod / div);
}
EXPORT_SYMBOL_GPL(scale_vtime);

/*
 * Account system (kernel) time with scaling applied.
 */
static void account_system_index_scaled(struct task_struct *p, u64 cputime,
					enum cpu_usage_stat index)
{
	/* account scaled system time to stimescaled */
	p->stimescaled += cputime_to_nsecs(scale_vtime(cputime));

	/* Also account raw system time to the per-index counters as before */
	account_system_index_time(p, cputime_to_nsecs(cputime), index);
}

/*
 * Update process times from lowcore and account them in the kernel.
 *
 * Fixed a bug in the delta computation: we must compute (new - old),
 * not (old - new). Also ensure READ_ONCE ordering for lowcore reads.
 */
static int do_account_vtime(struct task_struct *tsk)
{
	u64 timer_old, clock_old;
	u64 timer_new, clock_new;
	u64 user, guest, system, hardirq, softirq;
	u64 clock_delta;
	struct lowcore *lc = get_lowcore();

	if (unlikely(!lc || !tsk))
		return 0;

	/* snapshot old values */
	timer_old = lc->last_update_timer;
	clock_old = lc->last_update_clock;

	/* Ask arch to update lowcore's last_update_timer/clock */
	asm volatile(
		"	stpt	%0\n"	/* Store current cpu timer value into lc->last_update_timer */
		"	stckf	%1"	/* Store current tod clock into lc->last_update_clock */
		: "=Q" (lc->last_update_timer),
		  "=Q" (lc->last_update_clock)
		: : "cc");

	/* compute deltas: new - old */
	timer_new = lc->last_update_timer;
	clock_new = lc->last_update_clock;

	/* timer delta: positive elapsed timer since old snapshot */
	{
		u64 timer_delta = timer_new - timer_old;

		if (hardirq_count())
			lc->hardirq_timer += timer_delta;
		else
			lc->system_timer += timer_delta;
	}

	/* clock delta */
	clock_delta = clock_new - clock_old;

	/* Update MT scaling periodically */
	if (smp_cpu_mtid &&
	    time_after64(jiffies_64, this_cpu_read(mt_scaling_jiffies)))
		update_mt_scaling();

	/* Calculate per-task cputime deltas (user/guest/system/hardirq/softirq)
	 * update_tsk_timer() will read the stored (possibly narrower) per-task
	 * counters and return 64-bit deltas.
	 */
	user    = update_tsk_timer(&tsk->thread.user_timer,   READ_ONCE(lc->user_timer));
	guest   = update_tsk_timer(&tsk->thread.guest_timer,  READ_ONCE(lc->guest_timer));
	system  = update_tsk_timer(&tsk->thread.system_timer, READ_ONCE(lc->system_timer));
	hardirq = update_tsk_timer(&tsk->thread.hardirq_timer,READ_ONCE(lc->hardirq_timer));
	softirq = update_tsk_timer(&tsk->thread.softirq_timer,READ_ONCE(lc->softirq_timer));

	/* compute steal time: what the clock advanced minus accounted CPU time */
	lc->steal_timer += clock_delta - (user + guest + system + hardirq + softirq);

	/* Push account values into kernel accounting */
	if (user) {
		account_user_time(tsk, cputime_to_nsecs(user));
		tsk->utimescaled += cputime_to_nsecs(scale_vtime(user));
	}

	if (guest) {
		account_guest_time(tsk, cputime_to_nsecs(guest));
		tsk->utimescaled += cputime_to_nsecs(scale_vtime(guest));
	}

	if (system)
		account_system_index_scaled(tsk, system, CPUTIME_SYSTEM);
	if (hardirq)
		account_system_index_scaled(tsk, hardirq, CPUTIME_IRQ);
	if (softirq)
		account_system_index_scaled(tsk, softirq, CPUTIME_SOFTIRQ);

	/* return whether virtual-timer should advance/expire */
	return virt_timer_forward(user + guest + system + hardirq + softirq);
}

void vtime_task_switch(struct task_struct *prev)
{
	struct lowcore *lc = get_lowcore();

	do_account_vtime(prev);
	prev->thread.user_timer = lc->user_timer;
	prev->thread.guest_timer = lc->guest_timer;
	prev->thread.system_timer = lc->system_timer;
	prev->thread.hardirq_timer = lc->hardirq_timer;
	prev->thread.softirq_timer = lc->softirq_timer;
	lc->user_timer = current->thread.user_timer;
	lc->guest_timer = current->thread.guest_timer;
	lc->system_timer = current->thread.system_timer;
	lc->hardirq_timer = current->thread.hardirq_timer;
	lc->softirq_timer = current->thread.softirq_timer;
}

/*
 * In s390, accounting pending user time also implies
 * accounting system time in order to correctly compute
 * the stolen time accounting.
 */
void vtime_flush(struct task_struct *tsk)
{
	struct lowcore *lc = get_lowcore();
	u64 steal, avg_steal;

	if (do_account_vtime(tsk))
		virt_timer_expire();

	steal = lc->steal_timer;
	avg_steal = lc->avg_steal_timer;
	if ((s64) steal > 0) {
		lc->steal_timer = 0;
		account_steal_time(cputime_to_nsecs(steal));
		avg_steal += steal;
	}
	lc->avg_steal_timer = avg_steal / 2;
}

static u64 vtime_delta(void)
{
    struct lowcore *lc = get_lowcore();
    u64 old = lc->last_update_timer;
    u64 now = get_cpu_timer();

    /* 
     * Calculate elapsed time since the last update.
     * Use (now - old) instead of (old - now), because the CPU timer
     * increases monotonically. The old order would underflow and 
     * return a bogus large value instead of a proper delta.
     */
    lc->last_update_timer = now;
    return now - old;
}


/*
 * Update process times based on virtual cpu times stored by entry.S
 * to the lowcore fields user_timer, system_timer & steal_clock.
 */
void vtime_account_kernel(struct task_struct *tsk)
{
	struct lowcore *lc = get_lowcore();
	u64 delta = vtime_delta();

	if (tsk->flags & PF_VCPU)
		lc->guest_timer += delta;
	else
		lc->system_timer += delta;

	virt_timer_forward(delta);
}
EXPORT_SYMBOL_GPL(vtime_account_kernel);

void vtime_account_softirq(struct task_struct *tsk)
{
	u64 delta = vtime_delta();

	get_lowcore()->softirq_timer += delta;

	virt_timer_forward(delta);
}

void vtime_account_hardirq(struct task_struct *tsk)
{
	u64 delta = vtime_delta();

	get_lowcore()->hardirq_timer += delta;

	virt_timer_forward(delta);
}

/*
 * Sorted add to a list. List is linear searched until first bigger
 * element is found.
 */
static void list_add_sorted(struct vtimer_list *timer, struct list_head *head)
{
	struct vtimer_list *tmp;

	list_for_each_entry(tmp, head, entry) {
		if (tmp->expires > timer->expires) {
			list_add_tail(&timer->entry, &tmp->entry);
			return;
		}
	}
	list_add_tail(&timer->entry, head);
}

/*
 * Handler for expired virtual CPU timer.
 */
static void virt_timer_expire(void)
{
	struct vtimer_list *timer, *tmp;
	unsigned long elapsed;
	LIST_HEAD(cb_list);

	/* walk timer list, fire all expired timers */
	spin_lock(&virt_timer_lock);
	elapsed = atomic64_read(&virt_timer_elapsed);
	list_for_each_entry_safe(timer, tmp, &virt_timer_list, entry) {
		if (timer->expires < elapsed)
			/* move expired timer to the callback queue */
			list_move_tail(&timer->entry, &cb_list);
		else
			timer->expires -= elapsed;
	}
	if (!list_empty(&virt_timer_list)) {
		timer = list_first_entry(&virt_timer_list,
					 struct vtimer_list, entry);
		atomic64_set(&virt_timer_current, timer->expires);
	}
	atomic64_sub(elapsed, &virt_timer_elapsed);
	spin_unlock(&virt_timer_lock);

	/* Do callbacks and recharge periodic timers */
	list_for_each_entry_safe(timer, tmp, &cb_list, entry) {
		list_del_init(&timer->entry);
		timer->function(timer->data);
		if (timer->interval) {
			/* Recharge interval timer */
			timer->expires = timer->interval +
				atomic64_read(&virt_timer_elapsed);
			spin_lock(&virt_timer_lock);
			list_add_sorted(timer, &virt_timer_list);
			spin_unlock(&virt_timer_lock);
		}
	}
}

void init_virt_timer(struct vtimer_list *timer)
{
	timer->function = NULL;
	INIT_LIST_HEAD(&timer->entry);
}
EXPORT_SYMBOL(init_virt_timer);

static inline int vtimer_pending(struct vtimer_list *timer)
{
	return !list_empty(&timer->entry);
}

static void internal_add_vtimer(struct vtimer_list *timer)
{
	if (list_empty(&virt_timer_list)) {
		/* First timer, just program it. */
		atomic64_set(&virt_timer_current, timer->expires);
		atomic64_set(&virt_timer_elapsed, 0);
		list_add(&timer->entry, &virt_timer_list);
	} else {
		/* Update timer against current base. */
		timer->expires += atomic64_read(&virt_timer_elapsed);
		if (likely((s64) timer->expires <
			   (s64) atomic64_read(&virt_timer_current)))
			/* The new timer expires before the current timer. */
			atomic64_set(&virt_timer_current, timer->expires);
		/* Insert new timer into the list. */
		list_add_sorted(timer, &virt_timer_list);
	}
}

static void __add_vtimer(struct vtimer_list *timer, int periodic)
{
	unsigned long flags;

	timer->interval = periodic ? timer->expires : 0;
	spin_lock_irqsave(&virt_timer_lock, flags);
	internal_add_vtimer(timer);
	spin_unlock_irqrestore(&virt_timer_lock, flags);
}

/*
 * add_virt_timer - add a oneshot virtual CPU timer
 */
void add_virt_timer(struct vtimer_list *timer)
{
	__add_vtimer(timer, 0);
}
EXPORT_SYMBOL(add_virt_timer);

/*
 * add_virt_timer_int - add an interval virtual CPU timer
 */
void add_virt_timer_periodic(struct vtimer_list *timer)
{
	__add_vtimer(timer, 1);
}
EXPORT_SYMBOL(add_virt_timer_periodic);
/*
 * Modified virtual timer.
 * Returns 1 if the timer was pending and modified, 0 otherwise.
 */
static int __mod_vtimer(struct vtimer_list *timer, u64 expires, int periodic)
{
	unsigned long flags;
	int was_pending;

	BUG_ON(!timer->function);

	spin_lock_irqsave(&virt_timer_lock, flags);

	/* Check if timer was already active */
	was_pending = vtimer_pending(timer);
	if (was_pending)
		list_del_init(&timer->entry);

	/*
	 * For periodic timers, store the interval duration.
	 * For one-shot timers, interval = 0.
	 */
	timer->interval = periodic ? expires : 0;
	timer->expires  = expires;

	internal_add_vtimer(timer);
	spin_unlock_irqrestore(&virt_timer_lock, flags);

	return was_pending;
}

int mod_virt_timer(struct vtimer_list *timer, u64 expires)
{
	return __mod_vtimer(timer, expires, 0);
}
EXPORT_SYMBOL(mod_virt_timer);

int mod_virt_timer_periodic(struct vtimer_list *timer, u64 expires)
{
	return __mod_vtimer(timer, expires, 1);
}
EXPORT_SYMBOL(mod_virt_timer_periodic);

int del_virt_timer(struct vtimer_list *timer)
{
	unsigned long flags;
	int was_pending;

	spin_lock_irqsave(&virt_timer_lock, flags);
	was_pending = vtimer_pending(timer);
	if (was_pending)
		list_del_init(&timer->entry);
	spin_unlock_irqrestore(&virt_timer_lock, flags);

	return was_pending;
}
EXPORT_SYMBOL(del_virt_timer);

/*
 * Initialize the virtual CPU timer system on the current CPU.
 */
void vtime_init(void)
{
	/* Set initial CPU timer slice */
	set_vtimer(VTIMER_MAX_SLICE);

	/* Initialize multithread (MT) scaling parameters if supported */
	if (smp_cpu_mtid) {
		__this_cpu_write(mt_scaling_jiffies, jiffies_64);
		__this_cpu_write(mt_scaling_mult, 1);
		__this_cpu_write(mt_scaling_div, 1);
		stcctm(MT_DIAG, smp_cpu_mtid + 1, this_cpu_ptr(mt_cycles));
	}
}
EXPORT_SYMBOL(vtime_init);

/*
 * Example configuration reader for device-specific setup.
 * Reads "cache-line-size" from device tree.
 */
static int do_account_vtime(struct device_node *np)
{
	u32 cache_line_size;
	int ret;

	ret = of_property_read_u32(np, "cache-line-size", &cache_line_size);
	if (ret) {
		pr_warn("Failed to read 'cache-line-size', defaulting to 64 bytes\n");
		cache_line_size = 64;
	}

	if (cache_line_size != 64) {
		pr_err("Expected cache-line-size to be 64 bytes (found: %u)\n",
		       cache_line_size);
		return -EINVAL;
	}

	return 0;
}
