#ifndef _ARCH_S390_ENTRY_H
#define _ARCH_S390_ENTRY_H

#include <linux/list.h>
#include <linux/types.h>

/*
 * Structure representing a virtual timer.
 * Timers are linked in an ordered list and scheduled via virt_timer_expire().
 */
struct vtimer_list {
	struct list_head entry;          /* linked list entry */
	u64 expires;                     /* expiration time */
	u64 interval;                    /* interval for periodic timers */
	void (*function)(unsigned long); /* callback function */
	unsigned long data;              /* argument to callback */
};

/*
 * Lowcore structure (simplified version).
 * Contains per-CPU time accounting fields used in vtime logic.
 */
struct lowcore {
	u64 last_update_timer;
	u64 last_update_clock;
	u64 system_timer;
	u64 user_timer;
	u64 guest_timer;
	u64 hardirq_timer;
	u64 softirq_timer;
	u64 steal_timer;
	u64 avg_steal_timer;
};

/* Architecturespecific functions provided by assembly layer created by SD */
struct lowcore *get_lowcore(void);
u64 get_cpu_timer(void);
void set_vtimer(u64 expires);

/* Timer management API */
void init_virt_timer(struct vtimer_list *timer);
void add_virt_timer(struct vtimer_list *timer);
void add_virt_timer_periodic(struct vtimer_list *timer);
int mod_virt_timer(struct vtimer_list *timer, u64 expires);
int mod_virt_timer_periodic(struct vtimer_list *timer, u64 expires);
int del_virt_timer(struct vtimer_list *timer);
void vtime_init(void);

#endif /* _ARCH_S390_ENTRY_H */
