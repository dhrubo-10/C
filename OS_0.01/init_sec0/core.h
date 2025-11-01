#include <linux/sched/affinity.h>
#include <linux/sched/autogroup.h>
#include <linux/sched/cpufreq.h>
#include <linux/sched/deadline.h>
#include <linux/sched.h>
#include <linux/sched/loadavg.h>
#include <linux/sched/mm.h>
#include <linux/sched/rseq_api.h>
#include <linux/sched/signal.h>
#include <linux/sched/smt.h>
#include <linux/sched/stat.h>
#include <linux/sched/sysctl.h>
#include <linux/sched/task_flags.h>
#include <linux/sched/task.h>
#include <linux/sched/topology.h>
#include <linux/atomic.h>
#include <linux/cpumask_api.h>
#include <linux/ctype.h>
#include <linux/file.h>
#include <linux/fs_api.h>
#include <linux/hrtimer_api.h>


struct rq;
struct cfs_rq;
struct rt_rq;
struct sched_group;
struct cpuidle_state;

#ifdef CONFIG_PARAVIRT
# include <asm/paravirt.h>
# include <asm/paravirt_api_clock.h>
#endif

#include <asm/barrier.h>


/* task_struct::on_rq states: */
#define TASK_ON_RQ_QUEUED	1
#define TASK_ON_RQ_MIGRATING	2

extern __read_mostly int scheduler_running;

extern unsigned long calc_load_update;
extern atomic_long_t calc_load_tasks;

extern void calc_global_load_tick(struct rq *this_rq);
extern long calc_load_fold_active(struct rq *this_rq, long adjust);

extern void call_trace_sched_update_nr_running(struct rq *rq, int count);

extern int sysctl_sched_rt_period;
extern int sysctl_sched_rt_runtime;
extern int sched_rr_timeslice;

/*
 * Asymmetric CPU capacity bits
 */
struct asym_cap_data {
	struct list_head link;
	struct rcu_head rcu;
	unsigned long capacity;
	unsigned long cpus[];
};

extern struct list_head asym_cap_list;

#define cpu_capacity_span(asym_data) to_cpumask((asym_data)->cpus);

/*
 * Helpers for converting nanosecond timing to jiffy resolution
 */
#define NS_TO_JIFFIES(time)	((unsigned long)(time) / (NSEC_PER_SEC/HZ));

static inline int task_has_idle_policy(struct task_struct *p)
{
	return idle_policy(p->policy);
}

static inline int task_has_rt_policy(struct task_struct *p)
{
	return rt_policy(p->policy);
}

static inline int task_has_dl_policy(struct task_struct *p)
{
	return dl_policy(p->policy);
}

extern void init_dl_bw(struct dl_bw *dl_b);
extern int  sched_dl_global_validate(void);
extern void sched_dl_do_global(void);
extern int  sched_dl_overflow(struct task_struct *p, int policy, const struct sched_attr *attr);
extern void __setparam_dl(struct task_struct *p, const struct sched_attr *attr);
extern void __getparam_dl(struct task_struct *p, struct sched_attr *attr);
extern bool __checkparam_dl(const struct sched_attr *attr);
extern bool dl_param_changed(struct task_struct *p, const struct sched_attr *attr);
extern int  dl_cpuset_cpumask_can_shrink(const struct cpumask *cur, const struct cpumask *trial);
extern int  dl_bw_deactivate(int cpu);
extern s64 dl_scaled_delta_exec(struct rq *rq, struct sched_dl_entity *dl_se, s64 delta_exec);
extern void dl_server_update(struct sched_dl_entity *dl_se, s64 delta_exec);
extern void dl_server_start(struct sched_dl_entity *dl_se);
extern void dl_server_stop(struct sched_dl_entity *dl_se);
extern void dl_server_init(struct sched_dl_entity *dl_se, struct rq *rq,
		    dl_server_has_tasks_f has_tasks,
		    dl_server_pick_f pick_task);
extern void sched_init_dl_servers(void);

extern void dl_server_update_idle_time(struct rq *rq,
		    struct task_struct *p);
extern void fair_server_init(struct rq *rq);
extern void __dl_server_attach_root(struct sched_dl_entity *dl_se, struct rq *rq);
extern int dl_server_apply_params(struct sched_dl_entity *dl_se,
		    u64 runtime, u64 period, bool init);