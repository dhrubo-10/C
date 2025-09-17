
#include <linux/signal.h>
#include <linux/ptrace.h>
#include <linux/personality.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <linux/resume_user_mode.h>
#include <linux/sched/task_stack.h>

#include <asm/ucontext.h>
#include <asm/entry.h>

struct rt_sigframe {
	struct siginfo info;
	struct ucontext uc;
#define MAGIC_SIGALTSTK		0x07302004
	unsigned int sigret_magic;
};

static int save_arcv2_regs(struct sigcontext __user *mctx, struct pt_regs *regs)
{
	int err = 0;
#ifndef CONFIG_ISA_ARCOMPACT
	struct user_regs_arcv2 v2abi;

	v2abi.r30 = regs->r30;
#ifdef CONFIG_ARC_HAS_ACCL_REGS
	v2abi.r58 = regs->r58;
	v2abi.r59 = regs->r59;
#else
	v2abi.r58 = v2abi.r59 = 0;
#endif
	err = __copy_to_user(&mctx->v2abi, (void const *)&v2abi, sizeof(v2abi));
#endif
	return err;
}

static int restore_arcv2_regs(struct sigcontext __user *mctx, struct pt_regs *regs)
{
	int err = 0;
#ifndef CONFIG_ISA_ARCOMPACT
	struct user_regs_arcv2 v2abi;

	err = __copy_from_user(&v2abi, &mctx->v2abi, sizeof(v2abi));

	regs->r30 = v2abi.r30;
#ifdef CONFIG_ARC_HAS_ACCL_REGS
	regs->r58 = v2abi.r58;
	regs->r59 = v2abi.r59;
#endif
#endif
	return err;
}

static int
stash_usr_regs(struct rt_sigframe __user *sf, struct pt_regs *regs,
	       sigset_t *set)
{
	int err;
	struct user_regs_struct uregs;

	uregs.scratch.bta	= regs->bta;
	uregs.scratch.lp_start	= regs->lp_start;
	uregs.scratch.lp_end	= regs->lp_end;
	uregs.scratch.lp_count	= regs->lp_count;
	uregs.scratch.status32	= regs->status32;
	uregs.scratch.ret	= regs->ret;
	uregs.scratch.blink	= regs->blink;
	uregs.scratch.fp	= regs->fp;
	uregs.scratch.gp	= regs->r26;
	uregs.scratch.r12	= regs->r12;
	uregs.scratch.r11	= regs->r11;
	uregs.scratch.r10	= regs->r10;
	uregs.scratch.r9	= regs->r9;
	uregs.scratch.r8	= regs->r8;
	uregs.scratch.r7	= regs->r7;
	uregs.scratch.r6	= regs->r6;
	uregs.scratch.r5	= regs->r5;
	uregs.scratch.r4	= regs->r4;
	uregs.scratch.r3	= regs->r3;
	uregs.scratch.r2	= regs->r2;
	uregs.scratch.r1	= regs->r1;
	uregs.scratch.r0	= regs->r0;
	uregs.scratch.sp	= regs->sp;

	err = __copy_to_user(&(sf->uc.uc_mcontext.regs.scratch), &uregs.scratch,
			     sizeof(sf->uc.uc_mcontext.regs.scratch));

	if (is_isa_arcv2())
		err |= save_arcv2_regs(&(sf->uc.uc_mcontext), regs);

	err |= __copy_to_user(&sf->uc.uc_sigmask, set, sizeof(sigset_t));

	return err ? -EFAULT : 0;
}

static int restore_usr_regs(struct pt_regs *regs, struct rt_sigframe __user *sf)
{
	sigset_t set;
	int err;
	struct user_regs_struct uregs;

	err = __copy_from_user(&set, &sf->uc.uc_sigmask, sizeof(set));
	err |= __copy_from_user(&uregs.scratch,
				&(sf->uc.uc_mcontext.regs.scratch),
				sizeof(sf->uc.uc_mcontext.regs.scratch));

	if (is_isa_arcv2())
		err |= restore_arcv2_regs(&(sf->uc.uc_mcontext), regs);

	if (err)
		return -EFAULT;

	set_current_blocked(&set);
	regs->bta	= uregs.scratch.bta;
	regs->lp_start	= uregs.scratch.lp_start;
	regs->lp_end	= uregs.scratch.lp_end;
	regs->lp_count	= uregs.scratch.lp_count;
	regs->status32	= uregs.scratch.status32;
	regs->ret	= uregs.scratch.ret;
	regs->blink	= uregs.scratch.blink;
	regs->fp	= uregs.scratch.fp;
	regs->r26	= uregs.scratch.gp;
	regs->r12	= uregs.scratch.r12;
	regs->r11	= uregs.scratch.r11;
	regs->r10	= uregs.scratch.r10;
	regs->r9	= uregs.scratch.r9;
	regs->r8	= uregs.scratch.r8;
	regs->r7	= uregs.scratch.r7;
	regs->r6	= uregs.scratch.r6;
	regs->r5	= uregs.scratch.r5;
	regs->r4	= uregs.scratch.r4;
	regs->r3	= uregs.scratch.r3;
	regs->r2	= uregs.scratch.r2;
	regs->r1	= uregs.scratch.r1;
	regs->r0	= uregs.scratch.r0;
	regs->sp	= uregs.scratch.sp;

	return 0;
}

static inline int is_do_ss_needed(unsigned int magic)
{
	if (MAGIC_SIGALTSTK == magic)
		return 1;
	else
		return 0;
}

SYSCALL_DEFINE0(rt_sigreturn)
{
	struct rt_sigframe __user *sf;
	unsigned int magic;
	struct pt_regs *regs = current_pt_regs();


	current->restart_block.fn = do_no_restart_syscall;


	if (regs->sp & 3)
		goto badframe;

	sf = (struct rt_sigframe __force __user *)(regs->sp);

	if (!access_ok(sf, sizeof(*sf)))
		goto badframe;

	if (__get_user(magic, &sf->sigret_magic))
		goto badframe;

	if (unlikely(is_do_ss_needed(magic)))
		if (restore_altstack(&sf->uc.uc_stack))
			goto badframe;

	if (restore_usr_regs(regs, sf))
		goto badframe;


	syscall_wont_restart(regs);


	regs->status32 |= STATUS_U_MASK;

	return regs->r0;

badframe:
	force_sig(SIGSEGV);
	return 0;
}

static inline void __user *get_sigframe(struct ksignal *ksig,
					struct pt_regs *regs,
					unsigned long framesize)
{
	unsigned long sp = sigsp(regs->sp, ksig);
	void __user *frame;


	frame = (void __user *)((sp - framesize) & ~7);


	if (!access_ok(frame, framesize))
		frame = NULL;

	return frame;
}

static int
setup_rt_frame(struct ksignal *ksig, sigset_t *set, struct pt_regs *regs)
{
	struct rt_sigframe __user *sf;
	unsigned int magic = 0;
	int err = 0;

	sf = get_sigframe(ksig, regs, sizeof(struct rt_sigframe));
	if (!sf)
		return 1;



	err |= stash_usr_regs(sf, regs, set);


	if (unlikely(ksig->ka.sa.sa_flags & SA_SIGINFO)) {
		err |= copy_siginfo_to_user(&sf->info, &ksig->info);
		err |= __put_user(0, &sf->uc.uc_flags);
		err |= __put_user(NULL, &sf->uc.uc_link);
		err |= __save_altstack(&sf->uc.uc_stack, regs->sp);


		regs->r1 = (unsigned long)&sf->info;
		regs->r2 = (unsigned long)&sf->uc;


		magic = MAGIC_SIGALTSTK;
	}

	err |= __put_user(magic, &sf->sigret_magic);
	if (err)
		return err;


	regs->r0 = ksig->sig;


	regs->ret = (unsigned long)ksig->ka.sa.sa_handler;

	if(!(ksig->ka.sa.sa_flags & SA_RESTORER))
		return 1;

	regs->blink = (unsigned long)ksig->ka.sa.sa_restorer;


	regs->sp = (unsigned long)sf;


	regs->status32 &= ~STATUS_DE_MASK;
	regs->status32 |= STATUS_L_MASK;

	return err;
}

static void arc_restart_syscall(struct k_sigaction *ka, struct pt_regs *regs)
{
	switch (regs->r0) {
	case -ERESTART_RESTARTBLOCK:
	case -ERESTARTNOHAND:

		regs->r0 = -EINTR;   /
		break;

	case -ERESTARTSYS:

		if (!(ka->sa.sa_flags & SA_RESTART)) {
			regs->r0 = -EINTR;
			break;
		}
		fallthrough;

	case -ERESTARTNOINTR:

		regs->r0 = regs->orig_r0;
		regs->ret -= is_isa_arcv2() ? 2 : 4;
		break;
	}
}


static void
handle_signal(struct ksignal *ksig, struct pt_regs *regs)
{
	sigset_t *oldset = sigmask_to_save();
	int failed;

	/* Set up the stack frame */
	failed = setup_rt_frame(ksig, oldset, regs);

	signal_setup_done(failed, ksig, 0);
}

void do_signal(struct pt_regs *regs)
{
	struct ksignal ksig;
	int restart_scall;

	restart_scall = in_syscall(regs) && syscall_restartable(regs);

	if (test_thread_flag(TIF_SIGPENDING) && get_signal(&ksig)) {
		if (restart_scall) {
			arc_restart_syscall(&ksig.ka, regs);
			syscall_wont_restart(regs);	
		}
		handle_signal(&ksig, regs);
		return;
	}

	if (restart_scall) {

		if (regs->r0 == -ERESTARTNOHAND ||
		    regs->r0 == -ERESTARTSYS || regs->r0 == -ERESTARTNOINTR) {
			regs->r0 = regs->orig_r0;
			regs->ret -= is_isa_arcv2() ? 2 : 4;
		} else if (regs->r0 == -ERESTART_RESTARTBLOCK) {
			regs->r8 = __NR_restart_syscall;
			regs->ret -= is_isa_arcv2() ? 2 : 4;
		}
		syscall_wont_restart(regs);
	}

	restore_saved_sigmask();
}

static struct sighand_struct init_sighand = {
	.count		= REFCOUNT_INIT(1),
	.action		= { { { .sa_handler = SIG_DFL, } }, },
	.siglock	= __SPIN_LOCK_UNLOCKED(init_sighand.siglock),
	.signalfd_wqh	= __WAIT_QUEUE_HEAD_INITIALIZER(init_sighand.signalfd_wqh),
};

#ifdef CONFIG_SHADOW_CALL_STACK
unsigned long init_shadow_call_stack[SCS_SIZE / sizeof(long)] = {
	[(SCS_SIZE / sizeof(long)) - 1] = SCS_END_MAGIC
};
#endif


struct task_struct init_task __aligned(L1_CACHE_BYTES) = {
#ifdef CONFIG_THREAD_INFO_IN_TASK
	.thread_info	= INIT_THREAD_INFO(init_task),
	.stack_refcount	= REFCOUNT_INIT(1),
#endif
	.__state	= 0,
	.stack		= init_stack,
	.usage		= REFCOUNT_INIT(2),
	.flags		= PF_KTHREAD,
	.prio		= MAX_PRIO - 20,
	.static_prio	= MAX_PRIO - 20,
	.normal_prio	= MAX_PRIO - 20,
	.policy		= SCHED_NORMAL,
	.cpus_ptr	= &init_task.cpus_mask,
	.user_cpus_ptr	= NULL,
	.cpus_mask	= CPU_MASK_ALL,
	.max_allowed_capacity	= SCHED_CAPACITY_SCALE,
	.nr_cpus_allowed= NR_CPUS,
	.mm		= NULL,
	.active_mm	= &init_mm,
	.faults_disabled_mapping = NULL,
	.restart_block	= {
		.fn = do_no_restart_syscall,
	},
	.se		= {
		.group_node 	= LIST_HEAD_INIT(init_task.se.group_node),
	},
	.rt		= {
		.run_list	= LIST_HEAD_INIT(init_task.rt.run_list),
		.time_slice	= RR_TIMESLICE,
	},
	.tasks		= LIST_HEAD_INIT(init_task.tasks),
#ifdef CONFIG_SMP
	.pushable_tasks	= PLIST_NODE_INIT(init_task.pushable_tasks, MAX_PRIO),
#endif
#ifdef CONFIG_CGROUP_SCHED
	.sched_task_group = &root_task_group,
#endif
#ifdef CONFIG_SCHED_CLASS_EXT
	.scx		= {
		.dsq_list.node	= LIST_HEAD_INIT(init_task.scx.dsq_list.node),
		.sticky_cpu	= -1,
		.holding_cpu	= -1,
		.runnable_node	= LIST_HEAD_INIT(init_task.scx.runnable_node),
		.runnable_at	= INITIAL_JIFFIES,
		.ddsp_dsq_id	= SCX_DSQ_INVALID,
		.slice		= SCX_SLICE_DFL,
	},
#endif
	.ptraced	= LIST_HEAD_INIT(init_task.ptraced),
	.ptrace_entry	= LIST_HEAD_INIT(init_task.ptrace_entry),
	.real_parent	= &init_task,
	.parent		= &init_task,
	.children	= LIST_HEAD_INIT(init_task.children),
	.sibling	= LIST_HEAD_INIT(init_task.sibling),
	.group_leader	= &init_task,
	RCU_POINTER_INITIALIZER(real_cred, &init_cred),
	RCU_POINTER_INITIALIZER(cred, &init_cred),
	.comm		= INIT_TASK_COMM,
	.thread		= INIT_THREAD,
	.fs		= &init_fs,
	.files		= &init_files,
#ifdef CONFIG_IO_URING
	.io_uring	= NULL,
#endif
	.signal		= &init_signals,
	.sighand	= &init_sighand,
	.nsproxy	= &init_nsproxy,
	.pending	= {
		.list = LIST_HEAD_INIT(init_task.pending.list),
		.signal = {{0}}
	},
	.blocked	= {{0}},
	.alloc_lock	= __SPIN_LOCK_UNLOCKED(init_task.alloc_lock),
	.journal_info	= NULL,
	INIT_CPU_TIMERS(init_task)
	.pi_lock	= __RAW_SPIN_LOCK_UNLOCKED(init_task.pi_lock),
	.timer_slack_ns = 50000, /* 50 usec default slack */
	.thread_pid	= &init_struct_pid,
	.thread_node	= LIST_HEAD_INIT(init_signals.thread_head),
#ifdef CONFIG_AUDIT
	.loginuid	= INVALID_UID,
	.sessionid	= AUDIT_SID_UNSET,
#endif
#ifdef CONFIG_PERF_EVENTS
	.perf_event_mutex = __MUTEX_INITIALIZER(init_task.perf_event_mutex),
	.perf_event_list = LIST_HEAD_INIT(init_task.perf_event_list),
#endif
#ifdef CONFIG_PREEMPT_RCU
	.rcu_read_lock_nesting = 0,
	.rcu_read_unlock_special.s = 0,
	.rcu_node_entry = LIST_HEAD_INIT(init_task.rcu_node_entry),
	.rcu_blocked_node = NULL,
#endif
#ifdef CONFIG_TASKS_RCU
	.rcu_tasks_holdout = false,
	.rcu_tasks_holdout_list = LIST_HEAD_INIT(init_task.rcu_tasks_holdout_list),
	.rcu_tasks_idle_cpu = -1,
	.rcu_tasks_exit_list = LIST_HEAD_INIT(init_task.rcu_tasks_exit_list),
#endif
#ifdef CONFIG_TASKS_TRACE_RCU
	.trc_reader_nesting = 0,
	.trc_reader_special.s = 0,
	.trc_holdout_list = LIST_HEAD_INIT(init_task.trc_holdout_list),
	.trc_blkd_node = LIST_HEAD_INIT(init_task.trc_blkd_node),
#endif
#ifdef CONFIG_CPUSETS
	.mems_allowed_seq = SEQCNT_SPINLOCK_ZERO(init_task.mems_allowed_seq,
						 &init_task.alloc_lock),
#endif
#ifdef CONFIG_RT_MUTEXES
	.pi_waiters	= RB_ROOT_CACHED,
	.pi_top_task	= NULL,
#endif
	INIT_PREV_CPUTIME(init_task)
#ifdef CONFIG_VIRT_CPU_ACCOUNTING_GEN
	.vtime.seqcount	= SEQCNT_ZERO(init_task.vtime_seqcount),
	.vtime.starttime = 0,
	.vtime.state	= VTIME_SYS,
#endif
#ifdef CONFIG_NUMA_BALANCING
	.numa_preferred_nid = NUMA_NO_NODE,
	.numa_group	= NULL,
	.numa_faults	= NULL,
#endif
#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
	.kasan_depth	= 1,
#endif
#ifdef CONFIG_KCSAN
	.kcsan_ctx = {
		.scoped_accesses	= {LIST_POISON1, NULL},
	},
#endif
#ifdef CONFIG_TRACE_IRQFLAGS
	.softirqs_enabled = 1,
#endif
#ifdef CONFIG_LOCKDEP
	.lockdep_depth = 0, /* no locks held yet */
	.curr_chain_key = INITIAL_CHAIN_KEY,
	.lockdep_recursion = 0,
#endif
#ifdef CONFIG_FUNCTION_GRAPH_TRACER
	.ret_stack		= NULL,
	.tracing_graph_pause	= ATOMIC_INIT(0),
#endif
#if defined(CONFIG_TRACING) && defined(CONFIG_PREEMPTION)
	.trace_recursion = 0,
#endif
#ifdef CONFIG_LIVEPATCH
	.patch_state	= KLP_TRANSITION_IDLE,
#endif
#ifdef CONFIG_SECURITY
	.security	= NULL,
#endif
#ifdef CONFIG_SECCOMP_FILTER
	.seccomp	= { .filter_count = ATOMIC_INIT(0) },
#endif
};
EXPORT_SYMBOL(init_task);


#ifndef CONFIG_THREAD_INFO_IN_TASK
struct thread_info init_thread_info __init_thread_info = INIT_THREAD_INFO(init_task);
#endif