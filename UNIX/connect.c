
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

	/* Always make any pending restarted system calls return -EINTR */
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

	/* Don't restart from sigreturn */
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

		/* setup args 2 and 3 for user mode handler */
		regs->r1 = (unsigned long)&sf->info;
		regs->r2 = (unsigned long)&sf->uc;


		magic = MAGIC_SIGALTSTK;
	}

	err |= __put_user(magic, &sf->sigret_magic);
	if (err)
		return err;

	/* #1 arg to the user Signal handler */
	regs->r0 = ksig->sig;

	/* setup PC of user space signal handler */
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

		regs->r0 = -EINTR;   /* ERESTART_xxx is internal */
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

/*
 * OK, we're invoking a handler
 */
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
			syscall_wont_restart(regs);	/* No more restarts */
		}
		handle_signal(&ksig, regs);
		return;
	}

	if (restart_scall) {
		/* No handler for syscall: restart it */
		if (regs->r0 == -ERESTARTNOHAND ||
		    regs->r0 == -ERESTARTSYS || regs->r0 == -ERESTARTNOINTR) {
			regs->r0 = regs->orig_r0;
			regs->ret -= is_isa_arcv2() ? 2 : 4;
		} else if (regs->r0 == -ERESTART_RESTARTBLOCK) {
			regs->r8 = __NR_restart_syscall;
			regs->ret -= is_isa_arcv2() ? 2 : 4;
		}
		syscall_wont_restart(regs);	/* No more restarts */
	}

	restore_saved_sigmask();
}

void do_notify_resume(struct pt_regs *regs)
{

	if (test_thread_flag(TIF_NOTIFY_RESUME))
		resume_user_mode_work(regs);
}
