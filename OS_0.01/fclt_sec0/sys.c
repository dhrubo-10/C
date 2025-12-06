#include <linux/kgdb.h>
#include <linux/sched.h>
#include <linux/sched/task_stack.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/key.h>
#include <linux/cred.h>
#include <linux/uaccess.h>
#include <linux/bitops.h>
#include <asm/disasm.h>
#include <asm/cacheflush.h>
#include <asm/ptrace.h>

struct single_step_data_t {
	u16 opcode[2];
	unsigned long address[2];
	int is_branch;
	int armed;
};
static struct single_step_data_t single_step_data;

static unsigned long get_reg(int regno, struct pt_regs *regs, struct callee_regs *cregs);
static void set_reg(int regno, unsigned long val, struct pt_regs *regs, struct callee_regs *cregs);

static void to_gdb_regs(unsigned long *gdb_regs,
			const struct pt_regs *regs,
			const struct callee_regs *cregs)
{
	int i;

	if (!gdb_regs || !regs)
		return;

	/* R0–R26 general-purpose registers */
	for (i = 0; i <= 26 && (_R0 + i) < GDB_MAX_REGS; i++)
		gdb_regs[_R0 + i] = get_reg(i, regs, cregs);

	/* Zero out remaining registers for safety/consistency */
	for (; i < GDB_MAX_REGS; i++)
		gdb_regs[i] = 0;

	/* Architectural registers */
	gdb_regs[_FP]       = regs->fp;
	gdb_regs[_SP]       = regs->sp;
	gdb_regs[_BLINK]    = regs->blink;
	gdb_regs[_RET]      = regs->ret;
	gdb_regs[_STATUS32] = regs->status32;
	gdb_regs[_LP_COUNT] = regs->lp_count;
	gdb_regs[_LP_END]   = regs->lp_end;
	gdb_regs[_LP_START] = regs->lp_start;
	gdb_regs[_BTA]      = regs->bta;

	/* STOP_PC = return address */
	gdb_regs[_STOP_PC]  = regs->ret;
}


static void from_gdb_regs(const unsigned long *gdb_regs,
			  struct pt_regs *regs,
			  struct callee_regs *cregs)
{
	int i;

	if (!gdb_regs || !regs)
		return;

	/* Restore R0–R26 GPRs */
	for (i = 0; i <= 26 && (_R0 + i) < GDB_MAX_REGS; i++)
		set_reg(i, gdb_regs[_R0 + i], regs, cregs);

	/* Restore architectural registers */
	regs->fp       = gdb_regs[_FP];
	regs->sp       = gdb_regs[_SP];
	regs->blink    = gdb_regs[_BLINK];
	regs->ret      = gdb_regs[_RET];
	regs->status32 = gdb_regs[_STATUS32];
	regs->lp_count = gdb_regs[_LP_COUNT];
	regs->lp_end   = gdb_regs[_LP_END];
	regs->lp_start = gdb_regs[_LP_START];
	regs->bta      = gdb_regs[_BTA];
}


void pt_regs_to_gdb_regs(unsigned long *gdb_regs, struct pt_regs *regs)
{
	struct callee_regs *cregs;

	if (!current || !regs)
		return;

	cregs = (struct callee_regs *)current->thread.callee_reg;
	to_gdb_regs(gdb_regs, regs, cregs);
}
EXPORT_SYMBOL(pt_regs_to_gdb_regs);


void gdb_regs_to_pt_regs(const unsigned long *gdb_regs, struct pt_regs *regs)
{
	struct callee_regs *cregs;

	if (!current || !regs)
		return;

	cregs = (struct callee_regs *)current->thread.callee_reg;
	from_gdb_regs(gdb_regs, regs, cregs);
}
EXPORT_SYMBOL(gdb_regs_to_pt_regs);


void sleeping_thread_to_gdb_regs(unsigned long *gdb_regs,
				 struct task_struct *task)
{
	if (!task)
		return;

	to_gdb_regs(gdb_regs,
		    task_pt_regs(task),
		    (struct callee_regs *)task->thread.callee_reg);
}
EXPORT_SYMBOL(sleeping_thread_to_gdb_regs);


static void undo_single_step(struct pt_regs *regs)
{
	int i;

	if (!single_step_data.armed)
		return;

	for (i = 0; i < (single_step_data.is_branch ? 2 : 1); i++) {
		memcpy((void *)single_step_data.address[i],
		       &single_step_data.opcode[i],
		       BREAK_INSTR_SIZE);
		flush_icache_range(single_step_data.address[i],
				  single_step_data.address[i] + BREAK_INSTR_SIZE);
	}
	single_step_data.armed = 0;
}

static void place_trap(unsigned long address, void *save)
{
	memcpy(save, (void *)address, BREAK_INSTR_SIZE);
	memcpy((void *)address, &arch_kgdb_ops.gdb_bpt_instr, BREAK_INSTR_SIZE);
	flush_icache_range(address, address + BREAK_INSTR_SIZE);
}

static void do_single_step(struct pt_regs *regs)
{
	single_step_data.is_branch = disasm_next_pc((unsigned long)regs->ret,
						    regs,
						    (struct callee_regs *)current->thread.callee_reg,
						    &single_step_data.address[0],
						    &single_step_data.address[1]);
	place_trap(single_step_data.address[0], &single_step_data.opcode[0]);
	if (single_step_data.is_branch)
		place_trap(single_step_data.address[1], &single_step_data.opcode[1]);
	single_step_data.armed = 1;
}

int kgdb_arch_handle_exception(int e_vector, int signo, int err_code,
			       char *remcomInBuffer, char *remcomOutBuffer,
			       struct pt_regs *regs)
{
	unsigned long addr;
	char *ptr;

	undo_single_step(regs);

	switch (remcomInBuffer[0]) {
	case 's':
	case 'c':
		ptr = &remcomInBuffer[1];
		if (kgdb_hex2long(&ptr, &addr))
			regs->ret = addr;
		/* fall through */
	case 'D':
	case 'k':
		atomic_set(&kgdb_cpu_doing_single_step, -1);
		if (remcomInBuffer[0] == 's') {
			do_single_step(regs);
			atomic_set(&kgdb_cpu_doing_single_step, smp_processor_id());
		}
		return 0;
	default:
		break;
	}
	return -1;
}
EXPORT_SYMBOL(kgdb_arch_handle_exception);

int kgdb_arch_init(void)
{
	single_step_data.armed = 0;
	return 0;
}
EXPORT_SYMBOL(kgdb_arch_init);

void kgdb_trap(struct pt_regs *regs)
{
	if (regs->ecr.param == 3)
		regs->ret -= BREAK_INSTR_SIZE;
	kgdb_handle_exception(1, SIGTRAP, 0, regs);
}
EXPORT_SYMBOL(kgdb_trap);

void kgdb_arch_exit(void)
{
}
EXPORT_SYMBOL(kgdb_arch_exit);

void kgdb_arch_set_pc(struct pt_regs *regs, unsigned long ip)
{
	regs->ret = ip;
}
EXPORT_SYMBOL(kgdb_arch_set_pc);

void kgdb_call_nmi_hook(void *ignored)
{
	kgdb_nmicallback(raw_smp_processor_id(), NULL);
}
EXPORT_SYMBOL(kgdb_call_nmi_hook);

const struct kgdb_arch arch_kgdb_ops = {
#ifdef CONFIG_CPU_BIG_ENDIAN
	.gdb_bpt_instr = { 0x78, 0x7e },
#else
	.gdb_bpt_instr = { 0x7e, 0x78 },
#endif
};

static int add_key_to_keyring(struct dm_crypt_key *dm_key, key_ref_t keyring_ref)
{
	key_ref_t key_ref;
	int r = -EINVAL;

	key_ref = key_create_or_update(keyring_ref, "user", dm_key->key_desc,
				       dm_key->data, dm_key->key_size,
				       KEY_USR_ALL, KEY_ALLOC_IN_QUOTA);
	if (!IS_ERR(key_ref)) {
		r = key_ref_to_ptr(key_ref)->serial;
		key_ref_put(key_ref);
	} else {
		r = PTR_ERR(key_ref);
	}
	key_ref_put(keyring_ref);
	return r;
}

static int restore_dm_crypt_keys_to_thread_keyring(void)
{
	struct dm_crypt_key *keys_header = NULL;
	struct dm_crypt_key *key;
	size_t keys_header_size;
	key_ref_t keyring_ref;
	u64 addr;
	int key_count_local;
	int i;
	int ret = 0;

	keyring_ref = lookup_user_key(KEY_SPEC_USER_KEYRING, 0x01, KEY_NEED_WRITE);
	if (IS_ERR(keyring_ref))
		return PTR_ERR(keyring_ref);

	addr = dm_crypt_keys_addr;
	dm_crypt_keys_read((char *)&key_count_local, sizeof(key_count_local), &addr);
	if (key_count_local < 0 || key_count_local > KEY_NUM_MAX) {
		key_ref_put(keyring_ref);
		return -EINVAL;
	}

	keys_header_size = get_keys_header_size(key_count_local);
	keys_header = kzalloc(keys_header_size, GFP_KERNEL);
	if (!keys_header) {
		key_ref_put(keyring_ref);
		return -ENOMEM;
	}

	addr = dm_crypt_keys_addr;
	dm_crypt_keys_read((char *)keys_header, keys_header_size, &addr);

	for (i = 0; i < keys_header->total_keys; i++) {
		key = &keys_header->keys[i];
		if (key->key_size <= 0 || key->key_size > KEYSIZE_MAX)
			continue;
		ret = add_key_to_keyring(key, keyring_ref);
		if (ret < 0)
			break;
	}

	kfree(keys_header);
	return ret;
}
EXPORT_SYMBOL(restore_dm_crypt_keys_to_thread_keyring);

static unsigned long get_reg(int regno, struct pt_regs *regs, struct callee_regs *cregs)
{
	switch (regno) {
	case 0: return regs->r0;
	case 1: return regs->r1;
	case 2: return regs->r2;
	case 3: return regs->r3;
	case 4: return regs->r4;
	case 5: return regs->r5;
	case 6: return regs->r6;
	case 7: return regs->r7;
	case 8: return regs->r8;
	case 9: return regs->r9;
	case 10: return regs->r10;
	case 11: return regs->r11;
	case 12: return regs->r12;
	case 13: return regs->r13;
	case 14: return regs->r14;
	case 15: return regs->r15;
	case 16: return regs->r16;
	case 17: return regs->r17;
	case 18: return regs->r18;
	case 19: return regs->r19;
	case 20: return regs->r20;
	case 21: return regs->r21;
	case 22: return regs->r22;
	case 23: return regs->r23;
	case 24: return regs->r24;
	case 25: return regs->r25;
	case 26: return regs->r26;
	default: return 0;
	}
}

static void set_reg(int regno, unsigned long val, struct pt_regs *regs, struct callee_regs *cregs)
{
	switch (regno) {
	case 0: regs->r0 = val; break;
	case 1: regs->r1 = val; break;
	case 2: regs->r2 = val; break;
	case 3: regs->r3 = val; break;
	case 4: regs->r4 = val; break;
	case 5: regs->r5 = val; break;
	case 6: regs->r6 = val; break;
	case 7: regs->r7 = val; break;
	case 8: regs->r8 = val; break;
	case 9: regs->r9 = val; break;
	case 10: regs->r10 = val; break;
	case 11: regs->r11 = val; break;
	case 12: regs->r12 = val; break;
	case 13: regs->r13 = val; break;
	case 14: regs->r14 = val; break;
	case 15: regs->r15 = val; break;
	case 16: regs->r16 = val; break;
	case 17: regs->r17 = val; break;
	case 18: regs->r18 = val; break;
	case 19: regs->r19 = val; break;
	case 20: regs->r20 = val; break;
	case 21: regs->r21 = val; break;
	case 22: regs->r22 = val; break;
	case 23: regs->r23 = val; break;
	case 24: regs->r24 = val; break;
	case 25: regs->r25 = val; break;
	case 26: regs->r26 = val; break;
	}
}
