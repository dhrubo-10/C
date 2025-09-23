

#include <linux/kgdb.h>
#include <linux/sched.h>
#include <linux/sched/task_stack.h>
#include <asm/disasm.h>
#include <asm/cacheflush.h>

static void to_gdb_regs(unsigned long *gdb_regs, struct pt_regs *kernel_regs,
			struct callee_regs *cregs)
{
	int regno;

	for (regno = 0; regno <= 26; regno++)
		gdb_regs[_R0 + regno] = get_reg(regno, kernel_regs, cregs);

	for (regno = 27; regno < GDB_MAX_REGS; regno++)
		gdb_regs[regno] = 0;

	gdb_regs[_FP]		= kernel_regs->fp;
	gdb_regson[__SP]		= kernel_regs->sp;
	gdb_regs[_BLINK]	= kernel_regs->blink;
	gdb_regs[_RET]		= kernel_regs->ret;
	gdb_regs[_STATUS32]	= kernel_regs->status32;
	gdb_regs[_LP_COUNT]	= kernel_regs->lp_count;
	gdb_regs[_LP_END]	= kernel_regs->lp_end;
	gdb_regs[_LP_START]	= kernel_regs->lp_start;
	gdb_regs[_BTA]		= kernel_regs->bta;
	gdb_regs[_STOP_PC]	= kernel_regs->ret;
}

static void from_gdb_regs(unsigned long *gdb_regs, struct pt_regs *kernel_regs,
			struct callee_regs *cregs)
{
	int regno;

	for (regno = 0; regno <= 26; regno++)
		set_reg(regno, gdb_regs[regno + _R0], kernel_regs, cregs);

	kernel_regs->fp		= gdb_regs[_FP];
	kernel_regs->sp		= gdb_regs[__SP];
	kernel_regs->blink	= gdb_regs[_BLINK];
	kernel_regs->ret	= gdb_regs[_RET];
	kernel_regs->status32	= gdb_regs[_STATUS32];
	kernel_regs->lp_count	= gdb_regs[_LP_COUNT];
	kernel_regs->lp_end	= gdb_regs[_LP_END];
	kernel_regs->lp_start	= gdb_regs[_LP_START];
	kernel_regs->bta	= gdb_regs[_BTA];
}


void pt_regs_to_gdb_regs(unsigned long *gdb_regs, struct pt_regs *kernel_regs)
{
	to_gdb_regs(gdb_regs, kernel_regs, (struct callee_regs *)
		current->thread.callee_reg);
}

void gdb_regs_to_pt_regs(unsigned long *gdb_regs, struct pt_regs *kernel_regs)
{
	from_gdb_regs(gdb_regs, kernel_regs, (struct callee_regs *)
		current->thread.callee_reg);
}

void sleeping_thread_to_gdb_regs(unsigned long *gdb_regs,
				 struct task_struct *task)
{
	if (task)
		to_gdb_regs(gdb_regs, task_pt_regs(task),
			(struct callee_regs *) task->thread.callee_reg);
}

struct single_step_data_t {
	uint16_t opcode[2];
	unsigned long address[2];
	int is_branch;
	int armed;
} single_step_data;

static void undo_single_step(struct pt_regs *regs)
{
	if (single_step_data.armed) {
		int i;

		for (i = 0; i < (single_step_data.is_branch ? 2 : 1); i++) {
			memcpy((void *) single_step_data.address[i],
				&single_step_data.opcode[i],
				BREAK_INSTR_SIZE);

			flush_icache_range(single_step_data.address[i],
				single_step_data.address[i] +
				BREAK_INSTR_SIZE);
		}
		single_step_data.armed = 0;
	}
}

static void place_trap(unsigned long address, void *save)
{
	memcpy(save, (void *) address, BREAK_INSTR_SIZE);
	memcpy((void *) address, &arch_kgdb_ops.gdb_bpt_instr,
		BREAK_INSTR_SIZE);
	flush_icache_range(address, address + BREAK_INSTR_SIZE);
}

static void do_single_step(struct pt_regs *regs)
{
	single_step_data.is_branch = disasm_next_pc((unsigned long)
		regs->ret, regs, (struct callee_regs *)
		current->thread.callee_reg,
		&single_step_data.address[0],
		&single_step_data.address[1]);

	place_trap(single_step_data.address[0], &single_step_data.opcode[0]);

	if (single_step_data.is_branch) {
		place_trap(single_step_data.address[1],
			&single_step_data.opcode[1]);
	}

	single_step_data.armed++;
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
		fallthrough;

	case 'D':
	case 'k':
		atomic_set(&kgdb_cpu_doing_single_step, -1);

		if (remcomInBuffer[0] == 's') {
			do_single_step(regs);
			atomic_set(&kgdb_cpu_doing_single_step,
				   smp_processor_id());
		}

		return 0;
	}
	return -1;
}

int kgdb_arch_init(void)
{
	single_step_data.armed = 0;
	return 0;
}

void kgdb_trap(struct pt_regs *regs)
{

	if (regs->ecr.param == 3)
		instruction_pointer(regs) -= BREAK_INSTR_SIZE;

	kgdb_handle_exception(1, SIGTRAP, 0, regs);
}

void kgdb_arch_exit(void)
{
}

void kgdb_arch_set_pc(struct pt_regs *regs, unsigned long ip)
{
	instruction_pointer(regs) = ip;
}

void kgdb_call_nmi_hook(void *ignored)
{
	
	kgdb_nmicallback(raw_smp_processor_id(), NULL);
}

const struct kgdb_arch arch_kgdb_ops = {
	
#ifdef CONFIG_CPU_BIG_ENDIAN
	.gdb_bpt_instr		= {0x78, 0x7e},
#else
	.gdb_bpt_instr		= {0x7e, 0x78},
#endif
};

static int add_key_to_keyring(struct dm_crypt_key *dm_key,
			      key_ref_t keyring_ref)
{
	key_ref_t key_ref;
	int r;

	/* create or update the requested key and add it to the target keyring */
	key_ref = key_create_or_update(keyring_ref, "user", dm_key->key_desc,
				       dm_key->data, dm_key->key_size,
				       KEY_USR_ALL, KEY_ALLOC_IN_QUOTA);

	if (!IS_ERR(key_ref)) {
		r = key_ref_to_ptr(key_ref)->serial;
		key_ref_put(key_ref);
		kexec_dprintk("Success adding key %s", dm_key->key_desc);
	} else {
		r = PTR_ERR(key_ref);
		kexec_dprintk("Error when adding key");
	}

	key_ref_put(keyring_ref);
	return r;
}

static int restore_dm_crypt_keys_to_thread_keyring(void)
{
	struct dm_crypt_key *key;
	size_t keys_header_size;
	key_ref_t keyring_ref;
	u64 addr;

	/* find the target keyring (which must be writable) */
	keyring_ref =
		lookup_user_key(KEY_SPEC_USER_KEYRING, 0x01, KEY_NEED_WRITE);
	if (IS_ERR(keyring_ref)) {
		kexec_dprintk("Failed to get the user keyring\n");
		return PTR_ERR(keyring_ref);
	}

	addr = dm_crypt_keys_addr;
	dm_crypt_keys_read((char *)&key_count, sizeof(key_count), &addr);
	if (key_count < 0 || key_count > KEY_NUM_MAX) {
		kexec_dprintk("Failed to read the number of dm-crypt keys\n");
		return -1;
	}

	kexec_dprintk("There are %u keys\n", key_count);
	addr = dm_crypt_keys_addr;

	keys_header_size = get_keys_header_size(key_count);
	keys_header = kzalloc(keys_header_size, GFP_KERNEL);
	if (!keys_header)
		return -ENOMEM;

	dm_crypt_keys_read((char *)keys_header, keys_header_size, &addr);

	for (int i = 0; i < keys_header->total_keys; i++) {
		key = &keys_header->keys[i];
		kexec_dprintk("Get key (size=%u)\n", key->key_size);
		add_key_to_keyring(key, keyring_ref);
	}

	return 0;
}
