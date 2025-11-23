#include <linux/capability.h>
#include <linux/msg.h>
#include <linux/spinlock.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/proc_fs.h>
#include <linux/list.h>
#include <linux/security.h>
#include <linux/sched/wake_q.h>
#include <linux/syscalls.h>
#include <linux/audit.h>
#include <linux/seq_file.h>
#include <linux/rwsem.h>
#include <linux/nsproxy.h>
#include <linux/ipc_namespace.h>
#include <linux/rhashtable.h>
#include <linux/percpu_counter.h>

#include <asm/current.h>
#include <linux/uaccess.h>

/* check this out/..~ */
struct msg_queue {
	struct kern_ipc_perm q_perm;
	time64_t q_stime;		/* last msgsnd time */
	time64_t q_rtime;		/* last msgrcv time */
	time64_t q_ctime;		/* last change time */
	unsigned long q_cbytes;		/* current number of bytes on queue */
	unsigned long q_qnum;		/* number of messages in queue */
	unsigned long q_qbytes;		/* max number of bytes on queue */
	struct pid *q_lspid;		/* pid of last msgsnd */
	struct pid *q_lrpid;		/* last receive pid */

	struct list_head q_messages;
	struct list_head q_receivers;
	struct list_head q_senders;
} __randomize_layout;


/* one msg_receiver structure for each sleeping receiver */
struct msg_receiver {
	struct list_head	r_list;
	struct task_struct	*r_tsk;

	int			r_mode;
	long			r_msgtype;
	long			r_maxsize;

	struct msg_msg		*r_msg;
};

/* one msg_sender for each sleeping sender */
struct msg_sender {
	struct list_head	list;
	struct task_struct	*tsk;
	size_t                  msgsz;
};

#define SEARCH_ANY		1
#define SEARCH_EQUAL		2
#define SEARCH_NOTEQUAL		3
#define SEARCH_LESSEQUAL	4
#define SEARCH_NUMBER		5

#define msg_ids(ns)	((ns)->ids[IPC_MSG_IDS])

static inline struct msg_queue *msq_obtain_object(struct ipc_namespace *ns, int id)
{
	struct kern_ipc_perm *ipcp = ipc_obtain_object_idr(&msg_ids(ns), id);

	if (IS_ERR(ipcp))
		return ERR_CAST(ipcp);

	return container_of(ipcp, struct msg_queue, q_perm);
}

static inline struct msg_queue *msq_obtain_object_check(struct ipc_namespace *ns,
							int id)
{
	struct kern_ipc_perm *ipcp = ipc_obtain_object_check(&msg_ids(ns), id);

	if (IS_ERR(ipcp))
		return ERR_CAST(ipcp);

	return container_of(ipcp, struct msg_queue, q_perm);
}

static inline void msg_rmid(struct ipc_namespace *ns, struct msg_queue *s)
{
	ipc_rmid(&msg_ids(ns), &s->q_perm);
}

static void msg_rcu_free(struct rcu_head *head)
{
	struct kern_ipc_perm *p = container_of(head, struct kern_ipc_perm, rcu);
	struct msg_queue *msq = container_of(p, struct msg_queue, q_perm);

	security_msg_queue_free(&msq->q_perm);
	kfree(msq);
}

static int newque(struct ipc_namespace *ns, struct ipc_params *params)
{
	struct msg_queue *msq;
	int retval;
	key_t key = params->key;
	int msgflg = params->flg;

	msq = kmalloc(sizeof(*msq), GFP_KERNEL_ACCOUNT);
	if (unlikely(!msq))
		return -ENOMEM;

	msq->q_perm.mode = msgflg & S_IRWXUGO;
	msq->q_perm.key = key;

	msq->q_perm.security = NULL;
	retval = security_msg_queue_alloc(&msq->q_perm);
	if (retval) {
		kfree(msq);
		return retval;
	}

	msq->q_stime = msq->q_rtime = 0;
	msq->q_ctime = ktime_get_real_seconds();
	msq->q_cbytes = msq->q_qnum = 0;
	msq->q_qbytes = ns->msg_ctlmnb;
	msq->q_lspid = msq->q_lrpid = NULL;
	INIT_LIST_HEAD(&msq->q_messages);
	INIT_LIST_HEAD(&msq->q_receivers);
	INIT_LIST_HEAD(&msq->q_senders);

	/* ipc_addid() locks msq upon success. */
	retval = ipc_addid(&msg_ids(ns), &msq->q_perm, ns->msg_ctlmni);
	if (retval < 0) {
		ipc_rcu_putref(&msq->q_perm, msg_rcu_free);
		return retval;
	}

	ipc_unlock_object(&msq->q_perm);
	rcu_read_unlock();

	return msq->q_perm.id;
}

static inline bool msg_fits_inqueue(struct msg_queue *msq, size_t msgsz)
{
	return msgsz + msq->q_cbytes <= msq->q_qbytes &&
		1 + msq->q_qnum <= msq->q_qbytes;
}
