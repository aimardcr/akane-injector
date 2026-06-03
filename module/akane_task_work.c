/*
 * akane task_work: redirect a target thread to an arbitrary PC. Queues a
 * task_work callback that, on the thread's next return-to-userspace,
 * optionally snapshots pt_regs to the target's mm, then sets x0 = arg0 and
 * pc = pc. No userspace artifacts, no signal.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/pid.h>
#include <linux/slab.h>
#include <linux/task_work.h>
#include <linux/ptrace.h>

#include "akane.h"

struct akane_tw_work {
	struct callback_head head;
	unsigned long pc;
	unsigned long arg0;
	unsigned long saved_state_addr;	/* 0 = don't snapshot */
};

typedef int (*task_work_add_fn)(struct task_struct *task,
				struct callback_head *twork,
				enum task_work_notify_mode notify);

static task_work_add_fn task_work_add_p;

static __nocfi int call_task_work_add(struct task_struct *task,
				      struct callback_head *twork,
				      enum task_work_notify_mode notify)
{
	return task_work_add_p(task, twork, notify);
}

static void akane_tw_callback(struct callback_head *cb)
{
	struct akane_tw_work *w = container_of(cb, struct akane_tw_work, head);
	struct pt_regs *regs = task_pt_regs(current);

	/* Runs in the target's context, so copy_to_user hits its address space. */
	if (w->saved_state_addr) {
		if (copy_to_user((void __user *)w->saved_state_addr,
				 regs, sizeof(*regs)) != 0) {
			pr_err("akane: task_work failed to write saved state to 0x%lx (tid=%d)\n",
			       w->saved_state_addr, task_pid_vnr(current));
			goto done;
		}
	}

	regs->regs[0] = w->arg0;
	regs->pc      = w->pc;
	pr_info("akane: task_work hijacked tid=%d pc<-0x%lx x0=0x%lx state@0x%lx\n",
		task_pid_vnr(current), w->pc, w->arg0, w->saved_state_addr);

done:
	kfree(w);
}

long akane_task_work_handle(unsigned long arg)
{
	struct akane_task_work req;
	struct task_struct *task;
	struct akane_tw_work *w;
	long ret;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;

	if (!req.pc)
		return -EINVAL;

	task = akane_get_task(req.pid);
	if (!task)
		return -ESRCH;

	w = kzalloc(sizeof(*w), GFP_KERNEL);
	if (!w) {
		put_task_struct(task);
		return -ENOMEM;
	}

	init_task_work(&w->head, akane_tw_callback);
	w->pc		    = (unsigned long)req.pc;
	w->arg0		    = (unsigned long)req.arg0;
	w->saved_state_addr = (unsigned long)req.saved_state_addr;

	/* TWA_SIGNAL wakes a thread blocked in a sleeping syscall. */
	ret = call_task_work_add(task, &w->head, TWA_SIGNAL);
	put_task_struct(task);
	if (ret) {
		kfree(w);
		return ret;
	}

	pr_info("akane: task_work queued pid=%d pc=0x%llx x0=0x%llx state=0x%llx\n",
		req.pid,
		(unsigned long long)req.pc,
		(unsigned long long)req.arg0,
		(unsigned long long)req.saved_state_addr);
	return 0;
}

int akane_task_work_init(void)
{
	task_work_add_p = (task_work_add_fn)
		akane_kallsyms_lookup("task_work_add");
	if (!task_work_add_p) {
		pr_err("akane: task_work: cannot resolve task_work_add\n");
		return -ENOENT;
	}
	return 0;
}

void akane_task_work_exit(void) {}
