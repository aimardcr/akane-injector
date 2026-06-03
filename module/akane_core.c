/* akane core: module init/exit, the /dev/akane misc device, ioctl dispatch,
 * and helpers shared across concerns. */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/pid.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/miscdevice.h>
#include <linux/kprobes.h>

#include "akane.h"

unsigned long akane_kallsyms_lookup(const char *name)
{
	struct kprobe kp = { .symbol_name = name };
	unsigned long addr;

	if (register_kprobe(&kp) < 0)
		return 0;
	addr = (unsigned long)kp.addr;
	unregister_kprobe(&kp);
	return addr;
}

unsigned long akane_prot_to_vm(unsigned int prot)
{
	unsigned long vm = 0;

	if (prot & AKANE_PROT_READ)
		vm |= VM_READ | VM_MAYREAD;
	if (prot & AKANE_PROT_WRITE)
		vm |= VM_WRITE | VM_MAYWRITE;
	if (prot & AKANE_PROT_EXEC)
		vm |= VM_EXEC | VM_MAYEXEC;

	return vm;
}

struct task_struct *akane_get_task(pid_t pid)
{
	struct task_struct *task;

	if (pid == 0) {
		task = current;
		get_task_struct(task);
		return task;
	}

	rcu_read_lock();
	task = pid_task(find_vpid(pid), PIDTYPE_PID);
	if (task)
		get_task_struct(task);
	rcu_read_unlock();
	return task;
}

struct mm_struct *akane_get_target_mm(pid_t pid)
{
	struct task_struct *task = akane_get_task(pid);
	struct mm_struct *mm;

	if (!task)
		return NULL;
	mm = get_task_mm(task);
	put_task_struct(task);
	return mm;
}

bool akane_is_root(void)
{
	return uid_eq(current_uid(), GLOBAL_ROOT_UID);
}

struct akane_handler {
	unsigned int cmd;
	long (*fn)(unsigned long arg);
};

static const struct akane_handler akane_handlers[] = {
	{ AKANE_IOC_MEMORY_ALLOC,	    akane_memory_alloc_handle	      },
	{ AKANE_IOC_MEMORY_FREE,	    akane_memory_free_handle	      },
	{ AKANE_IOC_MEMORY_DETACH,	    akane_memory_detach_handle	      },
	{ AKANE_IOC_MEMORY_READ,	    akane_memory_read_handle	      },
	{ AKANE_IOC_MEMORY_WRITE,	    akane_memory_write_handle	      },
	{ AKANE_IOC_MEMORY_PROTECT,	    akane_memory_protect_handle	      },
	{ AKANE_IOC_MAPS_SET_ATTRS,	    akane_maps_set_attrs_handle	      },
	{ AKANE_IOC_MAPS_SET_PROCESS_FLAGS, akane_maps_set_process_flags_handle },
	{ AKANE_IOC_HIDE_ADD,		    akane_hide_add_handle	      },
	{ AKANE_IOC_HIDE_REMOVE,	    akane_hide_remove_handle	      },
	{ AKANE_IOC_ADD_TASK_WORK,	    akane_task_work_handle	      },
};

static long akane_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(akane_handlers); i++) {
		if (akane_handlers[i].cmd == cmd)
			return akane_handlers[i].fn(arg);
	}
	return -ENOTTY;
}

/* nonseekable_open() replaces the .llseek = no_llseek pattern dropped in 6.12. */
static int akane_open(struct inode *inode, struct file *filp)
{
	return nonseekable_open(inode, filp);
}

static const struct file_operations akane_fops = {
	.owner		= THIS_MODULE,
	.open		= akane_open,
	.unlocked_ioctl = akane_ioctl,
	.compat_ioctl	= akane_ioctl,
};

static struct miscdevice akane_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = "akane",
	.fops  = &akane_fops,
	.mode  = 0600,
};

static int __init akane_init(void)
{
	int ret;

	ret = akane_memory_init();
	if (ret)
		return ret;

	ret = akane_maps_init();
	if (ret)
		goto err_maps;

	ret = akane_task_work_init();
	if (ret)
		goto err_task_work;

	ret = akane_hide_init();
	if (ret)
		goto err_hide;

	ret = misc_register(&akane_dev);
	if (ret)
		goto err_misc;

	pr_info("akane: loaded, /dev/akane ready\n");
	return 0;

err_misc:
	akane_hide_exit();
err_hide:
	akane_task_work_exit();
err_task_work:
	akane_maps_exit();
err_maps:
	akane_memory_exit();
	return ret;
}

static void __exit akane_exit(void)
{
	misc_deregister(&akane_dev);
	akane_hide_exit();
	akane_task_work_exit();
	akane_maps_exit();
	akane_memory_exit();
	pr_info("akane: unloaded\n");
}

module_init(akane_init);
module_exit(akane_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Akane");
MODULE_DESCRIPTION("Kernel-side support for the akane shared-library injector");
