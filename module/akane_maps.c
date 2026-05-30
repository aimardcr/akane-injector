/*
 * akane maps: control what /proc/<pid>/maps shows for a target.
 *
 * A single kretprobe on show_map_vma fakes the permission column for two
 * sets of VMAs, without touching the real page-table protection so the
 * target keeps running:
 *
 *	per-VMA registry	VMAs we created via MEMORY_ALLOC. The per-handle
 *				HIDE_FROM_MEMORY flag (set via MAPS_SET_ATTRS)
 *				masks R/W/X for that line.
 *	per-mm flags		AKANE_PROC_HIDE_RWX_ANON masks every anon W+X
 *				mapping in the target's mm (Frida trampolines).
 *
 * The pre-handler clears vm_flags, the print code reads the faked flags,
 * the return-handler restores them. The same HIDE_FROM_MEMORY bit also
 * gates the introspection blocking in akane_hide.c.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/pid.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "akane.h"

/*
 * vma->vm_flags became const in GKI 6.1+ (backported from upstream 6.3);
 * mutation has to go through the vm_flags_*() accessors. Earlier kernels
 * still allow direct assignment.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#define akane_vm_flags_clear(vma, flags) vm_flags_clear((vma), (flags))
#define akane_vm_flags_reset(vma, flags) vm_flags_reset((vma), (flags))
#else
#define akane_vm_flags_clear(vma, flags) ((vma)->vm_flags &= ~(flags))
#define akane_vm_flags_reset(vma, flags) ((vma)->vm_flags = (flags))
#endif

/* Per-VMA mask registry. */

struct akane_mask_entry {
	struct list_head link;
	void		*spec;		/* == &handle->spec; registry key */
	u32		flags;		/* AKANE_MAPS_* bitmap */
};

static LIST_HEAD(mask_list);
static DEFINE_SPINLOCK(mask_lock);

void akane_mask_register(void *spec, u32 flags)
{
	struct akane_mask_entry *e = kmalloc(sizeof(*e), GFP_KERNEL);

	if (!e)
		return;
	e->spec	 = spec;
	e->flags = flags;
	spin_lock(&mask_lock);
	list_add(&e->link, &mask_list);
	spin_unlock(&mask_lock);
}

void akane_mask_unregister(void *spec)
{
	struct akane_mask_entry *e, *tmp;

	spin_lock(&mask_lock);
	list_for_each_entry_safe(e, tmp, &mask_list, link) {
		if (e->spec == spec) {
			list_del(&e->link);
			spin_unlock(&mask_lock);
			kfree(e);
			return;
		}
	}
	spin_unlock(&mask_lock);
}

static void mask_set_flags(void *spec, u32 flags)
{
	struct akane_mask_entry *e;

	spin_lock(&mask_lock);
	list_for_each_entry(e, &mask_list, link) {
		if (e->spec == spec) {
			e->flags = flags;
			break;
		}
	}
	spin_unlock(&mask_lock);
}

static u32 mask_lookup_flags(void *spec)
{
	struct akane_mask_entry *e;
	u32 flags = 0;

	spin_lock(&mask_lock);
	list_for_each_entry(e, &mask_list, link) {
		if (e->spec == spec) {
			flags = e->flags;
			break;
		}
	}
	spin_unlock(&mask_lock);
	return flags;
}

bool akane_mask_vma_hidden_from_memory(struct vm_area_struct *vma)
{
	if (!vma)
		return false;
	return (mask_lookup_flags(vma->vm_private_data) &
		AKANE_MAPS_HIDE_FROM_MEMORY) != 0;
}

bool akane_mask_addr_hidden_from_memory(struct mm_struct *mm,
					unsigned long addr)
{
	struct am_handle *h;

	if (!mm)
		return false;
	h = akane_memory_find_handle(mm, addr);
	if (!h)
		return false;
	return (mask_lookup_flags(akane_memory_handle_spec(h)) &
		AKANE_MAPS_HIDE_FROM_MEMORY) != 0;
}

/*
 * Per-mm process flags. The mm is stored raw (no mmgrab): the entry leaks
 * if the mm dies, which is harmless -- lookup compares pointers, so a stale
 * entry matches no live VMA's vm_mm. Module exit reclaims it.
 */
struct akane_proc_entry {
	struct list_head  link;
	struct mm_struct *mm;
	u32		  flags;
};

static LIST_HEAD(proc_list);
static DEFINE_SPINLOCK(proc_lock);

static u32 proc_lookup_flags(struct mm_struct *mm)
{
	struct akane_proc_entry *e;
	u32 flags = 0;

	if (!mm)
		return 0;
	spin_lock(&proc_lock);
	list_for_each_entry(e, &proc_list, link) {
		if (e->mm == mm) {
			flags = e->flags;
			break;
		}
	}
	spin_unlock(&proc_lock);
	return flags;
}

static void proc_set_flags(struct mm_struct *mm, u32 flags)
{
	struct akane_proc_entry *e, *fresh;
	bool found = false;

	if (!mm)
		return;

	spin_lock(&proc_lock);
	list_for_each_entry(e, &proc_list, link) {
		if (e->mm == mm) {
			e->flags = flags;
			found = true;
			break;
		}
	}
	spin_unlock(&proc_lock);

	if (found)
		return;

	fresh = kmalloc(sizeof(*fresh), GFP_KERNEL);
	if (!fresh)
		return;
	fresh->mm    = mm;
	fresh->flags = flags;
	spin_lock(&proc_lock);
	list_add(&fresh->link, &proc_list);
	spin_unlock(&proc_lock);
}

/* kretprobe on show_map_vma (arm64: x0 = seq_file *, x1 = vm_area_struct *). */

struct mask_data {
	struct vm_area_struct *vma;
	unsigned long	       saved_flags;
	bool		       modified;
};

static int show_map_pre(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct mask_data *md = (struct mask_data *)ri->data;
	struct vm_area_struct *vma = (struct vm_area_struct *)regs->regs[1];
	u32 proc_flags;

	md->modified = false;
	md->vma	     = NULL;

	if (!vma)
		return 0;

	/* Path 1: VMA tracked in our per-VMA registry. */
	if (mask_lookup_flags(vma->vm_private_data) & AKANE_MAPS_HIDE_FROM_MEMORY) {
		md->vma		= vma;
		md->saved_flags = vma->vm_flags;
		akane_vm_flags_clear(vma, VM_READ | VM_WRITE | VM_EXEC);
		md->modified	= true;
		return 0;
	}

	/* Path 2: per-mm AKANE_PROC_HIDE_RWX_ANON on an anon W+X VMA. */
	proc_flags = proc_lookup_flags(vma->vm_mm);
	if ((proc_flags & AKANE_PROC_HIDE_RWX_ANON) &&
	    !vma->vm_file &&
	    (vma->vm_flags & (VM_WRITE | VM_EXEC)) == (VM_WRITE | VM_EXEC)) {
		md->vma		= vma;
		md->saved_flags = vma->vm_flags;
		akane_vm_flags_clear(vma, VM_READ | VM_WRITE | VM_EXEC);
		md->modified	= true;
	}
	return 0;
}

static int show_map_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct mask_data *md = (struct mask_data *)ri->data;

	if (md->modified && md->vma)
		akane_vm_flags_reset(md->vma, md->saved_flags);
	return 0;
}

static struct kretprobe show_map_kp = {
	.handler       = show_map_ret,
	.entry_handler = show_map_pre,
	.data_size     = sizeof(struct mask_data),
	.maxactive     = 0,
};

/* ioctl: SET_ATTRS / SET_PROCESS_FLAGS. */

long akane_maps_set_attrs_handle(unsigned long arg)
{
	struct akane_maps_set_attrs req;
	struct mm_struct *target_mm;
	struct am_handle *h;
	int rc;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;
	if (req.name_addr && (req.name_len == 0 || req.name_len > 4095))
		return -EINVAL;

	target_mm = akane_get_target_mm(req.pid);
	if (!target_mm)
		return -ESRCH;

	h = akane_memory_find_handle(target_mm, (unsigned long)req.addr);
	mmput(target_mm);
	if (!h)
		return -ENOENT;

	rc = akane_memory_handle_set_name(h,
			req.name_addr ?
				(const char __user *)(uintptr_t)req.name_addr :
				NULL,
			req.name_len);
	if (rc)
		return rc;

	mask_set_flags(akane_memory_handle_spec(h), req.flags);

	pr_info("akane: maps_set_attrs pid=%d addr=0x%llx flags=0x%x\n",
		req.pid, (unsigned long long)req.addr, req.flags);
	return 0;
}

long akane_maps_set_process_flags_handle(unsigned long arg)
{
	struct akane_maps_set_process_flags req;
	struct mm_struct *mm;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;

	mm = akane_get_target_mm(req.pid);
	if (!mm)
		return -ESRCH;

	proc_set_flags(mm, req.flags);
	mmput(mm);

	pr_info("akane: maps_set_process_flags pid=%d flags=0x%x\n",
		req.pid, req.flags);
	return 0;
}

/* Module-load init / unload teardown. */

int akane_maps_init(void)
{
	int ret;

	/* Fall back to show_map if the compiler inlined show_map_vma. */
	show_map_kp.kp.symbol_name = "show_map_vma";
	ret = register_kretprobe(&show_map_kp);
	if (ret == -ENOENT) {
		show_map_kp.kp.symbol_name = "show_map";
		ret = register_kretprobe(&show_map_kp);
	}
	if (ret) {
		pr_err("akane: maps: register_kretprobe failed: %d\n", ret);
		return ret;
	}
	pr_info("akane: maps: kretprobe on %s\n", show_map_kp.kp.symbol_name);
	return 0;
}

void akane_maps_exit(void)
{
	struct akane_mask_entry *e, *etmp;
	struct akane_proc_entry *p, *ptmp;

	unregister_kretprobe(&show_map_kp);

	spin_lock(&mask_lock);
	list_for_each_entry_safe(e, etmp, &mask_list, link) {
		list_del(&e->link);
		kfree(e);
	}
	spin_unlock(&mask_lock);

	spin_lock(&proc_lock);
	list_for_each_entry_safe(p, ptmp, &proc_list, link) {
		list_del(&p->link);
		kfree(p);
	}
	spin_unlock(&proc_lock);
}
