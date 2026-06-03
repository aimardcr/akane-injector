/*
 * akane memory: alloc/free/detach + read/write/protect in a target mm.
 *
 * Each ALLOC owns a page array and vm_special_mapping, tracked live in the
 * am_handles xarray or, after DETACH, on the am_detached list (mapping
 * persists past controller exit).
 *
 * We mmgrab() (not mmget()) the target mm so the struct stays valid for the
 * pointer comparisons in akane_memory_find_handle() while letting the address
 * space die; mmget_not_zero() at free time tells us whether it did.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/pid.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/xarray.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#include <asm/tlb.h>
#endif

#include "akane.h"

#define AM_MAX_PAGES	65536			/* 256 MiB at 4K pages */
#define AM_MAX_SIZE	(AM_MAX_PAGES * PAGE_SIZE)
#define AM_RW_CHUNK	PAGE_SIZE

struct am_handle {
	u32 id;
	struct mm_struct *mm;		/* mmgrab'd; NULL if never installed */
	unsigned long addr;
	unsigned long size;
	unsigned int nr_pages;
	struct page **pages;		/* nr_pages + 1 entries, NULL-terminated */
	struct vm_special_mapping spec;
	char *name;			/* kstrdup'd backing for spec.name; may be NULL */
	struct list_head detached;	/* list link while orphaned */
};

static DEFINE_XARRAY_ALLOC1(am_handles);
static LIST_HEAD(am_detached);
static DEFINE_MUTEX(am_detached_lock);

/* kallsyms-resolved kernel internals. */

typedef struct vm_area_struct *(*install_special_mapping_fn)(
	struct mm_struct *mm,
	unsigned long addr, unsigned long len,
	unsigned long vm_flags,
	const struct vm_special_mapping *spec);

typedef int (*do_munmap_fn)(struct mm_struct *mm,
			    unsigned long start, size_t len,
			    struct list_head *uf);

typedef int (*access_process_vm_fn)(struct task_struct *tsk,
				    unsigned long addr,
				    void *buf, int len,
				    unsigned int gup_flags);

/*
 * Resolved via kallsyms, so the prototype must match the target kernel
 * exactly: 6.0 added the mmu_gather arg, 6.3 added the vma_iterator ahead of
 * it. A mismatch shifts every argument and mprotect_fixup returns -EINVAL.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
typedef int (*mprotect_fixup_fn)(struct vma_iterator *vmi,
				 struct mmu_gather *tlb,
				 struct vm_area_struct *vma,
				 struct vm_area_struct **pprev,
				 unsigned long start, unsigned long end,
				 unsigned long newflags);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
typedef int (*mprotect_fixup_fn)(struct mmu_gather *tlb,
				 struct vm_area_struct *vma,
				 struct vm_area_struct **pprev,
				 unsigned long start, unsigned long end,
				 unsigned long newflags);
#else
typedef int (*mprotect_fixup_fn)(struct vm_area_struct *vma,
				 struct vm_area_struct **pprev,
				 unsigned long start, unsigned long end,
				 unsigned long newflags);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
typedef void (*tlb_gather_mmu_fn)(struct mmu_gather *tlb, struct mm_struct *mm);
typedef void (*tlb_finish_mmu_fn)(struct mmu_gather *tlb);
#endif

static install_special_mapping_fn install_special_mapping_p;
static do_munmap_fn		  do_munmap_p;
static access_process_vm_fn	  access_process_vm_p;
static mprotect_fixup_fn	  mprotect_fixup_p;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
static tlb_gather_mmu_fn	  tlb_gather_mmu_p;
static tlb_finish_mmu_fn	  tlb_finish_mmu_p;
#endif

static __nocfi struct vm_area_struct *
call_install_special_mapping(struct mm_struct *mm,
			     unsigned long addr, unsigned long len,
			     unsigned long vm_flags,
			     const struct vm_special_mapping *spec)
{
	return install_special_mapping_p(mm, addr, len, vm_flags, spec);
}

static __nocfi int
call_do_munmap(struct mm_struct *mm, unsigned long start, size_t len,
	       struct list_head *uf)
{
	return do_munmap_p(mm, start, len, uf);
}

static __nocfi int
call_access_process_vm(struct task_struct *tsk, unsigned long addr,
		       void *buf, int len, unsigned int flags)
{
	return access_process_vm_p(tsk, addr, buf, len, flags);
}

static __nocfi int
call_mprotect_fixup(struct mm_struct *mm, struct vm_area_struct *vma,
		    struct vm_area_struct **pprev,
		    unsigned long start, unsigned long end,
		    unsigned long newflags)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	struct mmu_gather tlb;
	int ret;

	tlb_gather_mmu_p(&tlb, mm);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	{
		VMA_ITERATOR(vmi, mm, start);
		ret = mprotect_fixup_p(&vmi, &tlb, vma, pprev, start, end, newflags);
	}
#else
	ret = mprotect_fixup_p(&tlb, vma, pprev, start, end, newflags);
#endif
	tlb_finish_mmu_p(&tlb);
	return ret;
#else
	(void)mm;
	return mprotect_fixup_p(vma, pprev, start, end, newflags);
#endif
}

/*
 * Newer kernels set special_mapping_vmops.may_split = special_mapping_split,
 * which returns -EINVAL and blocks sub-range PROTECT (mprotect_fixup must split
 * the VMA). akane owns the mapping and its page array is pgoff-indexed, so the
 * split is safe: give akane's VMAs a private vm_ops copy with may_split cleared.
 * All other hooks are preserved; only mremap-time special-mapping identity is
 * lost, which a hidden payload never relies on. Before ~5.11 the hook (.split)
 * had no veto, so splitting already works there and this is a no-op.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
static struct vm_operations_struct akane_special_vmops;
static bool akane_special_vmops_ready;
#endif

static void akane_allow_vma_split(struct vm_area_struct *vma)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
	if (!vma->vm_ops)
		return;
	if (!akane_special_vmops_ready) {
		akane_special_vmops = *vma->vm_ops;
		akane_special_vmops.may_split = NULL;
		akane_special_vmops_ready = true;
	}
	vma->vm_ops = &akane_special_vmops;
#else
	(void)vma;
#endif
}

/*
 * Find an unmapped region of `len` bytes in `mm`. get_unmapped_area() works
 * on current->mm, not the target, so we walk the target's own VMA list.
 * Caller holds mmap_write_lock(mm). 6.1 moved VMA storage to a maple tree,
 * dropping mm->mmap/vma->vm_next in favour of for_each_vma().
 */
static unsigned long am_find_unmapped(struct mm_struct *mm, unsigned long len)
{
	struct vm_area_struct *vma;
	unsigned long candidate = PAGE_ALIGN(mm->mmap_base);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	{
		VMA_ITERATOR(vmi, mm, 0);
		for_each_vma(vmi, vma) {
#else
		for (vma = mm->mmap; vma; vma = vma->vm_next) {
#endif
			if (vma->vm_end <= candidate)
				continue;
			if (vma->vm_start >= candidate + len)
				return candidate;
			candidate = PAGE_ALIGN(vma->vm_end);
		}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	}
#endif
	if (candidate + len <= TASK_SIZE)
		return candidate;
	return -ENOMEM;
}

static bool am_range_is_free(struct mm_struct *mm,
			     unsigned long hint, unsigned long len)
{
	struct vm_area_struct *vma = find_vma(mm, hint);

	if (vma && vma->vm_start < hint + len)
		return false;
	return hint + len <= TASK_SIZE;
}

static struct am_handle *am_handle_new(unsigned int nr_pages)
{
	struct am_handle *h;
	unsigned int i;

	h = kzalloc(sizeof(*h), GFP_KERNEL);
	if (!h)
		return NULL;

	/* kvcalloc: array can reach 512 KiB (65536 page pointers). */
	h->pages = kvcalloc(nr_pages + 1, sizeof(*h->pages), GFP_KERNEL);
	if (!h->pages)
		goto fail_pages_arr;

	for (i = 0; i < nr_pages; i++) {
		h->pages[i] = alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (!h->pages[i])
			goto fail_pages;
	}
	h->pages[nr_pages] = NULL;
	h->nr_pages = nr_pages;
	return h;

fail_pages:
	while (i--)
		__free_page(h->pages[i]);
	kvfree(h->pages);
fail_pages_arr:
	kfree(h);
	return NULL;
}

static void am_handle_free(struct am_handle *h)
{
	unsigned int i;

	if (!h)
		return;
	akane_mask_unregister(&h->spec);
	if (h->mm)
		mmdrop(h->mm);
	if (h->pages) {
		for (i = 0; i < h->nr_pages; i++)
			if (h->pages[i])
				__free_page(h->pages[i]);
		kvfree(h->pages);
	}
	kfree(h->name);
	kfree(h);
}

static void am_handle_destroy(struct am_handle *h)
{
	if (h->mm && mmget_not_zero(h->mm)) {
		mmap_write_lock(h->mm);
		call_do_munmap(h->mm, h->addr, h->size, NULL);
		mmap_write_unlock(h->mm);
		mmput(h->mm);
	}
	am_handle_free(h);
}

static long am_create(pid_t pid, u32 prot, unsigned long size,
		      unsigned long hint_addr,
		      unsigned long *out_addr, u32 *out_id)
{
	struct mm_struct *mm;
	struct am_handle *h;
	struct vm_area_struct *vma;
	unsigned long addr;
	unsigned int nr_pages;
	long ret;

	if (!size || size > AM_MAX_SIZE || (size & ~PAGE_MASK))
		return -EINVAL;
	if (prot & ~AKANE_PROT_MASK)
		return -EINVAL;
	if (hint_addr & ~PAGE_MASK)
		return -EINVAL;

	nr_pages = size >> PAGE_SHIFT;

	mm = akane_get_target_mm(pid);
	if (!mm)
		return -ESRCH;

	h = am_handle_new(nr_pages);
	if (!h) {
		ret = -ENOMEM;
		goto out_mmput;
	}

	ret = xa_alloc(&am_handles, &h->id, h, xa_limit_31b, GFP_KERNEL);
	if (ret < 0)
		goto out_free_handle;

	h->spec.name  = NULL;
	h->spec.pages = h->pages;

	mmap_write_lock(mm);

	if (hint_addr) {
		if (!am_range_is_free(mm, hint_addr, size)) {
			ret = -ENOMEM;
			goto out_unlock;
		}
		addr = hint_addr;
	} else {
		addr = am_find_unmapped(mm, size);
		if (IS_ERR_VALUE(addr)) {
			ret = (long)addr;
			goto out_unlock;
		}
	}

	vma = call_install_special_mapping(mm, addr, size,
			akane_prot_to_vm(prot) | VM_DONTEXPAND | VM_DONTDUMP,
			&h->spec);
	if (IS_ERR(vma)) {
		ret = PTR_ERR(vma);
		goto out_unlock;
	}

	/* So a later PROTECT can narrow a sub-range (see akane_allow_vma_split). */
	akane_allow_vma_split(vma);

	mmap_write_unlock(mm);

	mmgrab(mm);
	h->mm	= mm;
	h->addr = addr;
	h->size = size;

	mmput(mm);

	/* Hidden by default; controller exposes it later via MAPS_SET_ATTRS. */
	akane_mask_register(&h->spec, AKANE_MAPS_HIDE_FROM_MEMORY);

	*out_addr = addr;
	*out_id   = h->id;

	pr_info("akane: memory_alloc id=%u %lu bytes at 0x%lx (pid=%d)\n",
		h->id, size, addr, pid ? pid : task_pid_vnr(current));
	return 0;

out_unlock:
	mmap_write_unlock(mm);
	xa_erase(&am_handles, h->id);
out_free_handle:
	am_handle_free(h);
out_mmput:
	mmput(mm);
	return ret;
}

long akane_memory_alloc_handle(unsigned long arg)
{
	struct akane_memory_alloc req;
	unsigned long addr = 0;
	u32 id = 0;
	long ret;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;

	ret = am_create(req.pid, req.prot,
			(unsigned long)req.size,
			(unsigned long)req.hint_addr,
			&addr, &id);
	if (ret)
		return ret;

	req.addr   = addr;
	req.handle = id;
	if (copy_to_user((void __user *)arg, &req, sizeof(req)))
		return -EFAULT;
	return 0;
}

long akane_memory_free_handle(unsigned long arg)
{
	struct akane_memory_handle req;
	struct am_handle *h;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;

	if (req.handle == 0 || req.handle > U32_MAX)
		return -EINVAL;

	h = xa_erase(&am_handles, (u32)req.handle);
	if (!h)
		return -ENOENT;

	pr_info("akane: memory_free id=%u 0x%lx (%lu bytes)\n",
		h->id, h->addr, h->size);
	am_handle_destroy(h);
	return 0;
}

/* DETACH: drop the kernel handle but leave the mapping in place. */
long akane_memory_detach_handle(unsigned long arg)
{
	struct akane_memory_handle req;
	struct am_handle *h;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;

	if (req.handle == 0 || req.handle > U32_MAX)
		return -EINVAL;

	h = xa_erase(&am_handles, (u32)req.handle);
	if (!h)
		return -ENOENT;

	mutex_lock(&am_detached_lock);
	list_add(&h->detached, &am_detached);
	mutex_unlock(&am_detached_lock);

	pr_info("akane: memory_detach id=%u 0x%lx (%lu bytes) -- mapping persists\n",
		h->id, h->addr, h->size);
	return 0;
}

/*
 * Chunk through a kernel bounce buffer. A short transfer (done < len) is not
 * an error and returns 0; -EFAULT only when zero bytes moved.
 */
static long am_rw(pid_t pid, unsigned long addr,
		  void __user *ubuf, unsigned long len,
		  bool write, unsigned long *out_done)
{
	struct task_struct *task;
	char *kbuf;
	unsigned long done = 0;
	unsigned int flags = write ? FOLL_WRITE : 0;
	long ret = 0;

	*out_done = 0;
	if (!len)
		return 0;
	if (len > INT_MAX)
		return -EINVAL;

	task = akane_get_task(pid);
	if (!task)
		return -ESRCH;

	kbuf = kmalloc(AM_RW_CHUNK, GFP_KERNEL);
	if (!kbuf) {
		put_task_struct(task);
		return -ENOMEM;
	}

	while (done < len) {
		size_t chunk = min_t(size_t, len - done, AM_RW_CHUNK);
		int moved;

		if (write && copy_from_user(kbuf, ubuf + done, chunk)) {
			ret = -EFAULT;
			break;
		}

		moved = call_access_process_vm(task, addr + done, kbuf,
					       (int)chunk, flags);
		if (moved <= 0) {
			if (done == 0)
				ret = -EFAULT;
			break;
		}

		if (!write && copy_to_user(ubuf + done, kbuf, moved)) {
			ret = -EFAULT;
			break;
		}

		done += moved;
		if ((size_t)moved < chunk)
			break;
	}

	kfree(kbuf);
	put_task_struct(task);
	*out_done = done;
	return ret;
}

static long am_rw_handle(unsigned long arg, bool write)
{
	struct akane_memory_io req;
	unsigned long done = 0;
	long ret;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;

	ret = am_rw((pid_t)req.pid,
		    (unsigned long)req.addr,
		    (void __user *)(unsigned long)req.buf,
		    (unsigned long)req.len,
		    write, &done);

	req.done = done;
	if (copy_to_user((void __user *)arg, &req, sizeof(req)))
		return -EFAULT;
	return ret;
}

long akane_memory_read_handle(unsigned long arg)
{
	return am_rw_handle(arg, false);
}

long akane_memory_write_handle(unsigned long arg)
{
	return am_rw_handle(arg, true);
}

/*
 * mprotect_fixup() against an arbitrary mm. The range must fit inside a single
 * VMA (the common loader case); mprotect_fixup() may split it at the boundary.
 */
static long am_protect(pid_t pid, unsigned int prot,
		       unsigned long addr, unsigned long len)
{
	struct mm_struct *mm;
	struct vm_area_struct *vma, *prev;
	unsigned long end, newflags;
	long ret;

	if (!len || (len & ~PAGE_MASK) || (addr & ~PAGE_MASK))
		return -EINVAL;
	if (prot & ~AKANE_PROT_MASK)
		return -EINVAL;
	end = addr + len;
	if (end < addr)
		return -EINVAL;

	mm = akane_get_target_mm(pid);
	if (!mm)
		return -ESRCH;

	mmap_write_lock(mm);

	vma = find_vma(mm, addr);
	if (!vma || vma->vm_start > addr) {
		ret = -ENOMEM;
		goto unlock;
	}
	if (end > vma->vm_end) {
		ret = -ERANGE;
		goto unlock;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	/* 6.1+ mprotect_fixup populates *pprev itself (vm_prev is gone). */
	prev = NULL;
#else
	prev = vma->vm_prev;
#endif
	newflags = (vma->vm_flags &
		    ~(VM_READ | VM_WRITE | VM_EXEC |
		      VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC)) |
		   akane_prot_to_vm(prot);

	ret = call_mprotect_fixup(mm, vma, &prev, addr, end, newflags);

unlock:
	mmap_write_unlock(mm);
	mmput(mm);

	if (!ret)
		pr_info("akane: memory_protect 0x%lx +%lu prot=0x%x pid=%d\n",
			addr, len, prot, pid ? pid : task_pid_vnr(current));
	return ret;
}

long akane_memory_protect_handle(unsigned long arg)
{
	struct akane_memory_protect req;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;

	return am_protect((pid_t)req.pid, req.prot,
			  (unsigned long)req.addr,
			  (unsigned long)req.len);
}

/* Accessors used by akane_maps.c. */

struct am_handle *akane_memory_find_handle(struct mm_struct *target_mm,
					   unsigned long addr)
{
	struct am_handle *h;
	unsigned long index;

	xa_for_each(&am_handles, index, h) {
		if (h->mm == target_mm &&
		    addr >= h->addr && addr < h->addr + h->size)
			return h;
	}

	mutex_lock(&am_detached_lock);
	list_for_each_entry(h, &am_detached, detached) {
		if (h->mm == target_mm &&
		    addr >= h->addr && addr < h->addr + h->size) {
			mutex_unlock(&am_detached_lock);
			return h;
		}
	}
	mutex_unlock(&am_detached_lock);
	return NULL;
}

int akane_memory_handle_set_name(struct am_handle *h,
				 const char __user *user_name, u32 len)
{
	char *new_name = NULL;

	if (user_name) {
		if (len == 0 || len > 4095)
			return -EINVAL;
		new_name = kzalloc(len + 1, GFP_KERNEL);
		if (!new_name)
			return -ENOMEM;
		if (copy_from_user(new_name, user_name, len)) {
			kfree(new_name);
			return -EFAULT;
		}
		new_name[len] = '\0';
	}

	/* Clear spec.name before freeing so a concurrent show_map_vma reader
	 * sees NULL, not a half-freed pointer. */
	h->spec.name = NULL;
	if (h->name) {
		kfree(h->name);
		h->name = NULL;
	}
	if (new_name) {
		h->name	     = new_name;
		h->spec.name = new_name;
	}
	return 0;
}

void *akane_memory_handle_spec(struct am_handle *h)
{
	return &h->spec;
}

int akane_memory_init(void)
{
	install_special_mapping_p = (install_special_mapping_fn)
		akane_kallsyms_lookup("_install_special_mapping");
	do_munmap_p = (do_munmap_fn)
		akane_kallsyms_lookup("do_munmap");
	access_process_vm_p = (access_process_vm_fn)
		akane_kallsyms_lookup("access_process_vm");
	mprotect_fixup_p = (mprotect_fixup_fn)
		akane_kallsyms_lookup("mprotect_fixup");

	if (!install_special_mapping_p || !do_munmap_p ||
	    !access_process_vm_p || !mprotect_fixup_p) {
		pr_err("akane: memory: failed to resolve a required symbol\n");
		return -ENOENT;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	/* Not EXPORT_SYMBOL'd on every kernel; resolve rather than link. */
	tlb_gather_mmu_p = (tlb_gather_mmu_fn)
		akane_kallsyms_lookup("tlb_gather_mmu");
	tlb_finish_mmu_p = (tlb_finish_mmu_fn)
		akane_kallsyms_lookup("tlb_finish_mmu");
	if (!tlb_gather_mmu_p || !tlb_finish_mmu_p) {
		pr_err("akane: memory: failed to resolve tlb_gather_mmu/tlb_finish_mmu\n");
		return -ENOENT;
	}
#endif
	return 0;
}

void akane_memory_exit(void)
{
	struct am_handle *h, *tmp;
	unsigned long index;

	xa_for_each(&am_handles, index, h) {
		xa_erase(&am_handles, index);
		am_handle_destroy(h);
	}
	xa_destroy(&am_handles);

	mutex_lock(&am_detached_lock);
	list_for_each_entry_safe(h, tmp, &am_detached, detached) {
		list_del(&h->detached);
		am_handle_destroy(h);
	}
	mutex_unlock(&am_detached_lock);
}
