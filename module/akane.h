/*
 * akane: kernel-side support for the akane shared-library injector.
 *
 * The module is split into one translation unit per concern:
 *
 *	akane_core.c		/dev/akane, ioctl dispatch, shared helpers
 *	akane_memory.c		alloc/free/detach + read/write/protect in a target mm
 *	akane_maps.c		/proc/<pid>/maps perm-faking and per-mm filters
 *	akane_hide.c		hiding paths / modules / ports / flagged VMAs
 *	akane_task_work.c	redirect a target thread via task_work_add()
 *
 * This header declares only the symbols that cross those boundaries;
 * everything else is file-local. The ioctl ABI lives in akane_uapi.h.
 */
#ifndef _AKANE_H
#define _AKANE_H

#include <linux/kernel.h>
#include <linux/sched.h>
#include "akane_uapi.h"

/* Shared helpers (akane_core.c). */

/*
 * Resolve a non-exported kernel symbol via the register_kprobe() address
 * trick. Returns 0 on failure. Sleepable context only.
 */
unsigned long akane_kallsyms_lookup(const char *name);

/* Translate an AKANE_PROT_* mask to VM_R/W/X | VM_MAY*. */
unsigned long akane_prot_to_vm(unsigned int prot);

/*
 * pid == 0 means "the caller". akane_get_task() returns a task with a
 * reference held (release with put_task_struct); akane_get_target_mm()
 * returns its mm with a reference held (release with mmput). Both return
 * NULL on miss.
 */
struct task_struct *akane_get_task(pid_t pid);
struct mm_struct *akane_get_target_mm(pid_t pid);

/* True if the calling task is root; hide hooks bail in that case. */
bool akane_is_root(void);

/* AKANE_MEMORY (akane_memory.c). */

int akane_memory_init(void);
void akane_memory_exit(void);

long akane_memory_alloc_handle(unsigned long arg);
long akane_memory_free_handle(unsigned long arg);
long akane_memory_detach_handle(unsigned long arg);
long akane_memory_read_handle(unsigned long arg);
long akane_memory_write_handle(unsigned long arg);
long akane_memory_protect_handle(unsigned long arg);

/*
 * Accessors used by akane_maps.c to attach attributes to an existing
 * allocation without reaching into struct am_handle (kept opaque here).
 */
struct am_handle;
struct am_handle *akane_memory_find_handle(struct mm_struct *mm,
					   unsigned long addr);
int akane_memory_handle_set_name(struct am_handle *h,
				 const char __user *user_name, u32 len);
void *akane_memory_handle_spec(struct am_handle *h);

/* AKANE_MAPS (akane_maps.c). */

int akane_maps_init(void);
void akane_maps_exit(void);

long akane_maps_set_attrs_handle(unsigned long arg);
long akane_maps_set_process_flags_handle(unsigned long arg);

/*
 * Per-VMA mask registry. spec is the address of a vm_special_mapping we
 * own and serves as the registry key; flags is an AKANE_MAPS_* bitmap.
 * akane_memory.c registers/unregisters as allocations come and go.
 */
void akane_mask_register(void *spec, u32 flags);
void akane_mask_unregister(void *spec);

/*
 * HIDE_FROM_MEMORY queries used by the akane_hide.c memory hooks. The
 * _vma form is the fast path when the hook already holds the VMA; the
 * _addr form is for hooks that only have (mm, addr). Both false on miss.
 */
struct vm_area_struct;
bool akane_mask_vma_hidden_from_memory(struct vm_area_struct *vma);
bool akane_mask_addr_hidden_from_memory(struct mm_struct *mm,
					unsigned long addr);

/* AKANE_HIDE (akane_hide.c). */

int akane_hide_init(void);
void akane_hide_exit(void);

long akane_hide_add_handle(unsigned long arg);
long akane_hide_remove_handle(unsigned long arg);

/* AKANE_TASK_WORK (akane_task_work.c). */

int akane_task_work_init(void);
void akane_task_work_exit(void);
long akane_task_work_handle(unsigned long arg);

#endif /* _AKANE_H */
