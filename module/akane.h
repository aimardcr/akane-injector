/* akane: kernel-side support for the shared-library injector. */
#ifndef _AKANE_H
#define _AKANE_H

#include <linux/kernel.h>
#include <linux/sched.h>
#include "akane_uapi.h"

/* akane_core.c. Resolves non-exported symbols; sleepable context only. */
unsigned long akane_kallsyms_lookup(const char *name);
unsigned long akane_prot_to_vm(unsigned int prot);

/* pid == 0 means the caller. Both hold a reference (put_task_struct/mmput). */
struct task_struct *akane_get_task(pid_t pid);
struct mm_struct *akane_get_target_mm(pid_t pid);

bool akane_is_root(void);

/* akane_memory.c */
int akane_memory_init(void);
void akane_memory_exit(void);

long akane_memory_alloc_handle(unsigned long arg);
long akane_memory_free_handle(unsigned long arg);
long akane_memory_detach_handle(unsigned long arg);
long akane_memory_read_handle(unsigned long arg);
long akane_memory_write_handle(unsigned long arg);
long akane_memory_protect_handle(unsigned long arg);

/* Accessors for akane_maps.c; struct am_handle stays opaque here. */
struct am_handle;
struct am_handle *akane_memory_find_handle(struct mm_struct *mm,
					   unsigned long addr);
int akane_memory_handle_set_name(struct am_handle *h,
				 const char __user *user_name, u32 len);
void *akane_memory_handle_spec(struct am_handle *h);

/* akane_maps.c */
int akane_maps_init(void);
void akane_maps_exit(void);

long akane_maps_set_attrs_handle(unsigned long arg);
long akane_maps_set_process_flags_handle(unsigned long arg);

/* Per-VMA mask registry, keyed by the vm_special_mapping address (spec). */
void akane_mask_register(void *spec, u32 flags);
void akane_mask_unregister(void *spec);

struct vm_area_struct;
bool akane_mask_vma_hidden_from_memory(struct vm_area_struct *vma);
bool akane_mask_addr_hidden_from_memory(struct mm_struct *mm,
					unsigned long addr);

/* akane_hide.c */
int akane_hide_init(void);
void akane_hide_exit(void);

long akane_hide_add_handle(unsigned long arg);
long akane_hide_remove_handle(unsigned long arg);

/* akane_task_work.c */
int akane_task_work_init(void);
void akane_task_work_exit(void);
long akane_task_work_handle(unsigned long arg);

#endif /* _AKANE_H */
