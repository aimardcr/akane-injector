#define _GNU_SOURCE
#include "inject.h"
#include "log.h"
#include "runtime.h"
#include "payload.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include "akane_uapi.h"
#include "akane_backend.h"

/* Bootstrap blob, embedded at link time. See bootstrap/bootstrap.S. */
extern char akane_bootstrap_start[];
extern char akane_bootstrap_end[];
extern char akane_init_runner[];

#define BOOT_REGION_SIZE   8192          /* 1 page code + 1 page saved_state */
#define BOOT_CODE_OFFSET   0
#define BOOT_STATE_OFFSET  4096
/* Offset within saved_state where the bootstrap writes the "done" flag.
 * Must match the offset hardcoded in bootstrap.S. */
#define BOOT_DONE_FLAG_OFF 512

struct boot_region {
	uint64_t base;
	uint64_t handle;
};

/* Read argv[0] from /proc/<pid>/cmdline (the package name on Android). */
static int read_cmdline(pid_t pid, char *out, size_t cap)
{
	char path[64];
	snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
	int fd = open(path, O_RDONLY);
	if (fd < 0) return -1;
	ssize_t n = read(fd, out, cap - 1);
	close(fd);
	if (n <= 0) return -1;
	out[n] = '\0';
	return 0;
}

/* Zero a target-side range that may be non-writable: page-align, flip each
 * page to RW, write zeros, restore. Best-effort; failures are logged.
 * `restore_prot` must match the wiped pages' original segment perms (RX for
 * all current callers, which wipe the first PT_LOAD of an Android .so). */
static void wipe_target_range(int akane_fd, pid_t target_pid,
                              uint64_t addr, uint64_t size,
                              uint32_t restore_prot, const char *what)
{
	if (!addr || !size) return;

	uint64_t page_start = addr & ~(uint64_t)0xFFF;
	uint64_t page_end   = (addr + size + 0xFFFULL) & ~(uint64_t)0xFFF;
	uint64_t page_len   = page_end - page_start;

	struct akane_memory_protect rw = {
		.pid  = target_pid,
		.prot = AKANE_PROT_READ | AKANE_PROT_WRITE,
		.addr = page_start,
		.len  = page_len,
	};
	if (ioctl(akane_fd, AKANE_IOC_MEMORY_PROTECT, &rw) < 0) {
		DETAIL("strip(%s): mem_protect RW failed (%s)", what, strerror(errno));
		return;
	}

	/* Stream zeros in PAGE_SIZE chunks. */
	static const unsigned char zeros[4096] = { 0 };
	uint64_t off = 0;
	while (off < size) {
		uint64_t this = size - off;
		if (this > sizeof(zeros)) this = sizeof(zeros);
		struct akane_memory_io w = {
			.pid  = target_pid,
			.addr = addr + off,
			.buf  = (uint64_t)(uintptr_t)zeros,
			.len  = this,
		};
		if (ioctl(akane_fd, AKANE_IOC_MEMORY_WRITE, &w) < 0 || w.done != this) {
			DETAIL("strip(%s): mem_write failed at +0x%llx (%s)",
			       what, (unsigned long long)off, strerror(errno));
			break;
		}
		off += this;
	}

	struct akane_memory_protect r = {
		.pid  = target_pid,
		.prot = restore_prot,
		.addr = page_start,
		.len  = page_len,
	};
	if (ioctl(akane_fd, AKANE_IOC_MEMORY_PROTECT, &r) < 0)
		DETAIL("strip(%s): mem_protect restore failed (%s)", what, strerror(errno));
	else
		DETAIL("stripped %s: 0x%llx +%llu", what,
		       (unsigned long long)addr, (unsigned long long)size);
}

enum elf_strip_phase {
	/* Pre-init: ELF header only. Unconditional; defeats \x7fELF magic scans. */
	ELF_STRIP_PRE_INIT,
	/* Post-init: .dynstr + .note.gnu.build-id (YARA targets). Gated on
	 * --hide-from-memory; payloads that re-introspect after init see empty. */
	ELF_STRIP_POST_INIT,
};

static void strip_elf_metadata(int akane_fd, pid_t target_pid,
                               const struct akane_payload_info *pl,
                               enum elf_strip_phase phase)
{
	const uint32_t rx = AKANE_PROT_READ | AKANE_PROT_EXEC;

	switch (phase) {
	case ELF_STRIP_PRE_INIT:
		wipe_target_range(akane_fd, target_pid,
		                  pl->base, 64, rx, "ELF header");
		break;
	case ELF_STRIP_POST_INIT:
		wipe_target_range(akane_fd, target_pid,
		                  pl->strip_dynstr_addr, pl->strip_dynstr_size,
		                  rx, ".dynstr");
		wipe_target_range(akane_fd, target_pid,
		                  pl->strip_buildid_addr, pl->strip_buildid_size,
		                  rx, ".note.gnu.build-id");
		break;
	}
}

/* Allocate the target-side boot region, write the bootstrap blob, RX the code page. */
static int setup_boot_region(int akane_fd, pid_t target_pid,
                             struct boot_region *out)
{
	size_t bs_size = (size_t)(akane_bootstrap_end - akane_bootstrap_start);
	if (bs_size == 0 || bs_size > 4096) {
		ERR("bootstrap blob size out of range (%zu)", bs_size);
		return -1;
	}

	struct akane_memory_alloc alloc_req = {
		.pid       = target_pid,
		.prot      = AKANE_PROT_READ | AKANE_PROT_WRITE | AKANE_PROT_EXEC,
		.size      = BOOT_REGION_SIZE,
	};
	if (ioctl(akane_fd, AKANE_IOC_MEMORY_ALLOC, &alloc_req) < 0) {
		ERR("alloc_mem(boot): %s", strerror(errno));
		return -1;
	}

	struct akane_memory_io wio = {
		.pid  = target_pid,
		.addr = alloc_req.addr + BOOT_CODE_OFFSET,
		.buf  = (uint64_t)(uintptr_t)akane_bootstrap_start,
		.len  = bs_size,
	};
	if (ioctl(akane_fd, AKANE_IOC_MEMORY_WRITE, &wio) < 0 || wio.done != bs_size) {
		ERR("mem_write(boot): %s (%llu/%zu)",
			strerror(errno), (unsigned long long)wio.done, bs_size);
		struct akane_memory_handle fr = { .handle = alloc_req.handle };
		ioctl(akane_fd, AKANE_IOC_MEMORY_FREE, &fr);
		return -1;
	}

	struct akane_memory_protect prot_req = {
		.pid  = target_pid,
		.prot = AKANE_PROT_READ | AKANE_PROT_EXEC,
		.addr = alloc_req.addr + BOOT_CODE_OFFSET,
		.len  = 4096,
	};
	if (ioctl(akane_fd, AKANE_IOC_MEMORY_PROTECT, &prot_req) < 0) {
		ERR("mem_protect(boot): %s", strerror(errno));
		struct akane_memory_handle fr = { .handle = alloc_req.handle };
		ioctl(akane_fd, AKANE_IOC_MEMORY_FREE, &fr);
		return -1;
	}

	out->base   = alloc_req.addr;
	out->handle = alloc_req.handle;
	DETAIL("bootstrap at 0x%llx (%zu bytes)",
	       (unsigned long long)alloc_req.addr, bs_size);
	return 0;
}

/* akane allocations are hidden by default, so the runtime/bootstrap regions
 * need no override. The payload is exposed by default (real perms + .so path,
 * as self-introspecting payloads like the Frida gadget expect);
 * --hide-from-memory leaves it hidden like the rest. */
static void apply_visibility(int akane_fd, pid_t target_pid,
                             uint64_t payload_base,
                             const char *so_path, int hide_from_memory)
{
	const char *payload_name = hide_from_memory ? NULL : so_path;
	uint32_t payload_flags   = hide_from_memory ? AKANE_MAPS_HIDE_FROM_MEMORY : 0;

	struct akane_maps_set_attrs attrs = {
		.pid       = target_pid,
		.flags     = payload_flags,
		.addr      = payload_base,
		.name_addr = (uint64_t)(uintptr_t)payload_name,
		.name_len  = payload_name ? (uint32_t)strlen(payload_name) : 0,
	};
	if (ioctl(akane_fd, AKANE_IOC_MAPS_SET_ATTRS, &attrs) < 0) {
		ERR("set_attrs: %s", strerror(errno));
	} else {
		DETAIL("payload visibility: name=%s perms=%s",
		       payload_name ? payload_name : "(hidden)",
		       payload_flags ? "masked, hidden from memory" : "real");
	}
}

/* Redirect the payload's dl* GOT slots to the runtime hooks. The GOT page is
 * RO post-RELRO, so flip to RW, write, flip back. */
static void patch_got_slots(int akane_fd, pid_t target_pid,
                            const struct akane_payload_info *pl,
                            const struct akane_runtime_info *rt)
{
	struct {
		const char *name;
		uint64_t    got;
		uint64_t    hook;
	} patches[] = {
		{ "dl_iterate_phdr", pl->got_dl_iterate_phdr, rt->hook_dl_iterate_phdr },
		{ "dladdr",          pl->got_dladdr,          rt->hook_dladdr          },
		{ "dlopen",          pl->got_dlopen,          rt->hook_dlopen          },
		{ "dlsym",           pl->got_dlsym,           rt->hook_dlsym           },
		{ "dlclose",         pl->got_dlclose,         rt->hook_dlclose         },
		{ "dlerror",         pl->got_dlerror,         rt->hook_dlerror         },
	};
	const size_t n = sizeof(patches) / sizeof(patches[0]);

	int patched = 0;
	for (size_t i = 0; i < n; i++) {
		if (!patches[i].got || !patches[i].hook) continue;

		uint64_t got_page = patches[i].got & ~(uint64_t)0xFFF;
		struct akane_memory_protect rw = {
			.pid  = target_pid,
			.prot = AKANE_PROT_READ | AKANE_PROT_WRITE,
			.addr = got_page,
			.len  = 4096,
		};
		if (ioctl(akane_fd, AKANE_IOC_MEMORY_PROTECT, &rw) < 0) continue;

		struct akane_memory_io w = {
			.pid  = target_pid,
			.addr = patches[i].got,
			.buf  = (uint64_t)(uintptr_t)&patches[i].hook,
			.len  = sizeof(uint64_t),
		};
		if (ioctl(akane_fd, AKANE_IOC_MEMORY_WRITE, &w) == 0
		    && w.done == sizeof(uint64_t))
			patched++;

		struct akane_memory_protect r = {
			.pid  = target_pid,
			.prot = AKANE_PROT_READ,
			.addr = got_page,
			.len  = 4096,
		};
		ioctl(akane_fd, AKANE_IOC_MEMORY_PROTECT, &r);
	}
	DETAIL("hooks: %d/%zu planted", patched, n);
}

/* Register the payload in the runtime's globals (slot 0; each invocation gets
 * a fresh runtime instance). Their .data is RW, so we mem_write directly. */
static void write_payload_registry(int akane_fd, pid_t target_pid,
                                   const struct akane_payload_info *pl,
                                   const struct akane_runtime_info *rt,
                                   const char *so_path)
{
	struct akane_rt_payload_entry entry = {
		.base  = pl->base,
		.size  = pl->map_size,
		.phdr  = pl->phdr_target,
		.phnum = pl->phnum,
	};
	struct akane_memory_io w_entry = {
		.pid  = target_pid,
		.addr = rt->payloads_addr,
		.buf  = (uint64_t)(uintptr_t)&entry,
		.len  = sizeof(entry),
	};
	ioctl(akane_fd, AKANE_IOC_MEMORY_WRITE, &w_entry);

	size_t name_len = strlen(so_path) + 1;
	if (name_len > AKANE_RT_NAME_LEN) name_len = AKANE_RT_NAME_LEN;
	struct akane_memory_io w_name = {
		.pid  = target_pid,
		.addr = rt->names_addr,
		.buf  = (uint64_t)(uintptr_t)so_path,
		.len  = name_len,
	};
	ioctl(akane_fd, AKANE_IOC_MEMORY_WRITE, &w_name);

	int32_t one = 1;
	struct akane_memory_io w_count = {
		.pid  = target_pid,
		.addr = rt->count_addr,
		.buf  = (uint64_t)(uintptr_t)&one,
		.len  = sizeof(one),
	};
	ioctl(akane_fd, AKANE_IOC_MEMORY_WRITE, &w_count);

	DETAIL("registered as payload[0]");
}

/* Plant the runtime function's VA at saved_state+424 so akane_init_runner
 * calls it before iterating init_array (+424 clears the init_info triple at
 * +384..+408 and the tid slot at +408..+416). */
static void arm_linker_register(int akane_fd, pid_t target_pid,
                                const struct boot_region *boot,
                                uint64_t linker_register_fn)
{
	uint64_t slot = boot->base + BOOT_STATE_OFFSET + 424ULL;
	struct akane_memory_io w_lr = {
		.pid  = target_pid,
		.addr = slot,
		.buf  = (uint64_t)(uintptr_t)&linker_register_fn,
		.len  = sizeof(linker_register_fn),
	};
	if (ioctl(akane_fd, AKANE_IOC_MEMORY_WRITE, &w_lr) == 0
	    && w_lr.done == sizeof(linker_register_fn))
		DETAIL("solist registration: arming akane_rt_linker_register at 0x%llx",
		       (unsigned long long)linker_register_fn);
	else
		ERR("solist registration: mem_write failed (%s)",
		    strerror(errno));
}

/* Plant the (init_array_addr, count, pthread_create_addr) triple at
 * saved_state+384 -- the contract bootstrap.S reads on entry. The kernel
 * writes pt_regs only at +0; the rest of the buffer is ours. */
static int plant_init_info(int akane_fd, pid_t target_pid,
                           const struct boot_region *boot,
                           const struct akane_payload_info *pl)
{
	uint64_t init_info[3] = {
		pl->init_array_target,
		pl->init_array_count,
		pl->pthread_create_target,
	};
	struct akane_memory_io w_init = {
		.pid  = target_pid,
		.addr = boot->base + BOOT_STATE_OFFSET + 384ULL,
		.buf  = (uint64_t)(uintptr_t)&init_info,
		.len  = sizeof(init_info),
	};
	if (ioctl(akane_fd, AKANE_IOC_MEMORY_WRITE, &w_init) < 0
	    || w_init.done != sizeof(init_info)) {
		ERR("mem_write init_info: %s", strerror(errno));
		return -1;
	}
	return 0;
}

static int submit_task_work(int akane_fd, pid_t target_pid,
                            const struct boot_region *boot)
{
	uint64_t saved_state_base = boot->base + BOOT_STATE_OFFSET;
	struct akane_task_work tw_req = {
		.pid              = target_pid,
		.pc               = boot->base + BOOT_CODE_OFFSET,
		.arg0             = saved_state_base,
		.saved_state_addr = saved_state_base,
	};
	if (ioctl(akane_fd, AKANE_IOC_ADD_TASK_WORK, &tw_req) < 0) {
		ERR("task_work: %s", strerror(errno));
		return -1;
	}
	return 0;
}

/* Poll the bootstrap's done flag at saved_state+512 (5s timeout). */
static uint8_t wait_for_done_flag(int akane_fd, pid_t target_pid,
                                  const struct boot_region *boot)
{
	uint64_t flag_addr = boot->base + BOOT_STATE_OFFSET + BOOT_DONE_FLAG_OFF;
	uint8_t flag = 0;
	for (int i = 0; i < 50; i++) {
		struct akane_memory_io rio = {
			.pid  = target_pid,
			.addr = flag_addr,
			.buf  = (uint64_t)(uintptr_t)&flag,
			.len  = 1,
		};
		if (ioctl(akane_fd, AKANE_IOC_MEMORY_READ, &rio) == 0 && flag)
			break;
		usleep(100000);
	}
	return flag;
}

/* Detach rather than free: the bootstrap's worker thread keeps running
 * init_runner from this blob, so the mapping must outlive the controller. */
static void detach_boot(int akane_fd, const struct boot_region *boot)
{
	struct akane_memory_handle dt = { .handle = boot->handle };
	ioctl(akane_fd, AKANE_IOC_MEMORY_DETACH, &dt);
}

/* Diagnostic: did the payload invoke our dl* hooks? Retries so we catch the
 * counters before the target is reaped. */
static void log_hook_call_counts(int akane_fd, pid_t target_pid,
                                 uint64_t call_counts_addr)
{
	if (!call_counts_addr) {
		DETAIL("hook calls: counter symbol missing (stale runtime?)");
		return;
	}

	uint64_t cc[6] = {0};
	int read_ok = 0;
	for (int i = 0; i < 20; i++) {
		usleep(50000);   /* 1s window */
		struct akane_memory_io rio = {
			.pid  = target_pid,
			.addr = call_counts_addr,
			.buf  = (uint64_t)(uintptr_t)cc,
			.len  = sizeof(cc),
		};
		if (ioctl(akane_fd, AKANE_IOC_MEMORY_READ, &rio) != 0)
			break;
		read_ok = 1;
		if (cc[0] || cc[1] || cc[2] || cc[3] || cc[4] || cc[5])
			break;
	}
	if (read_ok)
		DETAIL("hook calls: dl_iterate_phdr=%llu dladdr=%llu dlopen=%llu dlsym=%llu dlclose=%llu dlerror=%llu",
		       (unsigned long long)cc[0], (unsigned long long)cc[1],
		       (unsigned long long)cc[2], (unsigned long long)cc[3],
		       (unsigned long long)cc[4], (unsigned long long)cc[5]);
	else
		DETAIL("hook calls: mem_read failed (%s)", strerror(errno));
}

/* Mirror of struct akane_linker_state's prefix (layout controlled on both sides). */
struct linker_state_mirror {
	uint32_t version;
	uint32_t flags;
	char     linker_path[256];
	uint64_t linker_load_bias;
	uint64_t solist_addr;
	uint64_t somain_addr;
	uint64_t sonext_addr;
	uint64_t dl_mutex_addr;
	uint64_t solist_value;
	uint64_t somain_value;
	uint64_t sonext_value;
	uint8_t  somain_buf[256];
	struct {
		uint16_t base, size, phdr, phnum, dynamic;
		uint16_t strtab, symtab, bias, strsz, next;
	} offsets;
};

static void log_linker_state(int akane_fd, pid_t target_pid,
                             uint64_t linker_state_addr)
{
	struct linker_state_mirror ls = {0};
	struct akane_memory_io rio = {
		.pid  = target_pid,
		.addr = linker_state_addr,
		.buf  = (uint64_t)(uintptr_t)&ls,
		.len  = sizeof(ls),
	};
	if (ioctl(akane_fd, AKANE_IOC_MEMORY_READ, &rio) != 0) {
		DETAIL("linker state: read failed (%s)", strerror(errno));
		return;
	}
	if (ls.version == 0) {
		DETAIL("linker state: discovery never ran (version=0)");
		return;
	}

	ls.linker_path[sizeof(ls.linker_path) - 1] = '\0';
	DETAIL("linker: %s @ load_bias 0x%llx",
	       ls.linker_path,
	       (unsigned long long)ls.linker_load_bias);
	DETAIL("  flags=0x%x (resolved=%d base_off=%d)",
	       ls.flags, !!(ls.flags & 1), !!(ls.flags & 2));
	DETAIL("  solist=0x%llx somain=0x%llx sonext=0x%llx mutex=0x%llx",
	       (unsigned long long)ls.solist_addr,
	       (unsigned long long)ls.somain_addr,
	       (unsigned long long)ls.sonext_addr,
	       (unsigned long long)ls.dl_mutex_addr);
	DETAIL("  values: solist->0x%llx somain->0x%llx sonext->0x%llx",
	       (unsigned long long)ls.solist_value,
	       (unsigned long long)ls.somain_value,
	       (unsigned long long)ls.sonext_value);
	DETAIL("  offsets: base=0x%x size=0x%x phdr=0x%x phnum=0x%x dynamic=0x%x",
	       ls.offsets.base, ls.offsets.size,
	       ls.offsets.phdr, ls.offsets.phnum,
	       ls.offsets.dynamic);
	DETAIL("           strtab=0x%x symtab=0x%x bias=0x%x strsz=0x%x next=0x%x",
	       ls.offsets.strtab, ls.offsets.symtab,
	       ls.offsets.bias, ls.offsets.strsz,
	       ls.offsets.next);
	if (ls.offsets.base != 0xFFFF) {
		DETAIL("  somain soinfo (first 128 bytes):");
		for (size_t row = 0; row < 128; row += 16) {
			uint64_t a, b;
			memcpy(&a, ls.somain_buf + row,     8);
			memcpy(&b, ls.somain_buf + row + 8, 8);
			DETAIL("    +%02zx: %016llx %016llx",
			       row,
			       (unsigned long long)a,
			       (unsigned long long)b);
		}
	}
}

int akane_inject(const struct akane_args *args)
{
	struct akane_backend backend;
	if (akane_backend_init(&backend, args->target_pid) != 0) {
		ERR("akane_backend_init failed (is /dev/akane present?)");
		return 1;
	}

	char name[256] = "";
	if (read_cmdline(args->target_pid, name, sizeof(name)) == 0 && name[0])
		INFO("loading %s into pid %d (%s)", args->so_path, args->target_pid, name);
	else
		INFO("loading %s into pid %d", args->so_path, args->target_pid);

	/* Runtime first: its addresses feed the payload's GOT patch and registry. */
	struct akane_runtime_info rt;
	if (akane_runtime_load(&backend, &rt) != 0) {
		akane_backend_deinit(&backend);
		return 1;
	}

	struct akane_payload_info pl;
	if (akane_payload_load(&backend, args->so_path, &pl) != 0) {
		akane_backend_deinit(&backend);
		return 1;
	}

	apply_visibility(backend.akane_fd, args->target_pid,
	                 pl.base, args->so_path, args->hide_from_memory);

	strip_elf_metadata(backend.akane_fd, args->target_pid, &pl, ELF_STRIP_PRE_INIT);

	struct boot_region boot = {0};
	if (setup_boot_region(backend.akane_fd, args->target_pid, &boot) != 0) {
		akane_backend_deinit(&backend);
		return 1;
	}

	patch_got_slots(backend.akane_fd, args->target_pid, &pl, &rt);
	write_payload_registry(backend.akane_fd, args->target_pid, &pl, &rt, args->so_path);

	if (args->register_to_solist) {
		if (rt.linker_register_fn) {
			arm_linker_register(backend.akane_fd, args->target_pid,
			                    &boot, rt.linker_register_fn);
		} else {
			ERR("--register-to-solist requested but akane_rt_linker_register unresolved");
		}
	}

	if (plant_init_info(backend.akane_fd, args->target_pid, &boot, &pl) != 0) {
		struct akane_memory_handle fr = { .handle = boot.handle };
		ioctl(backend.akane_fd, AKANE_IOC_MEMORY_FREE, &fr);
		akane_backend_deinit(&backend);
		return 1;
	}

	if (submit_task_work(backend.akane_fd, args->target_pid, &boot) != 0) {
		struct akane_memory_handle fr = { .handle = boot.handle };
		ioctl(backend.akane_fd, AKANE_IOC_MEMORY_FREE, &fr);
		akane_backend_deinit(&backend);
		return 1;
	}

	uint8_t flag = wait_for_done_flag(backend.akane_fd, args->target_pid, &boot);
	INFO("injected via task_work");

	detach_boot(backend.akane_fd, &boot);
	if (flag)
		DETAIL("bootstrap detached (worker thread spawned)");
	else
		DETAIL("bootstrap detached (no completion flag -- hijack may have stalled)");

	/* Post-init strip waits for the done flag: .init_array may read .dynstr /
	 * build-id during self-init, and a premature strip could break it. */
	if (args->hide_from_memory && flag)
		strip_elf_metadata(backend.akane_fd, args->target_pid, &pl,
		                   ELF_STRIP_POST_INIT);

	log_hook_call_counts(backend.akane_fd, args->target_pid, rt.call_counts_addr);

	if (args->register_to_solist && rt.linker_state_addr)
		log_linker_state(backend.akane_fd, args->target_pid, rt.linker_state_addr);

	akane_backend_deinit(&backend);
	return 0;
}
