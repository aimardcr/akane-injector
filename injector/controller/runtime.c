#define _GNU_SOURCE
#include "runtime.h"
#include "log.h"

#include <stdint.h>
#include "csoloader.h"
#include "elf_util.h"

int akane_runtime_load(struct akane_backend *backend,
                       struct akane_runtime_info *out)
{
	struct csoloader rt = {0};
	rt.mem_ops = &backend->ops;

	if (!csoloader_load(&rt, RUNTIME_LIB_PATH)) {
		ERR("runtime load failed: %s", RUNTIME_LIB_PATH);
		return -1;
	}

	out->hook_dl_iterate_phdr = (uint64_t)
		csoloader_elf_symb_address_exported(rt.img, "akane_rt_dl_iterate_phdr");
	out->hook_dladdr  = (uint64_t)
		csoloader_elf_symb_address_exported(rt.img, "akane_rt_dladdr");
	out->hook_dlopen  = (uint64_t)
		csoloader_elf_symb_address_exported(rt.img, "akane_rt_dlopen");
	out->hook_dlsym   = (uint64_t)
		csoloader_elf_symb_address_exported(rt.img, "akane_rt_dlsym");
	out->hook_dlclose = (uint64_t)
		csoloader_elf_symb_address_exported(rt.img, "akane_rt_dlclose");
	out->hook_dlerror = (uint64_t)
		csoloader_elf_symb_address_exported(rt.img, "akane_rt_dlerror");

	out->payloads_addr = (uint64_t)
		csoloader_elf_symb_address_exported(rt.img, "g_akane_rt_payloads");
	out->names_addr = (uint64_t)
		csoloader_elf_symb_address_exported(rt.img, "g_akane_rt_names");
	out->count_addr = (uint64_t)
		csoloader_elf_symb_address_exported(rt.img, "g_akane_rt_payload_count");
	out->call_counts_addr = (uint64_t)
		csoloader_elf_symb_address_exported(rt.img, "g_akane_rt_call_counts");
	out->linker_register_fn = (uint64_t)
		csoloader_elf_symb_address_exported(rt.img, "akane_rt_linker_register");
	out->linker_state_addr = (uint64_t)
		csoloader_elf_symb_address_exported(rt.img, "g_akane_linker_state");

	if (!out->hook_dl_iterate_phdr || !out->hook_dladdr ||
	    !out->hook_dlopen || !out->hook_dlsym ||
	    !out->hook_dlclose || !out->hook_dlerror ||
	    !out->payloads_addr || !out->names_addr || !out->count_addr) {
		ERR("runtime symbols not all resolved (dl_iterate_phdr=%llx dladdr=%llx payloads=%llx count=%llx)",
		    (unsigned long long)out->hook_dl_iterate_phdr,
		    (unsigned long long)out->hook_dladdr,
		    (unsigned long long)out->payloads_addr,
		    (unsigned long long)out->count_addr);
		csoloader_abandon(&rt);
		return -1;
	}

	out->base = (uint64_t)(uintptr_t)rt.img->target_base;
	DETAIL("runtime mapped at 0x%llx", (unsigned long long)out->base);

	csoloader_abandon(&rt);
	return 0;
}
