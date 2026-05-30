#ifndef AKANE_CTRL_RUNTIME_H
#define AKANE_CTRL_RUNTIME_H

#include <stdint.h>
#include "akane_backend.h"

#define RUNTIME_LIB_PATH  "/data/local/tmp/libakane-runtime.so"
#define AKANE_RT_NAME_LEN 256

/* Mirror of struct akane_rt_payload in runtime/runtime.c. The controller
 * writes one of these into g_akane_rt_payloads[count] before exec. */
struct akane_rt_payload_entry {
	uint64_t base;
	uint64_t size;
	uint64_t phdr;
	uint16_t phnum;
	uint16_t _pad0;
	uint32_t _pad1;
};

/* Symbol/address bundle extracted from the runtime library after load.
 * Zero-valued fields mean "symbol not present" (older runtime build);
 * the orchestrator decides whether each is required. */
struct akane_runtime_info {
	uint64_t base;
	uint64_t hook_dl_iterate_phdr;
	uint64_t hook_dladdr;
	uint64_t hook_dlopen;
	uint64_t hook_dlsym;
	uint64_t hook_dlclose;
	uint64_t hook_dlerror;
	uint64_t payloads_addr;
	uint64_t names_addr;
	uint64_t count_addr;
	uint64_t call_counts_addr;
	uint64_t linker_register_fn;
	uint64_t linker_state_addr;
};

/* Load libakane-runtime.so into the target via CSOLoader, resolve the
 * hook + registry symbols, and abandon the loader handle. Returns 0 on
 * success; on failure, prints an error and returns -1. */
int akane_runtime_load(struct akane_backend *backend,
                       struct akane_runtime_info *out);

#endif /* AKANE_CTRL_RUNTIME_H */
