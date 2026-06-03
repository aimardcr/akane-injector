#ifndef AKANE_CTRL_PAYLOAD_H
#define AKANE_CTRL_PAYLOAD_H

#include <stdint.h>
#include "akane_backend.h"

/* What the controller needs from the payload after mapping. Any field may be
 * 0 (symbol/section absent); the GOT patcher and metadata wiper skip zeros.
 * The strip_* ranges are wiped post-init under --hide-from-memory. */
struct akane_payload_info {
	uint64_t base;
	uint64_t map_size;

	uint64_t phdr_target;
	uint16_t phnum;

	uint64_t init_array_target;
	uint64_t init_array_count;
	uint64_t pthread_create_target;

	uint64_t got_dl_iterate_phdr;
	uint64_t got_dladdr;
	uint64_t got_dlopen;
	uint64_t got_dlsym;
	uint64_t got_dlclose;
	uint64_t got_dlerror;

	uint64_t strip_dynstr_addr;
	uint64_t strip_dynstr_size;
	uint64_t strip_buildid_addr;
	uint64_t strip_buildid_size;
};

/* Load the user .so into the target and resolve its GOT slots, init_array,
 * and pthread_create. Returns 0 on success, -1 on failure. */
int akane_payload_load(struct akane_backend *backend, const char *so_path,
                       struct akane_payload_info *out);

#endif /* AKANE_CTRL_PAYLOAD_H */
