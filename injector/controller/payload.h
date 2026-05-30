#ifndef AKANE_CTRL_PAYLOAD_H
#define AKANE_CTRL_PAYLOAD_H

#include <stdint.h>
#include "akane_backend.h"

/* Snapshot of everything we need from the payload after CSOLoader has
 * mapped it into the target and we've abandoned the loader handle.
 *
 * GOT slot fields may be 0 if the payload doesn't import that symbol --
 * the GOT patcher skips zero entries. init_array_count == 0 means the
 * payload has no constructors; pthread_create_target is then unused.
 *
 * The strip_* ranges describe metadata that can be wiped post-init_array
 * for --hide-from-memory: dynstr (.dynstr) is consulted at runtime only
 * by libraries that re-introspect themselves, build-id note is YARA
 * candy with no runtime use. Any field may be 0 if the section wasn't
 * present or its bounds couldn't be determined; the wiper skips zeros. */
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

/* Load the user-supplied .so into the target via CSOLoader. Walks PT_DYNAMIC
 * to locate JUMP_SLOT entries for the six dl* symbols, resolves init_array
 * and pthread_create against the target's libc, then abandons the loader
 * handle. Returns 0 on success, -1 on failure (error already printed). */
int akane_payload_load(struct akane_backend *backend, const char *so_path,
                       struct akane_payload_info *out);

#endif /* AKANE_CTRL_PAYLOAD_H */
