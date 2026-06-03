/* akane_runtime: bionic linker introspection (see linker.c). */
#ifndef AKANE_RUNTIME_LINKER_H
#define AKANE_RUNTIME_LINKER_H

#include <stdint.h>
#include <stdbool.h>

#define AKANE_LINKER_OFF_NF  0xFFFF   /* "not found" sentinel */

/* Field offsets within bionic's soinfo, discovered at runtime;
 * AKANE_LINKER_OFF_NF if unmatched. */
struct akane_linker_offsets {
	uint16_t base;
	uint16_t size;
	uint16_t phdr;
	uint16_t phnum;
	uint16_t dynamic;
	uint16_t strtab;
	uint16_t symtab;
	uint16_t bias;
	uint16_t strsz;
	uint16_t next;
};

/* Linker discovery results; exported so the controller can mem_read it whole. */
struct akane_linker_state {
	uint32_t version;
	uint32_t flags;         /* bit0 = symbols resolved, bit1 = base found, bit2 = next found */

	char     linker_path[256];
	uint64_t linker_load_bias;

	/* Resolved runtime addresses; 0 if unresolved. */
	uint64_t solist_addr;
	uint64_t somain_addr;
	uint64_t sonext_addr;
	uint64_t dl_mutex_addr;

	/* Read-back values at those addresses. */
	uint64_t solist_value;
	uint64_t somain_value;
	uint64_t sonext_value;

	uint8_t  somain_buf[256];   /* first 256 bytes of somain's soinfo */

	struct akane_linker_offsets offsets;
};

extern struct akane_linker_state g_akane_linker_state;

/* Run discovery. Idempotent; true if symbols + base offset resolved. */
bool akane_linker_discover(void);

/* Splice a synthetic soinfo for the payload into bionic's solist.
 * `name` must outlive the call (we copy it). Returns true on success. */
bool akane_linker_register_payload(uint64_t base, uint64_t size,
				   uint64_t phdr, uint16_t phnum,
				   const char *name);

#endif /* AKANE_RUNTIME_LINKER_H */
