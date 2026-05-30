/*
 * akane_runtime: bionic linker introspection.
 *
 * Phase 1 (current): read-only discovery. Resolves linker globals
 * (solist / somain / sonext / g_dl_mutex) by parsing the linker ELF on
 * disk + computing runtime VAs from /proc/self/maps. Reads somain's
 * soinfo and finds the `base` offset by ELF-magic check on candidate
 * fields. Results stashed in g_akane_linker_state for the controller
 * to mem_read and inspect.
 *
 * No mutations yet. Phase 3 will add splice.
 */

#ifndef AKANE_RUNTIME_LINKER_H
#define AKANE_RUNTIME_LINKER_H

#include <stdint.h>
#include <stdbool.h>

#define AKANE_LINKER_OFF_NF  0xFFFF   /* "not found" sentinel */

/* Field offsets within bionic's soinfo struct. Discovered at runtime
 * by matching expected values; stays AKANE_LINKER_OFF_NF if we couldn't
 * find a match. Phase 1 only fills `base`. */
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

/* Snapshot of linker discovery results. Layout is also exported so
 * the controller can mem_read this single struct rather than chasing
 * individual symbols. */
struct akane_linker_state {
	uint32_t version;       /* layout version (1 = phase 1) */
	uint32_t flags;         /* bit 0 = symbols resolved, bit 1 = base offset found */

	/* Linker ELF on disk. */
	char     linker_path[256];
	uint64_t linker_load_bias;

	/* Resolved runtime addresses. 0 if unresolved. */
	uint64_t solist_addr;
	uint64_t somain_addr;
	uint64_t sonext_addr;
	uint64_t dl_mutex_addr;

	/* Read-back values at those addresses. */
	uint64_t solist_value;
	uint64_t somain_value;
	uint64_t sonext_value;

	/* somain's soinfo: first 256 bytes captured for the controller
	 * to inspect. */
	uint8_t  somain_buf[256];

	struct akane_linker_offsets offsets;
};

extern struct akane_linker_state g_akane_linker_state;

/* Run discovery. Idempotent; safe to call multiple times. Returns
 * true if symbols resolved + base offset found. */
bool akane_linker_discover(void);

/* Splice a synthetic soinfo for the given payload into bionic's solist.
 * The payload is described by:
 *   base   - runtime VA of the payload's first PT_LOAD
 *   size   - aligned size in bytes (max VMA end - first VMA start)
 *   phdr   - runtime VA of the payload's program header table
 *   phnum  - number of program headers
 *   name   - file path string (must outlive the call; we copy it)
 * Returns true on success.
 *
 * Internally: clones solist's head as template, overwrites the relevant
 * fields, takes g_dl_mutex if found, atomically swings the solist head
 * to point at our entry. */
bool akane_linker_register_payload(uint64_t base, uint64_t size,
				   uint64_t phdr, uint16_t phnum,
				   const char *name);

#endif /* AKANE_RUNTIME_LINKER_H */
