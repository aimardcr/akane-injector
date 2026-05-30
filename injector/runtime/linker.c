/*
 * akane_runtime: bionic linker introspection.
 *
 * Phase 1: read-only discovery.
 *   1. Find the dynamic linker (`/.../linker64`) via /proc/self/maps,
 *      capture its load_bias (first segment start).
 *   2. mmap the linker file and walk its .symtab / .dynsym to find
 *      the well-known internal symbols:
 *          __dl__ZL6solist       -> head pointer (variable)
 *          __dl__ZL6somain       -> main exe's soinfo (variable)
 *          __dl__ZL6sonext       -> tail pointer (variable)
 *          __dl__ZL10g_dl_mutex  -> linker mutex (variable)
 *      Add load_bias to convert to runtime VA.
 *   3. Read somain's soinfo and find the `base` offset by scanning
 *      candidate qwords; the right one points at an ELF mapping in
 *      our address space (verified via /proc/self/maps).
 *
 * No mutations yet -- this is the safe checkpoint where the controller
 * mem_reads g_akane_linker_state and we verify our discovery is sane.
 */

#define _GNU_SOURCE
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <elf.h>
#include <link.h>

#include "linker.h"

/* Persistent storage for our synthetic soinfo and its path string.
 * Sized to comfortably hold any bionic soinfo (typical max ~0xe0 bytes
 * across all Android versions with bias around 0xd0). The buffers live
 * in this library's BSS; the runtime's mapping persists for the
 * target process's lifetime, so once spliced into solist these are
 * stable references for any introspection that follows. */
static uint8_t g_akane_syn_soinfo[256] __attribute__((aligned(8)));
static char    g_akane_syn_name[256];
static bool    g_akane_syn_active;

__attribute__((visibility("default")))
struct akane_linker_state g_akane_linker_state;

/* ------------------------------------------------------------------ */
/* /proc/self/maps walking */

typedef bool (*akl_map_cb)(uint64_t start, uint64_t end, int prot,
			   const char *path, void *data);

static void akl_iter_maps(akl_map_cb cb, void *data)
{
	FILE *fp = fopen("/proc/self/maps", "re");
	if (!fp) return;
	char line[1024];
	while (fgets(line, sizeof(line), fp)) {
		unsigned long long start, end;
		char perms[8];
		char path[512] = {0};
		int n = sscanf(line, "%llx-%llx %7s %*s %*s %*s %511[^\n]",
			       &start, &end, perms, path);
		if (n < 3) continue;
		const char *p = path;
		while (*p == ' ' || *p == '\t') p++;
		int prot = 0;
		if (perms[0] == 'r') prot |= PROT_READ;
		if (perms[1] == 'w') prot |= PROT_WRITE;
		if (perms[2] == 'x') prot |= PROT_EXEC;
		if (!cb((uint64_t)start, (uint64_t)end, prot, p, data))
			break;
	}
	fclose(fp);
}

/* ------------------------------------------------------------------ */
/* Address validation: is `addr` in any readable mapping? */

struct akl_addr_in_range_ctx {
	uint64_t addr;
	bool     found;
};

static bool akl_addr_in_range_cb(uint64_t start, uint64_t end, int prot,
				 const char *path, void *data)
{
	(void)path;
	struct akl_addr_in_range_ctx *c = data;
	if (c->addr >= start && c->addr < end && (prot & PROT_READ)) {
		c->found = true;
		return false;
	}
	return true;
}

static bool akl_addr_readable(uint64_t addr)
{
	struct akl_addr_in_range_ctx c = { .addr = addr, .found = false };
	akl_iter_maps(akl_addr_in_range_cb, &c);
	return c.found;
}

/* ------------------------------------------------------------------ */
/* Find the bionic linker mapping. */

struct akl_find_linker_ctx {
	char     path[256];
	uint64_t load_bias;
	bool     found;
};

static bool akl_find_linker_cb(uint64_t start, uint64_t end, int prot,
			       const char *path, void *data)
{
	(void)end; (void)prot;
	struct akl_find_linker_ctx *c = data;
	if (c->found) return false;

#ifdef __LP64__
	const char *suffix = "/linker64";
#else
	const char *suffix = "/linker";
#endif
	size_t plen = strlen(path);
	size_t slen = strlen(suffix);
	if (plen < slen) return true;
	if (strcmp(path + plen - slen, suffix) != 0) return true;

	size_t cp = plen < sizeof(c->path) - 1 ? plen : sizeof(c->path) - 1;
	memcpy(c->path, path, cp);
	c->path[cp] = '\0';
	c->load_bias = start;
	c->found = true;
	return false;
}

/* ------------------------------------------------------------------ */
/* ELF symbol lookup: search .symtab first (local symbols live there),
 * fall back to .dynsym. Returns symbol's st_value (file vaddr), or 0. */

static uint64_t akl_elf_find_symbol_in_section(const uint8_t *elf,
					       const ElfW(Shdr) *sym_shdr,
					       const char *strtab,
					       const char *name)
{
	const ElfW(Sym) *syms = (const ElfW(Sym) *)(elf + sym_shdr->sh_offset);
	size_t n = sym_shdr->sh_size / sizeof(ElfW(Sym));
	for (size_t i = 0; i < n; i++) {
		const char *sname = strtab + syms[i].st_name;
		if (strcmp(sname, name) == 0)
			return (uint64_t)syms[i].st_value;
	}
	return 0;
}

static uint64_t akl_elf_find_symbol(const uint8_t *elf, size_t elf_size,
				    const char *name)
{
	if (elf_size < sizeof(ElfW(Ehdr))) return 0;
	const ElfW(Ehdr) *eh = (const ElfW(Ehdr) *)elf;
	if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0) return 0;
	if (!eh->e_shoff || !eh->e_shnum || !eh->e_shentsize) return 0;

	const ElfW(Shdr) *shdrs = (const ElfW(Shdr) *)(elf + eh->e_shoff);

	uint32_t want_types[] = { SHT_SYMTAB, SHT_DYNSYM };
	for (size_t k = 0; k < sizeof(want_types) / sizeof(want_types[0]); k++) {
		for (int i = 0; i < eh->e_shnum; i++) {
			if (shdrs[i].sh_type != want_types[k]) continue;
			if (shdrs[i].sh_link >= eh->e_shnum) continue;
			const ElfW(Shdr) *strtab_shdr = &shdrs[shdrs[i].sh_link];
			if (strtab_shdr->sh_type != SHT_STRTAB) continue;
			const char *strtab = (const char *)(elf + strtab_shdr->sh_offset);
			uint64_t v = akl_elf_find_symbol_in_section(elf, &shdrs[i],
								    strtab, name);
			if (v) return v;
		}
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* Page protection lookup + RW write helper. */

struct akl_prot_ctx {
	uint64_t addr;
	int      prot;
	bool     found;
};

static bool akl_prot_cb(uint64_t start, uint64_t end, int prot,
			const char *path, void *data)
{
	(void)path;
	struct akl_prot_ctx *c = data;
	if (c->addr >= start && c->addr < end) {
		c->prot = prot;
		c->found = true;
		return false;
	}
	return true;
}

static int akl_get_prot(uint64_t addr)
{
	struct akl_prot_ctx c = { .addr = addr, .prot = PROT_READ, .found = false };
	akl_iter_maps(akl_prot_cb, &c);
	return c.found ? c.prot : -1;
}

/* Write a 64-bit value to an address that may live in a read-only page
 * (e.g. linker .data after RELRO). mprotects to RW, writes, restores. */
static bool akl_write_qword(uint64_t addr, uint64_t value)
{
	long page = sysconf(_SC_PAGE_SIZE);
	if (page <= 0) page = 4096;
	uint64_t mask = (uint64_t)page - 1;
	uint64_t page_start = addr & ~mask;

	int orig_prot = akl_get_prot(addr);
	if (orig_prot < 0)
		return false;

	bool need_rw = !(orig_prot & PROT_WRITE);
	if (need_rw) {
		if (mprotect((void *)(uintptr_t)page_start, (size_t)page,
			     orig_prot | PROT_WRITE) != 0)
			return false;
	}

	*(volatile uint64_t *)(uintptr_t)addr = value;

	if (need_rw)
		mprotect((void *)(uintptr_t)page_start, (size_t)page, orig_prot);

	return true;
}

/* ------------------------------------------------------------------ */
/* Public: run discovery. */

bool akane_linker_discover(void)
{
	struct akane_linker_state *st = &g_akane_linker_state;

	/* idempotent */
	if (st->version != 0)
		return (st->flags & 2) != 0;

	st->version = 1;
	st->offsets.base    = AKANE_LINKER_OFF_NF;
	st->offsets.size    = AKANE_LINKER_OFF_NF;
	st->offsets.phdr    = AKANE_LINKER_OFF_NF;
	st->offsets.phnum   = AKANE_LINKER_OFF_NF;
	st->offsets.dynamic = AKANE_LINKER_OFF_NF;
	st->offsets.strtab  = AKANE_LINKER_OFF_NF;
	st->offsets.symtab  = AKANE_LINKER_OFF_NF;
	st->offsets.bias    = AKANE_LINKER_OFF_NF;
	st->offsets.strsz   = AKANE_LINKER_OFF_NF;
	st->offsets.next    = AKANE_LINKER_OFF_NF;

	/* Step 1: find linker mapping. */
	struct akl_find_linker_ctx fctx = {0};
	akl_iter_maps(akl_find_linker_cb, &fctx);
	if (!fctx.found)
		return false;

	size_t plen = strlen(fctx.path);
	if (plen >= sizeof(st->linker_path))
		plen = sizeof(st->linker_path) - 1;
	memcpy(st->linker_path, fctx.path, plen);
	st->linker_path[plen] = '\0';
	st->linker_load_bias = fctx.load_bias;

	/* Step 2: mmap linker file, parse symbols. */
	int fd = open(fctx.path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return false;
	struct stat sb;
	if (fstat(fd, &sb) != 0 || sb.st_size <= 0) {
		close(fd);
		return false;
	}
	void *elf_map = mmap(NULL, (size_t)sb.st_size, PROT_READ,
			     MAP_PRIVATE, fd, 0);
	close(fd);
	if (elf_map == MAP_FAILED)
		return false;

	uint64_t solist_off = akl_elf_find_symbol(elf_map, sb.st_size,
						  "__dl__ZL6solist");
	uint64_t somain_off = akl_elf_find_symbol(elf_map, sb.st_size,
						  "__dl__ZL6somain");
	uint64_t sonext_off = akl_elf_find_symbol(elf_map, sb.st_size,
						  "__dl__ZL6sonext");
	uint64_t mutex_off  = akl_elf_find_symbol(elf_map, sb.st_size,
						  "__dl__ZL10g_dl_mutex");
	if (!mutex_off)
		mutex_off = akl_elf_find_symbol(elf_map, sb.st_size,
						"__dl_g_dl_mutex");
	munmap(elf_map, (size_t)sb.st_size);

	if (solist_off) st->solist_addr   = solist_off + st->linker_load_bias;
	if (somain_off) st->somain_addr   = somain_off + st->linker_load_bias;
	if (sonext_off) st->sonext_addr   = sonext_off + st->linker_load_bias;
	if (mutex_off)  st->dl_mutex_addr = mutex_off  + st->linker_load_bias;

	if (st->solist_addr && st->somain_addr)
		st->flags |= 1;

	/* Step 3: read values + somain's soinfo. */
	if (st->solist_addr && akl_addr_readable(st->solist_addr))
		memcpy(&st->solist_value,
		       (const void *)(uintptr_t)st->solist_addr,
		       sizeof(st->solist_value));
	if (st->somain_addr && akl_addr_readable(st->somain_addr))
		memcpy(&st->somain_value,
		       (const void *)(uintptr_t)st->somain_addr,
		       sizeof(st->somain_value));
	if (st->sonext_addr && akl_addr_readable(st->sonext_addr))
		memcpy(&st->sonext_value,
		       (const void *)(uintptr_t)st->sonext_addr,
		       sizeof(st->sonext_value));

	uint64_t ref_si = st->somain_value ? st->somain_value : st->sonext_value;
	if (!ref_si || !akl_addr_readable(ref_si))
		return false;

	memcpy(st->somain_buf, (const void *)(uintptr_t)ref_si,
	       sizeof(st->somain_buf));

	/* Step 4: find `base` offset. Each non-zero qword that points at
	 * a readable mapping whose first 4 bytes are ELFMAG is a candidate;
	 * accept the first one. */
	uint64_t found_base = 0;
	for (size_t i = 0; i + 8 <= sizeof(st->somain_buf); i += 8) {
		uint64_t cand;
		memcpy(&cand, st->somain_buf + i, 8);
		if (!cand) continue;
		if (!akl_addr_readable(cand)) continue;
		uint8_t magic[4];
		memcpy(magic, (const void *)(uintptr_t)cand, 4);
		if (memcmp(magic, ELFMAG, SELFMAG) == 0) {
			st->offsets.base = (uint16_t)i;
			found_base = cand;
			st->flags |= 2;
			break;
		}
	}

	if (!found_base)
		return false;

	/* Step 5: compute expected values from the ELF at `found_base`,
	 * then scan the soinfo buffer for matches. Each field is filled
	 * only on the first match so a value coincidence elsewhere doesn't
	 * mask the real field. */
	const ElfW(Ehdr) *eh = (const ElfW(Ehdr) *)(uintptr_t)found_base;
	if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0)
		return true;   /* base resolved, give up on the rest */

	uint64_t expected_phdr  = found_base + eh->e_phoff;
	uint64_t expected_phnum = eh->e_phnum;

	const ElfW(Phdr) *phdrs = (const ElfW(Phdr) *)(uintptr_t)expected_phdr;
	uint64_t expected_bias    = 0;
	uint64_t expected_dynamic = 0;
	uint64_t load_min = UINT64_MAX, load_max = 0;
	bool first_load = true;
	for (int i = 0; i < eh->e_phnum; i++) {
		if (phdrs[i].p_type == PT_LOAD) {
			if (first_load) {
				expected_bias = found_base - phdrs[i].p_vaddr;
				first_load = false;
			}
			if (phdrs[i].p_vaddr < load_min)
				load_min = phdrs[i].p_vaddr;
			uint64_t e = phdrs[i].p_vaddr + phdrs[i].p_memsz;
			if (e > load_max) load_max = e;
		}
		if (phdrs[i].p_type == PT_DYNAMIC && expected_dynamic == 0)
			expected_dynamic = expected_bias + phdrs[i].p_vaddr;
	}

	long page = sysconf(_SC_PAGE_SIZE);
	if (page <= 0) page = 4096;
	uint64_t pmask = (uint64_t)page - 1;
	uint64_t aligned_min = load_min & ~pmask;
	uint64_t aligned_max = (load_max + pmask) & ~pmask;
	uint64_t expected_size = (load_max > 0) ? (aligned_max - aligned_min) : 0;

	uint64_t expected_strtab = 0, expected_symtab = 0;
	uint64_t expected_strsz  = 0;
	if (expected_dynamic && akl_addr_readable(expected_dynamic)) {
		const ElfW(Dyn) *dyn = (const ElfW(Dyn) *)(uintptr_t)expected_dynamic;
		for (int i = 0; i < 512; i++) {
			if (dyn[i].d_tag == DT_NULL)
				break;
			switch (dyn[i].d_tag) {
			case DT_STRTAB:
				expected_strtab = (uint64_t)dyn[i].d_un.d_ptr;
				break;
			case DT_SYMTAB:
				expected_symtab = (uint64_t)dyn[i].d_un.d_ptr;
				break;
			case DT_STRSZ:
				expected_strsz  = (uint64_t)dyn[i].d_un.d_val;
				break;
			}
		}
	}
	/* DT_STRTAB/DT_SYMTAB may store either file-vaddrs (unbiased) or
	 * runtime VAs depending on linker version; bionic stores runtime
	 * VAs in soinfo, so prepare both candidates. */
	uint64_t biased_strtab = expected_strtab ? expected_strtab + expected_bias : 0;
	uint64_t biased_symtab = expected_symtab ? expected_symtab + expected_bias : 0;

	for (size_t i = 0; i + 8 <= sizeof(st->somain_buf); i += 8) {
		if (i == st->offsets.base) continue;
		uint64_t v;
		memcpy(&v, st->somain_buf + i, 8);
		if (!v) continue;

		if (st->offsets.phdr == AKANE_LINKER_OFF_NF
		    && v == expected_phdr) {
			st->offsets.phdr = (uint16_t)i;
		} else if (st->offsets.dynamic == AKANE_LINKER_OFF_NF
			   && expected_dynamic && v == expected_dynamic) {
			st->offsets.dynamic = (uint16_t)i;
		} else if (st->offsets.strtab == AKANE_LINKER_OFF_NF
			   && (expected_strtab || biased_strtab)
			   && (v == expected_strtab || v == biased_strtab)) {
			st->offsets.strtab = (uint16_t)i;
		} else if (st->offsets.symtab == AKANE_LINKER_OFF_NF
			   && (expected_symtab || biased_symtab)
			   && (v == expected_symtab || v == biased_symtab)) {
			st->offsets.symtab = (uint16_t)i;
		} else if (st->offsets.size == AKANE_LINKER_OFF_NF
			   && expected_size && v == expected_size) {
			st->offsets.size = (uint16_t)i;
		} else if (st->offsets.bias == AKANE_LINKER_OFF_NF
			   && v == expected_bias) {
			st->offsets.bias = (uint16_t)i;
		} else if (st->offsets.phnum == AKANE_LINKER_OFF_NF
			   && v == expected_phnum) {
			st->offsets.phnum = (uint16_t)i;
		} else if (st->offsets.strsz == AKANE_LINKER_OFF_NF
			   && expected_strsz && v == expected_strsz) {
			st->offsets.strsz = (uint16_t)i;
		}
	}

	/* Step 6: discover the `next` pointer offset. solist's head soinfo
	 * is a real entry; one of its qwords (excluding the offsets we've
	 * already identified) is a pointer to ANOTHER valid soinfo. We
	 * verify by chasing: the candidate must be readable, and reading
	 * (candidate + base_offset) must give us another address whose
	 * first 4 bytes are ELFMAG. */
	uint64_t solist_head = st->solist_value;
	if (solist_head && akl_addr_readable(solist_head) && st->offsets.base != AKANE_LINKER_OFF_NF) {
		uint8_t head_buf[256];
		memcpy(head_buf, (const void *)(uintptr_t)solist_head, sizeof(head_buf));

		for (size_t i = 0; i + 8 <= sizeof(head_buf); i += 8) {
			if (i == st->offsets.base    ||
			    i == st->offsets.size    ||
			    i == st->offsets.phdr    ||
			    i == st->offsets.phnum   ||
			    i == st->offsets.dynamic ||
			    i == st->offsets.strtab  ||
			    i == st->offsets.symtab  ||
			    i == st->offsets.bias    ||
			    i == st->offsets.strsz)
				continue;
			uint64_t maybe_next;
			memcpy(&maybe_next, head_buf + i, 8);
			if (!maybe_next || !akl_addr_readable(maybe_next))
				continue;

			/* Read what would be base_addr in the next entry. */
			uint64_t next_base_addr = maybe_next + st->offsets.base;
			if (!akl_addr_readable(next_base_addr))
				continue;
			uint64_t maybe_base;
			memcpy(&maybe_base, (const void *)(uintptr_t)next_base_addr, 8);
			if (!maybe_base || !akl_addr_readable(maybe_base))
				continue;
			uint8_t magic[4];
			memcpy(magic, (const void *)(uintptr_t)maybe_base, 4);
			if (memcmp(magic, ELFMAG, SELFMAG) != 0)
				continue;

			st->offsets.next = (uint16_t)i;
			st->flags |= 4;
			break;
		}
	}

	return true;
}

/* ------------------------------------------------------------------ */
/* Public: register a payload in solist. */

static inline void akl_set_qword(uint8_t *buf, uint16_t off, uint64_t v)
{
	if (off != AKANE_LINKER_OFF_NF)
		memcpy(buf + off, &v, 8);
}

bool akane_linker_register_payload(uint64_t base, uint64_t size,
				   uint64_t phdr, uint16_t phnum,
				   const char *name)
{
	struct akane_linker_state *st = &g_akane_linker_state;

	if (!akane_linker_discover())
		return false;
	if (st->offsets.base == AKANE_LINKER_OFF_NF
	    || st->offsets.next == AKANE_LINKER_OFF_NF
	    || !st->solist_addr)
		return false;
	if (g_akane_syn_active)
		return false;   /* already registered, this version supports one */

	uint64_t old_head = st->solist_value;
	if (!old_head || !akl_addr_readable(old_head))
		return false;

	/* Clone solist's head as template -- it's a real, well-formed
	 * soinfo whose layout matches what bionic expects. Any field we
	 * don't explicitly overwrite inherits a sane (libdl-ish) value. */
	memcpy(g_akane_syn_soinfo, (const void *)(uintptr_t)old_head,
	       sizeof(g_akane_syn_soinfo));

	/* Copy name into our buffer; point the soinfo's strtab-adjacent
	 * pointer fields at it later if needed. For now the path is just
	 * stored locally so callers can find it via dl_iterate_phdr. */
	if (name) {
		size_t i = 0;
		while (i < sizeof(g_akane_syn_name) - 1 && name[i]) {
			g_akane_syn_name[i] = name[i];
			i++;
		}
		g_akane_syn_name[i] = '\0';
	} else {
		g_akane_syn_name[0] = '\0';
	}

	/* Patch the fields the introspectors actually read. */
	akl_set_qword(g_akane_syn_soinfo, st->offsets.base,  base);
	akl_set_qword(g_akane_syn_soinfo, st->offsets.size,  size);
	akl_set_qword(g_akane_syn_soinfo, st->offsets.phdr,  phdr);
	akl_set_qword(g_akane_syn_soinfo, st->offsets.phnum, (uint64_t)phnum);
	/* For our payload the gadget's first PT_LOAD has p_vaddr = 0, so
	 * load_bias == base. (csoloader maps the first LOAD at the
	 * allocation start without a vaddr offset.) */
	akl_set_qword(g_akane_syn_soinfo, st->offsets.bias,  base);

	/* Take dl_mutex around the splice if available. Bionic's own
	 * dl_iterate_phdr / solist walkers take this same mutex, so a
	 * concurrent reader will block until we publish the new head. */
	pthread_mutex_t *dlm = NULL;
	if (st->dl_mutex_addr)
		dlm = (pthread_mutex_t *)(uintptr_t)st->dl_mutex_addr;
	if (dlm)
		pthread_mutex_lock(dlm);

	/* Re-read head under the lock in case it moved. */
	uint64_t cur_head = 0;
	memcpy(&cur_head, (const void *)(uintptr_t)st->solist_addr,
	       sizeof(cur_head));

	akl_set_qword(g_akane_syn_soinfo, st->offsets.next, cur_head);

	uint64_t our_si_addr = (uint64_t)(uintptr_t)g_akane_syn_soinfo;
	bool ok = akl_write_qword(st->solist_addr, our_si_addr);
	if (ok) {
		st->solist_value = our_si_addr;
		g_akane_syn_active = true;
	}

	if (dlm)
		pthread_mutex_unlock(dlm);

	return ok;
}
