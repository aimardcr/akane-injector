/*
 * akane runtime library: dl* hook implementations + a payload registry the
 * controller fills via mem_write before the payload's init_array runs.
 *
 * The controller patches the payload's GOT to route dl* imports here, so
 * libraries that introspect their own image (Frida gadget) can find
 * themselves via dl_iterate_phdr / dladdr despite being outside bionic's
 * solist. Non-payload code and this library's own GOT are untouched, so our
 * hooks forwarding to the real implementations still reach solist normally.
 */

#define _GNU_SOURCE
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <dlfcn.h>
#include <link.h>
#include <elf.h>

#include "linker.h"

/* Registry capacity: one entry per concurrent injection. */
#define AKANE_RT_MAX_PAYLOADS  16
#define AKANE_RT_NAME_LEN      256

struct akane_rt_payload {
	void              *base;
	uint64_t           size;
	const ElfW(Phdr)  *phdr;
	uint16_t           phnum;
	uint16_t           _pad0;
	uint32_t           _pad1;
};

/* Controller's API surface, resolved via dynsym and written via mem_write. */
__attribute__((visibility("default")))
struct akane_rt_payload g_akane_rt_payloads[AKANE_RT_MAX_PAYLOADS];

__attribute__((visibility("default")))
char g_akane_rt_names[AKANE_RT_MAX_PAYLOADS][AKANE_RT_NAME_LEN];

__attribute__((visibility("default")))
int32_t g_akane_rt_payload_count;

/* Per-hook call counters; the controller reads these as a diagnostic. */
#define AKANE_RT_CC_DL_ITERATE_PHDR 0
#define AKANE_RT_CC_DLADDR          1
#define AKANE_RT_CC_DLOPEN          2
#define AKANE_RT_CC_DLSYM           3
#define AKANE_RT_CC_DLCLOSE         4
#define AKANE_RT_CC_DLERROR         5
#define AKANE_RT_CC_COUNT           6

__attribute__((visibility("default")))
volatile uint64_t g_akane_rt_call_counts[AKANE_RT_CC_COUNT];

/* Forward decls so akane_rt_dlsym can return these by name. */
__attribute__((visibility("default")))
int akane_rt_dl_iterate_phdr(int (*cb)(struct dl_phdr_info *, size_t, void *),
			     void *data);
__attribute__((visibility("default")))
int akane_rt_dladdr(const void *addr, Dl_info *info);
__attribute__((visibility("default")))
void *akane_rt_dlopen(const char *filename, int flags);
__attribute__((visibility("default")))
void *akane_rt_dlsym(void *handle, const char *symbol);
__attribute__((visibility("default")))
int akane_rt_dlclose(void *handle);
__attribute__((visibility("default")))
char *akane_rt_dlerror(void);

/*
 * Self-contained dlsym for RTLD_DEFAULT. Bionic resolves RTLD_DEFAULT via the
 * caller's soinfo (__builtin_return_address); an akane payload isn't in solist,
 * so that always fails. Instead we walk solist via dl_iterate_phdr and parse
 * each module's dynsym/strtab/hash ourselves.
 */
struct rt_dlsym_search {
	const char *name;
	void       *result;
};

static uint32_t rt_elf_hash(const char *name)
{
	uint32_t h = 0, g;
	while (*name) {
		h = (h << 4) + (uint8_t)*name++;
		g = h & 0xf0000000u;
		if (g) h ^= g >> 24;
		h &= ~g;
	}
	return h;
}

static uint32_t rt_gnu_hash(const char *name)
{
	uint32_t h = 5381;
	while (*name)
		h = h * 33 + (uint8_t)*name++;
	return h;
}

static int rt_dlsym_iter_cb(struct dl_phdr_info *info, size_t size, void *data)
{
	(void)size;
	struct rt_dlsym_search *s = (struct rt_dlsym_search *)data;

	const ElfW(Phdr) *dyn_phdr = NULL;
	for (int i = 0; i < info->dlpi_phnum; i++) {
		if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
			dyn_phdr = &info->dlpi_phdr[i];
			break;
		}
	}
	if (!dyn_phdr)
		return 0;

	const ElfW(Dyn) *dyn = (const ElfW(Dyn) *)
		((uintptr_t)info->dlpi_addr + dyn_phdr->p_vaddr);

	const ElfW(Sym) *symtab   = NULL;
	const char      *strtab   = NULL;
	const uint32_t  *hash     = NULL;
	const uint32_t  *gnu_hash = NULL;

	for (; dyn->d_tag != DT_NULL; dyn++) {
		switch (dyn->d_tag) {
		case DT_SYMTAB:
			symtab = (const ElfW(Sym) *)
				((uintptr_t)info->dlpi_addr + dyn->d_un.d_ptr);
			break;
		case DT_STRTAB:
			strtab = (const char *)
				((uintptr_t)info->dlpi_addr + dyn->d_un.d_ptr);
			break;
		case DT_HASH:
			hash = (const uint32_t *)
				((uintptr_t)info->dlpi_addr + dyn->d_un.d_ptr);
			break;
		case 0x6ffffef5: /* DT_GNU_HASH */
			gnu_hash = (const uint32_t *)
				((uintptr_t)info->dlpi_addr + dyn->d_un.d_ptr);
			break;
		}
	}
	if (!symtab || !strtab)
		return 0;

	/* GNU hash first (modern bionic uses it almost exclusively). */
	if (gnu_hash) {
		uint32_t nbucket    = gnu_hash[0];
		uint32_t symoffset  = gnu_hash[1];
		uint32_t bloom_size = gnu_hash[2];
		uint32_t bloom_shift = gnu_hash[3];
		const uintptr_t *bloom = (const uintptr_t *)(gnu_hash + 4);
		const uint32_t  *buckets = (const uint32_t *)(bloom + bloom_size);
		const uint32_t  *chain   = buckets + nbucket;

		uint32_t h = rt_gnu_hash(s->name);
		uintptr_t word = bloom[(h / (sizeof(uintptr_t) * 8)) % bloom_size];
		uintptr_t mask = ((uintptr_t)1 << (h % (sizeof(uintptr_t) * 8))) |
				 ((uintptr_t)1 << ((h >> bloom_shift) % (sizeof(uintptr_t) * 8)));
		if ((word & mask) != mask)
			goto try_elf_hash;

		uint32_t idx = buckets[h % nbucket];
		if (idx < symoffset)
			goto try_elf_hash;

		for (;;) {
			uint32_t chain_h = chain[idx - symoffset];
			if ((chain_h | 1) == (h | 1)) {
				const ElfW(Sym) *sym = &symtab[idx];
				if (strcmp(strtab + sym->st_name, s->name) == 0
				    && sym->st_shndx != 0) {
					s->result = (void *)
						((uintptr_t)info->dlpi_addr + sym->st_value);
					return 1;
				}
			}
			if (chain_h & 1)
				break;
			idx++;
		}
	}

try_elf_hash:
	if (hash) {
		uint32_t nbucket = hash[0];
		const uint32_t *bucket = hash + 2;
		const uint32_t *chain  = bucket + nbucket;

		uint32_t h = rt_elf_hash(s->name);
		for (uint32_t idx = bucket[h % nbucket]; idx; idx = chain[idx]) {
			const ElfW(Sym) *sym = &symtab[idx];
			if (sym->st_shndx != 0
			    && strcmp(strtab + sym->st_name, s->name) == 0) {
				s->result = (void *)
					((uintptr_t)info->dlpi_addr + sym->st_value);
				return 1;
			}
		}
	}
	return 0;
}

static void *rt_dlsym_default(const char *symbol)
{
	struct rt_dlsym_search s = { .name = symbol, .result = NULL };
	dl_iterate_phdr(rt_dlsym_iter_cb, &s);
	return s.result;
}

/* dl_iterate_phdr hook: emit each registered payload, then forward to libc. */
__attribute__((visibility("default")))
int akane_rt_dl_iterate_phdr(int (*cb)(struct dl_phdr_info *, size_t, void *),
			     void *data)
{
	g_akane_rt_call_counts[AKANE_RT_CC_DL_ITERATE_PHDR]++;
	int n = g_akane_rt_payload_count;
	if (n > AKANE_RT_MAX_PAYLOADS)
		n = AKANE_RT_MAX_PAYLOADS;

	for (int i = 0; i < n; i++) {
		struct akane_rt_payload *p = &g_akane_rt_payloads[i];
		if (!p->base)
			continue;

		struct dl_phdr_info info;
		__builtin_memset(&info, 0, sizeof(info));
		info.dlpi_addr  = (ElfW(Addr))p->base;
		info.dlpi_name  = g_akane_rt_names[i];
		info.dlpi_phdr  = p->phdr;
		info.dlpi_phnum = p->phnum;

		int r = cb(&info, sizeof(info), data);
		if (r != 0)
			return r;
	}
	return dl_iterate_phdr(cb, data);
}

__attribute__((visibility("default")))
int akane_rt_dladdr(const void *addr, Dl_info *info)
{
	g_akane_rt_call_counts[AKANE_RT_CC_DLADDR]++;
	uintptr_t a = (uintptr_t)addr;
	int n = g_akane_rt_payload_count;
	if (n > AKANE_RT_MAX_PAYLOADS)
		n = AKANE_RT_MAX_PAYLOADS;

	for (int i = 0; i < n; i++) {
		struct akane_rt_payload *p = &g_akane_rt_payloads[i];
		if (!p->base || !p->size)
			continue;
		uintptr_t lo = (uintptr_t)p->base;
		if (a < lo || a >= lo + p->size)
			continue;
		if (info) {
			info->dli_fname = g_akane_rt_names[i];
			info->dli_fbase = p->base;
			info->dli_sname = NULL;
			info->dli_saddr = NULL;
		}
		return 1;
	}
	return dladdr(addr, info);
}

__attribute__((visibility("default")))
void *akane_rt_dlopen(const char *filename, int flags)
{
	g_akane_rt_call_counts[AKANE_RT_CC_DLOPEN]++;
	return dlopen(filename, flags);
}

__attribute__((visibility("default")))
void *akane_rt_dlsym(void *handle, const char *symbol)
{
	g_akane_rt_call_counts[AKANE_RT_CC_DLSYM]++;

	if (!symbol)
		return dlsym(handle, symbol);

	/* Known dl* names resolve to our hooks, so callers that cache the
	 * pointer (Gum-style) keep routing through us. */
	if (!strcmp(symbol, "dl_iterate_phdr"))
		return (void *)akane_rt_dl_iterate_phdr;
	if (!strcmp(symbol, "dladdr"))
		return (void *)akane_rt_dladdr;
	if (!strcmp(symbol, "dlopen"))
		return (void *)akane_rt_dlopen;
	if (!strcmp(symbol, "dlsym"))
		return (void *)akane_rt_dlsym;
	if (!strcmp(symbol, "dlclose"))
		return (void *)akane_rt_dlclose;
	if (!strcmp(symbol, "dlerror"))
		return (void *)akane_rt_dlerror;

	/* RTLD_DEFAULT/RTLD_NEXT need caller soinfo, which akane payloads lack;
	 * resolve ourselves and fall through to libc only on a miss. */
	if (handle == RTLD_DEFAULT || handle == RTLD_NEXT) {
		void *r = rt_dlsym_default(symbol);
		if (r)
			return r;
	}

	return dlsym(handle, symbol);
}

__attribute__((visibility("default")))
int akane_rt_dlclose(void *handle)
{
	g_akane_rt_call_counts[AKANE_RT_CC_DLCLOSE]++;
	return dlclose(handle);
}

__attribute__((visibility("default")))
char *akane_rt_dlerror(void)
{
	g_akane_rt_call_counts[AKANE_RT_CC_DLERROR]++;
	return dlerror();
}

/* Splice each registered payload into bionic's solist so it appears as a real
 * loaded module. Called by the bootstrap worker before init_array, under
 * --register-to-solist. */
__attribute__((visibility("default")))
int akane_rt_linker_register(void)
{
	if (!akane_linker_discover())
		return -1;

	int n = g_akane_rt_payload_count;
	if (n > AKANE_RT_MAX_PAYLOADS) n = AKANE_RT_MAX_PAYLOADS;

	int ok = 0;
	for (int i = 0; i < n; i++) {
		struct akane_rt_payload *p = &g_akane_rt_payloads[i];
		if (!p->base || !p->size)
			continue;
		if (akane_linker_register_payload(
			(uint64_t)p->base, p->size,
			(uint64_t)p->phdr, p->phnum,
			g_akane_rt_names[i]))
			ok++;
	}
	return ok > 0 ? 0 : -1;
}
