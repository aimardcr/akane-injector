#define _GNU_SOURCE
#include "payload.h"
#include "log.h"

#include <stdint.h>
#include <string.h>
#include <elf.h>
#include <link.h>

#include "csoloader.h"
#include "linker.h"
#include "elf_util.h"

/* Find an exported symbol across all loaded deps; returns its target VA. */
static uint64_t resolve_dep_symbol(const struct linker *lk, const char *name)
{
	for (int i = 0; i < lk->dep_count; i++) {
		struct csoloader_elf *dep = lk->dependencies[i].img;
		if (!dep) continue;
		ElfW(Addr) addr = csoloader_elf_symb_address_exported(dep, name);
		if (addr) return (uint64_t)addr;
	}
	return 0;
}

/* Target-side VA + size of the .dynstr block (from PT_DYNAMIC DT_STRTAB/STRSZ);
 * 0 size if absent. */
static void find_dynstr_target_range(struct csoloader_elf *img,
                                     uint64_t *addr_out, uint64_t *size_out)
{
	*addr_out = 0;
	*size_out = 0;
	if (!img || !img->header) return;

	ElfW(Ehdr) *eh = img->header;
	if (eh->e_phoff == 0 || eh->e_phnum == 0) return;

	ElfW(Phdr) *phdr = (ElfW(Phdr) *)((uint8_t *)eh + eh->e_phoff);
	ElfW(Addr) dyn_vaddr = 0;
	for (int i = 0; i < eh->e_phnum; i++) {
		if (phdr[i].p_type == PT_DYNAMIC) {
			dyn_vaddr = phdr[i].p_vaddr;
			break;
		}
	}
	if (!dyn_vaddr) return;

	ElfW(Dyn) *dyn = (ElfW(Dyn) *)((uintptr_t)img->base + dyn_vaddr - img->bias);
	ElfW(Addr) strtab_va = 0;
	uint64_t   strsz     = 0;
	for (ElfW(Dyn) *d = dyn; d->d_tag != DT_NULL; d++) {
		if (d->d_tag == DT_STRTAB) strtab_va = d->d_un.d_ptr;
		else if (d->d_tag == DT_STRSZ) strsz = d->d_un.d_val;
	}
	if (!strtab_va || !strsz) return;

	*addr_out = (uint64_t)((uintptr_t)img->target_base + strtab_va - img->bias);
	*size_out = strsz;
}

/* Target-side VA + size of the .note.gnu.build-id record in PT_NOTE
 * (note layout: namesz, descsz, type, then 4-padded name + desc). */
#ifndef NT_GNU_BUILD_ID
#define NT_GNU_BUILD_ID 3
#endif
static void find_buildid_target_range(struct csoloader_elf *img,
                                      uint64_t *addr_out, uint64_t *size_out)
{
	*addr_out = 0;
	*size_out = 0;
	if (!img || !img->header) return;

	ElfW(Ehdr) *eh = img->header;
	if (eh->e_phoff == 0 || eh->e_phnum == 0) return;

	ElfW(Phdr) *phdr = (ElfW(Phdr) *)((uint8_t *)eh + eh->e_phoff);
	for (int i = 0; i < eh->e_phnum; i++) {
		if (phdr[i].p_type != PT_NOTE) continue;
		uint8_t *p   = (uint8_t *)((uintptr_t)img->base
		                           + phdr[i].p_vaddr - img->bias);
		uint8_t *end = p + phdr[i].p_filesz;
		while (p + 12 <= end) {
			uint32_t namesz, descsz, type;
			memcpy(&namesz, p,     4);
			memcpy(&descsz, p + 4, 4);
			memcpy(&type,   p + 8, 4);
			size_t name_aligned = (namesz + 3) & ~3u;
			size_t desc_aligned = (descsz + 3) & ~3u;
			size_t rec_len = 12 + name_aligned + desc_aligned;
			if (p + rec_len > end || rec_len > (size_t)phdr[i].p_filesz)
				break;
			if (type == NT_GNU_BUILD_ID && namesz == 4 &&
			    memcmp(p + 12, "GNU\0", 4) == 0) {
				*addr_out = (uint64_t)((uintptr_t)img->target_base
				                       + phdr[i].p_vaddr - img->bias
				                       + (p - (uint8_t *)((uintptr_t)img->base
				                                          + phdr[i].p_vaddr - img->bias)));
				*size_out = rec_len;
				return;
			}
			p += rec_len;
		}
	}
}

/* Target VA of `img`'s GOT slot for a JMPREL symbol (PT_DYNAMIC DT_JMPREL),
 * or 0 if not found. */
static uint64_t find_jumpslot_target_va(struct csoloader_elf *img, const char *name)
{
	if (!img || !img->header) return 0;
	ElfW(Ehdr) *eh = img->header;
	if (eh->e_phoff == 0 || eh->e_phnum == 0) return 0;

	ElfW(Phdr) *phdr = (ElfW(Phdr) *)((uint8_t *)eh + eh->e_phoff);
	ElfW(Addr) dyn_vaddr = 0;
	for (int i = 0; i < eh->e_phnum; i++) {
		if (phdr[i].p_type == PT_DYNAMIC) {
			dyn_vaddr = phdr[i].p_vaddr;
			break;
		}
	}
	if (!dyn_vaddr) return 0;

	ElfW(Dyn) *dyn = (ElfW(Dyn) *)((uintptr_t)img->base + dyn_vaddr - img->bias);

	ElfW(Addr) jmprel_va = 0, symtab_va = 0, strtab_va = 0;
	uint64_t pltrelsz = 0;
	int pltrel = DT_REL;
	for (ElfW(Dyn) *d = dyn; d->d_tag != DT_NULL; d++) {
		switch (d->d_tag) {
		case DT_JMPREL:   jmprel_va = d->d_un.d_ptr; break;
		case DT_PLTRELSZ: pltrelsz  = d->d_un.d_val; break;
		case DT_PLTREL:   pltrel    = (int)d->d_un.d_val; break;
		case DT_SYMTAB:   symtab_va = d->d_un.d_ptr; break;
		case DT_STRTAB:   strtab_va = d->d_un.d_ptr; break;
		}
	}
	if (!jmprel_va || !pltrelsz || pltrel != DT_RELA) return 0;
	if (!symtab_va || !strtab_va) return 0;

	ElfW(Sym) *symtab = (ElfW(Sym) *)((uintptr_t)img->base + symtab_va - img->bias);
	char *strtab = (char *)((uintptr_t)img->base + strtab_va - img->bias);
	ElfW(Rela) *rela = (ElfW(Rela) *)((uintptr_t)img->base + jmprel_va - img->bias);
	size_t n = pltrelsz / sizeof(ElfW(Rela));

	for (size_t i = 0; i < n; i++) {
		uint32_t sym_idx = ELF64_R_SYM(rela[i].r_info);
		const char *sname = strtab + symtab[sym_idx].st_name;
		if (strcmp(sname, name) == 0)
			return (uint64_t)((uintptr_t)img->target_base
					+ rela[i].r_offset - img->bias);
	}
	return 0;
}

int akane_payload_load(struct akane_backend *backend, const char *so_path,
                       struct akane_payload_info *out)
{
	struct csoloader lib = {0};
	lib.mem_ops = &backend->ops;

	memset(out, 0, sizeof(*out));

	if (!csoloader_load(&lib, so_path)) {
		ERR("load failed: %s", so_path);
		return -1;
	}

	size_t map_kib = lib.linker.main_map_size / 1024;
	uintptr_t map_lo = (uintptr_t)lib.img->target_base;
	uintptr_t map_hi = map_lo + lib.linker.main_map_size;
	out->base     = (uint64_t)map_lo;
	out->map_size = (uint64_t)lib.linker.main_map_size;
	DETAIL("mapped 0x%lx-0x%lx (%zu KiB)",
	       (unsigned long)map_lo, (unsigned long)map_hi, map_kib);

	if (lib.linker.dep_count > 0) {
		DETAIL("resolved %d %s",
		       lib.linker.dep_count,
		       lib.linker.dep_count == 1 ? "dependency" : "dependencies");
	}

	/* Resolve init_array *before* abandon tears the linker down. */
	if (lib.img->init_array && lib.img->init_array_count > 0) {
		uintptr_t off = (uintptr_t)lib.img->init_array
		              - (uintptr_t)lib.img->base;
		out->init_array_target = (uint64_t)((uintptr_t)lib.img->target_base + off);
		out->init_array_count  = (uint64_t)lib.img->init_array_count;
		DETAIL("init_array: %llu %s at 0x%llx",
		       (unsigned long long)out->init_array_count,
		       out->init_array_count == 1 ? "entry" : "entries",
		       (unsigned long long)out->init_array_target);
	} else {
		DETAIL("init_array: none");
	}

	/* pthread_create lets the bootstrap run .init_array on a fresh thread
	 * instead of the hijacked one. */
	if (out->init_array_count > 0) {
		out->pthread_create_target = resolve_dep_symbol(&lib.linker, "pthread_create");
		if (!out->pthread_create_target) {
			ERR("pthread_create not resolved in any dep; .init_array would block hijacked thread");
			csoloader_abandon(&lib);
			return -1;
		}
		DETAIL("pthread_create at 0x%llx",
		       (unsigned long long)out->pthread_create_target);
	}

	/* GOT slots to redirect to the runtime hooks; 0 means the payload
	 * doesn't import that function and the patcher skips it. */
	out->got_dl_iterate_phdr = find_jumpslot_target_va(lib.img, "dl_iterate_phdr");
	out->got_dladdr          = find_jumpslot_target_va(lib.img, "dladdr");
	out->got_dlopen          = find_jumpslot_target_va(lib.img, "dlopen");
	out->got_dlsym           = find_jumpslot_target_va(lib.img, "dlsym");
	out->got_dlclose         = find_jumpslot_target_va(lib.img, "dlclose");
	out->got_dlerror         = find_jumpslot_target_va(lib.img, "dlerror");

	/* phdr table for the registry; the runtime synthesizes dl_phdr_info from it. */
	if (lib.img->header && lib.img->header->e_phoff && lib.img->header->e_phnum) {
		out->phdr_target = (uint64_t)((uintptr_t)lib.img->target_base
		                              + lib.img->header->e_phoff);
		out->phnum = lib.img->header->e_phnum;
	}

	/* Metadata ranges for the post-init strip, computed while we still own
	 * the loader handle. */
	find_dynstr_target_range (lib.img, &out->strip_dynstr_addr,  &out->strip_dynstr_size);
	find_buildid_target_range(lib.img, &out->strip_buildid_addr, &out->strip_buildid_size);

	csoloader_abandon(&lib);
	return 0;
}
