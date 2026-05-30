/* Copyright (c) 2025 ThePedroo. All rights reserved.
 *
 * This source code is licensed under the GNU AGPLv3 License found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * csoloader_mem_ops: pluggable memory backend for CSOLoader.
 *
 * Default backend (csoloader_local_mem_ops) is a thin wrapper over
 * mmap/mprotect/munmap, preserving the loader's original in-process
 * behavior with no observable difference. Cross-process backends
 * (e.g. akane_backend.c) implement the same vtable but redirect into
 * another process's address space.
 *
 * Lifecycle of one library:
 *   ops->reserve()                                 -> ctx + storage base
 *   ops->map_segment() / ops->map_zero() / ...     any number of times
 *   relocations / direct writes via base+offset    (step 1: direct; the
 *                                                   cross-process backend
 *                                                   will defer these to a
 *                                                   later patch)
 *   ops->release()                                 -> tear down
 */
#ifndef CSOLOADER_MEM_OPS_H
#define CSOLOADER_MEM_OPS_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct csoloader_mem_ops;
struct csoloader_mem_ctx;   /* opaque, backend-specific */

struct csoloader_mem_ops {
	/* Reserve `size` bytes of address space.
	 *   *base_out   = where bytes are read/written in THIS process
	 *                 (the storage / mirror).
	 *   *target_out = runtime VA the image will live at (in local mode
	 *                 equal to *base_out; in cross-process mode it's an
	 *                 address in the target).
	 * `hint` may be NULL. On success returns 0. */
	int (*reserve)(struct csoloader_mem_ops *self,
		       void *hint, size_t size,
		       struct csoloader_mem_ctx **ctx_out,
		       void **base_out,
		       void **target_out);

	/* Load `len` bytes from fd at file_off into the reservation at
	 * (base + storage_off). prot is initial protection flags. */
	int (*map_segment)(struct csoloader_mem_ctx *ctx,
			   void *base, int fd, off_t file_off,
			   size_t storage_off, size_t len, int prot);

	/* Zero `len` bytes at (base + storage_off). */
	int (*map_zero)(struct csoloader_mem_ctx *ctx,
			void *base, size_t storage_off, size_t len, int prot);

	/* Change protection on a range. Cross-process backends may defer the
	 * actual mprotect/mem_protect until commit(). */
	int (*protect)(struct csoloader_mem_ctx *ctx,
		       void *base, size_t storage_off, size_t len, int prot);

	/* Called by the linker after relocations and RELRO are done, before
	 * (would-be) constructors. In-process backends: no-op. Cross-process
	 * backends: push the mirror to target and apply final per-range
	 * protections. May be NULL (treated as no-op). */
	int (*commit)(struct csoloader_mem_ctx *ctx, void *base, size_t size);

	/* Tear down everything (called on csoloader_unload). */
	int (*release)(struct csoloader_mem_ctx *ctx, void *base, size_t size);

	/* Called on csoloader_abandon: drop bookkeeping but leave the loaded
	 * image alive (in-process: don't munmap; cross-process: don't free
	 * the target VMA -- "fire and forget" semantics for an injector).
	 * In-process backends typically make this a no-op. May be NULL. */
	int (*detach)(struct csoloader_mem_ctx *ctx, void *base, size_t size);

	/* Locate a DT_NEEDED dependency in the target's address space.
	 * `name` is a SONAME basename (e.g. "libc.so").
	 * On success: writes the lib's filesystem path to *path_out (so the
	 * caller can mmap it for symbol parsing) and the lib's target-side
	 * load base to *target_base_out, returns 0.
	 * Returns -1 if the lib is not loaded in the target. May be NULL on
	 * in-process backends, in which case the loader falls back to its
	 * default dl_iterate_phdr-based lookup. */
	int (*find_dep_target)(struct csoloader_mem_ops *self,
			       const char *name,
			       char *path_out, size_t path_cap,
			       void **target_base_out);
};

extern struct csoloader_mem_ops csoloader_local_mem_ops;

#ifdef __cplusplus
}
#endif

#endif /* CSOLOADER_MEM_OPS_H */
