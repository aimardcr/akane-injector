/* Copyright (c) 2025 ThePedroo. All rights reserved.
 *
 * This source code is licensed under the GNU AGPLv3 License found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * Local memory backend.
 *
 * Each op is a direct passthrough to the libc primitive that CSOLoader was
 * calling before the abstraction landed. There is no per-region state, so
 * ctx is always NULL.
 */
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>

#include "csoloader_mem_ops.h"

static int lb_reserve(struct csoloader_mem_ops *self,
		      void *hint, size_t size,
		      struct csoloader_mem_ctx **ctx_out,
		      void **base_out, void **target_out)
{
	int flags = MAP_PRIVATE | MAP_ANONYMOUS;
	if (hint) flags |= MAP_FIXED;

	void *p = mmap(hint, size, PROT_NONE, flags, -1, 0);
	if (p == MAP_FAILED)
		return -1;

	(void)self;
	*ctx_out    = NULL;
	*base_out   = p;
	*target_out = p;       /* in-process: storage IS the runtime VA */
	return 0;
}

static int lb_map_segment(struct csoloader_mem_ctx *ctx,
			  void *base, int fd, off_t file_off,
			  size_t storage_off, size_t len, int prot)
{
	void *want = (char *)base + storage_off;
	void *got  = mmap(want, len, prot, MAP_FIXED | MAP_PRIVATE, fd, file_off);
	(void)ctx;
	return (got == want) ? 0 : -1;
}

static int lb_map_zero(struct csoloader_mem_ctx *ctx,
		       void *base, size_t storage_off, size_t len, int prot)
{
	void *want = (char *)base + storage_off;
	void *got  = mmap(want, len, prot,
			  MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	(void)ctx;
	return (got == want) ? 0 : -1;
}

static int lb_protect(struct csoloader_mem_ctx *ctx,
		      void *base, size_t storage_off, size_t len, int prot)
{
	(void)ctx;
	return mprotect((char *)base + storage_off, len, prot);
}

static int lb_release(struct csoloader_mem_ctx *ctx, void *base, size_t size)
{
	(void)ctx;
	return munmap(base, size);
}

/* Local backend is in-process, so commit and detach are no-ops. */
static int lb_commit(struct csoloader_mem_ctx *ctx, void *base, size_t size)
{
	(void)ctx; (void)base; (void)size;
	return 0;
}

static int lb_detach(struct csoloader_mem_ctx *ctx, void *base, size_t size)
{
	(void)ctx; (void)base; (void)size;
	return 0;
}

struct csoloader_mem_ops csoloader_local_mem_ops = {
	.reserve     = lb_reserve,
	.map_segment = lb_map_segment,
	.map_zero    = lb_map_zero,
	.protect     = lb_protect,
	.commit      = lb_commit,
	.release     = lb_release,
	.detach      = lb_detach,
};
