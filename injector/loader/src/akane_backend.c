/* Copyright (c) 2025 ThePedroo. All rights reserved.
 *
 * This source code is licensed under the GNU AGPLv3 License found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * Cross-process memory backend for CSOLoader, driven by /dev/akane.
 *
 * Lifecycle of one library:
 *   reserve     -> alloc_mem in target (RWX VMA, broad MAY-flags) +
 *                  malloc a controller-side mirror of the same size
 *   map_segment -> pread() ELF bytes from fd into the mirror
 *   map_zero    -> memset() into the mirror
 *   protect     -> record desired final per-range protection
 *   commit      -> mem_write(mirror -> target, full size) +
 *                  mem_protect each recorded range to its final perms
 *   release     -> AKANE_IOC_MEMORY_FREE + free(mirror)
 *
 * The mirror always stays writable in the controller during load, so the
 * intermediate "make-writable / restore-prot" mprotects from CSOLoader's
 * relocation engine are absorbed as record-only no-ops; only the LAST
 * recorded prot per (off, len) tuple matters at commit time.
 */
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "akane_backend.h"
#include "akane_uapi.h"

#define container_of(ptr, type, member) \
	((type *)((char *)(ptr) - offsetof(type, member)))

struct seg_prot {
	size_t off;
	size_t len;
	int    prot;
};

struct csoloader_mem_ctx {
	struct akane_backend *be;
	uint64_t handle;
	uint64_t target_addr;
	void    *mirror;
	size_t   size;

	struct seg_prot *segs;
	size_t segs_count;
	size_t segs_capacity;
};

static int seg_record(struct csoloader_mem_ctx *ctx,
		      size_t off, size_t len, int prot)
{
	if (ctx->segs_count == ctx->segs_capacity) {
		size_t cap = ctx->segs_capacity ? ctx->segs_capacity * 2 : 16;
		struct seg_prot *p = realloc(ctx->segs, cap * sizeof(*p));
		if (!p) return -1;
		ctx->segs = p;
		ctx->segs_capacity = cap;
	}
	ctx->segs[ctx->segs_count++] = (struct seg_prot){ off, len, prot };
	return 0;
}

static int akane_pidprot_from_unix(int prot)
{
	int p = 0;
	if (prot & PROT_READ)  p |= AKANE_PROT_READ;
	if (prot & PROT_WRITE) p |= AKANE_PROT_WRITE;
	if (prot & PROT_EXEC)  p |= AKANE_PROT_EXEC;
	return p;
}

static int ab_reserve(struct csoloader_mem_ops *self,
		      void *hint, size_t size,
		      struct csoloader_mem_ctx **ctx_out,
		      void **base_out, void **target_out)
{
	struct akane_backend *be = container_of(self, struct akane_backend, ops);
	struct csoloader_mem_ctx *ctx = calloc(1, sizeof(*ctx));
	if (!ctx) return -1;

	ctx->be    = be;
	ctx->size  = size;
	/*
	 * The mirror MUST be page-aligned: CSOLoader's segment loader does
	 * _page_start(base + p_vaddr) - base to compute storage offsets,
	 * which only gives sensible results when `base` itself sits on a
	 * page boundary. malloc() makes no such guarantee. Use mmap so we
	 * get both page alignment and zero-init in one shot (matching the
	 * behavior of MAP_ANONYMOUS / file tail past EOF in local mode).
	 */
	ctx->mirror = mmap(NULL, size, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (ctx->mirror == MAP_FAILED) {
		ctx->mirror = NULL;
		free(ctx);
		return -1;
	}

	/* The `hint` from CSOLoader was derived from /proc/self/maps in the
	 * controller -- meaningless (and usually colliding) in the target.
	 * Pass 0 so the kernel walks the target's own VMA list for a free
	 * gap via am_find_unmapped(). */
	(void)hint;
	struct akane_memory_alloc req = {
		.pid       = be->target_pid,
		/* Reserve with full perms so per-segment narrowing in commit
		 * is always allowed (MAY-flags follow initial prot in the
		 * kernel module). */
		.prot      = AKANE_PROT_READ | AKANE_PROT_WRITE | AKANE_PROT_EXEC,
		.size      = size,
		.hint_addr = 0,
		.addr      = 0,
		.handle    = 0,
	};
	if (ioctl(be->akane_fd, AKANE_IOC_MEMORY_ALLOC, &req) < 0) {
		fprintf(stderr,
			"akane_backend: AKANE_IOC_MEMORY_ALLOC(pid=%d, size=%zu): %s\n",
			be->target_pid, size, strerror(errno));
		munmap(ctx->mirror, size);   /* mmap'd above -- not free() */
		free(ctx);
		return -1;
	}

	ctx->handle      = req.handle;
	ctx->target_addr = req.addr;

	*ctx_out    = ctx;
	*base_out   = ctx->mirror;
	*target_out = (void *)(uintptr_t)req.addr;
	return 0;
}

static int ab_map_segment(struct csoloader_mem_ctx *ctx,
			  void *base, int fd, off_t file_off,
			  size_t storage_off, size_t len, int prot)
{
	(void)base;
	char *dst = (char *)ctx->mirror + storage_off;
	size_t remaining = len;
	while (remaining > 0) {
		ssize_t n = pread(fd, dst, remaining, file_off);
		if (n < 0) {
			if (errno == EINTR) continue;
			return -1;
		}
		if (n == 0) break;     /* EOF: the rest of the page is already
					* zero from calloc, matching what mmap
					* MAP_PRIVATE does past file end. */
		dst       += n;
		file_off  += n;
		remaining -= n;
	}
	return seg_record(ctx, storage_off, len, prot);
}

static int ab_map_zero(struct csoloader_mem_ctx *ctx,
		       void *base, size_t storage_off, size_t len, int prot)
{
	(void)base;
	memset((char *)ctx->mirror + storage_off, 0, len);
	return seg_record(ctx, storage_off, len, prot);
}

static int ab_protect(struct csoloader_mem_ctx *ctx,
		      void *base, size_t storage_off, size_t len, int prot)
{
	(void)base;
	/* Defer: just remember the latest desired prot for this range. */
	return seg_record(ctx, storage_off, len, prot);
}

static int ab_commit(struct csoloader_mem_ctx *ctx, void *base, size_t size)
{
	(void)base;
	struct akane_backend *be = ctx->be;

	/* 1. push the entire mirror to target in one shot. */
	struct akane_memory_io wio = {
		.pid  = be->target_pid,
		.addr = ctx->target_addr,
		.buf  = (uint64_t)(uintptr_t)ctx->mirror,
		.len  = size,
		.done = 0,
	};
	if (ioctl(be->akane_fd, AKANE_IOC_MEMORY_WRITE, &wio) < 0 ||
	    wio.done != size) {
		fprintf(stderr,
			"akane_backend: MEM_WRITE pid=%d addr=0x%llx size=%zu (done=%llu): %s\n",
			be->target_pid,
			(unsigned long long)ctx->target_addr, size,
			(unsigned long long)wio.done, strerror(errno));
		return -1;
	}

	/* 2. apply final per-range protections in recorded order. Last write
	 * to a given range wins, which mirrors what mprotect(2) would do. */
	for (size_t i = 0; i < ctx->segs_count; i++) {
		const struct seg_prot *s = &ctx->segs[i];
		struct akane_memory_protect pr = {
			.pid  = be->target_pid,
			.prot = akane_pidprot_from_unix(s->prot),
			.addr = ctx->target_addr + s->off,
			.len  = s->len,
		};
		if (ioctl(be->akane_fd, AKANE_IOC_MEMORY_PROTECT, &pr) < 0) {
			fprintf(stderr,
				"akane_backend: MEM_PROTECT off=0x%zx len=%zu prot=0x%x: %s\n",
				s->off, s->len, pr.prot, strerror(errno));
			return -1;
		}
	}
	return 0;
}

static int ab_release(struct csoloader_mem_ctx *ctx, void *base, size_t size)
{
	(void)base; (void)size;
	if (!ctx) return 0;

	struct akane_backend *be = ctx->be;
	if (ctx->handle) {
		struct akane_memory_handle req = { .handle = ctx->handle };
		if (ioctl(be->akane_fd, AKANE_IOC_MEMORY_FREE, &req) < 0) {
			/* Best-effort; the mapping may already be gone if the
			 * target exited. Don't fail the unload. */
			fprintf(stderr,
				"akane_backend: FREE_MEM handle=%llu: %s\n",
				(unsigned long long)ctx->handle, strerror(errno));
		}
	}
	if (ctx->mirror) munmap(ctx->mirror, ctx->size);
	free(ctx->segs);
	free(ctx);
	return 0;
}

/*
 * Detach: persistent injection. Tell the kernel to drop the handle but
 * KEEP the target's [akane:N] mapping alive. The target's pages stay
 * referenced via the live VMA; kernel-side bookkeeping migrates to the
 * detached list and is reclaimed on module unload. Then free our
 * controller-side mirror + ctx. After this, the .so persists in the
 * target until the target itself exits.
 */
static int ab_detach(struct csoloader_mem_ctx *ctx, void *base, size_t size)
{
	(void)base; (void)size;
	if (!ctx) return 0;

	struct akane_backend *be = ctx->be;
	if (ctx->handle) {
		struct akane_memory_handle req = { .handle = ctx->handle };
		if (ioctl(be->akane_fd, AKANE_IOC_MEMORY_DETACH, &req) < 0) {
			fprintf(stderr,
				"akane_backend: DETACH_MEM handle=%llu: %s\n",
				(unsigned long long)ctx->handle, strerror(errno));
			/* Fall through and free our side regardless. */
		}
	}
	if (ctx->mirror) munmap(ctx->mirror, ctx->size);
	free(ctx->segs);
	free(ctx);
	return 0;
}

/*
 * Walk /proc/<target_pid>/maps for a line whose path's basename matches
 * `name`. Take the lowest start address among matching lines as the
 * target-side load base (the first PT_LOAD lands there).
 */
static int ab_find_dep_target(struct csoloader_mem_ops *self,
			      const char *name,
			      char *path_out, size_t path_cap,
			      void **target_base_out)
{
	struct akane_backend *be = container_of(self, struct akane_backend, ops);
	char maps_path[64];
	snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", be->target_pid);

	FILE *f = fopen(maps_path, "r");
	if (!f) return -1;

	char line[1024];
	uint64_t lowest = 0;
	int found = 0;

	while (fgets(line, sizeof(line), f)) {
		uint64_t start, end, off, inode;
		char perms[8];
		unsigned int mj, mn;
		int pos = 0;
		if (sscanf(line, "%" SCNx64 "-%" SCNx64 " %7s %" SCNx64
			   " %x:%x %" SCNu64 " %n",
			   &start, &end, perms, &off, &mj, &mn, &inode, &pos) < 7)
			continue;
		if (pos == 0) continue;

		char *p = line + pos;
		while (*p == ' ' || *p == '\t') p++;
		char *eol = strchr(p, '\n');
		if (eol) *eol = '\0';
		if (*p == '\0' || *p == '[') continue;

		const char *base = strrchr(p, '/');
		base = base ? base + 1 : p;
		if (strcmp(base, name) != 0) continue;

		if (!found || start < lowest) {
			lowest = start;
			strncpy(path_out, p, path_cap - 1);
			path_out[path_cap - 1] = '\0';
			found = 1;
		}
	}

	fclose(f);
	if (!found) return -1;
	*target_base_out = (void *)(uintptr_t)lowest;
	return 0;
}

int akane_backend_init(struct akane_backend *be, pid_t target_pid)
{
	memset(be, 0, sizeof(*be));
	be->target_pid = target_pid;
	be->akane_fd   = open("/dev/akane", O_RDWR);
	if (be->akane_fd < 0) {
		fprintf(stderr, "akane_backend: open /dev/akane: %s\n",
			strerror(errno));
		return -1;
	}
	be->ops = (struct csoloader_mem_ops){
		.reserve         = ab_reserve,
		.map_segment     = ab_map_segment,
		.map_zero        = ab_map_zero,
		.protect         = ab_protect,
		.commit          = ab_commit,
		.release         = ab_release,
		.detach          = ab_detach,
		.find_dep_target = ab_find_dep_target,
	};
	return 0;
}

void akane_backend_deinit(struct akane_backend *be)
{
	if (be->akane_fd >= 0) {
		close(be->akane_fd);
		be->akane_fd = -1;
	}
}
