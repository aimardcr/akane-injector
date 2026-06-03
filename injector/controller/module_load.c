#define _GNU_SOURCE
#include "module_load.h"
#include "module_blobs.h"
#include "log.h"

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/utsname.h>

#define DEV_AKANE "/dev/akane"

static int sys_memfd_create(const char *name, unsigned int flags)
{
	return (int)syscall(__NR_memfd_create, name, flags);
}

static int sys_finit_module(int fd, const char *params, int flags)
{
	return (int)syscall(__NR_finit_module, fd, params, flags);
}

/* Parse uname.release (e.g. "5.10.236-android12-...") for kernel major.minor
 * and the -androidN tag. Unparsed fields are left untouched; returns 0 if at
 * least major.minor parsed. */
static int parse_kernel_release(const char *rel,
                                int *android_out,
                                int *major_out, int *minor_out)
{
	int kmaj = 0, kmin = 0;
	if (sscanf(rel, "%d.%d", &kmaj, &kmin) != 2)
		return -1;
	*major_out = kmaj;
	*minor_out = kmin;

	const char *tag = strstr(rel, "-android");
	if (tag) {
		int android = 0;
		if (sscanf(tag, "-android%d", &android) == 1)
			*android_out = android;
	}
	return 0;
}

/* Best-matching blob: exact (android, major.minor), else same major.minor any
 * android, else NULL. */
static const struct akane_ko_blob *select_blob(int android, int kmaj, int kmin)
{
	const struct akane_ko_blob *fallback = NULL;
	for (unsigned i = 0; i < akane_ko_blob_count; i++) {
		const struct akane_ko_blob *b = &akane_ko_blobs[i];
		if (b->kernel_major != kmaj || b->kernel_minor != kmin)
			continue;
		if (b->android == android)
			return b;
		if (!fallback)
			fallback = b;
	}
	return fallback;
}

static void log_supported_blobs(void)
{
	if (akane_ko_blob_count == 0) {
		ERR("this injector was built with no kernel-module blobs");
		ERR("did 'make module' produce any out/module/*/akane.ko?");
		return;
	}
	ERR("supported kernel variants in this injector:");
	for (unsigned i = 0; i < akane_ko_blob_count; i++) {
		ERR("  - %s", akane_ko_blobs[i].label);
	}
}

int akane_module_ensure_loaded(void)
{
	if (access(DEV_AKANE, F_OK) == 0)
		return 0;

	struct utsname uts;
	if (uname(&uts) != 0) {
		ERR("uname: %s", strerror(errno));
		return -1;
	}

	int android = 0, kmaj = 0, kmin = 0;
	if (parse_kernel_release(uts.release, &android, &kmaj, &kmin) != 0) {
		ERR("could not parse kernel release: '%s'", uts.release);
		log_supported_blobs();
		return -1;
	}

	const struct akane_ko_blob *b = select_blob(android, kmaj, kmin);
	if (!b) {
		ERR("no embedded akane.ko matches device kernel %d.%d (android%d)",
		    kmaj, kmin, android);
		log_supported_blobs();
		return -1;
	}

	int exact = (b->android == android);
	DETAIL("kernel %d.%d-android%d -> embedded blob '%s' (%s)",
	       kmaj, kmin, android, b->label,
	       exact ? "exact" : "kernel-only fallback");

	size_t blob_size = (size_t)(b->end - b->start);
	if (blob_size == 0) {
		ERR("blob '%s' is empty (build artifact corrupt?)", b->label);
		return -1;
	}

	/* memfd: a kernel-backed fd with no filesystem artifact for finit_module. */
	int fd = sys_memfd_create("akane.ko", 0);
	if (fd < 0) {
		ERR("memfd_create: %s", strerror(errno));
		return -1;
	}

	const unsigned char *p = b->start;
	size_t remaining = blob_size;
	while (remaining > 0) {
		ssize_t n = write(fd, p, remaining);
		if (n <= 0) {
			ERR("write blob to memfd: %s", strerror(errno));
			close(fd);
			return -1;
		}
		p += n;
		remaining -= (size_t)n;
	}

	if (sys_finit_module(fd, "", 0) < 0) {
		if (errno == EEXIST) {
			/* Loaded concurrently; success if /dev/akane now exists. */
			close(fd);
			return access(DEV_AKANE, F_OK) == 0 ? 0 : -1;
		}
		ERR("finit_module '%s': %s", b->label, strerror(errno));
		if (errno == ENOEXEC)
			ERR("  (vermagic / KMI mismatch -- kernel rejected the module)");
		else if (errno == EPERM)
			ERR("  (need CAP_SYS_MODULE; run as root)");
		close(fd);
		return -1;
	}
	close(fd);

	/* devtmpfs may need a tick to publish /dev/akane after init (1s timeout). */
	for (int i = 0; i < 50; i++) {
		if (access(DEV_AKANE, F_OK) == 0) {
			DETAIL("loaded akane.ko (%zu bytes from '%s')",
			       blob_size, b->label);
			return 0;
		}
		usleep(20000);
	}
	ERR("module loaded but " DEV_AKANE " never appeared");
	return -1;
}
