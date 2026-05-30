/* Copyright (c) 2025 ThePedroo. All rights reserved.
 *
 * This source code is licensed under the GNU AGPLv3 License found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * Akane cross-process backend for CSOLoader.
 *
 * Wraps /dev/akane ioctls behind a csoloader_mem_ops vtable so a
 * controller process can load shared libraries into a different PID's
 * address space.
 *
 * Usage:
 *   struct akane_backend ab;
 *   if (akane_backend_init(&ab, target_pid) != 0) ...;
 *   struct csoloader lib = { .mem_ops = &ab.ops };
 *   csoloader_load(&lib, "/path/to/lib.so");
 *   ...
 *   csoloader_unload(&lib);
 *   akane_backend_deinit(&ab);
 */
#ifndef AKANE_BACKEND_H
#define AKANE_BACKEND_H

#include <sys/types.h>

#include "csoloader_mem_ops.h"

#ifdef __cplusplus
extern "C" {
#endif

struct akane_backend {
	struct csoloader_mem_ops ops;     /* install in csoloader.mem_ops */
	pid_t target_pid;
	int   akane_fd;
};

int  akane_backend_init  (struct akane_backend *be, pid_t target_pid);
void akane_backend_deinit(struct akane_backend *be);

#ifdef __cplusplus
}
#endif

#endif
