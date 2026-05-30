/* Copyright (c) 2025 ThePedroo. All rights reserved.
 *
 * This source code is licensed under the GNU AGPLv3 License found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * akane fork: routes CSOLoader's diagnostic macros to stderr instead of
 * logcat, gated by a runtime verbosity level the injector sets. The
 * default level is 0 (errors + warnings only) so the controller's
 * console output stays clean. -v sets level 1 (info), -vv sets 2 (debug).
 */
#ifndef LOGGING_H
#define LOGGING_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define LOG_TAG "csoloader"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Set by the controller. 0 = silent (default), non-zero = all
 * CSOLoader diagnostics route to stderr. The injector flips this on
 * with -v. Fatal aborts still emit so we know what killed us.
 */
extern int g_csoloader_verbose;

#ifdef __cplusplus
}
#endif

#define _AKANE_CSO_LOG(level_str, ...) do { \
	fprintf(stderr, "[" level_str "] " LOG_TAG ": " __VA_ARGS__); \
	fputc('\n', stderr); \
} while (0)

#define LOGD(...) do { if (g_csoloader_verbose) _AKANE_CSO_LOG("D", __VA_ARGS__); } while (0)
#define LOGI(...) do { if (g_csoloader_verbose) _AKANE_CSO_LOG("I", __VA_ARGS__); } while (0)
#define LOGW(...) do { if (g_csoloader_verbose) _AKANE_CSO_LOG("W", __VA_ARGS__); } while (0)
#define LOGE(...) do { if (g_csoloader_verbose) _AKANE_CSO_LOG("E", __VA_ARGS__); } while (0)
#define LOGF(...) do { _AKANE_CSO_LOG("F", __VA_ARGS__); abort(); } while (0)
#define PLOGE(fmt, ...) do { \
	if (g_csoloader_verbose) \
		fprintf(stderr, "[E] " LOG_TAG ": " fmt ": %s\n", \
			##__VA_ARGS__, strerror(errno)); \
} while (0)

#endif /* LOGGING_H */
