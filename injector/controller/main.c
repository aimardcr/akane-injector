/*
 * akane-injector -- traceless external dynamic linker for Android.
 *
 *   akane-injector --pid PID --so PATH [-v]
 *
 * Loads any .so into a target via /dev/akane: relocations resolve against the
 * target's own libc/libm/libdl, .init_array fires inside the target, and the
 * .so persists past the injector's exit. The .so needs no awareness of akane.
 */
#define _GNU_SOURCE
#include "args.h"
#include "inject.h"
#include "log.h"
#include "module_load.h"

int akane_log_verbose = 0;
extern int g_csoloader_verbose;   /* defined by CSOLoader; we set it from args */

int main(int argc, char **argv)
{
	struct akane_args args;
	int rc = akane_args_parse(argc, argv, &args);
	if (rc == 1) return 0;     /* --help */
	if (rc != 0) return rc;    /* bad args */

	akane_log_verbose = args.verbose;
	g_csoloader_verbose = args.verbose;

	/* Loads the embedded akane.ko if /dev/akane isn't present; idempotent. */
	if (akane_module_ensure_loaded() != 0)
		return 1;

	return akane_inject(&args);
}
