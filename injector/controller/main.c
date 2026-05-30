/*
 * akane-injector -- traceless external dynamic linker for Android.
 *
 *   akane-injector --pid PID --so PATH [-v]
 *
 * Loads any .so into a target process via /dev/akane: relocations resolve
 * against the target's own libc/libm/libdl, .init_array fires inside the
 * target, the .so persists past the injector's exit.
 *
 * The .so does not need to know about akane. The bootstrap that drives
 * .init_array iteration and resumes the hijacked thread is embedded in
 * this binary; per injection a small "boot region" is allocated in the
 * target and the bootstrap bytes are mem_written into it.
 *
 * Thread redirect uses /dev/akane's task_work primitive: the injector
 * writes init_array_addr / count / pthread_create_addr into the saved
 * state buffer at +384 (the contract bootstrap.S reads), then asks the
 * kernel to redirect a target thread to the bootstrap.
 *
 * Source layout (controller/):
 *   args.{h,c}     -- CLI parsing
 *   runtime.{h,c}  -- load libakane-runtime.so + resolve hook symbols
 *   payload.{h,c}  -- load user .so + resolve GOT slots, init_array,
 *                     pthread_create
 *   inject.{h,c}   -- orchestration: visibility, boot region, ELF wipe,
 *                     GOT patch, registry write, task_work, diagnostics
 *   log.h          -- INFO/DETAIL/ERR macros + verbose flag
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

	/* Loads the embedded akane.ko if /dev/akane isn't already present.
	 * Idempotent once the device is up, so safe to call every invocation. */
	if (akane_module_ensure_loaded() != 0)
		return 1;

	return akane_inject(&args);
}
