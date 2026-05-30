#define _GNU_SOURCE
#include "args.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

void akane_args_usage(void)
{
	fprintf(stderr,
		"usage: akane-injector --pid PID --so PATH [options]\n"
		"\n"
		"  -p, --pid PID                target process id (required)\n"
		"  -s, --so PATH                path to the .so on the device (required)\n"
		"  -v, --verbose                repeat for more detail (-v info, -vv debug)\n"
		"      --hide-from-memory       full anti-introspection bundle:\n"
		"                                 * payload nameless + masked ---p in maps\n"
		"                                 * /proc/<pid>/{mem,smaps,pagemap} hide\n"
		"                                   the VMA from non-root readers\n"
		"                                 * process_vm_readv/writev + mincore\n"
		"                                   block non-root cross-process access\n"
		"                                 * post-init wipe of payload .dynstr +\n"
		"                                   build-id note for YARA resistance\n"
		"                               (default: --so PATH is reflected as the\n"
		"                               VMA name with real perms; needed for\n"
		"                               libraries that self-locate via /proc/maps)\n"
		"      --hide-from-maps         deprecated alias for --hide-from-memory.\n"
		"      --register-to-solist     splice payload into bionic's solist before\n"
		"                               its init_array runs. Required for libraries\n"
		"                               that introspect via solist (Frida gadget).\n"
		"                               Default off (stealthy: invisible to dl_*).\n");
}

int akane_args_parse(int argc, char **argv, struct akane_args *out)
{
	enum {
		OPT_HIDE_FROM_MEMORY = 0x100,
		OPT_HIDE_FROM_MAPS,
		OPT_REGISTER_TO_SOLIST,
	};

	static const struct option longopts[] = {
		{ "pid",                    required_argument, NULL, 'p' },
		{ "so",                     required_argument, NULL, 's' },
		{ "verbose",                no_argument,       NULL, 'v' },
		{ "help",                   no_argument,       NULL, 'h' },
		{ "hide-from-memory",       no_argument,       NULL, OPT_HIDE_FROM_MEMORY },
		{ "hide-from-maps",         no_argument,       NULL, OPT_HIDE_FROM_MAPS },
		{ "register-to-solist",     no_argument,       NULL, OPT_REGISTER_TO_SOLIST },
		{ 0, 0, 0, 0 },
	};

	memset(out, 0, sizeof(*out));

	int opt;
	while ((opt = getopt_long(argc, argv, "p:s:vh", longopts, NULL)) != -1) {
		switch (opt) {
		case 'p': out->target_pid = (pid_t)atoi(optarg); break;
		case 's': out->so_path    = optarg; break;
		case 'v': out->verbose++; break;
		case 'h': akane_args_usage(); return 1;
		case OPT_HIDE_FROM_MEMORY:   out->hide_from_memory   = 1; break;
		case OPT_HIDE_FROM_MAPS:
			fprintf(stderr, "akane-injector: --hide-from-maps is deprecated; use --hide-from-memory\n");
			out->hide_from_memory = 1;
			break;
		case OPT_REGISTER_TO_SOLIST: out->register_to_solist = 1; break;
		default:  akane_args_usage(); return 2;
		}
	}
	if (!out->target_pid || !out->so_path) {
		ERR("--pid and --so are required");
		akane_args_usage();
		return 2;
	}
	if (out->target_pid == getpid()) {
		ERR("--pid points at self");
		return 2;
	}
	return 0;
}
