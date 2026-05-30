#ifndef AKANE_CTRL_ARGS_H
#define AKANE_CTRL_ARGS_H

#include <sys/types.h>

struct akane_args {
	pid_t       target_pid;
	const char *so_path;
	int         hide_from_memory;
	int         register_to_solist;
	int         verbose;
};

void akane_args_usage(void);

/* Returns:
 *   0  on success (out fully populated)
 *   2  on bad args (usage already printed to stderr)
 *   1  on early-exit success (--help; caller should return 0)
 */
int akane_args_parse(int argc, char **argv, struct akane_args *out);

#endif /* AKANE_CTRL_ARGS_H */
