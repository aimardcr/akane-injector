#ifndef AKANE_CTRL_LOG_H
#define AKANE_CTRL_LOG_H

#include <stdio.h>

/* All output goes to stderr. akane_log_verbose (owned by main.c) only toggles
 * CSOLoader's chatter; the injector's own INFO/DETAIL/ERR are unaffected. */
extern int akane_log_verbose;

#define INFO(fmt, ...)   do { fprintf(stderr, fmt "\n", ##__VA_ARGS__); } while (0)
#define DETAIL(fmt, ...) do { fprintf(stderr, "  " fmt "\n", ##__VA_ARGS__); } while (0)
#define ERR(fmt, ...)    do { fprintf(stderr, "error: " fmt "\n", ##__VA_ARGS__); } while (0)

#endif /* AKANE_CTRL_LOG_H */
