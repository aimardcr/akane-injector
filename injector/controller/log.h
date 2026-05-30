#ifndef AKANE_CTRL_LOG_H
#define AKANE_CTRL_LOG_H

#include <stdio.h>

/* All injector output goes to stderr.
 *   INFO:   top-level step ("loading X into pid Y", "injected via Z").
 *   DETAIL: indented sub-line for addresses, sizes, counts.
 *   ERR:    failure path with "error: " prefix.
 *
 * akane_log_verbose only toggles CSOLoader's internal chatter (relocations,
 * segments, etc.) -- the injector's own output stays the same regardless.
 * Owned by main.c. */
extern int akane_log_verbose;

#define INFO(fmt, ...)   do { fprintf(stderr, fmt "\n", ##__VA_ARGS__); } while (0)
#define DETAIL(fmt, ...) do { fprintf(stderr, "  " fmt "\n", ##__VA_ARGS__); } while (0)
#define ERR(fmt, ...)    do { fprintf(stderr, "error: " fmt "\n", ##__VA_ARGS__); } while (0)

#endif /* AKANE_CTRL_LOG_H */
