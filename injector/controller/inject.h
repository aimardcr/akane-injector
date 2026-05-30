#ifndef AKANE_CTRL_INJECT_H
#define AKANE_CTRL_INJECT_H

#include "args.h"

/* End-to-end injection. Assumes:
 *   - the kernel module is loaded (caller's responsibility)
 *   - args are validated
 *
 * Returns 0 on success, 1 on failure (errors already printed). */
int akane_inject(const struct akane_args *args);

#endif /* AKANE_CTRL_INJECT_H */
