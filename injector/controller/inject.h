#ifndef AKANE_CTRL_INJECT_H
#define AKANE_CTRL_INJECT_H

#include "args.h"

/* End-to-end injection (module must already be loaded). Returns 0 / 1. */
int akane_inject(const struct akane_args *args);

#endif /* AKANE_CTRL_INJECT_H */
