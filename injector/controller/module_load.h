#ifndef AKANE_CTRL_MODULE_LOAD_H
#define AKANE_CTRL_MODULE_LOAD_H

/* Ensure /dev/akane exists, loading the embedded akane.ko via memfd +
 * finit_module if needed (requires CAP_SYS_MODULE). Returns 0 / -1. */
int akane_module_ensure_loaded(void);

#endif /* AKANE_CTRL_MODULE_LOAD_H */
