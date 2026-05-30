#ifndef AKANE_CTRL_MODULE_LOAD_H
#define AKANE_CTRL_MODULE_LOAD_H

/* Ensure /dev/akane exists. If the module is already loaded, returns 0
 * immediately. Otherwise writes the embedded akane.ko blob (linked into
 * the binary via akane_ko_blob.S / .incbin) to a memfd and finit_module()s
 * it -- no on-disk artifact left behind. Requires CAP_SYS_MODULE on the
 * caller (i.e. running as root).
 *
 * Returns 0 on success, -1 on failure (error already printed). */
int akane_module_ensure_loaded(void);

#endif /* AKANE_CTRL_MODULE_LOAD_H */
