#ifndef AKANE_CTRL_MODULE_BLOBS_H
#define AKANE_CTRL_MODULE_BLOBS_H

/* One entry per embedded akane.ko build. The table itself
 * (akane_ko_blobs / akane_ko_blob_count) is generated at injector-build
 * time by scripts/build-injector.sh -- one entry per .ko that built
 * successfully in out/module/. See module_blobs_table.c. */
struct akane_ko_blob {
	const char *label;             /* "android12-5.10" -- for diagnostics */
	int                  android;        /* 12 */
	int                  kernel_major;   /* 5 */
	int                  kernel_minor;   /* 10 */
	const unsigned char *start;
	const unsigned char *end;
};

extern const struct akane_ko_blob akane_ko_blobs[];
extern const unsigned akane_ko_blob_count;

#endif /* AKANE_CTRL_MODULE_BLOBS_H */
