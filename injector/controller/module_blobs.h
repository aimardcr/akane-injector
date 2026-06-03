#ifndef AKANE_CTRL_MODULE_BLOBS_H
#define AKANE_CTRL_MODULE_BLOBS_H

/* One entry per embedded akane.ko build; the table is generated at
 * injector-build time by scripts/build-injector.sh. */
struct akane_ko_blob {
	const char          *label;          /* e.g. "android12-5.10" */
	int                  android;
	int                  kernel_major;
	int                  kernel_minor;
	const unsigned char *start;
	const unsigned char *end;
};

extern const struct akane_ko_blob akane_ko_blobs[];
extern const unsigned akane_ko_blob_count;

#endif /* AKANE_CTRL_MODULE_BLOBS_H */
