LOCAL_PATH := $(call my-dir)

# Sibling locations relative to controller/.
BOOTSTRAP_DIR := $(LOCAL_PATH)/../bootstrap
LOADER_DIR    := $(LOCAL_PATH)/../loader
KM_DIR        := $(LOCAL_PATH)/../../module

# scripts/build-injector.sh scans out/module/*/akane.ko and writes a
# sources.mk + per-kernel .S files into $(BLOBS_DIR). The .mk sets
# AKANE_BLOB_SRCS, which we splice into LOCAL_SRC_FILES below. The hyphen
# on -include makes the build degrade gracefully when no blobs exist yet
# (the injector still links but module_load.c will fail at runtime with
# "no kernel-module blobs").
ifndef BLOBS_DIR
$(error BLOBS_DIR is not set -- build via the top-level Makefile (`make injector`))
endif
-include $(BLOBS_DIR)/sources.mk

include $(CLEAR_VARS)
LOCAL_MODULE     := akane-injector
LOCAL_SRC_FILES  := \
	main.c                                    \
	args.c                                    \
	runtime.c                                 \
	payload.c                                 \
	inject.c                                  \
	module_load.c                             \
	$(AKANE_BLOB_SRCS)                        \
	../bootstrap/bootstrap.S                  \
	../loader/src/csoloader.c                 \
	../loader/src/linker.c                    \
	../loader/src/elf_util.c                  \
	../loader/src/carray.c                    \
	../loader/src/sleb128.c                   \
	../loader/src/backtrace-support.c         \
	../loader/src/local_backend.c             \
	../loader/src/akane_backend.c
LOCAL_C_INCLUDES := \
	$(LOCAL_PATH)                             \
	$(KM_DIR)                                 \
	$(LOADER_DIR)/include
LOCAL_CFLAGS     := \
	-Wall -O2 -fPIC                           \
	-Wno-int-conversion                       \
	-fstack-protector-strong                  \
	-D_FORTIFY_SOURCE=2
include $(BUILD_EXECUTABLE)
