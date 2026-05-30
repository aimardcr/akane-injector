LOCAL_PATH := $(call my-dir)

# Companion library injected alongside each payload. Exposes dl* hooks
# and a payload registry (g_akane_rt_*). The controller patches the
# payload's GOT to redirect dl_iterate_phdr / dladdr / dlopen / dlsym /
# dlclose / dlerror to akane_rt_* here, so libraries that introspect
# their own loaded image (Frida gadget, etc.) can find themselves.
#
# -fvisibility=hidden + explicit __attribute__((visibility("default")))
# in the source keeps the dynsym minimal -- only the hooks and registry
# are exported.
include $(CLEAR_VARS)
LOCAL_MODULE     := akane-runtime
LOCAL_SRC_FILES  := \
	runtime.c \
	linker.c
LOCAL_CFLAGS     := -Wall -O2 -fPIC -fvisibility=hidden
LOCAL_LDLIBS     := -ldl
include $(BUILD_SHARED_LIBRARY)
