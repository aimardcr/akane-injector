LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := akane-native-probe
LOCAL_SRC_FILES := native_probe.c
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)
