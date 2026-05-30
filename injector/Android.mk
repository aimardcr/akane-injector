# Top-level orchestrator. Each component's Android.mk is self-contained
# and lists its own LOCAL_SRC_FILES relative to its own directory.
INJECTOR_ROOT := $(call my-dir)

include $(INJECTOR_ROOT)/controller/Android.mk
include $(INJECTOR_ROOT)/runtime/Android.mk
