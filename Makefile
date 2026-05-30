PROJECT_ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
OUT          := $(PROJECT_ROOT)/out
SCRIPTS      := $(PROJECT_ROOT)/scripts
ABI          ?= arm64-v8a

KERNELS ?= android16-6.12 android15-6.6 android14-6.1 android14-5.15 \
           android13-5.15 android13-5.10 android12-5.10

KO_TARGETS  := $(addsuffix /akane.ko,$(addprefix $(OUT)/module/,$(KERNELS)))
MODULE_SRCS := $(wildcard $(PROJECT_ROOT)/module/*.c) \
               $(wildcard $(PROJECT_ROOT)/module/*.h) \
               $(PROJECT_ROOT)/module/Kbuild

.PHONY: all module injector clean

all:
	@$(MAKE) --no-print-directory module
	@$(MAKE) --no-print-directory injector

module: $(KO_TARGETS)

# Per-kernel build is allowed to fail; injector embeds whichever succeeded.
$(OUT)/module/%/akane.ko: $(MODULE_SRCS)
	-@"$(SCRIPTS)/build-module.sh" "$(OUT)" "$*"

injector:
	@"$(SCRIPTS)/build-injector.sh" "$(OUT)" "$(ABI)"

clean:
	rm -rf "$(OUT)"
	@case "$$(uname -s)" in \
		Darwin) rm -rf $(PROJECT_ROOT)/module/build-* ;; \
		*)      sudo rm -rf $(PROJECT_ROOT)/module/build-* ;; \
	esac
