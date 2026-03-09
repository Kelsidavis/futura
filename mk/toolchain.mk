# mk/toolchain.mk - Shared cross-compilation toolchain detection
#
# Include this from sub-Makefiles to get correct CC/AS/AR/LD/OBJCOPY
# for the target PLATFORM, handling both macOS (Homebrew) and Linux (distro packages).
#
# Usage: include ../../../mk/toolchain.mk  (adjust relative path as needed)

ifeq ($(PLATFORM),arm64)
    ifeq ($(shell uname -s),Darwin)
        CROSS_COMPILE ?= /opt/homebrew/bin/aarch64-elf-
        CC  := $(CROSS_COMPILE)gcc
        AS  := $(CROSS_COMPILE)as
        AR  := $(CROSS_COMPILE)ar
        LD  := $(CROSS_COMPILE)ld
        OBJCOPY := $(CROSS_COMPILE)objcopy
    else
        CROSS_COMPILE ?= aarch64-linux-gnu-
        CC  := $(CROSS_COMPILE)gcc-14
        AS  := $(CROSS_COMPILE)as
        AR  := $(CROSS_COMPILE)ar
        LD  := $(CROSS_COMPILE)ld
        OBJCOPY := $(CROSS_COMPILE)objcopy
    endif
else
    # x86_64 platform
    ifeq ($(shell uname -s),Darwin)
        CROSS_COMPILE_X86 ?= /opt/homebrew/bin/x86_64-elf-
        CC  := $(CROSS_COMPILE_X86)gcc
        AS  := $(CROSS_COMPILE_X86)as
        AR  := $(CROSS_COMPILE_X86)ar
        LD  := $(CROSS_COMPILE_X86)ld
        OBJCOPY := $(CROSS_COMPILE_X86)objcopy
    else
        CC  ?= gcc-14
        AS  ?= as
        AR  ?= ar
        LD  ?= ld
        OBJCOPY ?= objcopy
    endif
endif
