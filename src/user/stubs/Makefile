# SPDX-License-Identifier: MPL-2.0
#
# Simple user-space stubs used by kernel exec regression tests.

# Platform detection (defaults to x86_64 if not specified)
PLATFORM ?= x86_64

# Toolchain (can be overridden by parent Makefile or command line)
ifeq ($(PLATFORM),arm64)
    CROSS_COMPILE ?= /opt/homebrew/bin/aarch64-elf-
    CC := $(CROSS_COMPILE)gcc
    LD := $(CROSS_COMPILE)ld
    AR := $(CROSS_COMPILE)ar
    ARCH_CFLAGS := -march=armv8-a -mtune=cortex-a53
else
    # x86_64 platform - use cross-compiler on macOS
    ifeq ($(shell uname -s),Darwin)
        CROSS_COMPILE_X86 ?= /opt/homebrew/bin/x86_64-elf-
        CC := $(CROSS_COMPILE_X86)gcc
        LD := $(CROSS_COMPILE_X86)ld
        AR := $(CROSS_COMPILE_X86)ar
    else
        CC := gcc
        LD := ld
        AR := ar
    endif
    ARCH_CFLAGS := -m64
endif

ROOT := ../../..
BUILD_ROOT := $(ROOT)/build
OBJ_DIR := $(BUILD_ROOT)/obj/$(PLATFORM)/user/stubs
BIN_DIR := $(BUILD_ROOT)/bin/$(PLATFORM)/user
LIB_DIR := $(BUILD_ROOT)/lib/$(PLATFORM)

CFLAGS := -std=c2x -ffreestanding -nostdlib -fno-builtin -fno-stack-protector
CFLAGS += -Wall -Wextra -Werror -g -O2
CFLAGS += $(ARCH_CFLAGS)
CFLAGS += -I$(ROOT)/include

# Linker flags
ifeq ($(PLATFORM),arm64)
    LDSCRIPT := ../libfutura/userland_arm64.ld
    LDFLAGS := -static -T $(LDSCRIPT)
    LIBGCC := $(shell $(CC) -print-libgcc-file-name)
else
    LDSCRIPT := ../libfutura/userland.ld
    LDFLAGS := -nostdlib -static -T $(LDSCRIPT)
    LIBGCC :=
endif

CRT0 := $(LIB_DIR)/crt0.o
LIBFUTURA := $(LIB_DIR)/libfutura.a

TARGETS := $(BIN_DIR)/init_stub $(BIN_DIR)/second

OBJS := \
	$(OBJ_DIR)/init_stub.o \
	$(OBJ_DIR)/second.o

.PHONY: all clean

all: $(TARGETS)

$(BIN_DIR)/init_stub: $(OBJ_DIR)/init_stub.o $(CRT0) $(LIBFUTURA) | $(BIN_DIR)
	@echo "LD $@"
	@$(LD) $(LDFLAGS) --unresolved-symbols=ignore-all -o $@ $(CRT0) $(OBJ_DIR)/init_stub.o $(LIBFUTURA) $(LIBGCC)

$(BIN_DIR)/second: $(OBJ_DIR)/second.o $(CRT0) $(LIBFUTURA) | $(BIN_DIR)
	@echo "LD $@"
	@$(LD) $(LDFLAGS) --unresolved-symbols=ignore-all -o $@ $(CRT0) $(OBJ_DIR)/second.o $(LIBFUTURA) $(LIBGCC)

$(OBJ_DIR)/init_stub.o: init_stub.c | $(OBJ_DIR)
	@echo "CC $<"
	@$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/second.o: second.c | $(OBJ_DIR)
	@echo "CC $<"
	@$(CC) $(CFLAGS) -c $< -o $@

$(CRT0):
	@$(MAKE) -C ../libfutura all

$(LIBFUTURA):
	@$(MAKE) -C ../libfutura all

$(OBJ_DIR):
	@mkdir -p $@

$(BIN_DIR):
	@mkdir -p $@

clean:
	@rm -rf $(OBJ_DIR)
	@rm -f $(TARGETS)
