# Makefile for Futura Init System
# Copyright (c) 2025 Kelsi Davis
# Licensed under MPL v2.0

# Platform detection
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

# Directories
BUILD_DIR := ../../../build
OBJ_DIR := $(BUILD_DIR)/obj/$(PLATFORM)/user/init
BIN_DIR := $(BUILD_DIR)/bin/$(PLATFORM)/user
LIB_DIR := $(BUILD_DIR)/lib/$(PLATFORM)

# Includes
INCLUDES := -I../../../include

# Compiler flags
CFLAGS := -std=c2x -ffreestanding -nostdlib -nostdinc -fno-builtin -fno-stack-protector
CFLAGS += -Wall -Wextra -Werror
CFLAGS += -g -O2
CFLAGS += $(ARCH_CFLAGS)
CFLAGS += $(INCLUDES)
CFLAGS += -isystem $(shell $(CC) -print-file-name=include)

# Linker flags
ifeq ($(PLATFORM),arm64)
    LDSCRIPT := ../libfutura/userland_arm64.ld
    LDFLAGS := -static -T $(LDSCRIPT)
    # libgcc for compiler-generated helper functions (atomics, etc.)
    LIBGCC := $(shell $(CC) -print-libgcc-file-name)
else
    LDSCRIPT := ../libfutura/userland.ld
    LDFLAGS := -nostdlib -static -T $(LDSCRIPT)
    LIBGCC :=
endif
CRT0 := $(LIB_DIR)/crt0.o
LIBFUTURA := $(LIB_DIR)/libfutura.a

# Source files
SRCS := main.c config.c service.c
OBJS := $(SRCS:%.c=$(OBJ_DIR)/%.o)

# Target binary
TARGET := $(BIN_DIR)/init

# Build rules
.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS) $(CRT0) $(LIBFUTURA) | $(BIN_DIR)
	@echo "LD $@"
	@$(LD) $(LDFLAGS) -o $@ $(CRT0) $(OBJS) $(LIBFUTURA) $(LIBGCC)
	@echo "Built init system: $@"

$(OBJ_DIR)/%.o: %.c | $(OBJ_DIR)
	@echo "CC $<"
	@$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR):
	@mkdir -p $(OBJ_DIR)

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

clean:
	rm -rf $(OBJ_DIR) $(TARGET)

# Dependencies
$(OBJ_DIR)/main.o: main.c ../../../include/user/futura_init.h
$(OBJ_DIR)/config.o: config.c ../../../include/user/futura_init.h
$(OBJ_DIR)/service.o: service.c ../../../include/user/futura_init.h
