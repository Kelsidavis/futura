# Makefile for Futura POSIX Daemon (posixd)
# Copyright (c) 2025 Kelsi Davis
# Licensed under MPL v2.0

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
    CC := gcc
    LD := ld
    AR := ar
    ARCH_CFLAGS := -m64
endif

# Directories
BUILD_DIR := ../../../build
OBJ_DIR := $(BUILD_DIR)/obj/$(PLATFORM)/user/posixd
BIN_DIR := $(BUILD_DIR)/bin/$(PLATFORM)/user
LIB_DIR := $(BUILD_DIR)/lib/$(PLATFORM)

# Includes
INCLUDES := -I../../../include

# Compiler flags
CFLAGS := -std=c2x -ffreestanding -nostdlib -fno-builtin -fno-stack-protector
CFLAGS += -Wall -Wextra -Werror
CFLAGS += -g -O2
CFLAGS += $(ARCH_CFLAGS)
CFLAGS += $(INCLUDES)

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

# Libfutura paths
CRT0 := $(LIB_DIR)/crt0.o
LIBFUTURA := $(LIB_DIR)/libfutura.a

# Source files
SRCS := main.c
OBJS := $(SRCS:%.c=$(OBJ_DIR)/%.o)

# Target binary
TARGET := $(BIN_DIR)/posixd

# Build rules
.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS) $(CRT0) $(LIBFUTURA) | $(BIN_DIR)
	$(LD) $(LDFLAGS) -o $@ $(CRT0) $(OBJS) $(LIBFUTURA) $(LIBGCC)
	@echo "Built posixd: $@"

$(OBJ_DIR)/%.o: %.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR):
	@mkdir -p $(OBJ_DIR)

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

$(CRT0):
	@$(MAKE) -C ../libfutura PLATFORM=$(PLATFORM) all

$(LIBFUTURA):
	@$(MAKE) -C ../libfutura PLATFORM=$(PLATFORM) all

clean:
	rm -rf $(OBJ_DIR) $(TARGET)

# Dependencies
$(OBJ_DIR)/main.o: main.c ../../../include/user/futura_posix.h
