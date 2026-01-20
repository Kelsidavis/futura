# Makefile for libfutura - Futura OS User-Space Library
# Copyright (c) 2025 Kelsi Davis
# Licensed under MPL v2.0

# Platform detection (defaults to x86_64 if not specified)
PLATFORM ?= x86_64

# Toolchain (can be overridden by parent Makefile or command line)
ifeq ($(PLATFORM),arm64)
    CROSS_COMPILE ?= /opt/homebrew/bin/aarch64-elf-
    CC := $(CROSS_COMPILE)gcc
    AS := $(CROSS_COMPILE)as
    AR := $(CROSS_COMPILE)ar
    ARCH_CFLAGS := -march=armv8-a -mtune=cortex-a53
    ARCH_ASFLAGS :=
else
    # x86_64 platform - use cross-compiler on macOS
    ifeq ($(shell uname -s),Darwin)
        CROSS_COMPILE_X86 ?= /opt/homebrew/bin/x86_64-elf-
        CC := $(CROSS_COMPILE_X86)gcc
        AS := $(CROSS_COMPILE_X86)as
        AR := $(CROSS_COMPILE_X86)ar
    else
        CC := gcc
        AS := as
        AR := ar
    endif
    ARCH_CFLAGS := -m64
    ARCH_ASFLAGS := --64
endif

# Directories
BUILD_DIR := ../../../build
OBJ_DIR := $(BUILD_DIR)/obj/$(PLATFORM)/user/libfutura
LIB_DIR := $(BUILD_DIR)/lib/$(PLATFORM)

# Includes
INCLUDES := -I../../../include

# Compiler flags
CFLAGS := -std=c2x -ffreestanding -nostdlib -nostdinc -fno-builtin -fno-stack-protector
CFLAGS += -Wall -Wextra -Werror
CFLAGS += -g -O2
CFLAGS += -fPIC  # Position-independent code for library
CFLAGS += $(ARCH_CFLAGS)
CFLAGS += $(INCLUDES)
# Include compiler's built-in headers (stdint.h, stddef.h, etc.)
ifeq ($(PLATFORM),arm64)
    CFLAGS += -isystem $(shell $(CC) -print-file-name=include)
else
    CFLAGS += -isystem $(shell $(CC) -print-file-name=include)
endif

# Assembly flags
ASFLAGS := $(ARCH_ASFLAGS)

# Source files (platform-specific crt0)
C_SRCS := abort.c string.c strerror.c env.c fputs.c fwrite.c malloc.c fipc.c fipc_stub.c posix.c fcntl.c mremap.c memory_map.c fstat.c eventfd.c printf.c printf_core.c vsnprintf.c posix_shm.c epoll.c poll.c timerfd.c signalfd.c time.c stack_chk.c pthread_stub.c assert.c signals.c socket_unix.c fd.c errno.c syscall_shim.c stat_stub.c capability.c

ifeq ($(PLATFORM),arm64)
    ASM_SRCS := crt0_arm64.S
else
    ASM_SRCS := crt0.S
endif

# Object files
C_OBJS := $(C_SRCS:%.c=$(OBJ_DIR)/%.o)
ASM_OBJS := $(ASM_SRCS:%.S=$(OBJ_DIR)/%.o)
ALL_OBJS := $(C_OBJS) $(ASM_OBJS)

# Target library
TARGET := $(LIB_DIR)/libfutura.a
# CRT0 object is platform-specific
CRT0_OBJ := $(ASM_OBJS)
CRT0_EXPORT := $(LIB_DIR)/crt0.o

# Build rules
.PHONY: all clean

all: $(TARGET) $(CRT0_EXPORT)

$(TARGET): $(C_OBJS) | $(LIB_DIR)
	@echo "AR $@"
	@$(AR) rcs $@ $(C_OBJS)
	@echo "Built libfutura: $@"

$(CRT0_EXPORT): $(CRT0_OBJ) | $(LIB_DIR)
	@echo "CP crt0 -> $(CRT0_EXPORT)"
	@cp -f $(CRT0_OBJ) $(CRT0_EXPORT)

# Compile C sources
$(OBJ_DIR)/%.o: %.c | $(OBJ_DIR)
	@echo "CC $<"
	@$(CC) $(CFLAGS) -c $< -o $@

# Assemble assembly sources
$(OBJ_DIR)/%.o: %.S | $(OBJ_DIR)
	@echo "AS $<"
	@$(AS) $(ASFLAGS) $< -o $@

# Create directories
$(OBJ_DIR):
	@mkdir -p $(OBJ_DIR)

$(LIB_DIR):
	@mkdir -p $(LIB_DIR)

clean:
	@rm -rf $(OBJ_DIR) $(TARGET) $(CRT0_EXPORT)

# Dependencies
$(OBJ_DIR)/string.o: string.c
$(OBJ_DIR)/malloc.o: malloc.c
$(OBJ_DIR)/fipc.o: fipc.c ../../../include/kernel/fut_fipc.h
$(OBJ_DIR)/posix.o: posix.c ../../../include/user/futura_posix.h
$(OBJ_DIR)/crt0.o: crt0.S
