# Makefile for Futura Filesystem Daemon (fsd)
# Copyright (c) 2025 Kelsi Davis
# Licensed under MPL v2.0

# Toolchain (use platform-specific compiler from main Makefile)
CC ?= gcc
LD ?= ld
AR ?= ar

# Directories
BUILD_DIR := ../../../build
OBJ_DIR := $(BUILD_DIR)/obj/user/fsd
BIN_DIR := $(BUILD_DIR)/bin/user

# Includes
INCLUDES := -I../../../include

# Compiler flags
CFLAGS := -std=c2x -ffreestanding -nostdlib -fno-builtin -fno-stack-protector
CFLAGS += -Wall -Wextra -Werror
CFLAGS += -g -O2
CFLAGS += $(INCLUDES)

# Linker flags
LDFLAGS := -nostdlib -static

# Libfutura paths
CRT0 := $(BUILD_DIR)/lib/crt0.o
LIBFUTURA := $(BUILD_DIR)/lib/libfutura.a

# Source files
SRCS := main.c
OBJS := $(SRCS:%.c=$(OBJ_DIR)/%.o)

# Target binary
TARGET := $(BIN_DIR)/fsd

# Build rules
.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS) $(CRT0) $(LIBFUTURA) | $(BIN_DIR)
	$(LD) $(LDFLAGS) -o $@ $(CRT0) $(OBJS) $(LIBFUTURA)
	@echo "Built fsd: $@"

$(OBJ_DIR)/%.o: %.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR):
	@mkdir -p $(OBJ_DIR)

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

clean:
	rm -rf $(OBJ_DIR) $(TARGET)

# Dependencies
$(OBJ_DIR)/main.o: main.c ../../../include/kernel/fut_vfs.h
