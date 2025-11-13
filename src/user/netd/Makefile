# Makefile for Futura Network Daemon (netd)
# Copyright (c) 2025 Kelsi Davis
# Licensed under MPL v2.0

# Toolchain (use platform-specific compiler from main Makefile)
CC ?= gcc
LD ?= ld
AR ?= ar

# Directories
BUILD_DIR := ../../../build
OBJ_DIR := $(BUILD_DIR)/obj/user/netd
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
SRCS := main.c netd_core.c
OBJS := $(SRCS:%.c=$(OBJ_DIR)/%.o)

# Target binary
TARGET := $(BIN_DIR)/netd

# Build rules
.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS) $(CRT0) $(LIBFUTURA) | $(BIN_DIR)
	$(LD) $(LDFLAGS) -o $@ $(CRT0) $(OBJS) $(LIBFUTURA)
	@echo "Built netd: $@"

$(OBJ_DIR)/%.o: %.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR):
	@mkdir -p $(OBJ_DIR)

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

clean:
	rm -rf $(OBJ_DIR) $(TARGET)

# Dependencies
$(OBJ_DIR)/main.o: main.c netd_core.h ../../../include/kernel/fut_fipc.h
$(OBJ_DIR)/netd_core.o: netd_core.c netd_core.h
