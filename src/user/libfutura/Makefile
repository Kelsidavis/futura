# Makefile for libfutura - Futura OS User-Space Library
# Copyright (c) 2025 Kelsi Davis
# Licensed under MPL v2.0

# Toolchain
CC := gcc
AS := as
AR := ar

# Directories
BUILD_DIR := ../../../build
OBJ_DIR := $(BUILD_DIR)/obj/user/libfutura
LIB_DIR := $(BUILD_DIR)/lib

# Includes
INCLUDES := -I../../../include

# Compiler flags
CFLAGS := -std=c2x -ffreestanding -nostdlib -fno-builtin -fno-stack-protector
CFLAGS += -Wall -Wextra -Werror
CFLAGS += -g -O2
CFLAGS += -fPIC  # Position-independent code for library
CFLAGS += $(INCLUDES)

# Assembly flags
ASFLAGS := --64

# Source files
C_SRCS := string.c malloc.c fipc.c posix.c printf.c posix_shm.c epoll.c timerfd.c time.c stack_chk.c pthread_stub.c assert.c signals.c socket_unix.c fd.c
ASM_SRCS := crt0.S

# Object files
C_OBJS := $(C_SRCS:%.c=$(OBJ_DIR)/%.o)
ASM_OBJS := $(ASM_SRCS:%.S=$(OBJ_DIR)/%.o)
ALL_OBJS := $(C_OBJS) $(ASM_OBJS)

# Target library
TARGET := $(LIB_DIR)/libfutura.a
CRT0_OBJ := $(OBJ_DIR)/crt0.o
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
