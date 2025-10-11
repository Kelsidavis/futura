# Makefile for Futura Init System
# Copyright (c) 2025 Kelsi Davis
# Licensed under MPL v2.0

# Toolchain
CC := gcc
LD := ld
AR := ar

# Directories
BUILD_DIR := ../../../build
OBJ_DIR := $(BUILD_DIR)/obj/user/init
BIN_DIR := $(BUILD_DIR)/bin/user

# Includes
INCLUDES := -I../../../include

# Compiler flags
CFLAGS := -std=c23 -ffreestanding -nostdlib -fno-builtin -fno-stack-protector
CFLAGS += -Wall -Wextra -Werror
CFLAGS += -g -O2
CFLAGS += $(INCLUDES)

# Linker flags
LDFLAGS := -nostdlib -static

# Source files
SRCS := main.c config.c service.c
OBJS := $(SRCS:%.c=$(OBJ_DIR)/%.o)

# Target binary
TARGET := $(BIN_DIR)/init

# Build rules
.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS) | $(BIN_DIR)
	$(LD) $(LDFLAGS) -o $@ $(OBJS)
	@echo "Built init system: $@"

$(OBJ_DIR)/%.o: %.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

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
