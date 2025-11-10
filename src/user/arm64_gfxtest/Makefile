# SPDX-License-Identifier: MPL-2.0
# ARM64 minimal graphics test

PROG := arm64_gfxtest
SRCS := main.c
OBJS := $(SRCS:.c=.o)

# ARM64 toolchain
CROSS_COMPILE ?= /opt/homebrew/bin/aarch64-elf-
CC := $(CROSS_COMPILE)gcc
LD := $(CROSS_COMPILE)ld
OBJDUMP := $(CROSS_COMPILE)objdump

# Paths
BUILD_DIR := ../../../build
OBJ_DIR := $(BUILD_DIR)/obj/arm64/user/gfxtest
BIN_DIR := $(BUILD_DIR)/bin/arm64/user
LIB_DIR := $(BUILD_DIR)/lib/arm64

# Build flags
CFLAGS := -std=c23 -O2 -g -Wall -Wextra -Werror \
	-ffreestanding -nostdlib \
	-I../../../include \
	-fno-stack-protector \
	-fno-pic -fno-pie \
	-mcmodel=large \
	-march=armv8-a

LDFLAGS := -nostdlib -static --build-id=none

# Dependencies
CRT0 := $(LIB_DIR)/crt0.o
LIBFUTURA := $(LIB_DIR)/libfutura.a
LDSCRIPT := ../libfutura/userland_arm64.ld
LIBGCC := $(shell $(CC) -print-libgcc-file-name)

TARGET := $(BIN_DIR)/$(PROG)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS) $(CRT0) $(LIBFUTURA) | $(BIN_DIR)
	$(LD) $(LDFLAGS) -T $(LDSCRIPT) -o $@ $(CRT0) $(OBJS) $(LIBFUTURA) $(LIBGCC)
	$(OBJDUMP) -d $@ > $(PROG).asm

%.o: %.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(CRT0):
	@$(MAKE) -C ../libfutura PLATFORM=arm64 all

$(LIBFUTURA):
	@$(MAKE) -C ../libfutura PLATFORM=arm64 all

$(OBJ_DIR):
	@mkdir -p $(OBJ_DIR)

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

clean:
	@rm -f $(OBJS) $(TARGET) $(PROG).asm

.PHONY: all clean
