# Makefile for echo utility

# Platform detection (defaults to x86_64 if not specified)
PLATFORM ?= x86_64

ifeq ($(PLATFORM),arm64)
    CROSS_COMPILE ?= /opt/homebrew/bin/aarch64-elf-
    CC := $(CROSS_COMPILE)gcc
    LD := $(CROSS_COMPILE)gcc
    ARCH_CFLAGS := -march=armv8-a -mtune=cortex-a53
    LINKER_SCRIPT := ../libfutura/userland_arm64.ld
else
    CC := gcc
    LD := gcc
    ARCH_CFLAGS := -m64
    LINKER_SCRIPT := ../libfutura/userland_x86_64.ld
endif

TARGET = echo
OBJS = main.o

CFLAGS = -std=c2x -ffreestanding -nostdlib -fno-builtin -fno-stack-protector \
         -Wall -Wextra -Werror -g -O2 -I../../../include
CFLAGS += $(ARCH_CFLAGS)

# Use gcc as the linker with proper flags
LDFLAGS = -nostdlib -Wl,-T,$(LINKER_SCRIPT) -Wl,--gc-sections

BUILD_DIR = ../../../build
OBJ_DIR = $(BUILD_DIR)/obj/$(PLATFORM)/user/$(TARGET)
BIN_DIR = $(BUILD_DIR)/bin/user
LIB_DIR = $(BUILD_DIR)/lib/$(PLATFORM)

all: $(BIN_DIR)/$(TARGET)

$(OBJ_DIR)/%.o: %.c
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BIN_DIR)/$(TARGET): $(addprefix $(OBJ_DIR)/, $(OBJS))
	@mkdir -p $(BIN_DIR)
	$(LD) $(LDFLAGS) -o $@ $(LIB_DIR)/crt0.o $^ $(LIB_DIR)/libfutura.a
	@echo "Built $(TARGET): $@"

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)/$(TARGET)

.PHONY: all clean
