# Makefile for fbtest user program

# Platform detection
PLATFORM ?= x86_64

# Toolchain (can be overridden by parent Makefile or command line)
ifeq ($(PLATFORM),arm64)
    CROSS_COMPILE ?= /opt/homebrew/bin/aarch64-elf-
    CC := $(CROSS_COMPILE)gcc
    LD := $(CROSS_COMPILE)ld
    ARCH_CFLAGS := -march=armv8-a -mtune=cortex-a53
else
    CC := gcc
    LD := ld
    ARCH_CFLAGS :=
endif

BUILD_DIR := ../../../build
ifeq ($(PLATFORM),arm64)
    OBJ_DIR := $(BUILD_DIR)/obj/arm64/user/fbtest
    BIN_DIR := $(BUILD_DIR)/bin/arm64/user
    LIB_DIR := $(BUILD_DIR)/lib/arm64
else
    OBJ_DIR := $(BUILD_DIR)/obj/user/fbtest
    BIN_DIR := $(BUILD_DIR)/bin/user
    LIB_DIR := $(BUILD_DIR)/lib
endif

INCLUDES := -I../../../include

CFLAGS := -std=c2x -ffreestanding -nostdlib -fno-builtin -fno-stack-protector
CFLAGS += -Wall -Wextra -Werror
CFLAGS += -g -O2
CFLAGS += $(ARCH_CFLAGS)
CFLAGS += $(INCLUDES)

ifeq ($(PLATFORM),arm64)
    LDSCRIPT := ../libfutura/userland_arm64.ld
    LIBGCC := $(shell $(CC) -print-libgcc-file-name)
else
    LDSCRIPT := ../libfutura/userland.ld
    LIBGCC :=
endif
CRT0 := $(LIB_DIR)/crt0.o
LIBFUTURA := $(LIB_DIR)/libfutura.a

SRCS := main.c
OBJS := $(SRCS:%.c=$(OBJ_DIR)/%.o)

TARGET := $(BIN_DIR)/fbtest

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS) $(CRT0) $(LIBFUTURA) | $(BIN_DIR)
	$(LD) -nostdlib -T $(LDSCRIPT) -o $@ $(CRT0) $(OBJS) $(LIBFUTURA) $(LIBGCC)
	@echo "Built fbtest: $@"

$(OBJ_DIR)/%.o: %.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(CRT0):
	@$(MAKE) -C ../libfutura PLATFORM=$(PLATFORM) all

$(LIBFUTURA):
	@$(MAKE) -C ../libfutura PLATFORM=$(PLATFORM) all

$(OBJ_DIR):
	@mkdir -p $(OBJ_DIR)

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

clean:
	@rm -rf $(OBJ_DIR) $(TARGET)
