# Futura OS Kernel Build System
#
# Copyright (c) 2025 Kelsi Davis
# Licensed under the MPL v2.0 — see LICENSE for details.
#
# Modular build system with platform abstraction.

# ============================================================
#   Build Configuration
# ============================================================

# Platform selection (x86, arm64, apple_silicon)
PLATFORM ?= x86

# Build mode (debug, release)
BUILD_MODE ?= debug

# Compiler and tools
CC := gcc
AS := as
LD := ld
AR := ar

# C standard and compiler flags
CFLAGS := -std=c23 -ffreestanding -nostdlib -fno-builtin
CFLAGS += -Wall -Wextra -Wpedantic -Werror
CFLAGS += -m32 -march=i686  # x86-32 specific
CFLAGS += -I./include

# Debug vs Release flags
ifeq ($(BUILD_MODE),debug)
    CFLAGS += -g -O0 -DDEBUG
else
    CFLAGS += -O2 -DNDEBUG
endif

# Assembly flags
ASFLAGS := --32  # x86-32 specific

# Linker flags
LDFLAGS := -m elf_i386 -nostdlib

# Output directories
BUILD_DIR := build
OBJ_DIR := $(BUILD_DIR)/obj
BIN_DIR := $(BUILD_DIR)/bin

# ============================================================
#   Source Files
# ============================================================

# Kernel core sources
KERNEL_SOURCES := \
    kernel/memory/fut_memory.c \
    kernel/threading/fut_task.c \
    kernel/threading/fut_thread.c \
    kernel/scheduler/fut_sched.c \
    kernel/scheduler/fut_stats.c \
    kernel/timer/fut_timer.c \
    kernel/interrupts/fut_idt.c \
    kernel/ipc/fut_object.c

# Platform-specific sources (x86)
ifeq ($(PLATFORM),x86)
    PLATFORM_SOURCES := \
        platform/x86/asm/fut_context.S \
        platform/x86/asm/fut_isr.S \
        platform/x86/asm/fut_thread_entry.S
endif

# Subsystem sources (POSIX compat)
SUBSYSTEM_SOURCES := \
    subsystems/posix_compat/posix_shim.c

# All sources
ALL_SOURCES := $(KERNEL_SOURCES) $(PLATFORM_SOURCES) $(SUBSYSTEM_SOURCES)

# Object files
OBJECTS := $(patsubst %.c,$(OBJ_DIR)/%.o,$(filter %.c,$(ALL_SOURCES)))
OBJECTS += $(patsubst %.S,$(OBJ_DIR)/%.o,$(filter %.S,$(ALL_SOURCES)))

# ============================================================
#   Build Targets
# ============================================================

.PHONY: all clean kernel

# Default target
all: kernel

# Create output directories
$(OBJ_DIR) $(BIN_DIR):
	@mkdir -p $@
	@mkdir -p $(OBJ_DIR)/kernel/memory
	@mkdir -p $(OBJ_DIR)/kernel/threading
	@mkdir -p $(OBJ_DIR)/kernel/scheduler
	@mkdir -p $(OBJ_DIR)/kernel/timer
	@mkdir -p $(OBJ_DIR)/kernel/interrupts
	@mkdir -p $(OBJ_DIR)/kernel/ipc
	@mkdir -p $(OBJ_DIR)/platform/x86/asm
	@mkdir -p $(OBJ_DIR)/subsystems/posix_compat

# Build kernel
kernel: $(BIN_DIR)/futura_kernel.elf

$(BIN_DIR)/futura_kernel.elf: $(OBJECTS) | $(BIN_DIR)
	@echo "LD $@"
	@$(LD) $(LDFLAGS) -o $@ $(OBJECTS)
	@echo "Build complete: $@"

# Compile C sources
$(OBJ_DIR)/%.o: %.c | $(OBJ_DIR)
	@echo "CC $<"
	@$(CC) $(CFLAGS) -c $< -o $@

# Assemble assembly sources
$(OBJ_DIR)/%.o: %.S | $(OBJ_DIR)
	@echo "AS $<"
	@$(AS) $(ASFLAGS) $< -o $@

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@echo "Clean complete"

# ============================================================
#   Platform-Specific Targets
# ============================================================

.PHONY: platform-x86 platform-arm64 platform-apple-silicon

platform-x86:
	@$(MAKE) PLATFORM=x86

platform-arm64:
	@$(MAKE) PLATFORM=arm64

platform-apple-silicon:
	@$(MAKE) PLATFORM=apple_silicon

# ============================================================
#   Help
# ============================================================

.PHONY: help

help:
	@echo "Futura OS Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all            - Build kernel (default)"
	@echo "  kernel         - Build kernel only"
	@echo "  clean          - Remove build artifacts"
	@echo "  help           - Show this help message"
	@echo ""
	@echo "Platform Targets:"
	@echo "  platform-x86   - Build for x86-32"
	@echo "  platform-arm64 - Build for ARM64"
	@echo "  platform-apple-silicon - Build for Apple Silicon"
	@echo ""
	@echo "Variables:"
	@echo "  PLATFORM       - Target platform (x86, arm64, apple_silicon)"
	@echo "  BUILD_MODE     - Build mode (debug, release)"
	@echo ""
	@echo "Examples:"
	@echo "  make                     - Build for x86 in debug mode"
	@echo "  make PLATFORM=arm64      - Build for ARM64"
	@echo "  make BUILD_MODE=release  - Build optimized release"
	@echo "  make clean               - Clean build artifacts"

# ============================================================
#   Dependency Generation (Future)
# ============================================================

# Automatic dependency generation will be added in Phase 2
