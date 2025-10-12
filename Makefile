# Futura OS Kernel Build System
#
# Copyright (c) 2025 Kelsi Davis
# Licensed under the MPL v2.0 — see LICENSE for details.
#
# Modular build system with platform abstraction.

# ============================================================
#   Build Configuration
# ============================================================

# Platform selection (x86_64, arm64)
PLATFORM ?= x86_64

# Build mode (debug, release)
BUILD_MODE ?= debug

# ============================================================
#   Platform-Specific Toolchain Configuration
# ============================================================

ifeq ($(PLATFORM),x86_64)
    # x86-64 toolchain
    CC := gcc-14
    AS := as
    LD := ld
    AR := ar
    ARCH_CFLAGS := -m64 -mcmodel=kernel -mno-red-zone
    ARCH_ASFLAGS := --64
    ARCH_LDFLAGS := -m elf_x86_64 -T platform/x86_64/link.ld
else ifeq ($(PLATFORM),arm64)
    # ARM64 cross-compilation toolchain
    CROSS_COMPILE ?= aarch64-linux-gnu-
    CC := $(CROSS_COMPILE)gcc
    AS := $(CROSS_COMPILE)as
    LD := $(CROSS_COMPILE)ld
    AR := $(CROSS_COMPILE)ar
    ARCH_CFLAGS := -march=armv8-a -mtune=cortex-a53
    ARCH_ASFLAGS :=
    ARCH_LDFLAGS := -T platform/arm64/link.ld
else
    $(error Unsupported platform: $(PLATFORM))
endif

# ============================================================
#   Common Compiler Flags
# ============================================================

# C standard and compiler flags
CFLAGS := -std=c23 -ffreestanding -nostdlib -fno-builtin -fno-stack-protector -fno-asynchronous-unwind-tables
CFLAGS += -Wall -Wextra -Wpedantic -Werror
CFLAGS += -fno-pic -fno-pie  # Disable PIC/PIE for kernel code
CFLAGS += -fcf-protection=none  # Disable CET (Control-flow Enforcement Technology)
CFLAGS += -I./include
CFLAGS += $(ARCH_CFLAGS)

# Debug vs Release flags
ifeq ($(BUILD_MODE),debug)
    CFLAGS += -g -O0 -DDEBUG
else
    CFLAGS += -O2 -DNDEBUG
endif

# Assembly flags
ASFLAGS := $(ARCH_ASFLAGS)

# Linker flags
LDFLAGS := -nostdlib $(ARCH_LDFLAGS)

# Output directories
BUILD_DIR := build
OBJ_DIR := $(BUILD_DIR)/obj
BIN_DIR := $(BUILD_DIR)/bin

# ============================================================
#   Source Files
# ============================================================

# Kernel core sources
KERNEL_SOURCES := \
    kernel/kernel_main.c \
    kernel/memory/fut_memory.c \
    kernel/threading/fut_task.c \
    kernel/threading/fut_thread.c \
    kernel/scheduler/fut_sched.c \
    kernel/scheduler/fut_stats.c \
    kernel/timer/fut_timer.c \
    kernel/ipc/fut_object.c \
    kernel/ipc/fut_fipc.c \
    kernel/crypto/fut_hmac.c \
    kernel/vfs/fut_vfs.c \
    kernel/vfs/ramfs.c \
    kernel/blockdev/fut_blockdev.c \
    kernel/blockdev/ramdisk.c \
    kernel/fs/futurafs.c \
    kernel/rt/memory.c \
    kernel/rt/stack_chk.c

# Platform-specific sources
ifeq ($(PLATFORM),x86_64)
    PLATFORM_SOURCES := \
        platform/x86_64/boot.S \
        platform/x86_64/gdt_idt.S \
        platform/x86_64/isr_stubs.S \
        platform/x86_64/context_switch.S \
        platform/x86_64/paging.c \
        platform/x86_64/platform_init.c
else ifeq ($(PLATFORM),arm64)
    PLATFORM_SOURCES := \
        platform/arm64/boot.S \
        platform/arm64/context_switch.S \
        platform/arm64/platform_init.c
endif

# Subsystem sources (POSIX compat)
SUBSYSTEM_SOURCES := \
    subsystems/posix_compat/posix_shim.c \
    subsystems/posix_compat/posix_syscall.c

# All sources
ALL_SOURCES := $(KERNEL_SOURCES) $(PLATFORM_SOURCES) $(SUBSYSTEM_SOURCES)

# Object files
OBJECTS := $(patsubst %.c,$(OBJ_DIR)/%.o,$(filter %.c,$(ALL_SOURCES)))
OBJECTS += $(patsubst %.S,$(OBJ_DIR)/%.o,$(filter %.S,$(ALL_SOURCES)))

# ============================================================
#   Build Targets
# ============================================================

.PHONY: all clean kernel userland

# Default target
all: kernel userland

# Create output directories
$(OBJ_DIR) $(BIN_DIR):
	@mkdir -p $@
	@mkdir -p $(OBJ_DIR)/kernel
	@mkdir -p $(OBJ_DIR)/kernel/memory
	@mkdir -p $(OBJ_DIR)/kernel/threading
	@mkdir -p $(OBJ_DIR)/kernel/scheduler
	@mkdir -p $(OBJ_DIR)/kernel/timer
	@mkdir -p $(OBJ_DIR)/kernel/crypto
	@mkdir -p $(OBJ_DIR)/kernel/interrupts
	@mkdir -p $(OBJ_DIR)/kernel/ipc
	@mkdir -p $(OBJ_DIR)/kernel/vfs
	@mkdir -p $(OBJ_DIR)/kernel/blockdev
	@mkdir -p $(OBJ_DIR)/kernel/fs
	@mkdir -p $(OBJ_DIR)/kernel/rt
	@mkdir -p $(OBJ_DIR)/platform/$(PLATFORM)
	@mkdir -p $(OBJ_DIR)/subsystems/posix_compat

# Build kernel
kernel: $(BIN_DIR)/futura_kernel.elf

$(BIN_DIR)/futura_kernel.elf: $(OBJECTS) | $(BIN_DIR)
	@echo "LD $@.tmp"
	@$(LD) $(LDFLAGS) -o $@.tmp $(OBJECTS)
	@cp $@.tmp /tmp/kernel_before_fix.elf
	@echo "FIX-ELF $@"
	@python3 tools/fix_multiboot_offset.py $@.tmp $@
	@rm $@.tmp
	@echo "Build complete: $@"

# Build userland services
userland:
	@echo "Building userland services..."
	@$(MAKE) -C src/user all

.PHONY: tests tools

tests:
	@$(MAKE) -C tests

tools:
	@$(MAKE) -C tools

# Compile C sources
$(OBJ_DIR)/%.o: %.c | $(OBJ_DIR)
	@echo "CC $<"
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS) -c $< -o $@

# Assemble assembly sources
$(OBJ_DIR)/%.o: %.S | $(OBJ_DIR)
	@echo "AS $<"
	@mkdir -p $(dir $@)
	@$(AS) $(ASFLAGS) $< -o $@

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@rm -f futura.iso
	@$(MAKE) -C src/user clean
	@echo "Clean complete"

# ============================================================
#   ISO and Testing Targets
# ============================================================

.PHONY: iso test

# Build bootable ISO with GRUB (required for proper testing)
iso: kernel
	@echo "Creating bootable ISO..."
	@cp $(BIN_DIR)/futura_kernel.elf iso/boot/
	@grub-mkrescue -o futura.iso iso/ 2>&1 | grep -E "(completed|error)" || echo "ISO build complete"
	@echo "✓ Bootable ISO created: futura.iso"

# Test kernel with GRUB (proper boot method)
test: iso
	@echo "Testing kernel with GRUB..."
	@echo "⚠️  Press Ctrl+C to exit QEMU"
	@qemu-system-x86_64 \
		-cdrom futura.iso \
		-serial stdio \
		-display none \
		-m 256M

# ============================================================
#   Platform-Specific Targets
# ============================================================

.PHONY: platform-x86_64 platform-arm64 qemu-x86_64 qemu-arm64

platform-x86_64:
	@$(MAKE) PLATFORM=x86_64

platform-arm64:
	@$(MAKE) PLATFORM=arm64

# QEMU test targets
qemu-x86_64: platform-x86_64
	@echo "Running x86_64 kernel in QEMU..."
	@qemu-system-x86_64 -kernel $(BIN_DIR)/futura_kernel.elf -serial stdio -nographic

qemu-arm64: platform-arm64
	@echo "Running ARM64 kernel in QEMU..."
	@qemu-system-aarch64 -M virt -cpu cortex-a53 -kernel $(BIN_DIR)/futura_kernel.elf -serial stdio -nographic

# ============================================================
#   Help
# ============================================================

.PHONY: help

help:
	@echo "Futura OS Build System - Phase 3 Userland Genesis"
	@echo ""
	@echo "Targets:"
	@echo "  all               - Build kernel and userland (default)"
	@echo "  kernel            - Build kernel only"
	@echo "  userland          - Build userland services only"
	@echo "  iso               - Build bootable GRUB ISO (required for testing)"
	@echo "  test              - Build and test kernel with GRUB (recommended)"
	@echo "  clean             - Remove build artifacts"
	@echo "  help              - Show this help message"
	@echo ""
	@echo "Platform Targets:"
	@echo "  platform-x86_64   - Build for x86-64"
	@echo "  platform-arm64    - Build for ARM64"
	@echo ""
	@echo "⚠️  IMPORTANT: Use 'make test' for proper kernel testing!"
	@echo "   Direct QEMU kernel boot (-kernel) causes triple-faults."
	@echo "   The kernel MUST be booted via GRUB. See docs/TESTING.md"
	@echo ""
	@echo "Userland Services:"
	@echo "  - init            - System init daemon (PID 1)"
	@echo "  - fsd             - Filesystem daemon"
	@echo "  - posixd          - POSIX compatibility daemon"
	@echo "  - futurawayd      - FuturaWay display compositor"
	@echo ""
	@echo "Variables:"
	@echo "  PLATFORM          - Target platform (x86_64, arm64)"
	@echo "  BUILD_MODE        - Build mode (debug, release)"
	@echo "  CROSS_COMPILE     - Cross-compiler prefix (for ARM64)"
	@echo ""
	@echo "Examples:"
	@echo "  make                          - Build kernel and userland"
	@echo "  make kernel                   - Build kernel only"
	@echo "  make userland                 - Build userland only"
	@echo "  make PLATFORM=arm64           - Build for ARM64"
	@echo "  make BUILD_MODE=release       - Build optimized release"
	@echo "  make qemu-x86_64              - Test x86-64 kernel in QEMU"
	@echo "  make qemu-arm64               - Test ARM64 kernel in QEMU"
	@echo "  make clean                    - Clean build artifacts"

# ============================================================
#   Dependency Generation (Future)
# ============================================================

# Automatic dependency generation will be added in Phase 2
