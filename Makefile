# Futura OS Kernel Build System
#
# Copyright (c) 2025 Kelsi Davis
# Licensed under the MPL v2.0 — see LICENSE for details.
#
# Modular build system with platform abstraction.

SHELL := /bin/bash

# ============================================================
#   Build Configuration
# ============================================================

# Platform selection (x86_64, arm64)
PLATFORM ?= x86_64

# Build mode (debug, release)
BUILD_MODE ?= debug

# QEMU test harness configuration
QEMU_MEM       ?= 256
QEMU_IMG_SIZE  ?= 64M
QEMU_DISK_IMG  ?= futura_disk.img

QEMU_FLAGS += -device isa-debug-exit,iobase=0xf4,iosize=0x4 -no-reboot -no-shutdown
QEMU_FLAGS += -drive if=virtio,file=$(QEMU_DISK_IMG),format=raw
QEMU_FLAGS += -netdev user,id=net0 -device virtio-net,netdev=net0

# ============================================================
#   Run Configuration Defaults
# ============================================================

MEM              ?= 1024
HEADFUL          ?= 0
DEBUG            ?= 0
ASYNC            ?= 0
EXTRA_QEMU_FLAGS ?=

# Set QEMU binary based on platform
ifeq ($(PLATFORM),arm64)
QEMU             ?= qemu-system-aarch64
else
QEMU             ?= qemu-system-x86_64
endif

INITROOT  = $(BUILD_DIR)/initroot
INITRAMFS = $(BUILD_DIR)/initramfs.cpio

WAYLAND_ENV = XDG_RUNTIME_DIR=/tmp WAYLAND_DISPLAY=wayland-0 WAYLAND_MULTI=1 \
              WAYLAND_BACKBUFFER=1 WAYLAND_DECO=1 WAYLAND_SHADOW=1 \
              WAYLAND_RESIZE=1 WAYLAND_THROTTLE=1
ifeq ($(DEBUG),1)
WAYLAND_ENV += DEBUG_WAYLAND=1 DEBUG_NETUNIX=1
endif

KAPPEND :=
ifeq ($(ASYNC),1)
KAPPEND += async-tests=1
endif
ifneq ($(strip $(WAYLAND_ENV)),)
KAPPEND += $(WAYLAND_ENV)
endif
ifeq ($(HEADFUL),1)
KAPPEND += WAYLAND_INTERACTIVE=1
KAPPEND += fb-fallback=1
endif
KAPPEND := $(strip $(KAPPEND))

RUN_QEMU_FLAGS := -m $(MEM) -serial stdio -no-reboot -no-shutdown

# Add platform-specific QEMU flags
ifeq ($(PLATFORM),arm64)
RUN_QEMU_FLAGS += -machine virt -cpu cortex-a72
endif

ifeq ($(HEADFUL),1)
# Headful mode: use display backend with virtio-gpu
# GTK is default for native graphics output, falls back to VNC if no display server
ifeq ($(VNC),1)
RUN_QEMU_FLAGS += -vnc :0
else ifeq ($(SPICE),1)
RUN_QEMU_FLAGS += -display spice-app
else ifeq ($(SDL),1)
RUN_QEMU_FLAGS += -display sdl
else
# GTK provides native graphics window via virtio-gpu
# Requires X11 (DISPLAY) or Wayland (WAYLAND_DISPLAY) to be set
# NOTE: gl=off for 2D framebuffer operations (gl=on requires virgl 3D)
RUN_QEMU_FLAGS += -display gtk,gl=off
endif
RUN_QEMU_FLAGS += -device virtio-gpu-pci
RUN_QEMU_FLAGS += -vga none
else
RUN_QEMU_FLAGS += -display none
RUN_QEMU_FLAGS += -vga none
endif

# Add platform-specific devices (isa-debug-exit is x86-64 only)
ifeq ($(PLATFORM),x86_64)
RUN_QEMU_FLAGS += -device isa-debug-exit,iobase=0xf4,iosize=0x4
endif

RUN_QEMU_FLAGS += -drive if=virtio,file=$(QEMU_DISK_IMG),format=raw
RUN_QEMU_FLAGS += $(EXTRA_QEMU_FLAGS)

ifeq ($(strip $(KAPPEND)),)
RUN_QEMU_APPEND :=
else
RUN_QEMU_APPEND := -append "$(KAPPEND)"
endif

# ============================================================
#   Platform-Specific Toolchain Configuration
# ============================================================

ifeq ($(PLATFORM),x86_64)
    # x86-64 toolchain
    CC := gcc-14
    AS := as
    LD := ld
    AR := ar
    OBJCOPY := objcopy
    ARCH_CFLAGS := -m64 -mcmodel=kernel -mno-red-zone -mno-sse -mno-avx -mno-avx2 -fno-tree-vectorize
    ARCH_ASFLAGS := --64
    ARCH_LDFLAGS := -m elf_x86_64 -T platform/x86_64/link.ld
    # Binary format for embedding blobs
    OBJCOPY_BIN_FMT := elf64-x86-64
    OBJCOPY_BIN_ARCH := i386:x86-64
else ifeq ($(PLATFORM),arm64)
    # ARM64 cross-compilation toolchain
    CROSS_COMPILE ?= aarch64-linux-gnu-
    CC := $(CROSS_COMPILE)gcc
    AS := $(CROSS_COMPILE)as
    LD := $(CROSS_COMPILE)ld
    AR := $(CROSS_COMPILE)ar
    OBJCOPY := $(CROSS_COMPILE)objcopy
    ARCH_CFLAGS := -march=armv8-a -mtune=cortex-a53 -Wno-pedantic
    ARCH_ASFLAGS :=
    ARCH_LDFLAGS := -T platform/arm64/link.ld /usr/lib/gcc-cross/aarch64-linux-gnu/13/libgcc.a
    # Binary format for embedding blobs
    OBJCOPY_BIN_FMT := elf64-aarch64
    OBJCOPY_BIN_ARCH := aarch64
else
    $(error Unsupported platform: $(PLATFORM))
endif

# ============================================================
#   Common Compiler Flags
# ============================================================

# Reproducible build toggles
REPRO ?= 0

ifeq ($(REPRO),1)
export LC_ALL := C
export TZ := UTC
SOURCE_DATE_EPOCH ?= 1700000000
export SOURCE_DATE_EPOCH
REPRO_CFLAGS := -g0 -fno-record-gcc-switches -ffile-prefix-map=$(CURDIR)=.
REPRO_LDFLAGS := -Wl,--build-id=none
BUILD_DATE_UTC := $(shell python3 -c 'import datetime,os;print(datetime.datetime.utcfromtimestamp(int(os.environ.get("SOURCE_DATE_EPOCH","1700000000"))).strftime("%Y-%m-%dT%H:%M:%SZ"))')
BUILD_HOST := unknown
BUILD_USER := unknown
else
REPRO_CFLAGS :=
REPRO_LDFLAGS :=
BUILD_DATE_UTC := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
BUILD_HOST := $(shell hostname)
BUILD_USER := $(shell whoami)
endif
export REPRO_CFLAGS
export REPRO_LDFLAGS

# C standard and compiler flags
CFLAGS := -std=c2x -ffreestanding -nostdlib -fno-builtin -fno-stack-protector -fno-asynchronous-unwind-tables
CFLAGS += -Wall -Wextra -Wpedantic -Werror
CFLAGS += -fno-pic -fno-pie  # Disable PIC/PIE for kernel code
CFLAGS += -fcf-protection=none  # Disable CET (Control-flow Enforcement Technology)
CFLAGS += -I.
CFLAGS += -I./include
CFLAGS += $(ARCH_CFLAGS)
CFLAGS += $(REPRO_CFLAGS)

# Interactive mode for GUI testing (must be after main CFLAGS setup)
ifeq ($(HEADFUL),1)
CFLAGS += -DWAYLAND_INTERACTIVE_MODE=1
endif

# Feature toggles
ENABLE_WINSRV_DEMO ?= 0
ENABLE_WAYLAND_DEMO ?= 0

# Debug vs Release flags
ifeq ($(BUILD_MODE),debug)
    CFLAGS += -g -O0 -DDEBUG
else
    CFLAGS += -O2 -DNDEBUG
endif

# Propagate driver debugging into Rust builds when enabled for C.
ifneq (,$(findstring -DDEBUG_BLK,$(CFLAGS)))
    RUSTFLAGS += --cfg debug_blk
endif
ifneq (,$(findstring -DDEBUG_NET,$(CFLAGS)))
    RUSTFLAGS += --cfg debug_net
endif
export RUSTFLAGS

# Assembly flags
ASFLAGS := $(ARCH_ASFLAGS)

# Linker flags
LDFLAGS := -nostdlib $(ARCH_LDFLAGS) $(REPRO_LDFLAGS)

# Output directories
BUILD_DIR := build
OBJ_DIR := $(BUILD_DIR)/obj
BIN_DIR := $(BUILD_DIR)/bin
RELEASE_DIR := $(BUILD_DIR)/release
REPRO_ROOT := build/repro

# Optional third-party metadata (Wayland vendor build)
WAYLAND_PATHS_FILE := $(BUILD_DIR)/third_party/wayland/paths.mk
-include $(WAYLAND_PATHS_FILE)

ifneq ($(WAYLAND_PREFIX),)
PKG_CONFIG ?= $(shell command -v pkg-config 2>/dev/null)
export PKG_CONFIG
export PKG_CONFIG_PATH := $(WAYLAND_PKGCONFIG)$(if $(PKG_CONFIG_PATH),:$(PKG_CONFIG_PATH))
export WAYLAND_SCANNER
WAYLAND_CFLAGS := -I$(WAYLAND_INCLUDEDIR)
WAYLAND_LDFLAGS := -L$(WAYLAND_LIBDIR)
ifneq ($(PKG_CONFIG),)
WAYLAND_PC_FLAGS := $(shell PKG_CONFIG_PATH=$(WAYLAND_PKGCONFIG) $(PKG_CONFIG) --cflags wayland-server wayland-client 2>/dev/null)
WAYLAND_PC_LIBS := $(shell PKG_CONFIG_PATH=$(WAYLAND_PKGCONFIG) $(PKG_CONFIG) --static --libs wayland-server wayland-client 2>/dev/null)
ifneq ($(strip $(WAYLAND_PC_FLAGS)),)
WAYLAND_CFLAGS += $(WAYLAND_PC_FLAGS)
endif
ifneq ($(strip $(WAYLAND_PC_LIBS)),)
WAYLAND_LIBS := $(WAYLAND_PC_LIBS)
endif
endif
ifeq ($(strip $(WAYLAND_LIBS)),)
WAYLAND_LIBS := -lwayland-server -lwayland-client -lm -pthread -lrt -lffi -lexpat
endif
export WAYLAND_CFLAGS WAYLAND_LDFLAGS WAYLAND_LIBS
endif

# --- Build metadata (auto-generated) ---
GEN_DIR           := include/generated
GEN_VERSION_HDR   := $(GEN_DIR)/version.h
GEN_FEATURE_HDR   := $(GEN_DIR)/feature_flags.h
BUILD_GIT_DESC    := $(shell git describe --tags --always --dirty 2>/dev/null || echo "nogit")

KERNEL_DEPS       :=
KERNEL_DEPS      += $(GEN_VERSION_HDR)
KERNEL_DEPS      += $(GEN_FEATURE_HDR)

$(GEN_VERSION_HDR):
	@mkdir -p $(GEN_DIR)
	@echo "/* Auto-generated. Do not edit. */"                     >  $(GEN_VERSION_HDR)
	@echo "#pragma once"                                          >> $(GEN_VERSION_HDR)
	@echo "#define FUT_BUILD_DATE    \"$(BUILD_DATE_UTC)\""       >> $(GEN_VERSION_HDR)
	@echo "#define FUT_BUILD_GIT     \"$(BUILD_GIT_DESC)\""       >> $(GEN_VERSION_HDR)
	@echo "#define FUT_BUILD_HOST    \"$(BUILD_HOST)\""           >> $(GEN_VERSION_HDR)
	@echo "#define FUT_BUILD_USER    \"$(BUILD_USER)\""           >> $(GEN_VERSION_HDR)
	@echo "#define FUT_VERSION_STR   \"Futura $(BUILD_GIT_DESC)\"" >> $(GEN_VERSION_HDR)

.PHONY: FORCE

$(GEN_FEATURE_HDR): FORCE
	@mkdir -p $(GEN_DIR)
	@tmp=$@.tmp; \
	{ \
		echo "/* Auto-generated. Do not edit. */"; \
		echo "#pragma once"; \
		echo "#define ENABLE_WINSRV_DEMO $(ENABLE_WINSRV_DEMO)"; \
		echo "#define ENABLE_WAYLAND_DEMO $(ENABLE_WAYLAND_DEMO)"; \
	} > $$tmp; \
	if [ ! -f $@ ] || ! cmp -s $$tmp $@; then mv $$tmp $@; else rm $$tmp; fi

# ============================================================
#   Rust Toolchain Integration
# ============================================================

RUSTC := $(shell command -v rustc 2>/dev/null)
CARGO := $(shell command -v cargo 2>/dev/null)
RUST_AVAILABLE := $(if $(and $(RUSTC),$(CARGO)),yes,no)
RUST_TARGET := x86_64-unknown-linux-gnu
RUST_PROFILE := release
RUST_ROOT := drivers/rust
RUST_VIRTIO_BLK_DIR := $(RUST_ROOT)/virtio_blk
RUST_VIRTIO_NET_DIR := $(RUST_ROOT)/virtio_net
RUST_BUILD_DIR_BLK := $(RUST_VIRTIO_BLK_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_NET := $(RUST_VIRTIO_NET_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_LIB_VIRTIO_BLK := $(RUST_BUILD_DIR_BLK)/libvirtio_blk.a
RUST_LIB_VIRTIO_NET := $(RUST_BUILD_DIR_NET)/libvirtio_net.a

# Rust drivers are x86-64 only for now
ifeq ($(PLATFORM),x86_64)
RUST_LIBS := $(RUST_LIB_VIRTIO_BLK) $(RUST_LIB_VIRTIO_NET)
else
RUST_LIBS :=
endif
RUST_SOURCES := $(shell if [ -d $(RUST_ROOT) ]; then find $(RUST_ROOT) -type f \( -name '*.rs' -o -name 'Cargo.toml' -o -name 'build.rs' -o -name '*.toml' \); fi)

# ============================================================
#   Source Files
# ============================================================

# Kernel core sources
KERNEL_SOURCES := \
    kernel/kernel_main.c \
    kernel/boot/banner.c \
    kernel/boot/boot_args.c \
    kernel/memory/fut_memory.c \
    kernel/memory/fut_mm.c \
    kernel/memory/mmap_dump.c \
    kernel/memory/buddy_allocator.c \
    kernel/memory/slab_allocator.c \
    kernel/threading/fut_task.c \
    kernel/threading/fut_thread.c \
    kernel/scheduler/fut_sched.c \
    kernel/scheduler/fut_stats.c \
    kernel/scheduler/fut_waitq.c \
    kernel/timer/fut_timer.c \
    kernel/ipc/fut_object.c \
    kernel/ipc/fut_fipc.c \
    kernel/net/fut_net.c \
    kernel/net/fut_net_dev.c \
    kernel/net/fut_net_loopback.c \
    kernel/net/tcpip.c \
    kernel/net/dns.c \
    kernel/crypto/fut_hmac.c \
    kernel/vfs/fut_vfs.c \
    kernel/vfs/ramfs.c \
    kernel/exec/elf64.c \
    kernel/trap/page_fault.c \
    kernel/blockdev/fut_blockdev.c \
    kernel/blockdev/ramdisk.c \
    kernel/fs/futurafs.c \
    kernel/chrdev.c \
    kernel/sys_echo.c \
    kernel/sys_exit.c \
    kernel/sys_fork.c \
    kernel/sys_execve.c \
    kernel/sys_pipe.c \
    kernel/sys_dup2.c \
    kernel/sys_waitpid.c \
    kernel/sys_brk.c \
    kernel/sys_mmap.c \
    kernel/sys_nanosleep.c \
    kernel/sys_time.c \
    kernel/signal/signal.c \
    kernel/rt/memory.c \
    kernel/rt/stack_chk.c \
    kernel/uaccess.c \
    kernel/vfs/devfs.c \
    kernel/video/virtio_gpu.c \
    drivers/tty/console.c \
    drivers/tty/tty_ldisc.c \
    drivers/video/fb_console.c \
    kernel/rust/rustffi.c

# Platform-specific and architecture-specific kernel sources
ifeq ($(PLATFORM),x86_64)
    PLATFORM_SOURCES := \
        kernel/stubs_missing.c \
        platform/x86_64/boot.S \
        platform/x86_64/gdt_idt.S \
        platform/x86_64/isr_stubs.S \
        platform/x86_64/context_switch.S \
        platform/x86_64/user_iretq.S \
        platform/x86_64/gdt.c \
        arch/x86_64/pat.c \
        platform/x86_64/pmap.c \
        platform/x86_64/paging.c \
        platform/x86_64/cpu_features.c \
        platform/x86_64/platform_init.c \
        platform/x86_64/ps2.c \
        arch/x86_64/perf_clock.c \
        kernel/arch/x86_64/hal_halt.c \
        kernel/arch/x86_64/hal_interrupts.c \
        kernel/video/fb_mmio.c \
        kernel/video/pci_vga.c \
        kernel/video/cirrus_vga.c \
        drivers/video/fb.c \
        drivers/input/ps2_kbd.c \
        drivers/input/ps2_mouse.c \
        kernel/blk/blkcore.c \
        kernel/tests/echo_smoke.c \
        kernel/tests/input_smoke.c \
        kernel/tests/mm_tests.c \
        kernel/tests/perf.c \
        kernel/tests/perf_ipc.c \
        kernel/tests/perf_sched.c \
        kernel/tests/perf_blk.c \
        kernel/tests/perf_net.c \
        kernel/tests/fb_smoke.c \
        kernel/tests/exec_double.c \
        subsystems/futura_fs/futfs.c \
        subsystems/futura_fs/futfs_gc.c \
        platform/x86_64/drivers/ahci/ahci.c
else ifeq ($(PLATFORM),arm64)
    PLATFORM_SOURCES := \
        platform/arm64/boot.S \
        platform/arm64/context_switch.S \
        platform/arm64/platform_init.c \
        platform/arm64/arm64_stubs.c \
        platform/arm64/arm64_minimal_stubs.c \
        kernel/arch/arm64/hal_halt.c \
        kernel/arch/arm64/hal_interrupts.c \
        kernel/mm/arm64_paging.c \
        kernel/dtb/arm64_dtb.c \
        kernel/dtb/rpi_init.c
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

SHELL_BIN := $(BIN_DIR)/user/shell
SHELL_BLOB := $(OBJ_DIR)/kernel/blobs/shell_blob.o
FBTEST_BIN := $(BIN_DIR)/user/fbtest
FBTEST_BLOB := $(OBJ_DIR)/kernel/blobs/fbtest_blob.o
WINSRV_BIN := $(BIN_DIR)/user/winsrv
WINSRV_BLOB := $(OBJ_DIR)/kernel/blobs/winsrv_blob.o
WINSTUB_BIN := $(BIN_DIR)/user/winstub
WINSTUB_BLOB := $(OBJ_DIR)/kernel/blobs/winstub_blob.o
INIT_STUB_BIN := $(BIN_DIR)/user/init_stub
INIT_STUB_BLOB := $(OBJ_DIR)/kernel/blobs/init_stub_blob.o
SECOND_STUB_BIN := $(BIN_DIR)/user/second
SECOND_STUB_BLOB := $(OBJ_DIR)/kernel/blobs/second_stub_blob.o
WAYLAND_COMPOSITOR_BIN := $(BIN_DIR)/user/futura-wayland
WAYLAND_COMPOSITOR_BLOB := $(OBJ_DIR)/kernel/blobs/futura_wayland_blob.o
WAYLAND_CLIENT_BIN := $(BIN_DIR)/user/wl-simple
WAYLAND_CLIENT_BLOB := $(OBJ_DIR)/kernel/blobs/wl_simple_blob.o
WAYLAND_COLOR_BIN := $(BIN_DIR)/user/wl-colorwheel
WAYLAND_COLOR_BLOB := $(OBJ_DIR)/kernel/blobs/wl_colorwheel_blob.o

ifeq ($(PLATFORM),x86_64)
OBJECTS += $(SHELL_BLOB) $(FBTEST_BLOB)
ifeq ($(ENABLE_WINSRV_DEMO),1)
OBJECTS += $(WINSRV_BLOB) $(WINSTUB_BLOB)
endif
OBJECTS += $(INIT_STUB_BLOB) $(SECOND_STUB_BLOB)
ifeq ($(ENABLE_WAYLAND_DEMO),1)
OBJECTS += $(WAYLAND_COMPOSITOR_BLOB) $(WAYLAND_CLIENT_BLOB) $(WAYLAND_COLOR_BLOB)
endif
endif

# ============================================================
#   Build Targets
# ============================================================

.PHONY: all clean kernel userland rust-drivers

# Default target
all: rust-drivers kernel userland

# Create output directories
$(OBJ_DIR) $(BIN_DIR):
	@mkdir -p $@
	@mkdir -p $(OBJ_DIR)/kernel
	@mkdir -p $(OBJ_DIR)/kernel/memory
	@mkdir -p $(OBJ_DIR)/kernel/mm
	@mkdir -p $(OBJ_DIR)/kernel/threading
	@mkdir -p $(OBJ_DIR)/kernel/scheduler
	@mkdir -p $(OBJ_DIR)/kernel/timer
	@mkdir -p $(OBJ_DIR)/kernel/crypto
	@mkdir -p $(OBJ_DIR)/kernel/interrupts
	@mkdir -p $(OBJ_DIR)/kernel/ipc
	@mkdir -p $(OBJ_DIR)/kernel/net
	@mkdir -p $(OBJ_DIR)/kernel/vfs
	@mkdir -p $(OBJ_DIR)/kernel/exec
	@mkdir -p $(OBJ_DIR)/kernel/trap
	@mkdir -p $(OBJ_DIR)/kernel/blockdev
	@mkdir -p $(OBJ_DIR)/kernel/fs
	@mkdir -p $(OBJ_DIR)/kernel/rt
	@mkdir -p $(OBJ_DIR)/kernel/video
	@mkdir -p $(OBJ_DIR)/kernel/rust
	@mkdir -p $(OBJ_DIR)/kernel/blobs
	@mkdir -p $(OBJ_DIR)/platform/$(PLATFORM)
ifeq ($(PLATFORM),x86_64)
	@mkdir -p $(OBJ_DIR)/arch/x86_64
else ifeq ($(PLATFORM),arm64)
	@mkdir -p $(OBJ_DIR)/kernel/arch/arm64
	@mkdir -p $(OBJ_DIR)/kernel/dtb
endif
	@mkdir -p $(OBJ_DIR)/tests
	@mkdir -p $(OBJ_DIR)/subsystems/posix_compat
	@mkdir -p $(OBJ_DIR)/subsystems/futura_fs

# Build kernel
kernel: $(BIN_DIR)/futura_kernel.elf

.PHONY: futfs-crash-test
futfs-crash-test: kernel tools
	@tests/scripts/futfs_crash_gc.sh

$(BIN_DIR)/futura_kernel.elf: $(OBJECTS) $(RUST_LIBS) $(KERNEL_DEPS) | $(BIN_DIR)
	@echo "LD $@.tmp"
	@$(LD) $(LDFLAGS) -o $@.tmp $(OBJECTS) $(RUST_LIBS)
ifeq ($(PLATFORM),x86_64)
	@cp $@.tmp /tmp/kernel_before_fix.elf
	@echo "FIX-ELF $@"
	@python3 tools/fix_multiboot_offset.py $@.tmp $@
	@rm $@.tmp
else
	@cp $@.tmp $@
	@rm $@.tmp
endif
	@echo "Build complete: $@"

ifeq ($(RUST_AVAILABLE),yes)
rust-drivers: $(RUST_LIBS)

$(RUST_LIB_VIRTIO_BLK): $(RUST_SOURCES)
	@$(RUSTC) --print target-list | grep -q $(RUST_TARGET) >/dev/null || { \
		echo "error: rust target '$(RUST_TARGET)' not installed for $(RUSTC)." >&2; exit 1; }
	@echo "CARGO virtio_blk ($(RUST_PROFILE))"
	@cd $(RUST_VIRTIO_BLK_DIR) && RUSTFLAGS="-C panic=abort -C force-unwind-tables=no $(RUSTFLAGS)" $(CARGO) build --release --target $(RUST_TARGET)
	@tmpdir=$$(mktemp -d); \
	cd $$tmpdir && ar x $(abspath $(RUST_LIB_VIRTIO_BLK)) && for obj in *.o; do $(OBJCOPY) --remove-section='.gcc_except_table*' --remove-section='.eh_frame*' $$obj >/dev/null 2>&1 || true; done && ar rcs $(abspath $(RUST_LIB_VIRTIO_BLK)) *.o; \
	rm -rf $$tmpdir

$(RUST_LIB_VIRTIO_NET): $(RUST_SOURCES)
	@$(RUSTC) --print target-list | grep -q $(RUST_TARGET) >/dev/null || { \
		echo "error: rust target '$(RUST_TARGET)' not installed for $(RUSTC)." >&2; exit 1; }
	@echo "CARGO virtio_net ($(RUST_PROFILE))"
	@cd $(RUST_VIRTIO_NET_DIR) && RUSTFLAGS="-C panic=abort -C force-unwind-tables=no $(RUSTFLAGS)" $(CARGO) build --release --target $(RUST_TARGET)
	@tmpdir=$$(mktemp -d); \
	cd $$tmpdir && ar x $(abspath $(RUST_LIB_VIRTIO_NET)) && for obj in *.o; do $(OBJCOPY) --remove-section='.gcc_except_table*' --remove-section='.eh_frame*' $$obj >/dev/null 2>&1 || true; done && ar rcs $(abspath $(RUST_LIB_VIRTIO_NET)) *.o; \
	rm -rf $$tmpdir
else
rust-drivers:
	@echo "error: Rust toolchain (rustc/cargo) not found; install Rust to build rust-drivers." >&2
	@exit 1
endif

$(FBTEST_BIN):
	@$(MAKE) -C src/user fbtest

$(WINSRV_BIN):
	@$(MAKE) -C src/user services/winsrv

$(WINSTUB_BIN):
	@$(MAKE) -C src/user apps/winstub

$(INIT_STUB_BIN) $(SECOND_STUB_BIN):
	@$(MAKE) -C src/user stubs

$(WAYLAND_COMPOSITOR_BIN):
	@$(MAKE) -C src/user/compositor/futura-wayland all

$(WAYLAND_CLIENT_BIN):
	@$(MAKE) -C src/user/clients/wl-simple all

$(WAYLAND_COLOR_BIN):
	@$(MAKE) -C src/user/clients/wl-colorwheel all

$(OBJ_DIR)/kernel/blobs:
	@mkdir -p $@

$(SHELL_BIN):
	@$(MAKE) -C src/user shell

$(SHELL_BLOB): $(SHELL_BIN) | $(OBJ_DIR)/kernel/blobs
	@echo "OBJCOPY $@"
	@$(OBJCOPY) -I binary -O $(OBJCOPY_BIN_FMT) -B $(OBJCOPY_BIN_ARCH) $< $@

$(FBTEST_BLOB): $(FBTEST_BIN) | $(OBJ_DIR)/kernel/blobs
	@echo "OBJCOPY $@"
	@$(OBJCOPY) -I binary -O $(OBJCOPY_BIN_FMT) -B $(OBJCOPY_BIN_ARCH) $< $@

$(WINSRV_BLOB): $(WINSRV_BIN) | $(OBJ_DIR)/kernel/blobs
	@echo "OBJCOPY $@"
	@$(OBJCOPY) -I binary -O $(OBJCOPY_BIN_FMT) -B $(OBJCOPY_BIN_ARCH) $< $@

$(WINSTUB_BLOB): $(WINSTUB_BIN) | $(OBJ_DIR)/kernel/blobs
	@echo "OBJCOPY $@"
	@$(OBJCOPY) -I binary -O $(OBJCOPY_BIN_FMT) -B $(OBJCOPY_BIN_ARCH) $< $@

$(INIT_STUB_BLOB): $(INIT_STUB_BIN) | $(OBJ_DIR)/kernel/blobs
	@echo "OBJCOPY $@"
	@$(OBJCOPY) -I binary -O $(OBJCOPY_BIN_FMT) -B $(OBJCOPY_BIN_ARCH) $< $@

$(SECOND_STUB_BLOB): $(SECOND_STUB_BIN) | $(OBJ_DIR)/kernel/blobs
	@echo "OBJCOPY $@"
	@$(OBJCOPY) -I binary -O $(OBJCOPY_BIN_FMT) -B $(OBJCOPY_BIN_ARCH) $< $@

$(WAYLAND_COMPOSITOR_BLOB): $(WAYLAND_COMPOSITOR_BIN) | $(OBJ_DIR)/kernel/blobs
	@echo "OBJCOPY $@"
	@$(OBJCOPY) -I binary -O $(OBJCOPY_BIN_FMT) -B $(OBJCOPY_BIN_ARCH) $< $@

$(WAYLAND_CLIENT_BLOB): $(WAYLAND_CLIENT_BIN) | $(OBJ_DIR)/kernel/blobs
	@echo "OBJCOPY $@"
	@$(OBJCOPY) -I binary -O $(OBJCOPY_BIN_FMT) -B $(OBJCOPY_BIN_ARCH) $< $@

$(WAYLAND_COLOR_BLOB): $(WAYLAND_COLOR_BIN) | $(OBJ_DIR)/kernel/blobs
	@echo "OBJCOPY $@"
	@$(OBJCOPY) -I binary -O $(OBJCOPY_BIN_FMT) -B $(OBJCOPY_BIN_ARCH) $< $@

# Build userland services
userland:
	@echo "Building userland services..."
	@$(MAKE) -C src/user all

.PHONY: vendor libfutura userspace stage

vendor: third_party-wayland

libfutura:
	@$(MAKE) -C src/user/libfutura all

userspace: vendor libfutura
	@echo "Building Wayland demo userland..."
	@$(MAKE) -C src/user/compositor/futura-wayland all
	@$(MAKE) -C src/user/clients/wl-simple all
	@$(MAKE) -C src/user/clients/wl-colorwheel all
	@$(MAKE) -C src/user/stubs all

stage: userspace
	@echo "==> Staging userland into initramfs"
	@rm -rf $(INITROOT)
	@mkdir -p $(INITROOT)/sbin $(INITROOT)/bin $(INITROOT)/tmp
	@chmod 1777 $(INITROOT)/tmp
	@install -m 0755 $(WAYLAND_COMPOSITOR_BIN) $(INITROOT)/sbin/futura-wayland
	@install -m 0755 $(WAYLAND_CLIENT_BIN) $(INITROOT)/bin/wl-simple
	@install -m 0755 $(WAYLAND_COLOR_BIN) $(INITROOT)/bin/wl-colorwheel
	@if [ -f $(INIT_STUB_BIN) ]; then install -m 0755 $(INIT_STUB_BIN) $(INITROOT)/sbin/init; fi
	@if [ -f $(SECOND_STUB_BIN) ]; then install -m 0755 $(SECOND_STUB_BIN) $(INITROOT)/sbin/second; fi
	@mkdir -p $(dir $(INITRAMFS))
	@cd $(INITROOT) && find . -print0 | cpio --null -ov --format=newc --quiet > $(abspath $(INITRAMFS))
	@echo "==> Created initramfs $(INITRAMFS)"

.PHONY: tests tools

tests:
	@$(MAKE) -C tests

tools:
	@$(MAKE) -C tools

# Compile C sources
$(OBJ_DIR)/%.o: %.c $(GEN_VERSION_HDR) $(GEN_FEATURE_HDR) | $(OBJ_DIR)
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
ifeq ($(RUST_AVAILABLE),yes)
	@if [ -f $(RUST_VIRTIO_DIR)/Cargo.toml ]; then \
		cd $(RUST_VIRTIO_DIR) && $(CARGO) clean --target $(RUST_TARGET); \
	fi
	@rm -rf $(RUST_ROOT)/target
else
	@echo "Rust toolchain unavailable; skipping cargo clean."
endif
	@$(MAKE) -C src/user clean
	@echo "Clean complete"

# ============================================================
#   ISO and Testing Targets
# ============================================================

.PHONY: iso test

# Build bootable ISO with GRUB (useful for manual boots)
iso: kernel
	@echo "Creating bootable ISO..."
	@cp $(BIN_DIR)/futura_kernel.elf iso/boot/
	@grub-mkrescue -o futura.iso iso/ 2>&1 | grep -E "(completed|error)" || echo "ISO build complete"
	@echo "✓ Bootable ISO created: futura.iso"

$(QEMU_DISK_IMG):
	dd if=/dev/zero of=$@ bs=1M count=64

.PHONY: disk
disk: $(QEMU_DISK_IMG)

# Automated QEMU run with deterministic isa-debug-exit completion
test: iso disk
	@echo "Testing kernel under QEMU (isa-debug-exit)..."
	@img=$(QEMU_DISK_IMG); \
		echo "[HARNESS] Using test disk $$img"; \
		qemu-system-x86_64 \
			-serial stdio \
			-display none \
			-m $(QEMU_MEM) \
			$(QEMU_FLAGS) \
			-cdrom futura.iso \
			-boot d \
	; \
	code=$$?; \
	if [ $$code -eq 1 ]; then \
		echo "[HARNESS] PASS"; \
		exit 0; \
	else \
		echo "[HARNESS] FAIL (qemu code $$code)"; \
		exit $$code; \
	fi

.PHONY: desktop-step2
desktop-step2:
	@$(MAKE) ENABLE_WINSRV_DEMO=1 iso disk
	@echo "Running desktop-step2 scenario under QEMU..."
	@img=$(QEMU_DISK_IMG); \
		echo "[DESKTOP] Using disk $$img"; \
		qemu-system-x86_64 \
			-serial stdio \
			-display none \
			-m $(QEMU_MEM) \
			$(QEMU_FLAGS) \
			-cdrom futura.iso \
			-boot d \
	; \
	code=$$?; \
	if [ $$code -eq 1 ]; then \
		echo "[DESKTOP] PASS"; \
		exit 0; \
	else \
		echo "[DESKTOP] FAIL (qemu code $$code)"; \
		exit $$code; \
	fi

.PHONY: run run-debug run-headful run-clean help-run

run:
	@$(MAKE) ENABLE_WAYLAND_DEMO=1 vendor
	@$(MAKE) ENABLE_WAYLAND_DEMO=1 sym-audit
	@$(MAKE) ENABLE_WAYLAND_DEMO=1 libfutura
	@$(MAKE) ENABLE_WAYLAND_DEMO=1 DEBUG_WAYLAND=$(DEBUG) DEBUG_NETUNIX=$(DEBUG) userspace
	@$(MAKE) ENABLE_WAYLAND_DEMO=1 DEBUG_WAYLAND=$(DEBUG) DEBUG_NETUNIX=$(DEBUG) HEADFUL=$(HEADFUL) kernel
	@$(MAKE) ENABLE_WAYLAND_DEMO=1 DEBUG_WAYLAND=$(DEBUG) DEBUG_NETUNIX=$(DEBUG) stage
	@$(MAKE) disk >/dev/null
	@echo "==> Running QEMU (headful=$(HEADFUL), mem=$(MEM) MiB, debug=$(DEBUG))"
ifeq ($(HEADFUL),1)
ifeq ($(VNC),1)
	@echo "==> VNC server will be available at localhost:5900"
else
	@echo "==> Display: GTK with virtio-gpu (OpenGL enabled)"
	@if [ -z "$$DISPLAY" ] && [ -z "$$WAYLAND_DISPLAY" ]; then \
		echo "==> WARNING: No DISPLAY or WAYLAND_DISPLAY set!"; \
		echo "==>   GTK needs X11 or Wayland. Options:"; \
		echo "==>   1. Export DISPLAY (e.g., export DISPLAY=:0)"; \
		echo "==>   2. Use VNC: make VNC=1 run-headful"; \
		echo "==>   3. Use SSH X11 forwarding: ssh -X user@host"; \
	fi
endif
endif
	@set -o pipefail; \
	$(QEMU) $(RUN_QEMU_FLAGS) -kernel $(BIN_DIR)/futura_kernel.elf -initrd $(INITRAMFS) $(RUN_QEMU_APPEND) | tee qemu.log; \
	code=$${PIPESTATUS[0]}; \
	echo "[RUN] qemu exit $$code"; \
	if [ $$code -eq 1 ]; then \
	  echo "[RUN] PASS"; \
	  exit 0; \
	else \
	  printf '[RUN] FAIL (qemu code %s)\n' "$$code"; \
	  exit $$code; \
	fi

run-debug:
	@$(MAKE) DEBUG=1 run

run-headful:
	@$(MAKE) HEADFUL=1 run

run-clean:
	@rm -f qemu.log $(INITRAMFS)
	@rm -rf $(INITROOT)
	@$(MAKE) clean
	@$(MAKE) DEBUG=$(DEBUG) HEADFUL=$(HEADFUL) ASYNC=$(ASYNC) MEM=$(MEM) EXTRA_QEMU_FLAGS="$(EXTRA_QEMU_FLAGS)" run

help-run:
	@echo "make run              # build, stage, and boot headless Wayland demo"
	@echo "make run-debug        # enable DEBUG_* toggles and run headless"
	@echo "make run-headful      # run with QEMU display (GTK with virtio-gpu)"
	@echo "make run-clean        # clean artifacts and re-run demo"
	@echo
	@echo "Toggles (can be combined):"
	@echo "  MEM=1024            # increase guest memory (MiB)"
	@echo "  HEADFUL=1           # equivalent to make run-headful"
	@echo "  VNC=1               # use VNC display (headless-compatible)"
	@echo "  SDL=1               # use SDL display (requires X11)"
	@echo "  SPICE=1             # use SPICE display (headless-compatible)"
	@echo "  DEBUG=1             # enable DEBUG_WAYLAND/DEBUG_NETUNIX"
	@echo "  ASYNC=1             # enable async self-tests via kernel cmdline"
	@echo "  EXTRA_QEMU_FLAGS='-s -S' # append custom QEMU flags"
	@echo
	@echo "Display backend (HEADFUL mode):"
	@echo "  GTK (default)       # Native graphics window via virtio-gpu with OpenGL"
	@echo "                      # Requires X11 (DISPLAY) or Wayland (WAYLAND_DISPLAY)"
	@echo "  VNC                 # Remote viewing, works in headless (use VNC=1)"
	@echo "  SDL                 # Alternative native window (use SDL=1)"
	@echo "  SPICE               # Remote graphics protocol (use SPICE=1)"
	@echo
	@echo "Examples:"
	@echo "  make run-headful                    # GTK window with virtio-gpu"
	@echo "  export DISPLAY=:0 && make run-headful  # Set display first"
	@echo "  make VNC=1 run-headful              # VNC on localhost:5900"
	@echo "  make SDL=1 run-headful              # SDL window"

.PHONY: wayland-step2
wayland-step2:
	@$(MAKE) third_party-wayland
	@$(MAKE) DEBUG_WAYLAND=1 ENABLE_WAYLAND_DEMO=1 iso disk
	@echo "Running wayland-step2 scenario under QEMU..."
	@img=$(QEMU_DISK_IMG); \
		echo "[WAYLAND] Using disk $$img"; \
		qemu-system-x86_64 \
			-serial stdio \
			-display none \
			-m $(QEMU_MEM) \
			$(QEMU_FLAGS) \
			-cdrom futura.iso \
			-boot d \
	; \
	code=$$?; \
	if [ $$code -eq 1 ]; then \
		echo "[WAYLAND] PASS"; \
		exit 0; \
	else \
		echo "[WAYLAND] FAIL (qemu code $$code)"; \
		exit $$code; \
	fi

.PHONY: wayland-step3
wayland-step3:
	@$(MAKE) third_party-wayland
	@$(MAKE) sym-audit
	@$(MAKE) DEBUG_WAYLAND=1 ENABLE_WAYLAND_DEMO=1 iso disk
	@echo "Running wayland-step3 scenario under QEMU..."
	@img=$(QEMU_DISK_IMG); \
		echo "[WAYLAND] Using disk $$img"; \
		qemu-system-x86_64 \
			-serial stdio \
			-display none \
			-m $(QEMU_MEM) \
			$(QEMU_FLAGS) \
			-cdrom futura.iso \
			-boot d \
	; \
	code=$$?; \
	if [ $$code -eq 1 ]; then \
		echo "[WAYLAND] PASS"; \
		exit 0; \
	else \
		echo "[WAYLAND] FAIL (qemu code $$code)"; \
		exit $$code; \
	fi

.PHONY: perf perf-ci

perf: iso disk
	@echo "Running kernel performance harness..."
	@bash -c 'set -eo pipefail; OUT="$(BUILD_DIR)/perf_latest.txt"; mkdir -p "$(BUILD_DIR)"; rm -f "$$OUT"; \
	qemu-system-x86_64 -serial stdio -display none -m $(QEMU_MEM) $(QEMU_FLAGS) -cdrom futura.iso -boot d -append "perf=on" | tee "$$OUT"; \
	code=$${PIPESTATUS[0]}; \
	if [ $$code -eq 1 ]; then echo "[PERF] PASS"; exit 0; else echo "[PERF] FAIL (qemu code $$code)"; exit $$code; fi'

perf-ci: perf
	@python3 tools/perf_compare.py tests/baselines/perf_baseline.json $(BUILD_DIR)/perf_latest.txt

.PHONY: sym-audit
sym-audit:
	@files=$$(find build/third_party/wayland/build -name '*.a' -print); \
	if [ -z "$$files" ]; then \
		echo "[sym-audit] no archives found under third_party/wayland/build"; \
		exit 0; \
	fi; \
	if nm -Ao $$files | grep -E '@@GLIBC_|__.*_chk'; then \
		echo "[AUDIT] GLIBC/fortify symbols found in vendor libs"; \
		exit 1; \
	fi; \
	echo "[sym-audit] vendor archives clean"

.PHONY: release sbom sign metadata verify repro repro-ci release-ci

RELEASE_ARTIFACTS := $(RELEASE_DIR)/futura_kernel.elf \
                     $(RELEASE_DIR)/mkfutfs.static \
                     $(RELEASE_DIR)/fsck.futfs.static \
                     $(RELEASE_DIR)/futura.iso \
                     $(RELEASE_DIR)/futura_kernel.elf.cdx.json \
                     $(RELEASE_DIR)/tools.cdx.json

release: kernel tools iso
	@rm -rf $(RELEASE_DIR)
	@mkdir -p $(RELEASE_DIR)
	@cp $(BIN_DIR)/futura_kernel.elf $(RELEASE_DIR)/
	@if [ -f futura.iso ]; then cp futura.iso $(RELEASE_DIR)/futura.iso; fi
	@if [ -f $(BUILD_DIR)/tools/mkfutfs ]; then cp $(BUILD_DIR)/tools/mkfutfs $(RELEASE_DIR)/mkfutfs.static; fi
	@if [ -f $(BUILD_DIR)/tools/fsck.futfs ]; then cp $(BUILD_DIR)/tools/fsck.futfs $(RELEASE_DIR)/fsck.futfs.static; fi

sbom: release
	@tools/release/sbom.sh $(RELEASE_DIR)

sign: sbom
	@for f in $(RELEASE_ARTIFACTS); do \
		if [ -f $$f ]; then tools/release/sign.sh sign $$f $$f.sig; fi; \
	done

metadata: sign
	@python3 tools/release/metadata.py $(RELEASE_DIR) > $(RELEASE_DIR)/targets.json

repro:
	@rm -rf $(REPRO_ROOT)
	@$(MAKE) REPRO=1 BUILD_DIR=$(REPRO_ROOT)/A kernel tools >/dev/null
	@$(MAKE) REPRO=1 BUILD_DIR=$(REPRO_ROOT)/B kernel tools >/dev/null
	@cmp $(REPRO_ROOT)/A/bin/futura_kernel.elf $(REPRO_ROOT)/B/bin/futura_kernel.elf
	@cmp $(REPRO_ROOT)/A/tools/mkfutfs $(REPRO_ROOT)/B/tools/mkfutfs
	@cmp $(REPRO_ROOT)/A/tools/fsck.futfs $(REPRO_ROOT)/B/tools/fsck.futfs
	@echo "[REPRO] deterministic build confirmed"

verify: metadata repro
	@python3 tools/release/verify.py $(RELEASE_DIR)/targets.json $(RELEASE_DIR)
	@echo "[RELEASE] all artifacts verified and reproducible"

repro-ci: repro

release-ci:
	@$(MAKE) clean
	@$(MAKE) release
	@$(MAKE) sbom
	@$(MAKE) sign
	@$(MAKE) metadata
	@$(MAKE) verify

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
	@echo "  third_party-wayland - Build vendored Wayland libraries"
	@echo "  run               - Build and boot Wayland demo (headless)"
	@echo "  run-headful       - Build and boot with QEMU window"
	@echo "  run-debug         - Build, enable DEBUG toggles, and boot"
	@echo "  run-clean         - Clean artifacts then run demo"
	@echo "  help-run          - Usage information for run targets"
	@echo "  iso               - Build bootable GRUB ISO (required for testing)"
	@echo "  test              - Build and test kernel with GRUB (recommended)"
	@echo "  desktop-step2      - Boot winsrv/winstub demo (feature flag)"
	@echo "  wayland-step2      - Boot Wayland compositor/client skeleton"
	@echo "  wayland-step3      - Boot Wayland compositor with dual demo clients"
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
	@echo "  make desktop-step2            - Boot winsrv/winstub demo in QEMU"
	@echo "  make third_party-wayland      - Build vendored Wayland libs and scanner"
	@echo "  make clean                    - Clean build artifacts"

# ============================================================
#   Dependency Generation (Future)
# ============================================================

# Automatic dependency generation will be added in Phase 2
.PHONY: third_party-wayland
third_party-wayland:
	@$(MAKE) -C third_party/wayland all
