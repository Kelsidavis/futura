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
export PLATFORM

# Build profile: desktop (Horizon DE + Wayland) or server (headless, no GUI)
#   make PROFILE=desktop   — full desktop with Horizon compositor
#   make PROFILE=server    — headless server, no Wayland/GUI
PROFILE ?= desktop

# Build mode (debug, release)
BUILD_MODE ?= debug

# QEMU test harness configuration
QEMU_MEM       ?= 256
QEMU_IMG_SIZE  ?= 64M
QEMU_DISK_IMG  ?= futura_disk.img

QEMU_FLAGS += -cpu Broadwell,+smap  # Enable SMAP support for STAC/CLAC instructions
QEMU_FLAGS += -device isa-debug-exit,iobase=0xf4,iosize=0x4 -no-reboot -no-shutdown
QEMU_FLAGS += -drive if=virtio,file=$(QEMU_DISK_IMG),format=raw
# QEMU_FLAGS += -netdev user,id=net0 -device virtio-net,netdev=net0  # Disabled for perf testing

# ============================================================
#   Run Configuration Defaults
# ============================================================

MEM              ?= 1024
HEADFUL          ?= 0
DEBUG            ?= 0
ASYNC            ?= 0
AUTOEXIT        ?= 0
EXTRA_QEMU_FLAGS ?=
VNC_DISPLAY      ?= :0

# Set QEMU binary based on platform
ifeq ($(PLATFORM),arm64)
QEMU             ?= qemu-system-aarch64
else
QEMU             ?= qemu-system-x86_64
endif

INITROOT  = $(BUILD_DIR)/initroot
INITRAMFS = $(BUILD_DIR)/initramfs.cpio

WAYLAND_ENV = XDG_RUNTIME_DIR=/tmp WAYLAND_DISPLAY=wayland-0 WAYLAND_MULTI=1 \
              WAYLAND_BACKBUFFER=0 WAYLAND_DECO=1 WAYLAND_SHADOW=1 \
              WAYLAND_RESIZE=1 WAYLAND_THROTTLE=1
ifeq ($(DEBUG),1)
WAYLAND_ENV += DEBUG_WAYLAND=1 DEBUG_NETUNIX=1
endif

KAPPEND := futura.runtests
ifeq ($(ASYNC),1)
KAPPEND += async-tests=1
endif
ifeq ($(PERF),1)
KAPPEND += perf
endif
ifeq ($(AUTOEXIT),1)
KAPPEND += wayland-autoclose=1
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
else
RUN_QEMU_FLAGS += -cpu IvyBridge,+smep,+smap -smp 1
endif

ifeq ($(HEADFUL),1)
# Headful mode: use bochs VGA (QEMU stdvga) for display
# GTK is default for native graphics output, falls back to VNC if no display server
ifeq ($(VNC),1)
    RUN_QEMU_FLAGS += -vnc $(VNC_DISPLAY)
else ifeq ($(SPICE),1)
RUN_QEMU_FLAGS += -display spice-app
else ifeq ($(SDL),1)
RUN_QEMU_FLAGS += -display sdl
else
# GTK provides native graphics window
# Requires X11 (DISPLAY) or Wayland (WAYLAND_DISPLAY) to be set
RUN_QEMU_FLAGS += -display gtk,gl=off
endif
# Use bochs VGA (stdvga) - requires VBE DISPI initialization in kernel
RUN_QEMU_FLAGS += -vga std
else
RUN_QEMU_FLAGS += -display none
RUN_QEMU_FLAGS += -vga none
endif

# Add platform-specific devices (isa-debug-exit is x86-64 only)
ifeq ($(PLATFORM),x86_64)
RUN_QEMU_FLAGS += -device isa-debug-exit,iobase=0xf4,iosize=0x4
endif

ifeq ($(PLATFORM),arm64)
# ARM64 virt: use explicit MMIO device types
RUN_QEMU_FLAGS += -drive file=$(QEMU_DISK_IMG),if=none,id=hd0 -device virtio-blk-device,drive=hd0
RUN_QEMU_FLAGS += -netdev user,id=net0 -device virtio-net-device,netdev=net0
else
RUN_QEMU_FLAGS += -drive if=virtio,file=$(QEMU_DISK_IMG),format=raw
endif
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
    # On macOS, use the cross-compiler; on Linux, use native tools
    ifeq ($(shell uname -s),Darwin)
        CROSS_COMPILE_X86 ?= /opt/homebrew/bin/x86_64-elf-
        CC := $(CROSS_COMPILE_X86)gcc
        AS := $(CROSS_COMPILE_X86)as
        LD := $(CROSS_COMPILE_X86)ld
        AR := $(CROSS_COMPILE_X86)ar
        OBJCOPY := $(CROSS_COMPILE_X86)objcopy
    else
        CC := gcc-14
        AS := as
        LD := ld
        AR := ar
        OBJCOPY := objcopy
    endif
    ARCH_CFLAGS := -m64 -mcmodel=kernel -mno-red-zone -mno-sse -mno-avx -mno-avx2 -fno-tree-vectorize
    ARCH_ASFLAGS := --64
    ARCH_LDFLAGS := -m elf_x86_64 -T platform/x86_64/link.ld
    EXTRA_LDLIBS :=
    # Binary format for embedding blobs
    OBJCOPY_BIN_FMT := elf64-x86-64
    OBJCOPY_BIN_ARCH := i386:x86-64
else ifeq ($(PLATFORM),arm64)
    # ARM64 cross-compilation toolchain
    # On macOS, use the Homebrew cross-compiler; on Linux, use distro packages
    ifeq ($(shell uname -s),Darwin)
        CROSS_COMPILE ?= /opt/homebrew/bin/aarch64-elf-
        CC := $(CROSS_COMPILE)gcc
        AS := $(CROSS_COMPILE)as
        LD := $(CROSS_COMPILE)ld
        AR := $(CROSS_COMPILE)ar
        OBJCOPY := $(CROSS_COMPILE)objcopy
        EXTRA_LDLIBS := /opt/homebrew/Cellar/aarch64-elf-gcc/15.2.0/lib/gcc/aarch64-elf/15.2.0/libgcc.a
    else
        CROSS_COMPILE ?= aarch64-linux-gnu-
        CC := $(CROSS_COMPILE)gcc-14
        AS := $(CROSS_COMPILE)as
        LD := $(CROSS_COMPILE)ld
        AR := $(CROSS_COMPILE)ar
        OBJCOPY := $(CROSS_COMPILE)objcopy
        EXTRA_LDLIBS := $(shell $(CROSS_COMPILE)gcc-14 -print-libgcc-file-name 2>/dev/null)
    endif
    ARCH_CFLAGS := -march=armv8-a -mtune=cortex-a53 -Wno-pedantic -mno-outline-atomics
    ARCH_ASFLAGS :=
    ARCH_LDFLAGS := -T platform/arm64/link.ld
    # Binary format for embedding blobs
    OBJCOPY_BIN_FMT := elf64-littleaarch64
    OBJCOPY_BIN_ARCH := aarch64
else
    $(error Unsupported platform: $(PLATFORM))
endif

# Export toolchain variables for submakes (userland, etc.)
export CC AS LD AR OBJCOPY

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
CFLAGS += -Wall -Wextra -Wpedantic -Werror -Wno-unterminated-string-initialization
CFLAGS += -fno-pic -fno-pie  # Disable PIC/PIE for kernel code
CFLAGS += -fcf-protection=none  # Disable CET (Control-flow Enforcement Technology)
CFLAGS += -I.
CFLAGS += -I./include
CFLAGS += -I$(BUILD_GEN_ROOT)
CFLAGS += $(ARCH_CFLAGS)
CFLAGS += $(REPRO_CFLAGS)

# Interactive mode for GUI testing (must be after main CFLAGS setup)
ifeq ($(HEADFUL),1)
CFLAGS += -DWAYLAND_INTERACTIVE_MODE=1
endif

# Feature toggles
# Wayland compositor + Horizon DE (production UI)
# Auto-set by PROFILE: desktop=1, server=0
ifeq ($(PROFILE),server)
  ENABLE_WAYLAND ?= 0
else
  ENABLE_WAYLAND ?= 1
endif
# Wayland test clients (wl-simple, wl-colorwheel) - disabled by default
ENABLE_WAYLAND_TEST_CLIENTS ?= 0
# Optional: fbtest framebuffer diagnostic tool
ENABLE_FB_DIAGNOSTICS ?= 0
# ENABLE_WAYLAND is defined in $(GEN_FEATURE_HDR) to avoid redefinition conflicts

# macOS host build flag (disables userland blobs that can't build on macOS)
ifeq ($(shell uname -s),Darwin)
CFLAGS += -DFUTURA_MACOS_HOST_BUILD=1
endif

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
# -z noexecstack: Suppress warnings about missing .note.GNU-stack in blob files
LDFLAGS := -nostdlib -z noexecstack $(ARCH_LDFLAGS) $(REPRO_LDFLAGS)

# Output directories
BUILD_DIR := build
BUILD_GEN_ROOT := $(BUILD_DIR)/generated
BUILD_KERNEL_CMDLINE_DIR := $(BUILD_GEN_ROOT)/kernel
BOOT_CMDLINE_HEADER := $(BUILD_KERNEL_CMDLINE_DIR)/build_cmdline.h
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
KERNEL_DEPS      += $(BOOT_CMDLINE_HEADER)
# Linker scripts: changes require full relink
ifeq ($(PLATFORM),x86_64)
KERNEL_DEPS      += platform/x86_64/link.ld
else ifeq ($(PLATFORM),arm64)
KERNEL_DEPS      += platform/arm64/link.ld
endif

# Ensure 'all' is the default target even though generated-header rules
# appear before the 'all:' line.
.DEFAULT_GOAL := all

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
		echo "#define ENABLE_WAYLAND $(ENABLE_WAYLAND)"; \
		echo "#define ENABLE_WAYLAND_TEST_CLIENTS $(ENABLE_WAYLAND_TEST_CLIENTS)"; \
	} > $$tmp; \
	if [ ! -f $@ ] || ! cmp -s $$tmp $@; then mv $$tmp $@; else rm $$tmp; fi

$(BUILD_GEN_ROOT):
	@mkdir -p $(BUILD_GEN_ROOT)

$(BUILD_KERNEL_CMDLINE_DIR): | $(BUILD_GEN_ROOT)
	@mkdir -p $(BUILD_KERNEL_CMDLINE_DIR)

# Force regeneration of boot cmdline header when KAPPEND changes
# We use a marker file to track the last KAPPEND value
CMDLINE_MARKER := $(BUILD_KERNEL_CMDLINE_DIR)/.cmdline_marker
CURRENT_CMDLINE_HASH := $(shell echo "$(KAPPEND)" | md5sum | cut -d' ' -f1)

# Check if marker exists and matches current KAPPEND
ifneq ($(shell cat $(CMDLINE_MARKER) 2>/dev/null),$(CURRENT_CMDLINE_HASH))
.PHONY: $(BOOT_CMDLINE_HEADER)
endif

$(BOOT_CMDLINE_HEADER): | $(BUILD_KERNEL_CMDLINE_DIR)
	@echo "Generating boot cmdline header (KAPPEND=$(KAPPEND))"
	@python3 scripts/gen_boot_cmdline.py "$(KAPPEND)" "$(BOOT_CMDLINE_HEADER)"
	@echo "$(CURRENT_CMDLINE_HASH)" > $(CMDLINE_MARKER)

# ============================================================
#   Rust Toolchain Integration
# ============================================================ 

RUSTC := $(shell command -v rustc 2>/dev/null)
CARGO := $(shell command -v cargo 2>/dev/null)
RUST_AVAILABLE := $(if $(and $(RUSTC),$(CARGO)),yes,no)
# Set Rust target based on platform
ifeq ($(PLATFORM),arm64)
RUST_TARGET := aarch64-unknown-linux-gnu
else
RUST_TARGET := x86_64-unknown-linux-gnu
endif

RUST_PROFILE := release
RUST_ROOT := drivers/rust
RUST_VIRTIO_BLK_DIR   := $(RUST_ROOT)/virtio_blk
RUST_VIRTIO_NET_DIR   := $(RUST_ROOT)/virtio_net
RUST_VIRTIO_GPU_DIR   := $(RUST_ROOT)/virtio_gpu
RUST_VIRTIO_INPUT_DIR := $(RUST_ROOT)/virtio_input
RUST_APPLE_UART_DIR   := $(RUST_ROOT)/apple_uart
RUST_APPLE_RTKIT_DIR  := $(RUST_ROOT)/apple_rtkit
RUST_APPLE_ANS2_DIR   := $(RUST_ROOT)/apple_ans2
RUST_APPLE_AIC_DIR    := $(RUST_ROOT)/apple_aic
RUST_APPLE_DART_DIR   := $(RUST_ROOT)/apple_dart
RUST_APPLE_GPIO_DIR   := $(RUST_ROOT)/apple_gpio
RUST_APPLE_I2C_DIR    := $(RUST_ROOT)/apple_i2c
RUST_APPLE_PCIE_DIR   := $(RUST_ROOT)/apple_pcie
RUST_APPLE_SMC_DIR    := $(RUST_ROOT)/apple_smc
RUST_APPLE_SPI_DIR    := $(RUST_ROOT)/apple_spi
RUST_APPLE_MCA_DIR    := $(RUST_ROOT)/apple_mca
RUST_NVME_DIR         := $(RUST_ROOT)/nvme
RUST_XHCI_DIR        := $(RUST_ROOT)/xhci
RUST_RTL8111_DIR     := $(RUST_ROOT)/rtl8111
RUST_HDA_DIR          := $(RUST_ROOT)/hda
RUST_AMD_SMBUS_DIR   := $(RUST_ROOT)/amd_smbus
RUST_AMD_IOMMU_DIR   := $(RUST_ROOT)/amd_iommu
RUST_AHCI_DIR        := $(RUST_ROOT)/ahci
RUST_HPET_DIR        := $(RUST_ROOT)/hpet
RUST_IGC_DIR         := $(RUST_ROOT)/igc
RUST_AMD_WDT_DIR     := $(RUST_ROOT)/amd_wdt
RUST_AMD_GPIO_DIR    := $(RUST_ROOT)/amd_gpio
RUST_CMOS_RTC_DIR    := $(RUST_ROOT)/cmos_rtc
RUST_AMD_SPI_DIR     := $(RUST_ROOT)/amd_spi
RUST_TPM_CRB_DIR     := $(RUST_ROOT)/tpm_crb
RUST_AMD_SBTSI_DIR   := $(RUST_ROOT)/amd_sbtsi
RUST_AMD_PSTATE_DIR  := $(RUST_ROOT)/amd_pstate
RUST_I211_DIR        := $(RUST_ROOT)/i211
RUST_PCI_MSIX_DIR    := $(RUST_ROOT)/pci_msix
RUST_USB_HID_DIR     := $(RUST_ROOT)/usb_hid
RUST_USB_STORAGE_DIR := $(RUST_ROOT)/usb_storage
RUST_LAPIC_DIR       := $(RUST_ROOT)/lapic
RUST_UART16550_DIR   := $(RUST_ROOT)/uart16550
RUST_I8042_DIR       := $(RUST_ROOT)/i8042
RUST_PCIE_ECAM_DIR   := $(RUST_ROOT)/pcie_ecam
RUST_AMD_SMN_DIR     := $(RUST_ROOT)/amd_smn
RUST_AMD_UMC_DIR     := $(RUST_ROOT)/amd_umc
RUST_AMD_CCP_DIR     := $(RUST_ROOT)/amd_ccp
RUST_ACPI_PM_DIR     := $(RUST_ROOT)/acpi_pm
RUST_VESA_FB_DIR     := $(RUST_ROOT)/vesa_fb
RUST_PCI_PM_DIR      := $(RUST_ROOT)/pci_pm
RUST_AMD_DF_DIR      := $(RUST_ROOT)/amd_df
RUST_AMD_NBIO_DIR    := $(RUST_ROOT)/amd_nbio
RUST_USB_NET_DIR     := $(RUST_ROOT)/usb_net
RUST_USB_HUB_DIR     := $(RUST_ROOT)/usb_hub
RUST_HDA_REALTEK_DIR := $(RUST_ROOT)/hda_realtek
RUST_AMD_I2C_DIR     := $(RUST_ROOT)/amd_i2c
RUST_AMD_PSP_DIR     := $(RUST_ROOT)/amd_psp
RUST_X86_MCE_DIR     := $(RUST_ROOT)/x86_mce
RUST_PCI_AER_DIR     := $(RUST_ROOT)/pci_aer
RUST_ACPI_EC_DIR     := $(RUST_ROOT)/acpi_ec
RUST_ETH_PHY_DIR     := $(RUST_ROOT)/eth_phy
RUST_USB_AUDIO_DIR   := $(RUST_ROOT)/usb_audio
RUST_ACPI_THERMAL_DIR := $(RUST_ROOT)/acpi_thermal
RUST_DMA_POOL_DIR    := $(RUST_ROOT)/dma_pool
RUST_FB_CONSOLE_DIR  := $(RUST_ROOT)/fb_console
RUST_PCI_SRIOV_DIR   := $(RUST_ROOT)/pci_sriov
RUST_EDID_DIR        := $(RUST_ROOT)/edid
RUST_AMD_XGBE_DIR    := $(RUST_ROOT)/amd_xgbe
RUST_X86_TSC_DIR     := $(RUST_ROOT)/x86_tsc
RUST_AMD_SEV_DIR     := $(RUST_ROOT)/amd_sev
RUST_VIRTIO_CON_DIR  := $(RUST_ROOT)/virtio_console
RUST_ACPI_BTN_DIR    := $(RUST_ROOT)/acpi_button
RUST_AMD_MP2_DIR     := $(RUST_ROOT)/amd_mp2
RUST_X86_CPUID_DIR   := $(RUST_ROOT)/x86_cpuid
RUST_INTEL_VTD_DIR   := $(RUST_ROOT)/intel_vtd
RUST_INTEL_HWP_DIR   := $(RUST_ROOT)/intel_hwp
RUST_INTEL_LPSS_DIR  := $(RUST_ROOT)/intel_lpss
RUST_INTEL_PMC_DIR   := $(RUST_ROOT)/intel_pmc
RUST_INTEL_GPIO_DIR  := $(RUST_ROOT)/intel_gpio
RUST_INTEL_WDT_DIR   := $(RUST_ROOT)/intel_wdt
RUST_INTEL_MEI_DIR   := $(RUST_ROOT)/intel_mei
RUST_INTEL_TBT_DIR   := $(RUST_ROOT)/intel_tbt
RUST_INTEL_THERM_DIR := $(RUST_ROOT)/intel_thermal
RUST_INTEL_GNA_DIR   := $(RUST_ROOT)/intel_gna
RUST_INTEL_SST_DIR   := $(RUST_ROOT)/intel_sst
RUST_INTEL_HDMI_DIR  := $(RUST_ROOT)/intel_hda_hdmi
RUST_INTEL_CNVI_DIR  := $(RUST_ROOT)/intel_cnvi
RUST_INTEL_DMA_DIR   := $(RUST_ROOT)/intel_dma
RUST_INTEL_IPU_DIR   := $(RUST_ROOT)/intel_ipu
RUST_INTEL_P2SB_DIR  := $(RUST_ROOT)/intel_p2sb
RUST_INTEL_SMBUS_DIR := $(RUST_ROOT)/intel_smbus
RUST_INTEL_SPI_DIR   := $(RUST_ROOT)/intel_spi
RUST_RPI_AUDIO_DIR   := $(RUST_ROOT)/rpi_audio
RUST_RPI_DISPLAY_DIR := $(RUST_ROOT)/rpi_display
RUST_RPI_DMA_DIR     := $(RUST_ROOT)/rpi_dma
RUST_RPI_EMMC_DIR    := $(RUST_ROOT)/rpi_emmc
RUST_RPI_GENET_DIR   := $(RUST_ROOT)/rpi_genet
RUST_RPI_GPIO_DIR    := $(RUST_ROOT)/rpi_gpio
RUST_RPI_I2C_DIR     := $(RUST_ROOT)/rpi_i2c
RUST_RPI_MBOX_DIR    := $(RUST_ROOT)/rpi_mbox
RUST_RPI_PCIE_DIR    := $(RUST_ROOT)/rpi_pcie
RUST_RPI_PWM_DIR     := $(RUST_ROOT)/rpi_pwm
RUST_RPI_RNG_DIR     := $(RUST_ROOT)/rpi_rng
RUST_RPI_SPI_DIR     := $(RUST_ROOT)/rpi_spi
RUST_RPI_THERMAL_DIR := $(RUST_ROOT)/rpi_thermal
RUST_RPI_USB_DIR     := $(RUST_ROOT)/rpi_usb
RUST_RPI_WATCHDOG_DIR := $(RUST_ROOT)/rpi_watchdog
RUST_BUILD_DIR_RPI_AUDIO   := $(RUST_RPI_AUDIO_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_RPI_DISPLAY := $(RUST_RPI_DISPLAY_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_RPI_DMA     := $(RUST_RPI_DMA_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_RPI_EMMC    := $(RUST_RPI_EMMC_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_RPI_GENET   := $(RUST_RPI_GENET_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_RPI_GPIO    := $(RUST_RPI_GPIO_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_RPI_I2C     := $(RUST_RPI_I2C_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_RPI_MBOX    := $(RUST_RPI_MBOX_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_RPI_PCIE    := $(RUST_RPI_PCIE_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_RPI_PWM     := $(RUST_RPI_PWM_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_RPI_RNG     := $(RUST_RPI_RNG_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_RPI_SPI     := $(RUST_RPI_SPI_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_RPI_THERMAL := $(RUST_RPI_THERMAL_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_RPI_USB     := $(RUST_RPI_USB_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_RPI_WATCHDOG := $(RUST_RPI_WATCHDOG_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_BLK   := $(RUST_VIRTIO_BLK_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_NET   := $(RUST_VIRTIO_NET_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_GPU   := $(RUST_VIRTIO_GPU_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_INPUT := $(RUST_VIRTIO_INPUT_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_APPLE_UART  := $(RUST_APPLE_UART_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_APPLE_RTKIT := $(RUST_APPLE_RTKIT_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_APPLE_ANS2  := $(RUST_APPLE_ANS2_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_APPLE_AIC   := $(RUST_APPLE_AIC_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_APPLE_DART  := $(RUST_APPLE_DART_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_APPLE_GPIO  := $(RUST_APPLE_GPIO_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_APPLE_I2C   := $(RUST_APPLE_I2C_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_APPLE_PCIE  := $(RUST_APPLE_PCIE_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_APPLE_SMC   := $(RUST_APPLE_SMC_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_APPLE_SPI   := $(RUST_APPLE_SPI_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_APPLE_MCA   := $(RUST_APPLE_MCA_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_NVME        := $(RUST_NVME_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_XHCI       := $(RUST_XHCI_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_RTL8111    := $(RUST_RTL8111_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_HDA         := $(RUST_HDA_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_AMD_SMBUS  := $(RUST_AMD_SMBUS_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_AMD_IOMMU  := $(RUST_AMD_IOMMU_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_AHCI       := $(RUST_AHCI_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_HPET       := $(RUST_HPET_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_IGC        := $(RUST_IGC_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_AMD_WDT    := $(RUST_AMD_WDT_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_AMD_GPIO   := $(RUST_AMD_GPIO_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_CMOS_RTC   := $(RUST_CMOS_RTC_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_AMD_SPI    := $(RUST_AMD_SPI_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_TPM_CRB    := $(RUST_TPM_CRB_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_AMD_SBTSI  := $(RUST_AMD_SBTSI_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_AMD_PSTATE := $(RUST_AMD_PSTATE_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_I211       := $(RUST_I211_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_PCI_MSIX   := $(RUST_PCI_MSIX_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_USB_HID    := $(RUST_USB_HID_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_USB_STORAGE := $(RUST_USB_STORAGE_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_LAPIC      := $(RUST_LAPIC_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_UART16550  := $(RUST_UART16550_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_I8042      := $(RUST_I8042_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_PCIE_ECAM  := $(RUST_PCIE_ECAM_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_AMD_SMN    := $(RUST_AMD_SMN_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_AMD_UMC    := $(RUST_AMD_UMC_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_AMD_CCP    := $(RUST_AMD_CCP_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_ACPI_PM    := $(RUST_ACPI_PM_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_VESA_FB    := $(RUST_VESA_FB_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_PCI_PM     := $(RUST_PCI_PM_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_AMD_DF     := $(RUST_AMD_DF_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_AMD_NBIO   := $(RUST_AMD_NBIO_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_USB_NET    := $(RUST_USB_NET_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_USB_HUB    := $(RUST_USB_HUB_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_HDA_REALTEK := $(RUST_HDA_REALTEK_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_AMD_I2C    := $(RUST_AMD_I2C_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_AMD_PSP    := $(RUST_AMD_PSP_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_X86_MCE    := $(RUST_X86_MCE_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_PCI_AER    := $(RUST_PCI_AER_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_ACPI_EC    := $(RUST_ACPI_EC_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_ETH_PHY    := $(RUST_ETH_PHY_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_USB_AUDIO  := $(RUST_USB_AUDIO_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_ACPI_THERMAL := $(RUST_ACPI_THERMAL_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_DMA_POOL   := $(RUST_DMA_POOL_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_FB_CONSOLE := $(RUST_FB_CONSOLE_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_PCI_SRIOV := $(RUST_PCI_SRIOV_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_EDID       := $(RUST_EDID_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_AMD_XGBE   := $(RUST_AMD_XGBE_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_X86_TSC    := $(RUST_X86_TSC_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_AMD_SEV    := $(RUST_AMD_SEV_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_VIRTIO_CON := $(RUST_VIRTIO_CON_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_ACPI_BTN   := $(RUST_ACPI_BTN_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_AMD_MP2    := $(RUST_AMD_MP2_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_X86_CPUID  := $(RUST_X86_CPUID_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_INTEL_VTD  := $(RUST_INTEL_VTD_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_INTEL_HWP  := $(RUST_INTEL_HWP_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_INTEL_LPSS := $(RUST_INTEL_LPSS_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_INTEL_PMC  := $(RUST_INTEL_PMC_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_INTEL_GPIO := $(RUST_INTEL_GPIO_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_INTEL_WDT  := $(RUST_INTEL_WDT_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_INTEL_MEI  := $(RUST_INTEL_MEI_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_INTEL_TBT  := $(RUST_INTEL_TBT_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_INTEL_THERM := $(RUST_INTEL_THERM_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_INTEL_GNA  := $(RUST_INTEL_GNA_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_INTEL_SST  := $(RUST_INTEL_SST_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_INTEL_HDMI := $(RUST_INTEL_HDMI_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_INTEL_CNVI := $(RUST_INTEL_CNVI_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_INTEL_DMA  := $(RUST_INTEL_DMA_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_INTEL_IPU  := $(RUST_INTEL_IPU_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_INTEL_P2SB := $(RUST_INTEL_P2SB_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_INTEL_SMBUS := $(RUST_INTEL_SMBUS_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_BUILD_DIR_INTEL_SPI  := $(RUST_INTEL_SPI_DIR)/target/$(RUST_TARGET)/$(RUST_PROFILE)
RUST_LIB_VIRTIO_BLK   := $(RUST_BUILD_DIR_BLK)/libvirtio_blk.a
RUST_LIB_VIRTIO_NET   := $(RUST_BUILD_DIR_NET)/libvirtio_net.a
RUST_LIB_VIRTIO_GPU   := $(RUST_BUILD_DIR_GPU)/libvirtio_gpu.a
RUST_LIB_VIRTIO_INPUT := $(RUST_BUILD_DIR_INPUT)/libvirtio_input.a
RUST_LIB_APPLE_UART   := $(RUST_BUILD_DIR_APPLE_UART)/libapple_uart.a
RUST_LIB_APPLE_RTKIT  := $(RUST_BUILD_DIR_APPLE_RTKIT)/libapple_rtkit.a
RUST_LIB_APPLE_ANS2   := $(RUST_BUILD_DIR_APPLE_ANS2)/libapple_ans2.a
RUST_LIB_APPLE_AIC    := $(RUST_BUILD_DIR_APPLE_AIC)/libapple_aic.a
RUST_LIB_APPLE_DART   := $(RUST_BUILD_DIR_APPLE_DART)/libapple_dart.a
RUST_LIB_APPLE_GPIO   := $(RUST_BUILD_DIR_APPLE_GPIO)/libapple_gpio.a
RUST_LIB_APPLE_I2C    := $(RUST_BUILD_DIR_APPLE_I2C)/libapple_i2c.a
RUST_LIB_APPLE_PCIE   := $(RUST_BUILD_DIR_APPLE_PCIE)/libapple_pcie.a
RUST_LIB_APPLE_SMC    := $(RUST_BUILD_DIR_APPLE_SMC)/libapple_smc.a
RUST_LIB_APPLE_SPI    := $(RUST_BUILD_DIR_APPLE_SPI)/libapple_spi.a
RUST_LIB_APPLE_MCA    := $(RUST_BUILD_DIR_APPLE_MCA)/libapple_mca.a
RUST_LIB_NVME         := $(RUST_BUILD_DIR_NVME)/libnvme.a
RUST_LIB_XHCI        := $(RUST_BUILD_DIR_XHCI)/libxhci.a
RUST_LIB_RTL8111     := $(RUST_BUILD_DIR_RTL8111)/librtl8111.a
RUST_LIB_HDA          := $(RUST_BUILD_DIR_HDA)/libhda.a
RUST_LIB_AMD_SMBUS   := $(RUST_BUILD_DIR_AMD_SMBUS)/libamd_smbus.a
RUST_LIB_AMD_IOMMU   := $(RUST_BUILD_DIR_AMD_IOMMU)/libamd_iommu.a
RUST_LIB_AHCI        := $(RUST_BUILD_DIR_AHCI)/libahci.a
RUST_LIB_HPET        := $(RUST_BUILD_DIR_HPET)/libhpet.a
RUST_LIB_IGC         := $(RUST_BUILD_DIR_IGC)/libigc.a
RUST_LIB_AMD_WDT     := $(RUST_BUILD_DIR_AMD_WDT)/libamd_wdt.a
RUST_LIB_AMD_GPIO    := $(RUST_BUILD_DIR_AMD_GPIO)/libamd_gpio.a
RUST_LIB_CMOS_RTC    := $(RUST_BUILD_DIR_CMOS_RTC)/libcmos_rtc.a
RUST_LIB_AMD_SPI     := $(RUST_BUILD_DIR_AMD_SPI)/libamd_spi.a
RUST_LIB_TPM_CRB     := $(RUST_BUILD_DIR_TPM_CRB)/libtpm_crb.a
RUST_LIB_AMD_SBTSI   := $(RUST_BUILD_DIR_AMD_SBTSI)/libamd_sbtsi.a
RUST_LIB_AMD_PSTATE  := $(RUST_BUILD_DIR_AMD_PSTATE)/libamd_pstate.a
RUST_LIB_I211        := $(RUST_BUILD_DIR_I211)/libi211.a
RUST_LIB_PCI_MSIX    := $(RUST_BUILD_DIR_PCI_MSIX)/libpci_msix.a
RUST_LIB_USB_HID     := $(RUST_BUILD_DIR_USB_HID)/libusb_hid.a
RUST_LIB_USB_STORAGE := $(RUST_BUILD_DIR_USB_STORAGE)/libusb_storage.a
RUST_LIB_LAPIC       := $(RUST_BUILD_DIR_LAPIC)/liblapic.a
RUST_LIB_UART16550   := $(RUST_BUILD_DIR_UART16550)/libuart16550.a
RUST_LIB_I8042       := $(RUST_BUILD_DIR_I8042)/libi8042.a
RUST_LIB_PCIE_ECAM   := $(RUST_BUILD_DIR_PCIE_ECAM)/libpcie_ecam.a
RUST_LIB_AMD_SMN     := $(RUST_BUILD_DIR_AMD_SMN)/libamd_smn.a
RUST_LIB_AMD_UMC     := $(RUST_BUILD_DIR_AMD_UMC)/libamd_umc.a
RUST_LIB_AMD_CCP     := $(RUST_BUILD_DIR_AMD_CCP)/libamd_ccp.a
RUST_LIB_ACPI_PM     := $(RUST_BUILD_DIR_ACPI_PM)/libacpi_pm.a
RUST_LIB_VESA_FB     := $(RUST_BUILD_DIR_VESA_FB)/libvesa_fb.a
RUST_LIB_PCI_PM      := $(RUST_BUILD_DIR_PCI_PM)/libpci_pm.a
RUST_LIB_AMD_DF      := $(RUST_BUILD_DIR_AMD_DF)/libamd_df.a
RUST_LIB_AMD_NBIO    := $(RUST_BUILD_DIR_AMD_NBIO)/libamd_nbio.a
RUST_LIB_USB_NET     := $(RUST_BUILD_DIR_USB_NET)/libusb_net.a
RUST_LIB_USB_HUB     := $(RUST_BUILD_DIR_USB_HUB)/libusb_hub.a
RUST_LIB_HDA_REALTEK := $(RUST_BUILD_DIR_HDA_REALTEK)/libhda_realtek.a
RUST_LIB_AMD_I2C     := $(RUST_BUILD_DIR_AMD_I2C)/libamd_i2c.a
RUST_LIB_AMD_PSP     := $(RUST_BUILD_DIR_AMD_PSP)/libamd_psp.a
RUST_LIB_X86_MCE     := $(RUST_BUILD_DIR_X86_MCE)/libx86_mce.a
RUST_LIB_PCI_AER     := $(RUST_BUILD_DIR_PCI_AER)/libpci_aer.a
RUST_LIB_ACPI_EC     := $(RUST_BUILD_DIR_ACPI_EC)/libacpi_ec.a
RUST_LIB_ETH_PHY     := $(RUST_BUILD_DIR_ETH_PHY)/libeth_phy.a
RUST_LIB_USB_AUDIO   := $(RUST_BUILD_DIR_USB_AUDIO)/libusb_audio.a
RUST_LIB_ACPI_THERMAL := $(RUST_BUILD_DIR_ACPI_THERMAL)/libacpi_thermal.a
RUST_LIB_DMA_POOL    := $(RUST_BUILD_DIR_DMA_POOL)/libdma_pool.a
RUST_LIB_FB_CONSOLE  := $(RUST_BUILD_DIR_FB_CONSOLE)/libfb_console.a
RUST_LIB_PCI_SRIOV   := $(RUST_BUILD_DIR_PCI_SRIOV)/libpci_sriov.a
RUST_LIB_EDID        := $(RUST_BUILD_DIR_EDID)/libedid.a
RUST_LIB_AMD_XGBE    := $(RUST_BUILD_DIR_AMD_XGBE)/libamd_xgbe.a
RUST_LIB_X86_TSC     := $(RUST_BUILD_DIR_X86_TSC)/libx86_tsc.a
RUST_LIB_AMD_SEV     := $(RUST_BUILD_DIR_AMD_SEV)/libamd_sev.a
RUST_LIB_VIRTIO_CON  := $(RUST_BUILD_DIR_VIRTIO_CON)/libvirtio_console.a
RUST_LIB_ACPI_BTN    := $(RUST_BUILD_DIR_ACPI_BTN)/libacpi_button.a
RUST_LIB_AMD_MP2     := $(RUST_BUILD_DIR_AMD_MP2)/libamd_mp2.a
RUST_LIB_X86_CPUID   := $(RUST_BUILD_DIR_X86_CPUID)/libx86_cpuid.a
RUST_LIB_INTEL_VTD   := $(RUST_BUILD_DIR_INTEL_VTD)/libintel_vtd.a
RUST_LIB_INTEL_HWP   := $(RUST_BUILD_DIR_INTEL_HWP)/libintel_hwp.a
RUST_LIB_INTEL_LPSS  := $(RUST_BUILD_DIR_INTEL_LPSS)/libintel_lpss.a
RUST_LIB_INTEL_PMC   := $(RUST_BUILD_DIR_INTEL_PMC)/libintel_pmc.a
RUST_LIB_INTEL_GPIO  := $(RUST_BUILD_DIR_INTEL_GPIO)/libintel_gpio.a
RUST_LIB_INTEL_WDT   := $(RUST_BUILD_DIR_INTEL_WDT)/libintel_wdt.a
RUST_LIB_INTEL_MEI   := $(RUST_BUILD_DIR_INTEL_MEI)/libintel_mei.a
RUST_LIB_INTEL_TBT   := $(RUST_BUILD_DIR_INTEL_TBT)/libintel_tbt.a
RUST_LIB_INTEL_THERM := $(RUST_BUILD_DIR_INTEL_THERM)/libintel_thermal.a
RUST_LIB_INTEL_GNA   := $(RUST_BUILD_DIR_INTEL_GNA)/libintel_gna.a
RUST_LIB_INTEL_SST   := $(RUST_BUILD_DIR_INTEL_SST)/libintel_sst.a
RUST_LIB_INTEL_HDMI  := $(RUST_BUILD_DIR_INTEL_HDMI)/libintel_hda_hdmi.a
RUST_LIB_INTEL_CNVI  := $(RUST_BUILD_DIR_INTEL_CNVI)/libintel_cnvi.a
RUST_LIB_INTEL_DMA   := $(RUST_BUILD_DIR_INTEL_DMA)/libintel_dma.a
RUST_LIB_INTEL_IPU   := $(RUST_BUILD_DIR_INTEL_IPU)/libintel_ipu.a
RUST_LIB_INTEL_P2SB  := $(RUST_BUILD_DIR_INTEL_P2SB)/libintel_p2sb.a
RUST_LIB_INTEL_SMBUS := $(RUST_BUILD_DIR_INTEL_SMBUS)/libintel_smbus.a
RUST_LIB_INTEL_SPI   := $(RUST_BUILD_DIR_INTEL_SPI)/libintel_spi.a
RUST_LIB_RPI_AUDIO   := $(RUST_BUILD_DIR_RPI_AUDIO)/librpi_audio.a
RUST_LIB_RPI_DISPLAY := $(RUST_BUILD_DIR_RPI_DISPLAY)/librpi_display.a
RUST_LIB_RPI_DMA     := $(RUST_BUILD_DIR_RPI_DMA)/librpi_dma.a
RUST_LIB_RPI_EMMC    := $(RUST_BUILD_DIR_RPI_EMMC)/librpi_emmc.a
RUST_LIB_RPI_GENET   := $(RUST_BUILD_DIR_RPI_GENET)/librpi_genet.a
RUST_LIB_RPI_GPIO    := $(RUST_BUILD_DIR_RPI_GPIO)/librpi_gpio.a
RUST_LIB_RPI_I2C     := $(RUST_BUILD_DIR_RPI_I2C)/librpi_i2c.a
RUST_LIB_RPI_MBOX    := $(RUST_BUILD_DIR_RPI_MBOX)/librpi_mbox.a
RUST_LIB_RPI_PCIE    := $(RUST_BUILD_DIR_RPI_PCIE)/librpi_pcie.a
RUST_LIB_RPI_PWM     := $(RUST_BUILD_DIR_RPI_PWM)/librpi_pwm.a
RUST_LIB_RPI_RNG     := $(RUST_BUILD_DIR_RPI_RNG)/librpi_rng.a
RUST_LIB_RPI_SPI     := $(RUST_BUILD_DIR_RPI_SPI)/librpi_spi.a
RUST_LIB_RPI_THERMAL := $(RUST_BUILD_DIR_RPI_THERMAL)/librpi_thermal.a
RUST_LIB_RPI_USB     := $(RUST_BUILD_DIR_RPI_USB)/librpi_usb.a
RUST_LIB_RPI_WATCHDOG := $(RUST_BUILD_DIR_RPI_WATCHDOG)/librpi_watchdog.a

# ============================================================
#   Driver Selection — DRIVERS=qemu|amd|intel|all (default: all)
#
#   DRIVERS=qemu   — VirtIO only (fast builds, CI/QEMU testing)
#   DRIVERS=amd    — VirtIO + AMD chipset + common x86 platform
#   DRIVERS=intel  — VirtIO + Intel chipset + common x86 platform
#   DRIVERS=all    — Everything (real hardware deployment)
# ============================================================
DRIVERS ?= all

# Core VirtIO drivers (always included on x86_64)
RUST_VIRTIO_LIBS := $(RUST_LIB_VIRTIO_BLK) $(RUST_LIB_VIRTIO_NET) $(RUST_LIB_VIRTIO_INPUT) $(RUST_LIB_VIRTIO_CON)

# Common x86 platform drivers (timers, basic I/O, PCI)
RUST_X86_PLATFORM_LIBS := $(RUST_LIB_X86_CPUID) $(RUST_LIB_X86_TSC) $(RUST_LIB_HPET) $(RUST_LIB_CMOS_RTC) $(RUST_LIB_UART16550) $(RUST_LIB_I8042) $(RUST_LIB_PCIE_ECAM) $(RUST_LIB_PCI_MSIX) $(RUST_LIB_LAPIC) $(RUST_LIB_DMA_POOL) $(RUST_LIB_PCI_PM) $(RUST_LIB_VESA_FB) $(RUST_LIB_FB_CONSOLE) $(RUST_LIB_EDID) $(RUST_LIB_ACPI_PM) $(RUST_LIB_ACPI_EC) $(RUST_LIB_ACPI_BTN) $(RUST_LIB_ACPI_THERMAL) $(RUST_LIB_PCI_AER) $(RUST_LIB_PCI_SRIOV) $(RUST_LIB_ETH_PHY) $(RUST_LIB_TPM_CRB) $(RUST_LIB_X86_MCE)

# Storage + USB + Audio (common across vendors)
RUST_X86_STORAGE_LIBS := $(RUST_LIB_NVME) $(RUST_LIB_AHCI) $(RUST_LIB_XHCI) $(RUST_LIB_USB_HID) $(RUST_LIB_USB_STORAGE) $(RUST_LIB_USB_NET) $(RUST_LIB_USB_HUB) $(RUST_LIB_USB_AUDIO) $(RUST_LIB_HDA) $(RUST_LIB_HDA_REALTEK)

# Network (non-vendor-specific)
RUST_X86_NET_LIBS := $(RUST_LIB_RTL8111) $(RUST_LIB_IGC) $(RUST_LIB_I211)

# AMD chipset drivers
RUST_AMD_LIBS := $(RUST_LIB_AMD_SMBUS) $(RUST_LIB_AMD_IOMMU) $(RUST_LIB_AMD_SMN) $(RUST_LIB_AMD_UMC) $(RUST_LIB_AMD_CCP) $(RUST_LIB_AMD_DF) $(RUST_LIB_AMD_NBIO) $(RUST_LIB_AMD_I2C) $(RUST_LIB_AMD_PSP) $(RUST_LIB_AMD_SEV) $(RUST_LIB_AMD_PSTATE) $(RUST_LIB_AMD_SBTSI) $(RUST_LIB_AMD_GPIO) $(RUST_LIB_AMD_SPI) $(RUST_LIB_AMD_WDT) $(RUST_LIB_AMD_MP2) $(RUST_LIB_AMD_XGBE)

# Intel chipset drivers
RUST_INTEL_LIBS := $(RUST_LIB_INTEL_VTD) $(RUST_LIB_INTEL_HWP) $(RUST_LIB_INTEL_LPSS) $(RUST_LIB_INTEL_PMC) $(RUST_LIB_INTEL_GPIO) $(RUST_LIB_INTEL_WDT) $(RUST_LIB_INTEL_MEI) $(RUST_LIB_INTEL_TBT) $(RUST_LIB_INTEL_THERM) $(RUST_LIB_INTEL_GNA) $(RUST_LIB_INTEL_SST) $(RUST_LIB_INTEL_HDMI) $(RUST_LIB_INTEL_CNVI) $(RUST_LIB_INTEL_DMA) $(RUST_LIB_INTEL_IPU) $(RUST_LIB_INTEL_P2SB) $(RUST_LIB_INTEL_SMBUS) $(RUST_LIB_INTEL_SPI)

# Platform-specific Rust drivers — selected by DRIVERS variable
ifeq ($(PLATFORM),x86_64)
  ifeq ($(DRIVERS),qemu)
    RUST_LIBS := $(RUST_VIRTIO_LIBS)
    CFLAGS += -DDRIVERS_QEMU
  else ifeq ($(DRIVERS),amd)
    RUST_LIBS := $(RUST_VIRTIO_LIBS) $(RUST_X86_PLATFORM_LIBS) $(RUST_X86_STORAGE_LIBS) $(RUST_X86_NET_LIBS) $(RUST_AMD_LIBS)
    CFLAGS += -DDRIVERS_AMD
  else ifeq ($(DRIVERS),intel)
    RUST_LIBS := $(RUST_VIRTIO_LIBS) $(RUST_X86_PLATFORM_LIBS) $(RUST_X86_STORAGE_LIBS) $(RUST_X86_NET_LIBS) $(RUST_INTEL_LIBS)
    CFLAGS += -DDRIVERS_INTEL
  else
    # all: everything
    RUST_LIBS := $(RUST_VIRTIO_LIBS) $(RUST_X86_PLATFORM_LIBS) $(RUST_X86_STORAGE_LIBS) $(RUST_X86_NET_LIBS) $(RUST_AMD_LIBS) $(RUST_INTEL_LIBS)
    CFLAGS += -DDRIVERS_ALL
  endif
else ifeq ($(PLATFORM),arm64)
RUST_LIBS := $(RUST_LIB_VIRTIO_GPU) $(RUST_LIB_VIRTIO_NET) $(RUST_LIB_VIRTIO_BLK) $(RUST_LIB_VIRTIO_INPUT) $(RUST_LIB_APPLE_UART) $(RUST_LIB_APPLE_RTKIT) $(RUST_LIB_APPLE_ANS2) $(RUST_LIB_APPLE_AIC) $(RUST_LIB_APPLE_DART) $(RUST_LIB_APPLE_GPIO) $(RUST_LIB_APPLE_I2C) $(RUST_LIB_APPLE_PCIE) $(RUST_LIB_APPLE_SMC) $(RUST_LIB_APPLE_SPI) $(RUST_LIB_APPLE_MCA) $(RUST_LIB_RPI_AUDIO) $(RUST_LIB_RPI_DISPLAY) $(RUST_LIB_RPI_DMA) $(RUST_LIB_RPI_EMMC) $(RUST_LIB_RPI_GENET) $(RUST_LIB_RPI_GPIO) $(RUST_LIB_RPI_I2C) $(RUST_LIB_RPI_MBOX) $(RUST_LIB_RPI_PCIE) $(RUST_LIB_RPI_PWM) $(RUST_LIB_RPI_RNG) $(RUST_LIB_RPI_SPI) $(RUST_LIB_RPI_THERMAL) $(RUST_LIB_RPI_USB) $(RUST_LIB_RPI_WATCHDOG)
else
RUST_LIBS :=
endif
RUST_SOURCES := $(shell if [ -d $(RUST_ROOT) ]; then find $(RUST_ROOT) -type f \( -name '*.rs' -o -name 'Cargo.toml' -o -name 'build.rs' -o -name '*.toml' \); fi)

# ============================================================
#   Source Files
# ============================================================

# Kernel core sources
# Note: kernel_main.c is now shared across all platforms via platform hooks
KERNEL_SOURCES := \
    kernel/boot/banner.c \
    kernel/boot/boot_args.c \
    kernel/memory/fut_memory.c \
    kernel/memory/fut_mm.c \
    kernel/memory/mmap_dump.c \
    kernel/memory/buddy_allocator.c \
    kernel/memory/slab_allocator.c \
    kernel/memory/oom_kill.c \
    kernel/threading/fut_task.c \
    kernel/threading/fut_thread.c \
    kernel/scheduler/fut_sched.c \
    kernel/scheduler/asm_debug.c \
    kernel/scheduler/fut_stats.c \
    kernel/scheduler/fut_waitq.c \
    kernel/percpu/fut_percpu.c \
    kernel/timer/fut_timer.c \
    kernel/io_budget.c \
    kernel/acpi/acpi.c \
    kernel/ipc/fut_object.c \
    kernel/ipc/fut_fipc.c \
    kernel/ipc/fut_socket.c \
    kernel/capability.c \
    kernel/net/fut_net.c \
    kernel/net/fut_net_dev.c \
    kernel/net/fut_net_loopback.c \
    kernel/net/tcpip.c \
    kernel/net/dns.c \
    kernel/net/netif.c \
    kernel/net/bridge.c \
    kernel/net/gre.c \
    kernel/security/bpf.c \
    kernel/ns/pidns.c \
    kernel/ns/mntns.c \
    kernel/ns/utsns.c \
    kernel/ns/netns.c \
    kernel/ns/userns.c \
    kernel/ns/ipcns.c \
    kernel/cgroup/memcg.c \
    kernel/cgroup/cpucg.c \
    kernel/cgroup/iocg.c \
    kernel/cgroup/pidcg.c \
    kernel/cgroup/freezer.c \
    kernel/cgroup/cgroupfs.c \
    kernel/fs/ext2.c \
    kernel/fs/fat.c \
    kernel/fs/exfat.c \
    kernel/fs/overlayfs.c \
    kernel/fs/fuse.c \
    kernel/net/tc.c \
    kernel/net/ipsec.c \
    kernel/net/nat.c \
    kernel/net/filter.c \
    kernel/net/tun.c \
    kernel/crypto/fut_hmac.c \
    kernel/vfs/fut_vfs.c \
    kernel/vfs/vfs_dcache.c \
    kernel/vfs/fut_vfs_cap.c \
    kernel/vfs/ramfs.c \
    kernel/vfs/procfs.c \
    kernel/vfs/sysfs.c \
    kernel/vfs/debugfs.c \
    kernel/vfs/vfs_credentials.c \
    kernel/vfs/fut_lock.c \
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
    kernel/sys_epoll.c \
    kernel/sys_madvise.c \
    kernel/sys_cred.c \
    kernel/sys_proc.c \
    kernel/sys_rusage.c \
    kernel/sys_times.c \
    kernel/sys_sched.c \
    kernel/sys_alarm.c \
    kernel/sys_pause.c \
    kernel/sys_shutdown.c \
    kernel/sys_accept.c \
    kernel/sys_read.c \
    kernel/sys_write.c \
    kernel/sys_open.c \
    kernel/sys_close.c \
    kernel/sys_openat.c \
    kernel/sys_socket.c \
    kernel/sys_netlink.c \
    kernel/sys_bind.c \
    kernel/sys_listen.c \
    kernel/sys_connect.c \
    kernel/sys_sendto.c \
    kernel/sys_recvfrom.c \
    kernel/sys_sendmsg.c \
    kernel/sys_recvmsg.c \
    kernel/sys_sendmmsg.c \
    kernel/sys_recvmmsg.c \
    kernel/sys_kill.c \
    kernel/sys_sigaction.c \
    kernel/sys_sigprocmask.c \
    kernel/sys_sigpending.c \
    kernel/sys_sigsuspend.c \
    kernel/sys_sigaltstack.c \
    kernel/sys_ioctl.c \
    kernel/sys_select.c \
    kernel/sys_getpeername.c \
    kernel/sys_getsockname.c \
    kernel/sys_setsockopt.c \
    kernel/sys_getsockopt.c \
    kernel/sys_uname.c \
    kernel/sys_rename.c \
    kernel/sys_renameat.c \
    kernel/sys_stat.c \
    kernel/sys_fstat.c \
    kernel/sys_fstatat.c \
    kernel/sys_lstat.c \
    kernel/sys_unlinkat.c \
    kernel/sys_mkdirat.c \
    kernel/sys_chmod.c \
    kernel/sys_fchmod.c \
    kernel/sys_fchmodat.c \
    kernel/sys_xattr.c \
    kernel/sys_inotify.c \
    kernel/sys_splice.c \
    kernel/sys_filesystem_stats.c \
    kernel/sys_ioprio.c \
    kernel/sys_capability.c \
    kernel/sys_personality.c \
    kernel/sys_prctl.c \
    kernel/sys_ptrace.c \
    kernel/sys_arch_prctl.c \
    kernel/sys_getrandom.c \
    kernel/sys_fadvise.c \
    kernel/sys_sched_affinity.c \
    kernel/sys_syslog.c \
    kernel/sys_reboot.c \
    kernel/sys_memfd.c \
    kernel/sys_semaphore.c \
    kernel/sys_msgqueue.c \
    kernel/sys_mqueue.c \
    kernel/sys_shm.c \
    kernel/sys_process_vm.c \
    kernel/sys_pidfd.c \
    kernel/sys_seccomp.c \
    kernel/sys_kcmp.c \
    kernel/sys_execveat.c \
    kernel/sys_preadv2.c \
    kernel/sys_openat2.c \
    kernel/sys_sigtimedwait.c \
    kernel/sys_membarrier.c \
    kernel/sys_copy_file_range.c \
    kernel/sys_rseq.c \
    kernel/dev_null.c \
    kernel/pci.c \
    kernel/dev_loop.c \
    kernel/dev_watchdog.c \
    kernel/pty.c \
    kernel/sys_statx.c \
    kernel/sys_tgkill.c \
    kernel/sys_getcpu.c \
    kernel/sys_readahead.c \
    kernel/sys_futimesat.c \
    kernel/sys_aio.c \
    kernel/sys_landlock.c \
    kernel/sys_keyring.c \
    kernel/sys_fanotify.c \
    kernel/sys_userfaultfd.c \
    kernel/sys_perf.c \
    kernel/sys_mempolicy.c \
    kernel/sys_clone3.c \
    kernel/sys_socketpair.c \
    kernel/sys_groups.c \
    kernel/sys_unshare.c \
    kernel/sys_acct.c \
    kernel/sys_waitid.c \
    kernel/sys_set_tid_address.c \
    kernel/sys_mknodat.c \
    kernel/sys_fchdir.c \
    kernel/sys_mount.c \
    kernel/sys_umount2.c \
    kernel/sys_pivot_root.c \
    kernel/sys_chown.c \
    kernel/sys_fchown.c \
    kernel/sys_fchownat.c \
    kernel/sys_umask.c \
    kernel/sys_truncate.c \
    kernel/sys_ftruncate.c \
    kernel/sys_fcntl.c \
    kernel/sys_flock.c \
    kernel/sys_fsync.c \
    kernel/sys_fdatasync.c \
    kernel/sys_sync.c \
    kernel/sys_syncfs.c \
    kernel/sys_futimens.c \
    kernel/sys_access.c \
    kernel/sys_faccessat.c \
    kernel/sys_mkdir.c \
    kernel/sys_rmdir.c \
    kernel/sys_unlink.c \
    kernel/sys_link.c \
    kernel/sys_linkat.c \
    kernel/sys_symlink.c \
    kernel/sys_symlinkat.c \
    kernel/sys_readlink.c \
    kernel/sys_readlinkat.c \
    kernel/sys_getdents64.c \
    kernel/sys_getdents.c \
    kernel/sys_utimensat.c \
    kernel/sys_pread64.c \
    kernel/sys_pwrite64.c \
    kernel/sys_readv.c \
    kernel/sys_writev.c \
    kernel/sys_preadv.c \
    kernel/sys_pwritev.c \
    kernel/sys_lseek.c \
    kernel/sys_pipe.c \
    kernel/sys_poll.c \
    kernel/sys_dup.c \
    kernel/sys_dup2.c \
    kernel/sys_waitpid.c \
    kernel/sys_rt_sigqueue.c \
    kernel/sys_brk.c \
    kernel/sys_mmap.c \
    kernel/sys_mprotect.c \
    kernel/sys_pkey.c \
    kernel/sys_mremap.c \
    kernel/sys_msync.c \
    kernel/sys_mincore.c \
    kernel/sys_nanosleep.c \
    kernel/sys_time.c \
    kernel/sys_timer.c \
    kernel/sys_futex.c \
    kernel/sys_eventfd.c \
    kernel/sys_signalfd.c \
    kernel/sys_chdir.c \
    kernel/sys_getcwd.c \
    kernel/sys_vhangup.c \
    kernel/sys_quotactl.c \
    kernel/signal/signal.c \
    kernel/rt/memory.c \
    kernel/rt/stack_chk.c \
    kernel/uaccess.c \
    kernel/vfs/devfs.c \
    kernel/sys_fipc.c \
    kernel/sys_sched_advanced.c \
    kernel/sys_clock_advanced.c \
    kernel/sys_fileio_advanced.c \
    kernel/sys_mman.c \
    kernel/sys_cred_advanced.c \
    kernel/sys_prlimit.c \
    kernel/video/virtio_gpu.c \
    drivers/tty/console.c \
    drivers/tty/tty_ldisc.c \
    drivers/tty/kbd_console.c \
    drivers/video/fb_console.c \
    kernel/oops.c \
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
        platform/x86_64/ap_trampoline.S \
        platform/x86_64/gdt.c \
        platform/x86_64/memory/pat.c \
        platform/x86_64/interrupt/lapic.c \
        platform/x86_64/interrupt/ioapic.c \
        platform/x86_64/interrupt/smp.c \
        platform/x86_64/memory/pmap.c \
        platform/x86_64/memory/paging.c \
        platform/x86_64/cpu_features.c \
        platform/x86_64/platform_init.c \
        platform/x86_64/ps2.c \
        platform/x86_64/timing/perf_clock.c \
        kernel/kernel_main.c \
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
        kernel/tests/multiprocess.c \
        kernel/tests/sys_dup2.c \
        kernel/tests/sys_pipe.c \
        kernel/tests/sys_signal.c \
        kernel/tests/sys_cap.c \
        kernel/tests/sys_epoll.c \
        kernel/tests/sys_splice.c \
        kernel/tests/sys_clock_sched.c \
        kernel/tests/sys_vfs.c \
        kernel/tests/sys_poll.c \
        kernel/tests/sys_misc.c \
        kernel/tests/perf.c \
        kernel/tests/perf_ipc.c \
        kernel/tests/perf_sched.c \
        kernel/tests/perf_blk.c \
        kernel/tests/perf_net.c \
        kernel/tests/fb_smoke.c \
        kernel/tests/exec_double.c \
        subsystems/futura_fs/futfs.c \
        subsystems/futura_fs/futfs_gc.c
else ifeq ($(PLATFORM),arm64)
    PLATFORM_SOURCES := \
        platform/arm64/boot.S \
        platform/arm64/arm64_exception_entry.S \
        platform/arm64/arm64_vectors.S \
        platform/arm64/context_switch.S \
        platform/arm64/debug_context_switch.c \
        platform/arm64/platform_init.c \
        platform/arm64/userland_test.c \
        platform/arm64/exception_handlers.c \
        platform/arm64/syscall_table.c \
        platform/arm64/memory/pmap.c \
        platform/arm64/interrupt/arm64_stubs.c \
        platform/arm64/interrupt/arm64_minimal_stubs.c \
        platform/arm64/interrupt/gic_irq_handler.c \
        platform/arm64/interrupt/apple_aic.c \
        platform/arm64/drivers/apple_uart.c \
        platform/arm64/drivers/apple_rtkit.c \
        platform/arm64/drivers/apple_ans2.c \
        platform/arm64/drivers/apple_dcp.c \
        platform/arm64/drivers/apple_hid.c \
        platform/arm64/drivers/apple_power.c \
        platform/arm64/drivers/apple_xhci.c \
        platform/arm64/drivers/usb_cdc_ecm.c \
        platform/arm64/drivers/apple_audio.c \
        platform/arm64/drivers/virtio_mmio.c \
        platform/arm64/timing/perf_clock.c \
        platform/arm64/pci_ecam.c \
        kernel/arch/arm64/hal_halt.c \
        kernel/arch/arm64/hal_interrupts.c \
        kernel/arch/arm64/arm64_threading.c \
        kernel/mm/arm64_paging.c \
        kernel/dtb/arm64_dtb.c \
        kernel/dtb/rpi_init.c \
        kernel/tests/multiprocess.c \
        kernel/tests/sys_dup2.c \
        kernel/tests/sys_pipe.c \
        kernel/tests/sys_signal.c \
        kernel/tests/sys_cap.c \
        kernel/tests/sys_epoll.c \
        kernel/tests/sys_splice.c \
        kernel/tests/sys_clock_sched.c \
        kernel/tests/sys_vfs.c \
        kernel/tests/sys_poll.c \
        kernel/tests/sys_misc.c \
        tests/test_blkcore.c \
        tests/test_net.c \
        tests/test_futfs.c \
        subsystems/futura_fs/futfs.c \
        subsystems/futura_fs/futfs_gc.c \
        kernel/kernel_main.c \
        kernel/video/fb_mmio.c \
        kernel/video/virtio_gpu_mmio.c \
        drivers/video/fb.c \
        kernel/blk/blkcore.c
endif

# Subsystem sources (POSIX compat)
SUBSYSTEM_SOURCES := \
    subsystems/posix_compat/posix_shim.c \
    subsystems/posix_compat/posix_syscall.c \
    kernel/input/virtio_input_ffi.c

# All sources
ALL_SOURCES := $(KERNEL_SOURCES) $(PLATFORM_SOURCES) $(SUBSYSTEM_SOURCES)

# Object files
OBJECTS := $(patsubst %.c,$(OBJ_DIR)/%.o,$(filter %.c,$(ALL_SOURCES)))
OBJECTS += $(patsubst %.S,$(OBJ_DIR)/%.o,$(filter %.S,$(ALL_SOURCES)))

SHELL_BIN := $(BIN_DIR)/$(PLATFORM)/user/shell
SHELL_BLOB := $(OBJ_DIR)/kernel/blobs/shell_blob.o
FBTEST_BIN := $(BIN_DIR)/$(PLATFORM)/user/fbtest
FBTEST_BLOB := $(OBJ_DIR)/kernel/blobs/fbtest_blob.o
INIT_BIN := $(BIN_DIR)/$(PLATFORM)/user/init
INIT_BLOB := $(OBJ_DIR)/kernel/blobs/init_blob.o
SECOND_STUB_BIN := $(BIN_DIR)/$(PLATFORM)/user/second
SECOND_STUB_BLOB := $(OBJ_DIR)/kernel/blobs/second_stub_blob.o
WAYLAND_COMPOSITOR_BIN := $(BIN_DIR)/$(PLATFORM)/user/futura-wayland
WAYLAND_COMPOSITOR_BLOB := $(OBJ_DIR)/kernel/blobs/futura_wayland_blob.o
WAYLAND_CLIENT_BIN := $(BIN_DIR)/$(PLATFORM)/user/wl-simple
WAYLAND_CLIENT_BLOB := $(OBJ_DIR)/kernel/blobs/wl_simple_blob.o
WAYLAND_COLOR_BIN := $(BIN_DIR)/$(PLATFORM)/user/wl-colorwheel
WAYLAND_COLOR_BLOB := $(OBJ_DIR)/kernel/blobs/wl_colorwheel_blob.o
WAYLAND_SHELL_BIN := $(BIN_DIR)/$(PLATFORM)/user/futura-shell
WAYLAND_SHELL_BLOB := $(OBJ_DIR)/kernel/blobs/futura_shell_blob.o
WL_TERM_BIN := $(BIN_DIR)/$(PLATFORM)/user/wl-term
WL_TERM_BLOB := $(OBJ_DIR)/kernel/blobs/wl_term_blob.o

# ARM64 userland binaries
ARM64_INIT_BIN := $(BIN_DIR)/arm64/user/init
ARM64_INIT_BLOB := $(OBJ_DIR)/kernel/blobs/arm64_init_blob.o
ARM64_SHELL_BIN := $(BIN_DIR)/arm64/user/shell
ARM64_SHELL_BLOB := $(OBJ_DIR)/kernel/blobs/arm64_shell_blob.o
ARM64_FBTEST_BIN := $(BIN_DIR)/arm64/user/fbtest
ARM64_FBTEST_BLOB := $(OBJ_DIR)/kernel/blobs/arm64_fbtest_blob.o
ARM64_UIDEMO_BIN := $(BIN_DIR)/arm64/user/arm64_uidemo
ARM64_UIDEMO_BLOB := $(OBJ_DIR)/kernel/blobs/arm64_uidemo_blob.o
ARM64_FORKTEST_BIN := $(BIN_DIR)/arm64/user/forktest
ARM64_FORKTEST_BLOB := $(OBJ_DIR)/kernel/blobs/arm64_forktest_blob.o
ARM64_NANO_BIN := $(BIN_DIR)/arm64/user/nano
ARM64_NANO_BLOB := $(OBJ_DIR)/kernel/blobs/arm64_nano_blob.o

ifeq ($(PLATFORM),x86_64)
# Skip shell blob on macOS (uses GNU nested functions not supported by clang)
ifneq ($(shell uname -s),Darwin)
OBJECTS += $(SHELL_BLOB)
endif
OBJECTS += $(INIT_BLOB) $(SECOND_STUB_BLOB)
# Diagnostics (optional)
ifeq ($(ENABLE_FB_DIAGNOSTICS),1)
OBJECTS += $(FBTEST_BLOB)
endif
# Core Wayland binaries (production) - only when ENABLE_WAYLAND=1 on Linux
ifeq ($(ENABLE_WAYLAND),1)
ifneq ($(shell uname -s),Darwin)
OBJECTS += $(WAYLAND_COMPOSITOR_BLOB) $(WAYLAND_SHELL_BLOB) $(WL_TERM_BLOB)
ifeq ($(ENABLE_WAYLAND_TEST_CLIENTS),1)
OBJECTS += $(WAYLAND_CLIENT_BLOB) $(WAYLAND_COLOR_BLOB)
endif
endif
endif
else ifeq ($(PLATFORM),arm64)
# Re-enabled for UI testing
OBJECTS += $(ARM64_INIT_BLOB) $(ARM64_UIDEMO_BLOB) $(ARM64_SHELL_BLOB) $(ARM64_FORKTEST_BLOB) $(ARM64_NANO_BLOB)
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
	@mkdir -p $(OBJ_DIR)/kernel/percpu
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
	@mkdir -p $(OBJ_DIR)/platform/$(PLATFORM)/interrupt
	@mkdir -p $(OBJ_DIR)/platform/$(PLATFORM)/memory
	@mkdir -p $(OBJ_DIR)/platform/$(PLATFORM)/timing
ifeq ($(PLATFORM),arm64)
	@mkdir -p $(OBJ_DIR)/kernel/dtb
	@mkdir -p $(OBJ_DIR)/kernel/sched
endif
	@mkdir -p $(OBJ_DIR)/tests
	@mkdir -p $(OBJ_DIR)/subsystems/posix_compat
	@mkdir -p $(OBJ_DIR)/subsystems/futura_fs

# Build kernel (depends on userland to ensure Wayland binaries are built)
kernel: userland $(BIN_DIR)/futura_kernel.elf

.PHONY: futfs-crash-test
futfs-crash-test: kernel tools
	@tests/scripts/futfs_crash_gc.sh

$(BIN_DIR)/futura_kernel.elf: $(OBJECTS) $(RUST_LIBS) $(KERNEL_DEPS) | $(BIN_DIR)
	@echo "LD $@.tmp"
	@$(LD) $(LDFLAGS) -o $@.tmp $(OBJECTS) $(RUST_LIBS) $(EXTRA_LDLIBS)
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
ifeq ($(PLATFORM),arm64)
	@echo "OBJCOPY $(BIN_DIR)/futura_kernel.bin"
	@$(OBJCOPY) -O binary $@ $(BIN_DIR)/futura_kernel.bin
endif

ifeq ($(RUST_AVAILABLE),yes)
rust-drivers: $(RUST_LIBS)

$(RUST_LIB_VIRTIO_BLK): $(RUST_SOURCES)
	@$(RUSTC) --print target-list | grep -q $(RUST_TARGET) >/dev/null || { \
		echo "error: rust target '$(RUST_TARGET)' not installed for $(RUSTC)." >&2; exit 1; }
	@echo "CARGO virtio_blk ($(RUST_PROFILE))"
	@cd $(RUST_VIRTIO_BLK_DIR) && RUSTFLAGS="-C panic=abort -C force-unwind-tables=no $(RUSTFLAGS)" $(CARGO) build --release --target $(RUST_TARGET)
	@tmpdir=$$(mktemp -d); \
	cd $$tmpdir && $(AR) x $(abspath $(RUST_LIB_VIRTIO_BLK)) && for obj in *.o; do $(OBJCOPY) --remove-section='.gcc_except_table*' --remove-section='.eh_frame*' $$obj >/dev/null 2>&1 || true; done && $(AR) rcs $(abspath $(RUST_LIB_VIRTIO_BLK)) *.o; \
	rm -rf $$tmpdir

$(RUST_LIB_VIRTIO_NET): $(RUST_SOURCES)
	@$(RUSTC) --print target-list | grep -q $(RUST_TARGET) >/dev/null || { \
		echo "error: rust target '$(RUST_TARGET)' not installed for $(RUSTC)." >&2; exit 1; }
	@echo "CARGO virtio_net ($(RUST_PROFILE))"
	@cd $(RUST_VIRTIO_NET_DIR) && RUSTFLAGS="-C panic=abort -C force-unwind-tables=no $(RUSTFLAGS)" $(CARGO) build --release --target $(RUST_TARGET)
	@tmpdir=$$(mktemp -d); \
	cd $$tmpdir && $(AR) x $(abspath $(RUST_LIB_VIRTIO_NET)) && for obj in *.o; do $(OBJCOPY) --remove-section='.gcc_except_table*' --remove-section='.eh_frame*' $$obj >/dev/null 2>&1 || true; done && $(AR) rcs $(abspath $(RUST_LIB_VIRTIO_NET)) *.o; \
	rm -rf $$tmpdir

$(RUST_LIB_VIRTIO_GPU): $(RUST_SOURCES)
	@$(RUSTC) --print target-list | grep -q $(RUST_TARGET) >/dev/null || { \
		echo "error: rust target '$(RUST_TARGET)' not installed for $(RUSTC)." >&2; exit 1; }
	@echo "CARGO virtio_gpu ($(RUST_PROFILE))"
	@cd $(RUST_VIRTIO_GPU_DIR) && RUSTFLAGS="-C panic=abort -C force-unwind-tables=no $(RUSTFLAGS)" $(CARGO) build --release --target $(RUST_TARGET)
	@tmpdir=$$(mktemp -d); \
	cd $$tmpdir && $(AR) x $(abspath $(RUST_LIB_VIRTIO_GPU)) && for obj in *.o; do $(OBJCOPY) --remove-section='.gcc_except_table*' --remove-section='.eh_frame*' $$obj >/dev/null 2>&1 || true; done && $(AR) rcs $(abspath $(RUST_LIB_VIRTIO_GPU)) *.o; \
	rm -rf $$tmpdir

$(RUST_LIB_VIRTIO_INPUT): $(RUST_SOURCES)
	@$(RUSTC) --print target-list | grep -q $(RUST_TARGET) >/dev/null || { \
		echo "error: rust target '$(RUST_TARGET)' not installed for $(RUSTC)." >&2; exit 1; }
	@echo "CARGO virtio_input ($(RUST_PROFILE))"
	@cd $(RUST_VIRTIO_INPUT_DIR) && RUSTFLAGS="-C panic=abort -C force-unwind-tables=no $(RUSTFLAGS)" $(CARGO) build --release --target $(RUST_TARGET)
	@tmpdir=$$(mktemp -d); \
	cd $$tmpdir && $(AR) x $(abspath $(RUST_LIB_VIRTIO_INPUT)) && for obj in *.o; do $(OBJCOPY) --remove-section='.gcc_except_table*' --remove-section='.eh_frame*' $$obj >/dev/null 2>&1 || true; done && $(AR) rcs $(abspath $(RUST_LIB_VIRTIO_INPUT)) *.o; \
	rm -rf $$tmpdir

# AMD Ryzen platform drivers (x86_64 only)
define RUST_DRIVER_RULE
$(1): $(RUST_SOURCES)
	@echo "CARGO $(2) ($(RUST_PROFILE))"
	@cd $(3) && RUSTFLAGS="-C panic=abort -C force-unwind-tables=no $(RUSTFLAGS)" $(CARGO) build --release --target $(RUST_TARGET)
	@tmpdir=$$$$(mktemp -d); \
	cd $$$$tmpdir && $(AR) x $(abspath $(1)) && for obj in *.o; do $(OBJCOPY) --remove-section='.gcc_except_table*' --remove-section='.eh_frame*' $$$$obj >/dev/null 2>&1 || true; done && $(AR) rcs $(abspath $(1)) *.o; \
	rm -rf $$$$tmpdir
endef

$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_NVME),nvme,$(RUST_NVME_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_XHCI),xhci,$(RUST_XHCI_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_RTL8111),rtl8111,$(RUST_RTL8111_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_HDA),hda,$(RUST_HDA_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_AMD_SMBUS),amd_smbus,$(RUST_AMD_SMBUS_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_AMD_IOMMU),amd_iommu,$(RUST_AMD_IOMMU_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_AHCI),ahci,$(RUST_AHCI_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_HPET),hpet,$(RUST_HPET_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_IGC),igc,$(RUST_IGC_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_AMD_WDT),amd_wdt,$(RUST_AMD_WDT_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_AMD_GPIO),amd_gpio,$(RUST_AMD_GPIO_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_CMOS_RTC),cmos_rtc,$(RUST_CMOS_RTC_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_AMD_SPI),amd_spi,$(RUST_AMD_SPI_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_TPM_CRB),tpm_crb,$(RUST_TPM_CRB_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_AMD_SBTSI),amd_sbtsi,$(RUST_AMD_SBTSI_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_AMD_PSTATE),amd_pstate,$(RUST_AMD_PSTATE_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_I211),i211,$(RUST_I211_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_PCI_MSIX),pci_msix,$(RUST_PCI_MSIX_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_USB_HID),usb_hid,$(RUST_USB_HID_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_USB_STORAGE),usb_storage,$(RUST_USB_STORAGE_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_LAPIC),lapic,$(RUST_LAPIC_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_UART16550),uart16550,$(RUST_UART16550_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_I8042),i8042,$(RUST_I8042_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_PCIE_ECAM),pcie_ecam,$(RUST_PCIE_ECAM_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_AMD_SMN),amd_smn,$(RUST_AMD_SMN_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_AMD_UMC),amd_umc,$(RUST_AMD_UMC_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_AMD_CCP),amd_ccp,$(RUST_AMD_CCP_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_ACPI_PM),acpi_pm,$(RUST_ACPI_PM_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_VESA_FB),vesa_fb,$(RUST_VESA_FB_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_PCI_PM),pci_pm,$(RUST_PCI_PM_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_AMD_DF),amd_df,$(RUST_AMD_DF_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_AMD_NBIO),amd_nbio,$(RUST_AMD_NBIO_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_USB_NET),usb_net,$(RUST_USB_NET_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_USB_HUB),usb_hub,$(RUST_USB_HUB_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_HDA_REALTEK),hda_realtek,$(RUST_HDA_REALTEK_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_AMD_I2C),amd_i2c,$(RUST_AMD_I2C_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_AMD_PSP),amd_psp,$(RUST_AMD_PSP_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_X86_MCE),x86_mce,$(RUST_X86_MCE_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_PCI_AER),pci_aer,$(RUST_PCI_AER_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_ACPI_EC),acpi_ec,$(RUST_ACPI_EC_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_ETH_PHY),eth_phy,$(RUST_ETH_PHY_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_USB_AUDIO),usb_audio,$(RUST_USB_AUDIO_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_ACPI_THERMAL),acpi_thermal,$(RUST_ACPI_THERMAL_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_DMA_POOL),dma_pool,$(RUST_DMA_POOL_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_FB_CONSOLE),fb_console,$(RUST_FB_CONSOLE_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_PCI_SRIOV),pci_sriov,$(RUST_PCI_SRIOV_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_EDID),edid,$(RUST_EDID_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_AMD_XGBE),amd_xgbe,$(RUST_AMD_XGBE_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_X86_TSC),x86_tsc,$(RUST_X86_TSC_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_AMD_SEV),amd_sev,$(RUST_AMD_SEV_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_VIRTIO_CON),virtio_console,$(RUST_VIRTIO_CON_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_ACPI_BTN),acpi_button,$(RUST_ACPI_BTN_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_AMD_MP2),amd_mp2,$(RUST_AMD_MP2_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_X86_CPUID),x86_cpuid,$(RUST_X86_CPUID_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_INTEL_VTD),intel_vtd,$(RUST_INTEL_VTD_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_INTEL_HWP),intel_hwp,$(RUST_INTEL_HWP_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_INTEL_LPSS),intel_lpss,$(RUST_INTEL_LPSS_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_INTEL_PMC),intel_pmc,$(RUST_INTEL_PMC_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_INTEL_GPIO),intel_gpio,$(RUST_INTEL_GPIO_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_INTEL_WDT),intel_wdt,$(RUST_INTEL_WDT_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_INTEL_MEI),intel_mei,$(RUST_INTEL_MEI_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_INTEL_TBT),intel_tbt,$(RUST_INTEL_TBT_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_INTEL_THERM),intel_thermal,$(RUST_INTEL_THERM_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_INTEL_GNA),intel_gna,$(RUST_INTEL_GNA_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_INTEL_SST),intel_sst,$(RUST_INTEL_SST_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_INTEL_HDMI),intel_hda_hdmi,$(RUST_INTEL_HDMI_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_INTEL_CNVI),intel_cnvi,$(RUST_INTEL_CNVI_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_INTEL_DMA),intel_dma,$(RUST_INTEL_DMA_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_INTEL_IPU),intel_ipu,$(RUST_INTEL_IPU_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_INTEL_P2SB),intel_p2sb,$(RUST_INTEL_P2SB_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_INTEL_SMBUS),intel_smbus,$(RUST_INTEL_SMBUS_DIR)))
$(eval $(call RUST_DRIVER_RULE,$(RUST_LIB_INTEL_SPI),intel_spi,$(RUST_INTEL_SPI_DIR)))

$(RUST_LIB_APPLE_UART): $(RUST_SOURCES)
	@$(RUSTC) --print target-list | grep -q $(RUST_TARGET) >/dev/null || { \
		echo "error: rust target '$(RUST_TARGET)' not installed for $(RUSTC)." >&2; exit 1; }
	@echo "CARGO apple_uart ($(RUST_PROFILE))"
	@cd $(RUST_APPLE_UART_DIR) && RUSTFLAGS="-C panic=abort -C force-unwind-tables=no $(RUSTFLAGS)" $(CARGO) build --release --target $(RUST_TARGET)
	@tmpdir=$$(mktemp -d); \
	cd $$tmpdir && $(AR) x $(abspath $(RUST_LIB_APPLE_UART)) && for obj in *.o; do $(OBJCOPY) --remove-section='.gcc_except_table*' --remove-section='.eh_frame*' $$obj >/dev/null 2>&1 || true; done && $(AR) rcs $(abspath $(RUST_LIB_APPLE_UART)) *.o; \
	rm -rf $$tmpdir

$(RUST_LIB_APPLE_RTKIT): $(RUST_SOURCES)
	@$(RUSTC) --print target-list | grep -q $(RUST_TARGET) >/dev/null || { \
		echo "error: rust target '$(RUST_TARGET)' not installed for $(RUSTC)." >&2; exit 1; }
	@echo "CARGO apple_rtkit ($(RUST_PROFILE))"
	@cd $(RUST_APPLE_RTKIT_DIR) && RUSTFLAGS="-C panic=abort -C force-unwind-tables=no $(RUSTFLAGS)" $(CARGO) build --release --target $(RUST_TARGET)
	@tmpdir=$$(mktemp -d); \
	cd $$tmpdir && $(AR) x $(abspath $(RUST_LIB_APPLE_RTKIT)) && for obj in *.o; do $(OBJCOPY) --remove-section='.gcc_except_table*' --remove-section='.eh_frame*' $$obj >/dev/null 2>&1 || true; done && $(AR) rcs $(abspath $(RUST_LIB_APPLE_RTKIT)) *.o; \
	rm -rf $$tmpdir

$(RUST_LIB_APPLE_ANS2): $(RUST_SOURCES)
	@$(RUSTC) --print target-list | grep -q $(RUST_TARGET) >/dev/null || { \
		echo "error: rust target '$(RUST_TARGET)' not installed for $(RUSTC)." >&2; exit 1; }
	@echo "CARGO apple_ans2 ($(RUST_PROFILE))"
	@cd $(RUST_APPLE_ANS2_DIR) && RUSTFLAGS="-C panic=abort -C force-unwind-tables=no $(RUSTFLAGS)" $(CARGO) build --release --target $(RUST_TARGET)
	@tmpdir=$$(mktemp -d); \
	cd $$tmpdir && $(AR) x $(abspath $(RUST_LIB_APPLE_ANS2)) && for obj in *.o; do $(OBJCOPY) --remove-section='.gcc_except_table*' --remove-section='.eh_frame*' $$obj >/dev/null 2>&1 || true; done && $(AR) rcs $(abspath $(RUST_LIB_APPLE_ANS2)) *.o; \
	rm -rf $$tmpdir

$(RUST_LIB_APPLE_AIC): $(RUST_SOURCES)
	@$(RUSTC) --print target-list | grep -q $(RUST_TARGET) >/dev/null || { \
		echo "error: rust target '$(RUST_TARGET)' not installed for $(RUSTC)." >&2; exit 1; }
	@echo "CARGO apple_aic ($(RUST_PROFILE))"
	@cd $(RUST_APPLE_AIC_DIR) && RUSTFLAGS="-C panic=abort -C force-unwind-tables=no $(RUSTFLAGS)" $(CARGO) build --release --target $(RUST_TARGET)
	@tmpdir=$$(mktemp -d); \
	cd $$tmpdir && $(AR) x $(abspath $(RUST_LIB_APPLE_AIC)) && for obj in *.o; do $(OBJCOPY) --remove-section='.gcc_except_table*' --remove-section='.eh_frame*' $$obj >/dev/null 2>&1 || true; done && $(AR) rcs $(abspath $(RUST_LIB_APPLE_AIC)) *.o; \
	rm -rf $$tmpdir

$(RUST_LIB_APPLE_DART): $(RUST_SOURCES)
	@$(RUSTC) --print target-list | grep -q $(RUST_TARGET) >/dev/null || { \
		echo "error: rust target '$(RUST_TARGET)' not installed for $(RUSTC)." >&2; exit 1; }
	@echo "CARGO apple_dart ($(RUST_PROFILE))"
	@cd $(RUST_APPLE_DART_DIR) && RUSTFLAGS="-C panic=abort -C force-unwind-tables=no $(RUSTFLAGS)" $(CARGO) build --release --target $(RUST_TARGET)
	@tmpdir=$$(mktemp -d); \
	cd $$tmpdir && $(AR) x $(abspath $(RUST_LIB_APPLE_DART)) && for obj in *.o; do $(OBJCOPY) --remove-section='.gcc_except_table*' --remove-section='.eh_frame*' $$obj >/dev/null 2>&1 || true; done && $(AR) rcs $(abspath $(RUST_LIB_APPLE_DART)) *.o; \
	rm -rf $$tmpdir

$(RUST_LIB_APPLE_GPIO): $(RUST_SOURCES)
	@$(RUSTC) --print target-list | grep -q $(RUST_TARGET) >/dev/null || { \
		echo "error: rust target '$(RUST_TARGET)' not installed for $(RUSTC)." >&2; exit 1; }
	@echo "CARGO apple_gpio ($(RUST_PROFILE))"
	@cd $(RUST_APPLE_GPIO_DIR) && RUSTFLAGS="-C panic=abort -C force-unwind-tables=no $(RUSTFLAGS)" $(CARGO) build --release --target $(RUST_TARGET)
	@tmpdir=$$(mktemp -d); \
	cd $$tmpdir && $(AR) x $(abspath $(RUST_LIB_APPLE_GPIO)) && for obj in *.o; do $(OBJCOPY) --remove-section='.gcc_except_table*' --remove-section='.eh_frame*' $$obj >/dev/null 2>&1 || true; done && $(AR) rcs $(abspath $(RUST_LIB_APPLE_GPIO)) *.o; \
	rm -rf $$tmpdir

$(RUST_LIB_APPLE_I2C): $(RUST_SOURCES)
	@$(RUSTC) --print target-list | grep -q $(RUST_TARGET) >/dev/null || { \
		echo "error: rust target '$(RUST_TARGET)' not installed for $(RUSTC)." >&2; exit 1; }
	@echo "CARGO apple_i2c ($(RUST_PROFILE))"
	@cd $(RUST_APPLE_I2C_DIR) && RUSTFLAGS="-C panic=abort -C force-unwind-tables=no $(RUSTFLAGS)" $(CARGO) build --release --target $(RUST_TARGET)
	@tmpdir=$$(mktemp -d); \
	cd $$tmpdir && $(AR) x $(abspath $(RUST_LIB_APPLE_I2C)) && for obj in *.o; do $(OBJCOPY) --remove-section='.gcc_except_table*' --remove-section='.eh_frame*' $$obj >/dev/null 2>&1 || true; done && $(AR) rcs $(abspath $(RUST_LIB_APPLE_I2C)) *.o; \
	rm -rf $$tmpdir

$(RUST_LIB_APPLE_PCIE): $(RUST_SOURCES)
	@$(RUSTC) --print target-list | grep -q $(RUST_TARGET) >/dev/null || { \
		echo "error: rust target '$(RUST_TARGET)' not installed for $(RUSTC)." >&2; exit 1; }
	@echo "CARGO apple_pcie ($(RUST_PROFILE))"
	@cd $(RUST_APPLE_PCIE_DIR) && RUSTFLAGS="-C panic=abort -C force-unwind-tables=no $(RUSTFLAGS)" $(CARGO) build --release --target $(RUST_TARGET)
	@tmpdir=$$(mktemp -d); \
	cd $$tmpdir && $(AR) x $(abspath $(RUST_LIB_APPLE_PCIE)) && for obj in *.o; do $(OBJCOPY) --remove-section='.gcc_except_table*' --remove-section='.eh_frame*' $$obj >/dev/null 2>&1 || true; done && $(AR) rcs $(abspath $(RUST_LIB_APPLE_PCIE)) *.o; \
	rm -rf $$tmpdir

$(RUST_LIB_APPLE_SMC): $(RUST_SOURCES)
	@$(RUSTC) --print target-list | grep -q $(RUST_TARGET) >/dev/null || { \
		echo "error: rust target '$(RUST_TARGET)' not installed for $(RUSTC)." >&2; exit 1; }
	@echo "CARGO apple_smc ($(RUST_PROFILE))"
	@cd $(RUST_APPLE_SMC_DIR) && RUSTFLAGS="-C panic=abort -C force-unwind-tables=no $(RUSTFLAGS)" $(CARGO) build --release --target $(RUST_TARGET)
	@tmpdir=$$(mktemp -d); \
	cd $$tmpdir && $(AR) x $(abspath $(RUST_LIB_APPLE_SMC)) && for obj in *.o; do $(OBJCOPY) --remove-section='.gcc_except_table*' --remove-section='.eh_frame*' $$obj >/dev/null 2>&1 || true; done && $(AR) rcs $(abspath $(RUST_LIB_APPLE_SMC)) *.o; \
	rm -rf $$tmpdir

$(RUST_LIB_APPLE_SPI): $(RUST_SOURCES)
	@$(RUSTC) --print target-list | grep -q $(RUST_TARGET) >/dev/null || { \
		echo "error: rust target '$(RUST_TARGET)' not installed for $(RUSTC)." >&2; exit 1; }
	@echo "CARGO apple_spi ($(RUST_PROFILE))"
	@cd $(RUST_APPLE_SPI_DIR) && RUSTFLAGS="-C panic=abort -C force-unwind-tables=no $(RUSTFLAGS)" $(CARGO) build --release --target $(RUST_TARGET)
	@tmpdir=$$(mktemp -d); \
	cd $$tmpdir && $(AR) x $(abspath $(RUST_LIB_APPLE_SPI)) && for obj in *.o; do $(OBJCOPY) --remove-section='.gcc_except_table*' --remove-section='.eh_frame*' $$obj >/dev/null 2>&1 || true; done && $(AR) rcs $(abspath $(RUST_LIB_APPLE_SPI)) *.o; \
	rm -rf $$tmpdir

$(RUST_LIB_APPLE_MCA): $(RUST_SOURCES)
	@$(RUSTC) --print target-list | grep -q $(RUST_TARGET) >/dev/null || { \
		echo "error: rust target '$(RUST_TARGET)' not installed for $(RUSTC)." >&2; exit 1; }
	@echo "CARGO apple_mca ($(RUST_PROFILE))"
	@cd $(RUST_APPLE_MCA_DIR) && RUSTFLAGS="-C panic=abort -C force-unwind-tables=no $(RUSTFLAGS)" $(CARGO) build --release --target $(RUST_TARGET)
	@tmpdir=$$(mktemp -d); \
	cd $$tmpdir && $(AR) x $(abspath $(RUST_LIB_APPLE_MCA)) && for obj in *.o; do $(OBJCOPY) --remove-section='.gcc_except_table*' --remove-section='.eh_frame*' $$obj >/dev/null 2>&1 || true; done && $(AR) rcs $(abspath $(RUST_LIB_APPLE_MCA)) *.o; \
	rm -rf $$tmpdir
# RPi drivers — Raspberry Pi 3/4/5 peripheral drivers (Rust)
define RPI_CARGO_RULE
$(1): $(RUST_SOURCES)
	@$$(RUSTC) --print target-list | grep -q $$(RUST_TARGET) >/dev/null || { \
		echo "error: rust target '$$(RUST_TARGET)' not installed for $$(RUSTC)." >&2; exit 1; }
	@echo "CARGO $(3) ($$(RUST_PROFILE))"
	@cd $(2) && RUSTFLAGS="-C panic=abort -C force-unwind-tables=no $$(RUSTFLAGS)" $$(CARGO) build --release --target $$(RUST_TARGET)
	@tmpdir=$$$$(mktemp -d); \
	cd $$$$tmpdir && $$(AR) x $$(abspath $(1)) && for obj in *.o; do $$(OBJCOPY) --remove-section='.gcc_except_table*' --remove-section='.eh_frame*' $$$$obj >/dev/null 2>&1 || true; done && $$(AR) rcs $$(abspath $(1)) *.o; \
	rm -rf $$$$tmpdir
endef
$(eval $(call RPI_CARGO_RULE,$(RUST_LIB_RPI_AUDIO),$(RUST_RPI_AUDIO_DIR),rpi_audio))
$(eval $(call RPI_CARGO_RULE,$(RUST_LIB_RPI_DISPLAY),$(RUST_RPI_DISPLAY_DIR),rpi_display))
$(eval $(call RPI_CARGO_RULE,$(RUST_LIB_RPI_DMA),$(RUST_RPI_DMA_DIR),rpi_dma))
$(eval $(call RPI_CARGO_RULE,$(RUST_LIB_RPI_EMMC),$(RUST_RPI_EMMC_DIR),rpi_emmc))
$(eval $(call RPI_CARGO_RULE,$(RUST_LIB_RPI_GENET),$(RUST_RPI_GENET_DIR),rpi_genet))
$(eval $(call RPI_CARGO_RULE,$(RUST_LIB_RPI_GPIO),$(RUST_RPI_GPIO_DIR),rpi_gpio))
$(eval $(call RPI_CARGO_RULE,$(RUST_LIB_RPI_I2C),$(RUST_RPI_I2C_DIR),rpi_i2c))
$(eval $(call RPI_CARGO_RULE,$(RUST_LIB_RPI_MBOX),$(RUST_RPI_MBOX_DIR),rpi_mbox))
$(eval $(call RPI_CARGO_RULE,$(RUST_LIB_RPI_PCIE),$(RUST_RPI_PCIE_DIR),rpi_pcie))
$(eval $(call RPI_CARGO_RULE,$(RUST_LIB_RPI_PWM),$(RUST_RPI_PWM_DIR),rpi_pwm))
$(eval $(call RPI_CARGO_RULE,$(RUST_LIB_RPI_RNG),$(RUST_RPI_RNG_DIR),rpi_rng))
$(eval $(call RPI_CARGO_RULE,$(RUST_LIB_RPI_SPI),$(RUST_RPI_SPI_DIR),rpi_spi))
$(eval $(call RPI_CARGO_RULE,$(RUST_LIB_RPI_THERMAL),$(RUST_RPI_THERMAL_DIR),rpi_thermal))
$(eval $(call RPI_CARGO_RULE,$(RUST_LIB_RPI_USB),$(RUST_RPI_USB_DIR),rpi_usb))
$(eval $(call RPI_CARGO_RULE,$(RUST_LIB_RPI_WATCHDOG),$(RUST_RPI_WATCHDOG_DIR),rpi_watchdog))
else
rust-drivers:
	@echo "error: Rust toolchain (rustc/cargo) not found; install Rust to build rust-drivers." >&2
	@exit 1
endif

$(FBTEST_BIN):
	@$(MAKE) -C src/user fbtest

$(INIT_BIN) $(SECOND_STUB_BIN):
	@$(MAKE) -C src/user stubs

$(WAYLAND_COMPOSITOR_BIN):
	@$(MAKE) -C src/user/compositor/futura-wayland all

$(WAYLAND_CLIENT_BIN):
	@$(MAKE) -C src/user/clients/wl-simple all

$(WL_TERM_BIN):
	@$(MAKE) -C src/user/clients/wl-term all

$(WAYLAND_COLOR_BIN):
	@$(MAKE) -C src/user/clients/wl-colorwheel all

$(WAYLAND_SHELL_BIN):
	@$(MAKE) -C src/user/shell/futura-shell all

$(OBJ_DIR)/kernel/blobs:
	@mkdir -p $@

$(SHELL_BIN): libfutura
	@echo "Building shell..."
	@$(MAKE) -C src/user/shell -f Makefile.simple PLATFORM=$(PLATFORM) all

$(SHELL_BLOB): $(SHELL_BIN) | $(OBJ_DIR)/kernel/blobs
	@echo "OBJCOPY $@"
	@$(OBJCOPY) -I binary -O $(OBJCOPY_BIN_FMT) -B $(OBJCOPY_BIN_ARCH) $< $@

$(FBTEST_BLOB): $(FBTEST_BIN) | $(OBJ_DIR)/kernel/blobs
	@echo "OBJCOPY $@"
	@$(OBJCOPY) -I binary -O $(OBJCOPY_BIN_FMT) -B $(OBJCOPY_BIN_ARCH) $< $@

$(INIT_BLOB): $(INIT_BIN) | $(OBJ_DIR)/kernel/blobs
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

$(WL_TERM_BLOB): $(WL_TERM_BIN) | $(OBJ_DIR)/kernel/blobs
	@echo "OBJCOPY $@"
	@$(OBJCOPY) -I binary -O $(OBJCOPY_BIN_FMT) -B $(OBJCOPY_BIN_ARCH) $< $@

$(WAYLAND_COLOR_BLOB): $(WAYLAND_COLOR_BIN) | $(OBJ_DIR)/kernel/blobs
	@echo "OBJCOPY $@"
	@$(OBJCOPY) -I binary -O $(OBJCOPY_BIN_FMT) -B $(OBJCOPY_BIN_ARCH) $< $@

$(WAYLAND_SHELL_BLOB): $(WAYLAND_SHELL_BIN) | $(OBJ_DIR)/kernel/blobs
	@echo "OBJCOPY $@"
	@$(OBJCOPY) -I binary -O $(OBJCOPY_BIN_FMT) -B $(OBJCOPY_BIN_ARCH) $< $@

# ARM64 userland binaries and blobs
# Note: These cross-compilation rules only apply when building x86_64
# When PLATFORM=arm64, the generic SHELL_BIN/FBTEST_BIN rules handle
# the arm64 binaries directly (they expand to the same paths).
.PHONY: arm64-libfutura
arm64-libfutura:
	@$(MAKE) -C src/user/libfutura PLATFORM=arm64 all

ifeq ($(PLATFORM),x86_64)
# Cross-compilation rules for ARM64 binaries (only when building x86_64 kernel)
$(ARM64_INIT_BIN): arm64-libfutura
	@echo "Building ARM64 init..."
	@$(MAKE) -C src/user/init PLATFORM=arm64 all

$(ARM64_SHELL_BIN): arm64-libfutura
	@echo "Building ARM64 shell..."
	@$(MAKE) -C src/user/shell -f Makefile.simple PLATFORM=arm64 all

$(ARM64_FBTEST_BIN): arm64-libfutura
	@echo "Building ARM64 fbtest..."
	@$(MAKE) -C src/user/fbtest PLATFORM=arm64 all

$(ARM64_UIDEMO_BIN): arm64-libfutura
	@echo "Building ARM64 uidemo..."
	@$(MAKE) -C src/user/arm64_uidemo PLATFORM=arm64 all

$(ARM64_FORKTEST_BIN): arm64-libfutura
	@echo "Building ARM64 forktest..."
	@$(MAKE) -C src/user/forktest PLATFORM=arm64 all
endif

ifeq ($(PLATFORM),arm64)
# Native ARM64 build rules for ARM64-specific binaries
# (init, shell, fbtest are handled by generic rules that expand to the same paths)
$(ARM64_UIDEMO_BIN): arm64-libfutura
	@echo "Building ARM64 uidemo..."
	@$(MAKE) -C src/user/arm64_uidemo PLATFORM=arm64 all

$(ARM64_FORKTEST_BIN): arm64-libfutura
	@echo "Building ARM64 forktest..."
	@$(MAKE) -C src/user/forktest PLATFORM=arm64 all
endif

# Strip debug symbols before embedding. The symbol names are derived from
# the input file path, so we must use the original path as input.
$(ARM64_INIT_BLOB): $(ARM64_INIT_BIN) | $(OBJ_DIR)/kernel/blobs
	@$(OBJCOPY) --strip-debug $< $<.tmp && mv $<.tmp $<
	@$(OBJCOPY) -I binary -O $(OBJCOPY_BIN_FMT) -B $(OBJCOPY_BIN_ARCH) $< $@

$(ARM64_SHELL_BLOB): $(ARM64_SHELL_BIN) | $(OBJ_DIR)/kernel/blobs
	@$(OBJCOPY) --strip-debug $< $<.tmp && mv $<.tmp $<
	@$(OBJCOPY) -I binary -O $(OBJCOPY_BIN_FMT) -B $(OBJCOPY_BIN_ARCH) $< $@

$(ARM64_FBTEST_BLOB): $(ARM64_FBTEST_BIN) | $(OBJ_DIR)/kernel/blobs
	@$(OBJCOPY) --strip-debug $< $<.tmp && mv $<.tmp $<
	@$(OBJCOPY) -I binary -O $(OBJCOPY_BIN_FMT) -B $(OBJCOPY_BIN_ARCH) $< $@

$(ARM64_UIDEMO_BLOB): $(ARM64_UIDEMO_BIN) | $(OBJ_DIR)/kernel/blobs
	@$(OBJCOPY) --strip-debug $< $<.tmp && mv $<.tmp $<
	@$(OBJCOPY) -I binary -O $(OBJCOPY_BIN_FMT) -B $(OBJCOPY_BIN_ARCH) $< $@

$(ARM64_FORKTEST_BLOB): $(ARM64_FORKTEST_BIN) | $(OBJ_DIR)/kernel/blobs
	@$(OBJCOPY) --strip-debug $< $<.tmp && mv $<.tmp $<
	@$(OBJCOPY) -I binary -O $(OBJCOPY_BIN_FMT) -B $(OBJCOPY_BIN_ARCH) $< $@

$(ARM64_NANO_BLOB): $(ARM64_NANO_BIN) | $(OBJ_DIR)/kernel/blobs
	@$(OBJCOPY) --strip-debug $< $<.tmp && mv $<.tmp $<
	@$(OBJCOPY) -I binary -O $(OBJCOPY_BIN_FMT) -B $(OBJCOPY_BIN_ARCH) $< $@

$(ARM64_NANO_BIN):
	@echo "Building nano editor..."
	@$(MAKE) -C src/user/nano all

# Build userland services (all user binaries: compositor, shell, utilities)
userland: libfutura vendor
	@echo "Building userland services..."
	@$(MAKE) -C src/user all

.PHONY: vendor libfutura open_wrapper stage

# Skip Wayland on macOS or when ENABLE_WAYLAND=0
ifeq ($(shell uname -s),Darwin)
vendor:
	@echo "Skipping Wayland on macOS (requires Linux-specific syscalls)"
else ifeq ($(ENABLE_WAYLAND),0)
vendor:
	@echo "Skipping Wayland (ENABLE_WAYLAND=0)"
else
vendor: third_party-wayland
endif

libfutura:
	@$(MAKE) -C src/user/libfutura all

open_wrapper:
	@mkdir -p $(BUILD_DIR)/lib
	@gcc-14 -m64 -fPIC -shared -o $(BUILD_DIR)/lib/libopen_wrapper.so src/user/libfutura/open_wrapper.c

stage: userland
	@echo "==> Staging userland into initramfs"
	@rm -rf $(INITROOT)
	@mkdir -p $(INITROOT)/sbin $(INITROOT)/bin $(INITROOT)/lib $(INITROOT)/tmp
	@chmod 1777 $(INITROOT)/tmp
	@if [ -f $(WAYLAND_COMPOSITOR_BIN) ]; then install -m 0755 $(WAYLAND_COMPOSITOR_BIN) $(INITROOT)/sbin/futura-wayland; fi
	@if [ -f $(WL_TERM_BIN) ]; then install -m 0755 $(WL_TERM_BIN) $(INITROOT)/bin/wl-term; fi
	@if [ -f $(WAYLAND_CLIENT_BIN) ]; then install -m 0755 $(WAYLAND_CLIENT_BIN) $(INITROOT)/bin/wl-simple; fi
	@if [ -f $(WAYLAND_COLOR_BIN) ]; then install -m 0755 $(WAYLAND_COLOR_BIN) $(INITROOT)/bin/wl-colorwheel; fi
	@if [ -f $(WAYLAND_SHELL_BIN) ]; then install -m 0755 $(WAYLAND_SHELL_BIN) $(INITROOT)/sbin/futura-shell && install -m 0755 $(WAYLAND_SHELL_BIN) $(INITROOT)/bin/futura-shell; fi
	@if [ -f src/user/shell/futura-shell/launch_shell.sh ]; then install -m 0755 src/user/shell/futura-shell/launch_shell.sh $(INITROOT)/sbin/launch-shell; fi
	@if [ -f $(BUILD_DIR)/lib/libopen_wrapper.so ]; then install -m 0755 $(BUILD_DIR)/lib/libopen_wrapper.so $(INITROOT)/lib/libopen_wrapper.so; fi
	@if [ -f $(INIT_BIN) ]; then install -m 0755 $(INIT_BIN) $(INITROOT)/sbin/init; fi
	@if [ -f $(SECOND_STUB_BIN) ]; then install -m 0755 $(SECOND_STUB_BIN) $(INITROOT)/sbin/second; fi
	@mkdir -p $(dir $(INITRAMFS))
	@cd $(INITROOT) && find . -print0 | cpio --null -ov --format=newc --quiet > $(abspath $(INITRAMFS))
	@echo "==> Created initramfs $(INITRAMFS)"

.PHONY: tests tools

tests:
	@$(MAKE) -C tests all

tools:
	@$(MAKE) -C tools

# Compile C sources
$(OBJ_DIR)/%.o: %.c $(GEN_VERSION_HDR) $(GEN_FEATURE_HDR) $(BOOT_CMDLINE_HEADER) | $(OBJ_DIR)
	@echo "CC $<"
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

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

# Build test-mode ISO with async-tests enabled in GRUB config
test-iso: kernel
	@echo "Creating test ISO..."
	@cp $(BIN_DIR)/futura_kernel.elf iso/boot/
	@cp iso/boot/grub/grub.cfg iso/boot/grub/grub.cfg.bak
	@printf 'serial --unit=0 --speed=115200\nterminal_input serial\nterminal_output serial\nset timeout=0\nset default=0\nmenuentry "Futura OS (Tests)" {\n    multiboot2 /boot/futura_kernel.elf fb=1 async-tests=1 futura.runtests\n    boot\n}\n' > iso/boot/grub/grub.cfg
	@grub-mkrescue -o futura.iso iso/ 2>&1 | grep -E "(completed|error)" || echo "ISO build complete"
	@mv iso/boot/grub/grub.cfg.bak iso/boot/grub/grub.cfg

# Automated QEMU run with deterministic isa-debug-exit completion
test:
	@$(MAKE) ENABLE_WAYLAND=0 test-iso disk
	@# Kill any stale QEMU holding the disk image lock
	@fuser -k $(QEMU_DISK_IMG) 2>/dev/null || true
	@echo "Testing kernel under QEMU (isa-debug-exit, 180s timeout)..."
	@img=$(QEMU_DISK_IMG); \
		echo "[HARNESS] Using test disk $$img"; \
		timeout 600 qemu-system-x86_64 \
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
	elif [ $$code -eq 124 ]; then \
		echo "[HARNESS] FAIL (timed out after 600s)"; \
		exit 1; \
	else \
		echo "[HARNESS] FAIL (qemu code $$code)"; \
		exit $$code; \
	fi

.PHONY: run run-debug run-headful run-clean help-run

run:
	@$(MAKE) vendor
	@$(MAKE) sym-audit
	@$(MAKE) libfutura
	@$(MAKE) DEBUG_WAYLAND=$(DEBUG) DEBUG_NETUNIX=$(DEBUG) userland
	@$(MAKE) DEBUG_WAYLAND=$(DEBUG) DEBUG_NETUNIX=$(DEBUG) HEADFUL=$(HEADFUL) kernel
	@$(MAKE) DEBUG_WAYLAND=$(DEBUG) DEBUG_NETUNIX=$(DEBUG) stage
	@$(MAKE) disk >/dev/null
	@echo "==> Running QEMU (headful=$(HEADFUL), mem=$(MEM) MiB, debug=$(DEBUG))"
ifeq ($(HEADFUL),1)
ifeq ($(VNC),1)
	@echo "==> VNC server will be available at $(VNC_DISPLAY)"
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
	@echo "  AUTOEXIT=1          # request Wayland demo to auto-exit after launch"
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
	@$(MAKE) DEBUG_WAYLAND=1 ENABLE_WAYLAND=1 iso disk
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
	@$(MAKE) DEBUG_WAYLAND=1 ENABLE_WAYLAND=1 iso disk
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

perf: kernel disk
	@echo "Running kernel performance harness..."
	@bash -c 'set -eo pipefail; OUT="$(BUILD_DIR)/perf_latest.txt"; mkdir -p "$(BUILD_DIR)"; rm -f "$$OUT"; \
	qemu-system-x86_64 -kernel $(BIN_DIR)/futura_kernel.elf -nographic -m $(QEMU_MEM) $(QEMU_FLAGS) -append "perf=on" 2>&1 | tee "$$OUT"; \
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
	@echo "Running ARM64 kernel in QEMU (virt 10.0 with VirtIO GPU)..."
	@qemu-system-aarch64 -M virt-10.0 -cpu cortex-a53 -m 512M -kernel $(BIN_DIR)/futura_kernel.bin -device virtio-gpu-pci -display cocoa -serial stdio -no-reboot

# ARM64 test target (headless, semihosting for exit codes)
test-arm64:
	@$(MAKE) PLATFORM=arm64 ENABLE_WAYLAND=0 kernel
	@echo "Testing ARM64 kernel under QEMU (semihosting exit, 180s timeout)..."
	@timeout 600 qemu-system-aarch64 \
		-M virt -cpu cortex-a53 -m 512M \
		-kernel $(BIN_DIR)/futura_kernel.bin \
		-semihosting-config enable=on,target=native \
		-display none -serial stdio -no-reboot \
	; \
	rc=$$?; \
	if [ $$rc -eq 0 ] || [ $$rc -eq 1 ]; then \
		echo "[HARNESS] PASS"; \
	elif [ $$rc -eq 124 ]; then \
		echo "[HARNESS] FAIL (timed out after 600s)"; exit 1; \
	else \
		echo "[HARNESS] FAIL (qemu code $$rc)"; exit $$rc; \
	fi

# ============================================================
#   Apple Silicon / m1n1 Payload
# ============================================================

.PHONY: m1n1-payload m1n1-clean

# Build m1n1-compatible kernel payload for Apple Silicon
m1n1-payload: platform-arm64
	@echo "Creating m1n1 payload from ARM64 kernel..."
	@./scripts/create-m1n1-payload.sh $(BIN_DIR)/futura_kernel.elf build/m1n1

# Clean m1n1 payload artifacts
m1n1-clean:
	@rm -rf build/m1n1
	@echo "m1n1 payload artifacts cleaned"

# ============================================================
#   Raspberry Pi Image Generation
# ============================================================

# Build kernel8.img for Raspberry Pi 4/5 SD card boot
# Usage: make rpi-image
# Output: build/rpi/kernel8.img + config.txt
rpi-image:
	@echo "Building Raspberry Pi 4/5 kernel image..."
	@mkdir -p build/rpi
	@echo "  Creating config.txt..."
	@printf '# Futura OS - Raspberry Pi config.txt\n\
arm_64bit=1\n\
kernel=kernel8.img\n\
enable_uart=1\n\
uart_2ndstage=1\n\
disable_overscan=1\n\
dtparam=audio=off\n\
# For Pi4: use GIC (Generic Interrupt Controller)\n\
enable_gic=1\n\
# GPU memory split (minimum for headless)\n\
gpu_mem=16\n\
# Boot log over UART\n\
boot_delay=0\n' > build/rpi/config.txt
	@echo "  config.txt created"
	@echo ""
	@echo "=== RPi SD Card Setup ==="
	@echo "1. Format SD card as FAT32"
	@echo "2. Copy RPi firmware files (start4.elf, fixup4.dat, bcm2711-rpi-4-b.dtb)"
	@echo "3. Copy build/rpi/config.txt to SD card root"
	@echo "4. Copy build/rpi/kernel8.img to SD card root"
	@echo "5. Insert SD card and power on Pi"
	@echo "6. Connect serial console (115200 8N1) to GPIO pins 14/15"
	@echo ""
	@echo "Note: kernel8.img build requires cross-compilation with:"
	@echo "  PLATFORM=arm64 CROSS_COMPILE=aarch64-linux-gnu- make rpi-kernel"

# Build the RPi-specific kernel binary (requires ARM64 cross compiler)
rpi-kernel:
	@echo "Building RPi kernel (flat binary at 0x80000)..."
	@mkdir -p build/rpi
	@echo "  Note: Full RPi kernel build requires aarch64-linux-gnu- toolchain"
	@echo "  and separate compilation of platform/arm64/rpi_boot.S + rpi_entry.c"
	@echo "  with the boot/rpi.ld linker script."

# Test RPi kernel under QEMU raspi4b machine
rpi-test:
	@echo "Testing RPi4 kernel under QEMU raspi4b..."
	@echo "  Note: QEMU raspi4b machine support is experimental."
	@echo "  Use: qemu-system-aarch64 -M raspi4b -m 4G -kernel build/rpi/kernel8.img -serial stdio"

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
	@echo "  make third_party-wayland      - Build vendored Wayland libs and scanner"
	@echo "  make clean                    - Clean build artifacts"

# ============================================================
#   Automatic Dependency Generation
# ============================================================

# GCC generates .d files alongside .o files via -MMD -MP.
# -MMD: Write user-header dependencies to .d (not system headers)
# -MP:  Add phony targets for each header so deleted headers don't break make
DEPFILES := $(OBJECTS:.o=.d)
-include $(DEPFILES)
.PHONY: third_party-wayland
third_party-wayland:
	@$(MAKE) -C third_party/wayland all
CFLAGS += -I$(BUILD_GEN_ROOT)
