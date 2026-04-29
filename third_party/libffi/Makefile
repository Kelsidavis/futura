# libffi vendor build harness
#
# Cross-builds libffi for the Futura target architecture so libwayland
# (which has libffi as its only hard runtime dependency) can be linked
# into the compositor and wayland clients.
#
# Outputs:
#   build/third_party/libffi/install-<platform>/lib/libffi.a
#   build/third_party/libffi/install-<platform>/include/{ffi.h,ffitarget.h}
#
# PLATFORM defaults to arm64 since x86_64 hosts can use the system
# libffi from pkg-config; the cross-build only matters for ARM64-elf
# Futura where we have no system libc to provide it.

.POSIX:

PLATFORM ?= arm64

LIBFFI_VERSION := 3.4.6
LIBFFI_URL := https://github.com/libffi/libffi/releases/download/v$(LIBFFI_VERSION)/libffi-$(LIBFFI_VERSION).tar.gz
LIBFFI_SHA256 := b0dea9df23c863a7a50e825440f3ebffabd65df1497108e5d437747843895a4e

ROOT_DIR := $(abspath ../..)
BUILD_ROOT := $(ROOT_DIR)/build/third_party/libffi
SRC_ROOT := $(BUILD_ROOT)/src
SRC_DIR := $(SRC_ROOT)/libffi-$(LIBFFI_VERSION)
BUILD_DIR := $(BUILD_ROOT)/build-$(PLATFORM)
INSTALL_DIR := $(BUILD_ROOT)/install-$(PLATFORM)
STATE_DIR := $(BUILD_ROOT)/state-$(PLATFORM)

DOWNLOAD_DIR := vendor
TARBALL := $(DOWNLOAD_DIR)/libffi-$(LIBFFI_VERSION).tar.gz

STAMP_EXTRACT := $(STATE_DIR)/extract.stamp
STAMP_CONFIGURE := $(STATE_DIR)/configure.stamp
STAMP_BUILD := $(STATE_DIR)/build.stamp
STAMP_INSTALL := $(INSTALL_DIR)/.stamp-installed

ifeq ($(PLATFORM),arm64)
    ifeq ($(shell uname -s),Darwin)
        CROSS_COMPILE := /opt/homebrew/bin/aarch64-elf-
    else
        CROSS_COMPILE := aarch64-linux-gnu-
    endif
    HOST_TRIPLE := aarch64-elf
    TARGET_CC := $(CROSS_COMPILE)gcc
    TARGET_AR := $(CROSS_COMPILE)ar
    TARGET_LD := $(CROSS_COMPILE)ld
    TARGET_RANLIB := $(CROSS_COMPILE)ranlib
    # libffi sources reference longjmp/setjmp at the source level for
    # closures we don't use; freestanding flags keep us from needing a
    # full libc, and -DFFI_NO_RAW_API drops a ton of unused-in-Futura
    # surface (raw API is for closures-with-stack-relative-args).
    # libffi includes <stdlib.h>/<string.h>/<stdio.h>; the bare-metal
    # aarch64-elf toolchain ships no libc headers, so we point at
    # Futura's user-side libc surface in include/user/ which maps onto
    # libfutura syscall wrappers at link time.
    TARGET_CFLAGS := -ffreestanding -nostdlib -O2 -g0 \
        -fno-stack-protector -fvisibility=hidden \
        -march=armv8-a -mno-outline-atomics -mstrict-align \
        -DFFI_NO_RAW_API=1 \
        -I$(ROOT_DIR)/include/user
else
    TARGET_CC := gcc
    TARGET_AR := ar
    TARGET_LD := ld
    TARGET_RANLIB := ranlib
    HOST_TRIPLE := x86_64-pc-linux-gnu
    TARGET_CFLAGS := -O2 -g0 -fPIC -fvisibility=hidden
endif

.PHONY: all clean distclean info

all: $(STAMP_INSTALL)

info:
	@echo "libffi version : $(LIBFFI_VERSION)"
	@echo "Platform       : $(PLATFORM)"
	@echo "Host triple    : $(HOST_TRIPLE)"
	@echo "Target CC      : $(TARGET_CC)"
	@echo "Install prefix : $(INSTALL_DIR)"

$(DOWNLOAD_DIR):
	@mkdir -p $@

$(STATE_DIR):
	@mkdir -p $@

$(SRC_ROOT):
	@mkdir -p $@

$(BUILD_DIR):
	@mkdir -p $@

$(INSTALL_DIR):
	@mkdir -p $@

$(TARBALL): | $(DOWNLOAD_DIR)
	@echo ">> Downloading libffi $(LIBFFI_VERSION)"
	@curl -L $(LIBFFI_URL) -o $@.tmp
	@echo "$(LIBFFI_SHA256)  $@.tmp" | shasum -a 256 -c -
	@mv $@.tmp $@

$(STAMP_EXTRACT): $(TARBALL) | $(SRC_ROOT) $(STATE_DIR)
	@echo ">> Extracting $(TARBALL)"
	@rm -rf $(SRC_DIR)
	@tar -xzf $(TARBALL) -C $(SRC_ROOT)
	@touch $@

$(STAMP_CONFIGURE): $(STAMP_EXTRACT) | $(BUILD_DIR) $(INSTALL_DIR)
	@echo ">> Configuring libffi for $(PLATFORM)"
	@cd $(BUILD_DIR) && \
		CC="$(TARGET_CC)" \
		AR="$(TARGET_AR)" \
		LD="$(TARGET_LD)" \
		RANLIB="$(TARGET_RANLIB)" \
		CFLAGS="$(TARGET_CFLAGS)" \
		LDFLAGS="-nostdlib" \
		$(SRC_DIR)/configure \
			--host=$(HOST_TRIPLE) \
			--prefix=$(INSTALL_DIR) \
			--disable-shared \
			--enable-static \
			--disable-docs \
			--disable-multi-os-directory \
			--disable-symvers \
			--disable-exec-static-tramp
	@touch $@

$(STAMP_BUILD): $(STAMP_CONFIGURE)
	@echo ">> Building libffi"
	@$(MAKE) -C $(BUILD_DIR)
	@touch $@

$(STAMP_INSTALL): $(STAMP_BUILD)
	@echo ">> Installing libffi to $(INSTALL_DIR)"
	@$(MAKE) -C $(BUILD_DIR) install
	@touch $@

clean:
	@rm -rf $(BUILD_DIR) $(STATE_DIR)

distclean: clean
	@rm -rf $(BUILD_ROOT) $(TARBALL)
