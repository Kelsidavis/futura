# Vendor build harness for upstream Wayland
#
# Copyright (c) 2025 Kelsi Davis
# Licensed under the MPL v2.0 — see LICENSE for details.
#
# Two build modes, selected by PLATFORM:
#   PLATFORM=host  (default) — build wayland-scanner + libs for the host
#                              toolchain. Used so the protocol generator
#                              is available for both x86_64 and arm64
#                              userland builds.
#   PLATFORM=arm64           — cross-build libwayland-server.a /
#                              libwayland-client.a for aarch64-elf-Futura
#                              against include/user/ headers and the
#                              cross-built libffi.
#
# Outputs:
#   build/third_party/wayland/install-host/   wayland-scanner + host libs
#   build/third_party/wayland/install-arm64/  arm64-elf libs

.POSIX:

PLATFORM ?= host

WAYLAND_VERSION := 1.23.0
WAYLAND_URL := https://gitlab.freedesktop.org/wayland/wayland/-/archive/$(WAYLAND_VERSION)/wayland-$(WAYLAND_VERSION).tar.gz
WAYLAND_SHA256 := 7c5c28fa73f22d1c5021e17e1148f29ab17bf8b776a406f1c4489d3e2992ec3a

ROOT_DIR := $(abspath ../..)
BUILD_ROOT := $(ROOT_DIR)/build/third_party/wayland
SRC_ROOT := $(BUILD_ROOT)/src
SRC_DIR := $(SRC_ROOT)/wayland-$(WAYLAND_VERSION)
BUILD_DIR := $(BUILD_ROOT)/build-$(PLATFORM)
INSTALL_DIR := $(BUILD_ROOT)/install-$(PLATFORM)
STATE_DIR := $(BUILD_ROOT)/state-$(PLATFORM)
PATHS_FILE := $(BUILD_ROOT)/paths-$(PLATFORM).mk

# Backward-compat for existing parent Makefile rules expecting these.
HOST_INSTALL_DIR := $(BUILD_ROOT)/install-host
ifeq ($(PLATFORM),host)
COMPAT_LINK_DIR := $(BUILD_ROOT)/install
COMPAT_LINK_PATHS := $(BUILD_ROOT)/paths.mk
endif

HOST_SCANNER := $(shell command -v wayland-scanner 2>/dev/null)

DOWNLOAD_DIR := vendor
TARBALL := $(DOWNLOAD_DIR)/wayland-$(WAYLAND_VERSION).tar.gz

PATCH_DIR := patches
PATCHES := $(wildcard $(PATCH_DIR)/*.patch)

MESON := meson
NINJA := ninja

ARFLAGS ?= rcsD
export ARFLAGS

NATIVE_FILE := $(STATE_DIR)/native.ini
CROSS_FILE := $(STATE_DIR)/cross.ini
STAMP_EXTRACT := $(BUILD_ROOT)/state/extract.stamp
STAMP_PATCH := $(BUILD_ROOT)/state/patch.stamp
STAMP_CONFIGURE := $(STATE_DIR)/configure.stamp
STAMP_BUILD := $(STATE_DIR)/build.stamp
STAMP_INSTALL := $(INSTALL_DIR)/.stamp-installed

# Tell Meson where libffi lives for the ARM64 cross build (we cross-built
# it ourselves under third_party/libffi/). Host builds use system pkg-config.
LIBFFI_ARM64_PREFIX := $(ROOT_DIR)/build/third_party/libffi/install-arm64

MESON_FLAGS_COMMON := \
	--libdir lib \
	--includedir include \
	--bindir bin \
	--datadir share \
	--buildtype release \
	--default-library static \
	--wrap-mode nofallback \
	-Dlibraries=true \
	-Dtests=false \
	-Ddocumentation=false \
	-Ddtd_validation=false

# Host build also wants the scanner; cross build is libs-only.
ifeq ($(PLATFORM),host)
MESON_FLAGS_PLATFORM := -Dscanner=true
else
MESON_FLAGS_PLATFORM := -Dscanner=false
endif

MESON_FLAGS := --prefix $(INSTALL_DIR) $(MESON_FLAGS_COMMON) $(MESON_FLAGS_PLATFORM)

# Host C args — same as before; macOS clang differs slightly from gcc.
ifeq ($(shell uname -s),Darwin)
NATIVE_C_ARGS_LIST := '-O2', '-g0', '-fPIC', '-fvisibility=hidden', '-ffunction-sections', '-fdata-sections', '-fno-stack-protector', '-DFUTURA_NO_GLIBC=1', '-D_POSIX_C_SOURCE=200809L'
NATIVE_LINK_ARGS_LIST := '-Wl,-dead_strip'
else
NATIVE_C_ARGS_LIST := '-O2', '-g0', '-fPIC', '-fvisibility=hidden', '-ffunction-sections', '-fdata-sections', '-fno-semantic-interposition', '-fno-stack-protector', '-DFUTURA_NO_GLIBC=1'
NATIVE_LINK_ARGS_LIST := '-Wl,--build-id=none', '-Wl,--gc-sections'
endif

# Cross toolchain selection (PLATFORM=arm64).
ifeq ($(PLATFORM),arm64)
ifeq ($(shell uname -s),Darwin)
CROSS_PREFIX := /opt/homebrew/bin/aarch64-elf-
else
CROSS_PREFIX := aarch64-linux-gnu-
endif
CROSS_CC      := $(ROOT_DIR)/third_party/wayland/wrappers/aarch64-elf-gcc-no-pthread.sh
CROSS_AR      := $(CROSS_PREFIX)ar
CROSS_LD      := $(CROSS_PREFIX)ld
CROSS_STRIP   := $(CROSS_PREFIX)strip
CROSS_RANLIB  := $(CROSS_PREFIX)ranlib
endif

.PHONY: all clean distclean info

all: $(STAMP_INSTALL)

info:
	@echo "Wayland version: $(WAYLAND_VERSION)"
	@echo "Platform       : $(PLATFORM)"
	@echo "Install prefix : $(INSTALL_DIR)"

$(DOWNLOAD_DIR):
	@mkdir -p $@

$(STATE_DIR):
	@mkdir -p $@

$(BUILD_ROOT)/state:
	@mkdir -p $@

$(SRC_ROOT):
	@mkdir -p $@

$(BUILD_DIR):
	@mkdir -p $@

$(INSTALL_DIR):
	@mkdir -p $@

$(TARBALL): | $(DOWNLOAD_DIR)
	@echo ">> Downloading Wayland $(WAYLAND_VERSION)"
	@curl -L $(WAYLAND_URL) -o $@.tmp
	@echo "$(WAYLAND_SHA256)  $@.tmp" | shasum -a 256 -c -
	@mv $@.tmp $@

$(STAMP_EXTRACT): $(TARBALL) $(PATCHES) | $(SRC_ROOT) $(BUILD_ROOT)/state
	@echo ">> Extracting $(TARBALL)"
	@rm -rf $(SRC_ROOT)
	@mkdir -p $(SRC_ROOT)
	@tar -xzf $(TARBALL) -C $(SRC_ROOT)
	@touch $@

$(STAMP_PATCH): $(STAMP_EXTRACT) $(PATCHES)
ifneq ($(PATCHES),)
	@echo ">> Applying patches"
	@for patch in $(PATCHES); do \
		echo "   -> $$patch"; \
		patch -d $(SRC_DIR) -p1 < $$patch || true; \
	done
endif
	@cp $(ROOT_DIR)/third_party/wayland/wayland_nofortify.h $(SRC_DIR)/
	@sed -i.bak "s|add_project_arguments(cc_args, language: 'c')|cc_args += ['-D_GNU_SOURCE','-U_FORTIFY_SOURCE','-D_FORTIFY_SOURCE=0','-include','$(SRC_DIR)/wayland_nofortify.h']\\nadd_project_arguments(cc_args, language: 'c')|" $(SRC_DIR)/meson.build
	@sed -i.bak "s|#error \"Don't know how to read ucred on this platform\"|/* Futura: no ucred support, continue */|" $(SRC_DIR)/src/wayland-os.c
	@perl -0pi -e "s/if \(lstat\(socket->addr.sun_path, &socket_stat\) < 0 \)\s*\{\s*if \(errno != ENOENT\) \{\s*wl_log\(\"did not manage to stat file %s\\n\",\s*socket->addr.sun_path\);\s*goto err_fd;\s*\}\s*\}\s*else if \(socket_stat.st_mode & S_IWUSR \\|\\|\s*socket_stat.st_mode & S_IWGRP\) \{\s*unlink\(socket->addr.sun_path\);\s*\}/\tunlink(socket->addr.sun_path);\n/" $(SRC_DIR)/src/wayland-server.c
	@sed -i.bak '/SFD_CLOEXEC/d; /TFD_CLOEXEC/d' $(SRC_DIR)/meson.build
	@# macOS: Skip CLOCK_MONOTONIC check
	@sed -i.bak "s/error('@0@ is needed to compile Wayland libraries'.format(d\['symbol'\]))/# macOS: Skip check/" $(SRC_DIR)/meson.build
ifeq ($(shell uname -s),Darwin)
	@# macOS: Comment out Linux-specific includes (we provide stubs in wayland_nofortify.h)
	@sed -i.bak 's|#include <sys/epoll.h>|/* #include <sys/epoll.h> - using stub from wayland_nofortify.h */|' $(SRC_DIR)/src/wayland-os.c
	@sed -i.bak 's|#include <sys/epoll.h>|/* #include <sys/epoll.h> - using stub from wayland_nofortify.h */|' $(SRC_DIR)/src/event-loop.c
	@sed -i.bak 's|#include <sys/eventfd.h>|/* #include <sys/eventfd.h> - using stub from wayland_nofortify.h */|' $(SRC_DIR)/src/wayland-server.c
	@sed -i.bak 's|#include <sys/signalfd.h>|/* #include <sys/signalfd.h> - using stub from wayland_nofortify.h */|' $(SRC_DIR)/src/event-loop.c
	@sed -i.bak 's|#include <sys/timerfd.h>|/* #include <sys/timerfd.h> - using stub from wayland_nofortify.h */|' $(SRC_DIR)/src/event-loop.c
endif
	@touch $@

$(NATIVE_FILE): | $(STATE_DIR)
	@echo ">> Generating Meson native file"
	@{ \
		echo "[binaries]"; \
		echo "c = 'gcc'"; \
		echo "cpp = 'gcc'"; \
		echo "ar = 'ar'"; \
		echo "pkg-config = 'pkg-config'"; \
		echo "strip = 'strip'"; \
		echo ""; \
		echo "[built-in options]"; \
		printf "c_args = [%s]\n" "$(NATIVE_C_ARGS_LIST)"; \
		printf "c_link_args = [%s]\n" "$(NATIVE_LINK_ARGS_LIST)"; \
		echo "warning_level = '1'"; \
		echo ""; \
		echo "[properties]"; \
		echo "needs_exe_wrapper = false"; \
	} > $@

# Cross-file for ARM64 — points meson at the aarch64-elf toolchain and
# Futura's user-side libc surface (include/user/) plus our cross-built
# libffi. -DFUTURA_NO_GLIBC matches the macOS host build's flag and
# tells the wayland_nofortify.h shim to provide the Linux-only types
# (struct epoll_event, struct signalfd_siginfo, …) inline.
$(CROSS_FILE): | $(STATE_DIR)
	@echo ">> Generating Meson cross file for arm64"
	@{ \
		echo "[binaries]"; \
		echo "c = '$(CROSS_CC)'"; \
		echo "ar = '$(CROSS_AR)'"; \
		echo "ld = '$(CROSS_LD)'"; \
		echo "strip = '$(CROSS_STRIP)'"; \
		echo "ranlib = '$(CROSS_RANLIB)'"; \
		echo "pkg-config = 'pkg-config'"; \
		echo ""; \
		echo "[built-in options]"; \
		printf "c_args = ['-O2','-g0','-ffreestanding','-nostdlib','-fno-stack-protector','-fvisibility=hidden','-march=armv8-a','-mno-outline-atomics','-mstrict-align','-DFUTURA_NO_GLIBC=1','-D_POSIX_C_SOURCE=200809L','-I$(ROOT_DIR)/include/user','-I$(LIBFFI_ARM64_PREFIX)/include']\n"; \
		printf "c_link_args = ['-nostdlib','-Wl,--build-id=none','-Wl,--gc-sections','-L$(LIBFFI_ARM64_PREFIX)/lib']\n"; \
		echo "warning_level = '1'"; \
		echo ""; \
		echo "[host_machine]"; \
		echo "system = 'futura'"; \
		echo "cpu_family = 'aarch64'"; \
		echo "cpu = 'aarch64'"; \
		echo "endian = 'little'"; \
		echo ""; \
		echo "[properties]"; \
		echo "needs_exe_wrapper = true"; \
	} > $@

ifeq ($(PLATFORM),arm64)
$(STAMP_CONFIGURE): $(STAMP_PATCH) $(NATIVE_FILE) $(CROSS_FILE) | $(BUILD_DIR) $(INSTALL_DIR)
	@echo ">> Configuring Wayland (cross arm64)"
	@rm -rf $(BUILD_DIR)
	@# Make wayland-scanner.pc from the host build visible so meson can
	@# resolve the wayland-scanner build-dep via pkg-config — we already
	@# built and installed it under install-host/. Cross builds split
	@# pkg-config into FOR_BUILD (native, where wayland-scanner runs)
	@# and target (where libffi gets linked); set both.
	@PKG_CONFIG_PATH_FOR_BUILD="$(HOST_INSTALL_DIR)/lib/pkgconfig" \
	 PKG_CONFIG_PATH="$(LIBFFI_ARM64_PREFIX)/lib/pkgconfig" \
		$(MESON) setup $(BUILD_DIR) $(SRC_DIR) $(MESON_FLAGS) \
		--native-file $(NATIVE_FILE) \
		--cross-file $(CROSS_FILE)
	@touch $@
else
$(STAMP_CONFIGURE): $(STAMP_PATCH) $(NATIVE_FILE) | $(BUILD_DIR) $(INSTALL_DIR)
	@echo ">> Configuring Wayland (host)"
	@rm -rf $(BUILD_DIR)
	@$(MESON) setup $(BUILD_DIR) $(SRC_DIR) $(MESON_FLAGS) --native-file $(NATIVE_FILE)
	@touch $@
endif

$(STAMP_BUILD): $(STAMP_CONFIGURE)
	@echo ">> Building Wayland ($(PLATFORM))"
	@$(MESON) compile -C $(BUILD_DIR)
	@touch $@

$(PATHS_FILE): $(STAMP_BUILD) | $(INSTALL_DIR)
	@echo ">> Installing Wayland artifacts ($(PLATFORM))"
	@$(MESON) install -C $(BUILD_DIR) --no-rebuild
	@echo ">> Writing helper metadata"
	@{ \
		echo "# Autogenerated by third_party/wayland/Makefile (PLATFORM=$(PLATFORM))"; \
		echo "WAYLAND_PREFIX_$(PLATFORM) := $(INSTALL_DIR)"; \
		echo "WAYLAND_INCLUDEDIR_$(PLATFORM) := $(INSTALL_DIR)/include"; \
		echo "WAYLAND_LIBDIR_$(PLATFORM) := $(INSTALL_DIR)/lib"; \
		echo "WAYLAND_BINDIR_$(PLATFORM) := $(INSTALL_DIR)/bin"; \
		if [ -n "$(HOST_SCANNER)" ]; then \
			echo "WAYLAND_SCANNER_$(PLATFORM) := $(HOST_SCANNER)"; \
		else \
			echo "WAYLAND_SCANNER_$(PLATFORM) := $(HOST_INSTALL_DIR)/bin/wayland-scanner"; \
		fi; \
		echo "WAYLAND_PKGCONFIG_$(PLATFORM) := $(INSTALL_DIR)/lib/pkgconfig"; \
	} > $(PATHS_FILE)
ifeq ($(PLATFORM),host)
	@# Backward-compat: keep build/third_party/wayland/install and paths.mk
	@# pointing at the host build for any existing rules.
	@rm -f $(COMPAT_LINK_DIR)
	@ln -s install-host $(COMPAT_LINK_DIR)
	@cp $(PATHS_FILE) $(COMPAT_LINK_PATHS)
endif

$(STAMP_INSTALL): $(PATHS_FILE)
	@touch $@

clean:
	@echo ">> Cleaning Wayland build artifacts ($(PLATFORM))"
	@rm -rf $(BUILD_DIR) $(STATE_DIR) $(PATHS_FILE)

distclean: clean
	@echo ">> Removing all Wayland build artifacts and tarball"
	@rm -rf $(BUILD_ROOT) $(TARBALL) $(DOWNLOAD_DIR)
