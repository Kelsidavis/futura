# Vendor build harness for upstream Wayland
#
# Copyright (c) 2025 Kelsi Davis
# Licensed under the MPL v2.0 — see LICENSE for details.

.POSIX:

WAYLAND_VERSION := 1.23.0
WAYLAND_URL := https://gitlab.freedesktop.org/wayland/wayland/-/archive/$(WAYLAND_VERSION)/wayland-$(WAYLAND_VERSION).tar.gz
WAYLAND_SHA256 := 7c5c28fa73f22d1c5021e17e1148f29ab17bf8b776a406f1c4489d3e2992ec3a

ROOT_DIR := $(abspath ../..)
BUILD_ROOT := $(ROOT_DIR)/build/third_party/wayland
SRC_ROOT := $(BUILD_ROOT)/src
SRC_DIR := $(SRC_ROOT)/wayland-$(WAYLAND_VERSION)
BUILD_DIR := $(BUILD_ROOT)/build
INSTALL_DIR := $(BUILD_ROOT)/install
STATE_DIR := $(BUILD_ROOT)/state
PATHS_FILE := $(BUILD_ROOT)/paths.mk
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
STAMP_EXTRACT := $(STATE_DIR)/extract.stamp
STAMP_PATCH := $(STATE_DIR)/patch.stamp
STAMP_CONFIGURE := $(STATE_DIR)/configure.stamp
STAMP_BUILD := $(STATE_DIR)/build.stamp
STAMP_INSTALL := $(INSTALL_DIR)/.stamp-installed

MESON_FLAGS := \
	--prefix $(INSTALL_DIR) \
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

# macOS: Remove -fno-semantic-interposition (unsupported by Clang) and add -D_POSIX_C_SOURCE
ifeq ($(shell uname -s),Darwin)
NATIVE_C_ARGS_LIST := '-O2', '-g0', '-fPIC', '-fvisibility=hidden', '-ffunction-sections', '-fdata-sections', '-fno-stack-protector', '-DFUTURA_NO_GLIBC=1', '-D_POSIX_C_SOURCE=200809L'
else
NATIVE_C_ARGS_LIST := '-O2', '-g0', '-fPIC', '-fvisibility=hidden', '-ffunction-sections', '-fdata-sections', '-fno-semantic-interposition', '-fno-stack-protector', '-DFUTURA_NO_GLIBC=1'
endif
# macOS uses Apple ld, not GNU ld - use compatible flags
ifeq ($(shell uname -s),Darwin)
NATIVE_LINK_ARGS_LIST := '-Wl,-dead_strip'
else
NATIVE_LINK_ARGS_LIST := '-Wl,--build-id=none', '-Wl,--gc-sections'
endif

.PHONY: all clean distclean info

all: $(STAMP_INSTALL)

info:
	@echo "Wayland version: $(WAYLAND_VERSION)"
	@echo "Install prefix : $(INSTALL_DIR)"

$(DOWNLOAD_DIR):
	@mkdir -p $@

$(STATE_DIR):
	@mkdir -p $@

$(BUILD_ROOT):
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
	@echo "$(WAYLAND_SHA256)  $@.tmp" | sha256sum -c -
	@mv $@.tmp $@

$(STAMP_EXTRACT): $(TARBALL) $(PATCHES) | $(SRC_ROOT) $(STATE_DIR)
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

$(STAMP_CONFIGURE): $(STAMP_PATCH) $(NATIVE_FILE) | $(BUILD_DIR) $(INSTALL_DIR)
	@echo ">> Configuring Wayland build"
	@rm -rf $(BUILD_DIR)
	@$(MESON) setup $(BUILD_DIR) $(SRC_DIR) $(MESON_FLAGS) --native-file $(NATIVE_FILE)
	@touch $@

$(STAMP_BUILD): $(STAMP_CONFIGURE)
	@echo ">> Building Wayland"
	@$(MESON) compile -C $(BUILD_DIR)
	@touch $@

$(PATHS_FILE): $(STAMP_BUILD) | $(INSTALL_DIR)
	@echo ">> Installing Wayland artifacts"
	@$(MESON) install -C $(BUILD_DIR) --no-rebuild
	@echo ">> Writing helper metadata"
	@{ \
		echo "# Autogenerated by third_party/wayland/Makefile"; \
		echo "WAYLAND_PREFIX := $(INSTALL_DIR)"; \
		echo "WAYLAND_INCLUDEDIR := $(INSTALL_DIR)/include"; \
		echo "WAYLAND_LIBDIR := $(INSTALL_DIR)/lib"; \
		echo "WAYLAND_BINDIR := $(INSTALL_DIR)/bin"; \
		if [ -n "$(HOST_SCANNER)" ]; then \
			echo "WAYLAND_SCANNER := $(HOST_SCANNER)"; \
		else \
			echo "WAYLAND_SCANNER := $(INSTALL_DIR)/bin/wayland-scanner"; \
		fi; \
		echo "WAYLAND_PKGCONFIG := $(INSTALL_DIR)/lib/pkgconfig"; \
	} > $(PATHS_FILE)

$(STAMP_INSTALL): $(PATHS_FILE)
	@touch $@

clean:
	@echo ">> Cleaning Wayland build artifacts"
	@rm -rf $(BUILD_DIR) $(STATE_DIR) $(PATHS_FILE)

distclean: clean
	@echo ">> Removing downloaded artifacts"
	@rm -rf $(BUILD_ROOT) $(TARBALL) $(DOWNLOAD_DIR)
