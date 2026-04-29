# SPDX-License-Identifier: MPL-2.0

# Platform detection (defaults to x86_64 if not specified)
PLATFORM ?= x86_64

# Toolchain (can be overridden by parent Makefile or command line)
ifeq ($(PLATFORM),arm64)
    ifeq ($(shell uname -s),Darwin)
        CROSS_COMPILE ?= /opt/homebrew/bin/aarch64-elf-
        CC := $(CROSS_COMPILE)gcc
    else
        CROSS_COMPILE ?= aarch64-linux-gnu-
        CC := $(CROSS_COMPILE)gcc-14
    endif
    LD := $(CROSS_COMPILE)ld
    AR := $(CROSS_COMPILE)ar
    ARCH_CFLAGS := -march=armv8-a -mtune=cortex-a53 -mno-outline-atomics
else
    CC := gcc
    LD := ld
    AR := ar
    ARCH_CFLAGS := -m64
endif

ROOT := ../../../..
BUILD_ROOT := $(ROOT)/build
OBJ_DIR := $(BUILD_ROOT)/obj/$(PLATFORM)/user/compositor/futura-wayland
BIN_DIR := $(BUILD_ROOT)/bin/$(PLATFORM)/user

# WAYLAND_SCANNER must be visible to mk/wayland.mk's protocol-gen
# rules at the include site, so set it BEFORE the include.  The host
# build always supplies the scanner; the target arch's build never
# does.
WAYLAND_HOST_PREFIX := $(ROOT)/build/third_party/wayland/install-host
WAYLAND_SCANNER     := $(WAYLAND_HOST_PREFIX)/bin/wayland-scanner

include $(ROOT)/mk/wayland.mk

# Set the default goal explicitly — the wayland_proto_server eval
# below adds a rule for the protocol output directory which would
# otherwise become the implicit default.
.DEFAULT_GOAL := all

TARGET := $(BIN_DIR)/futura-wayland
SRCS := main.c bootstrap.c comp.c shm_backend.c xdg_shell.c output.c seat.c cursor.c ui_text.c shadow.c data_device.c syscall_wrappers.c

OUT ?= $(BUILD_ROOT)/generated/wayland
$(eval $(call wayland_proto_server,$(ROOT)/protocols/xdg-shell.xml,compositor))
WAYLAND_GEN_SRCS := $(OUT)/compositor/xdg-shell-protocol.c
WAYLAND_GEN_HDRS := $(OUT)/compositor/xdg-shell-server-protocol.h

OBJS := $(SRCS:%.c=$(OBJ_DIR)/%.o)
OBJS += $(OBJ_DIR)/xdg-shell-protocol.o

# libwayland target-arch lib prefix.
WAYLAND_PREFIX ?= $(ROOT)/build/third_party/wayland/install-$(PLATFORM)
WAYLAND_INCLUDEDIR ?= $(WAYLAND_PREFIX)/include
WAYLAND_LIBDIR ?= $(WAYLAND_PREFIX)/lib
WAYLAND_PKGCONFIG ?= $(WAYLAND_PREFIX)/lib/pkgconfig
LIBFFI_PREFIX ?= $(ROOT)/build/third_party/libffi/install-$(PLATFORM)

WAYLAND_CFLAGS ?= -I$(WAYLAND_INCLUDEDIR) -I$(LIBFFI_PREFIX)/include
WAYLAND_LDFLAGS ?= -L$(WAYLAND_LIBDIR) -L$(LIBFFI_PREFIX)/lib
# Futura's libfutura provides pthread/math/rt/c implementations as part
# of the static link below; we don't pull glibc-side -lpthread / -lm /
# -lrt / -lc for the cross build.
ifeq ($(PLATFORM),arm64)
WAYLAND_LIBS ?= -lwayland-server -lwayland-client -lffi
else
WAYLAND_LIBS ?= -lwayland-server -lwayland-client -lffi -lpthread -lm -lrt
endif

# Linker flags
ifeq ($(PLATFORM),arm64)
    LDSCRIPT := ../../libfutura/userland_arm64.ld
    LDFLAGS := -nostdlib -static -T $(LDSCRIPT)
    LIBGCC := $(shell $(CC) -print-libgcc-file-name)
else
    LDSCRIPT := ../../libfutura/userland.ld
    LDFLAGS := -nostdlib -static -T $(LDSCRIPT)
    LIBGCC :=
endif

CRT0 := $(BUILD_ROOT)/lib/$(PLATFORM)/crt0.o
LIBFUTURA := $(BUILD_ROOT)/lib/$(PLATFORM)/libfutura.a

CFLAGS := -std=c2x -ffreestanding -nostdlib -fno-builtin -fno-stack-protector
CFLAGS += -Wall -Wextra -Werror -g -O2
# wayland-server-core.h uses [[deprecated]] which aarch64-elf-gcc warns
# about as an unhandled attribute on free-standing builds; demote that
# specific warning so -Werror doesn't reject the third-party header.
CFLAGS += -Wno-attributes
CFLAGS += $(ARCH_CFLAGS)
CFLAGS += -I$(ROOT)/include -I$(ROOT)/include/user
CFLAGS += -I$(OUT)/compositor -I$(ROOT)/src/user/libfutura
CFLAGS += -I$(WAYLAND_INCLUDEDIR) $(WAYLAND_CFLAGS)

CPPFLAGS += -DWAYLAND_MULTI_BUILD=1

ifeq ($(DEBUG_WAYLAND),1)
CFLAGS += -DDEBUG_WAYLAND
endif

FINAL_LDFLAGS := $(LDFLAGS) -no-pie $(WAYLAND_LDFLAGS) -Wl,--wrap=openat -Wl,--wrap=syscall -Wl,--wrap=open -Wl,--wrap=open64 -Wl,--wrap=socket -Wl,--wrap=bind -Wl,--wrap=listen -Wl,--wrap=connect -Wl,--wrap=epoll_ctl -Wl,--wrap=flock -Wl,--wrap=close -Wl,--wrap=fcntl -Wl,--wrap=unlink -Wl,--wrap=chmod -Wl,--wrap=fchmod
LDLIBS := $(WAYLAND_LIBS) $(LIBFUTURA) $(LIBGCC)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS) $(CRT0) $(LIBFUTURA) | $(BIN_DIR)
	@echo "LD $@"
	$(CC) $(FINAL_LDFLAGS) $(CRT0) $(OBJS) $(LDLIBS) -o $@

$(OBJ_DIR)/%.o: %.c $(WAYLAND_GEN_HDRS) | $(OBJ_DIR)
	@echo "CC $<"
	@$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/xdg-shell-protocol.o: $(OUT)/compositor/xdg-shell-protocol.c $(WAYLAND_GEN_HDRS) | $(OBJ_DIR)
	@echo "CC $<"
	@$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(OBJ_DIR):
	@mkdir -p $@

$(BIN_DIR):
	@mkdir -p $@

$(CRT0):
	@$(MAKE) -C ../../libfutura all

$(LIBFUTURA):
	@$(MAKE) -C ../../libfutura all

clean:
	@rm -rf $(OBJ_DIR) $(TARGET)
