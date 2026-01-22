# SPDX-License-Identifier: MPL-2.0

# Platform detection (defaults to x86_64 if not specified)
PLATFORM ?= x86_64

# Toolchain (can be overridden by parent Makefile or command line)
ifeq ($(PLATFORM),arm64)
    CROSS_COMPILE ?= /opt/homebrew/bin/aarch64-elf-
    CC := $(CROSS_COMPILE)gcc
    LD := $(CROSS_COMPILE)ld
    AR := $(CROSS_COMPILE)ar
    ARCH_CFLAGS := -march=armv8-a -mtune=cortex-a53
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

include $(ROOT)/mk/wayland.mk

TARGET := $(BIN_DIR)/futura-wayland
SRCS := main.c bootstrap.c comp.c shm_backend.c xdg_shell.c output.c seat.c cursor.c ui_text.c shadow.c data_device.c syscall_wrappers.c

OUT ?= $(BUILD_ROOT)/generated/wayland
$(eval $(call wayland_proto_server,$(ROOT)/protocols/xdg-shell.xml,compositor))
WAYLAND_GEN_SRCS := $(OUT)/compositor/xdg-shell-protocol.c
WAYLAND_GEN_HDRS := $(OUT)/compositor/xdg-shell-server-protocol.h

OBJS := $(SRCS:%.c=$(OBJ_DIR)/%.o)
OBJS += $(OBJ_DIR)/xdg-shell-protocol.o

WAYLAND_PREFIX ?= $(ROOT)/build/third_party/wayland/install
WAYLAND_INCLUDEDIR ?= $(WAYLAND_PREFIX)/include
WAYLAND_LIBDIR ?= $(WAYLAND_PREFIX)/lib
WAYLAND_PKGCONFIG ?= $(WAYLAND_PREFIX)/lib/pkgconfig
WAYLAND_SCANNER ?= $(WAYLAND_PREFIX)/bin/wayland-scanner

# Extract Wayland flags using pkg-config
WAYLAND_CFLAGS ?= -I$(WAYLAND_INCLUDEDIR)
WAYLAND_LDFLAGS ?= -L$(WAYLAND_LIBDIR)
WAYLAND_LIBS ?= -lwayland-server -lwayland-client -lffi -lpthread -lm -lrt

# Linker flags
ifeq ($(PLATFORM),arm64)
    LDSCRIPT := ../../libfutura/userland_arm64.ld
    LDFLAGS := -static -T $(LDSCRIPT)
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
CFLAGS += $(ARCH_CFLAGS)
CFLAGS += -I$(ROOT)/include -I$(OUT)/compositor -I$(ROOT)/src/user/libfutura
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
	@$(CC) $(FINAL_LDFLAGS) $(CRT0) $(OBJS) $(LDLIBS) -o $@

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
