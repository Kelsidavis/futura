# SPDX-License-Identifier: MPL-2.0

ROOT := ../../../..
BUILD_ROOT := $(ROOT)/build
OBJ_DIR := $(BUILD_ROOT)/obj/user/compositor/futura-wayland
BIN_DIR := $(BUILD_ROOT)/bin/user

include $(ROOT)/mk/wayland.mk

TARGET := $(BIN_DIR)/futura-wayland
SRCS := main.c comp.c shm_backend.c xdg_shell.c output.c seat.c cursor.c ui_text.c shadow.c data_device.c syscall_wrappers.c

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

CC := gcc

# Extract Wayland flags using pkg-config
WAYLAND_CFLAGS ?= -I$(WAYLAND_INCLUDEDIR)
WAYLAND_LDFLAGS ?= -L$(WAYLAND_LIBDIR)
WAYLAND_LIBS ?= -lwayland-server -lwayland-client -lffi -lpthread -lm -lrt

LDSCRIPT := ../../libfutura/userland.ld
CRT0 := $(BUILD_ROOT)/lib/crt0.o
LIBFUTURA := $(BUILD_ROOT)/lib/libfutura.a

CFLAGS := -std=c2x -ffreestanding -nostdlib -fno-builtin -fno-stack-protector
CFLAGS += -Wall -Wextra -Werror -g -O2
CFLAGS += -I$(ROOT)/include -I$(OUT)/compositor
CFLAGS += -I$(WAYLAND_INCLUDEDIR) $(WAYLAND_CFLAGS)

CPPFLAGS += -DWAYLAND_MULTI_BUILD=1

ifeq ($(DEBUG_WAYLAND),1)
CFLAGS += -DDEBUG_WAYLAND
endif

LDFLAGS := -nostdlib -static -no-pie -T $(LDSCRIPT) $(WAYLAND_LDFLAGS) -Wl,--wrap=openat -Wl,--wrap=syscall -Wl,--wrap=open -Wl,--wrap=open64 -Wl,--wrap=socket -Wl,--wrap=bind -Wl,--wrap=listen -Wl,--wrap=connect -Wl,--wrap=flock -Wl,--wrap=close -Wl,--wrap=fcntl -Wl,--wrap=unlink -Wl,--wrap=chmod -Wl,--wrap=fchmod
LDLIBS := $(WAYLAND_LIBS) $(LIBFUTURA)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS) | $(BIN_DIR) $(CRT0) $(LIBFUTURA)
	@echo "LD $@"
	@$(CC) $(LDFLAGS) $(CRT0) $(OBJS) $(LDLIBS) -o $@

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
