# SPDX-License-Identifier: MPL-2.0

ROOT := ../../../..
PLATFORM ?= x86_64
BUILD_ROOT := $(ROOT)/build
OBJ_DIR := $(BUILD_ROOT)/obj/user/clients/wl-colorwheel
BIN_DIR := $(BUILD_ROOT)/bin/$(PLATFORM)/user

include $(ROOT)/mk/wayland.mk

TARGET := $(BIN_DIR)/wl-colorwheel
SRCS := main.c
OUT ?= $(BUILD_ROOT)/generated/wayland
$(eval $(call wayland_proto_client,$(ROOT)/protocols/xdg-shell.xml,client))

WAYLAND_GEN_SRCS := $(OUT)/client/xdg-shell-protocol.c
WAYLAND_GEN_HDRS := $(OUT)/client/xdg-shell-client-protocol.h

OBJS := $(SRCS:%.c=$(OBJ_DIR)/%.o)
OBJS += $(OBJ_DIR)/xdg-shell-protocol.o

WAYLAND_PREFIX ?= $(ROOT)/build/third_party/wayland/install
WAYLAND_INCLUDEDIR ?= $(WAYLAND_PREFIX)/include
WAYLAND_LIBDIR ?= $(WAYLAND_PREFIX)/lib
WAYLAND_PKGCONFIG ?= $(WAYLAND_PREFIX)/lib/pkgconfig
WAYLAND_SCANNER ?= $(WAYLAND_PREFIX)/bin/wayland-scanner

# Use platform-specific compiler from main Makefile
CC ?= gcc

# Extract Wayland flags
WAYLAND_CFLAGS ?= -I$(WAYLAND_INCLUDEDIR)
WAYLAND_LDFLAGS ?= -L$(WAYLAND_LIBDIR)
WAYLAND_LIBS ?= -lwayland-server -lwayland-client -lffi -lpthread -lm -lrt

PLATFORM ?= x86_64
LDSCRIPT := ../../libfutura/userland_$(PLATFORM).ld
CRT0 := $(BUILD_ROOT)/lib/$(PLATFORM)/crt0.o
LIBFUTURA := $(BUILD_ROOT)/lib/$(PLATFORM)/libfutura.a

CFLAGS := -std=c2x -ffreestanding -nostdlib -fno-builtin -fno-stack-protector
CFLAGS += -Wall -Wextra -Werror -g -O2
CFLAGS += -I$(ROOT)/include -I$(OUT)/client
CFLAGS += -I$(WAYLAND_INCLUDEDIR) $(WAYLAND_CFLAGS)

ifeq ($(DEBUG_WAYLAND),1)
CFLAGS += -DDEBUG_WAYLAND
endif

LDFLAGS := -nostdlib -T $(LDSCRIPT) $(WAYLAND_LDFLAGS)
LDLIBS := $(WAYLAND_LIBS) $(LIBFUTURA)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS) | $(BIN_DIR) $(CRT0) $(LIBFUTURA)
	@echo "LD $@"
	@$(CC) $(LDFLAGS) $(CRT0) $(OBJS) $(LDLIBS) -o $@

$(OBJ_DIR)/%.o: %.c $(WAYLAND_GEN_HDRS) | $(OBJ_DIR)
	@echo "CC $<"
	@$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/xdg-shell-protocol.o: $(OUT)/client/xdg-shell-protocol.c $(WAYLAND_GEN_HDRS) | $(OBJ_DIR)
	@echo "CC $<"
	@$(CC) $(CFLAGS) -c $< -o $@

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
