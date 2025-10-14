# SPDX-License-Identifier: MPL-2.0

ROOT := ../../../..
BUILD_ROOT := $(ROOT)/build
OBJ_DIR := $(BUILD_ROOT)/obj/user/compositor/futura-wayland
BIN_DIR := $(BUILD_ROOT)/bin/user
GEN_DIR := $(OBJ_DIR)/generated

include $(ROOT)/mk/wayland.mk

TARGET := $(BIN_DIR)/futura-wayland
SRCS := main.c comp.c shm_backend.c xdg_shell.c output.c
OBJS := $(SRCS:%.c=$(OBJ_DIR)/%.o)

PROTOCOL_XML := $(ROOT)/protocols/xdg-shell.xml
$(call wayland_proto,$(PROTOCOL_XML),$(GEN_DIR)/xdg-shell,xdg-shell)

PROTO_SERVER_HDR := $(GEN_DIR)/xdg-shell/xdg-shell-server-protocol.h
PROTO_CLIENT_HDR := $(GEN_DIR)/xdg-shell/xdg-shell-client-protocol.h

WAYLAND_PREFIX ?= $(ROOT)/build/third_party/wayland/install
WAYLAND_INCLUDEDIR ?= $(WAYLAND_PREFIX)/include
WAYLAND_SCANNER ?= $(WAYLAND_PREFIX)/bin/wayland-scanner

CC := gcc

LDSCRIPT := ../../libfutura/userland.ld
CRT0 := $(BUILD_ROOT)/lib/crt0.o
LIBFUTURA := $(BUILD_ROOT)/lib/libfutura.a

CFLAGS := -std=c2x -ffreestanding -nostdlib -fno-builtin -fno-stack-protector
CFLAGS += -Wall -Wextra -Werror -g -O2
CFLAGS += -I$(ROOT)/include -I$(GEN_DIR)/xdg-shell
CFLAGS += -I$(WAYLAND_INCLUDEDIR)

ifeq ($(DEBUG_WAYLAND),1)
CFLAGS += -DDEBUG_WAYLAND
endif

LDFLAGS := -nostdlib -T $(LDSCRIPT)
LDLIBS := $(LIBFUTURA) $(WAYLAND_LIBS)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS) | $(BIN_DIR) $(CRT0) $(LIBFUTURA)
	@echo "LD $@"
	@$(CC) $(LDFLAGS) $(CRT0) $(OBJS) $(LDLIBS) -o $@

$(OBJ_DIR)/%.o: %.c $(PROTO_SERVER_HDR) $(PROTO_CLIENT_HDR) | $(OBJ_DIR)
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
