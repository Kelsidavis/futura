# Makefile - Host-side FIPC transport support library
# SPDX-License-Identifier: MPL-2.0
#
# Builds libfipc_host.a which reuses the kernel FIPC core with
# freestanding stubs backed by libc so that host tools/tests can
# exercise distributed transport behaviour.

CC := gcc
AR := ar

ROOT := ../..
BUILD_DIR ?= build
ABS_BUILD_DIR := $(ROOT)/$(BUILD_DIR)
OBJ_DIR := $(ABS_BUILD_DIR)/obj/host/transport
LIB_DIR := $(ABS_BUILD_DIR)/lib

INCLUDES := -I$(ROOT)/include -I$(ROOT)

CFLAGS := -std=c2x -Wall -Wextra -Werror -g -O2 -DFIPC_HOST_BUILD $(INCLUDES)
CFLAGS += $(REPRO_CFLAGS)

KERNEL_SOURCES := \
	kernel/ipc/fut_fipc.c \
	kernel/crypto/fut_hmac.c

HOST_SOURCES := \
	fipc_host_shim.c

SOURCES := $(KERNEL_SOURCES) $(HOST_SOURCES)

OBJECTS := $(addprefix $(OBJ_DIR)/,$(SOURCES:.c=.o))

TARGET := $(LIB_DIR)/libfipc_host.a

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJECTS) | $(LIB_DIR)
	@echo "AR $@"
	@$(AR) rcs $@ $(OBJECTS)

$(OBJ_DIR)/kernel/%.o: $(ROOT)/kernel/%.c | $(OBJ_DIR)
	@echo "CC $<"
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/%.o: %.c | $(OBJ_DIR)
	@echo "CC $<"
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR):
	@mkdir -p $(OBJ_DIR)

$(LIB_DIR):
	@mkdir -p $(LIB_DIR)

clean:
	@rm -rf $(OBJ_DIR) $(TARGET)
