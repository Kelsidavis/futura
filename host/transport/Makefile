# Makefile - Host-side FIPC transport support library
# SPDX-License-Identifier: MPL-2.0
#
# Builds libfipc_host.a which reuses the kernel FIPC core with
# freestanding stubs backed by libc so that host tools/tests can
# exercise distributed transport behaviour.

CC := gcc
AR := ar

ROOT := ../..
BUILD_DIR := $(ROOT)/build
OBJ_DIR := $(BUILD_DIR)/obj/host/transport
LIB_DIR := $(BUILD_DIR)/lib

INCLUDES := -I$(ROOT)/include -I$(ROOT)

CFLAGS := -std=c2x -Wall -Wextra -Werror -g -O2 -DFIPC_HOST_BUILD $(INCLUDES)

SOURCES := \
	$(ROOT)/kernel/ipc/fut_fipc.c \
	fipc_host_shim.c

OBJECTS := $(SOURCES:%.c=$(OBJ_DIR)/%.o)

TARGET := $(LIB_DIR)/libfipc_host.a

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJECTS) | $(LIB_DIR)
	@echo "AR $@"
	@$(AR) rcs $@ $(OBJECTS)

$(OBJ_DIR)/%.o: %.c | $(OBJ_DIR)
	@echo "CC $<"
	@$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR):
	@mkdir -p $(OBJ_DIR)

$(LIB_DIR):
	@mkdir -p $(LIB_DIR)

clean:
	@rm -rf $(OBJ_DIR) $(TARGET)
