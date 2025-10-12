# Makefile - Host test suite
# SPDX-License-Identifier: MPL-2.0

CC := gcc

ROOT := ..
BUILD_DIR := $(ROOT)/build
OBJ_DIR := $(BUILD_DIR)/obj/tests
BIN_DIR := $(BUILD_DIR)/tests
LIB_DIR := $(BUILD_DIR)/lib

LIBFIPC_HOST := $(LIB_DIR)/libfipc_host.a

INCLUDES := -I$(ROOT)/include -I$(ROOT)
CFLAGS := -std=c2x -Wall -Wextra -Werror -g -O2 $(INCLUDES)
LDFLAGS := -pthread

TESTS := fipc_remote_loopback

.PHONY: all clean $(TESTS)

all: $(addprefix $(BIN_DIR)/,$(TESTS))

$(TESTS): %: $(BIN_DIR)/%

$(LIBFIPC_HOST):
	@$(MAKE) -C $(ROOT)/host/transport

$(BIN_DIR)/fipc_remote_loopback: fipc_remote_loopback.c $(LIBFIPC_HOST) | $(BIN_DIR)
	@echo "CC $@"
	@$(CC) $(CFLAGS) -o $@ fipc_remote_loopback.c \
		$(ROOT)/src/user/netd/netd_core.c \
		$(LIBFIPC_HOST) $(LDFLAGS)

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

clean:
	@rm -rf $(OBJ_DIR) $(BIN_DIR)
