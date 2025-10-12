# Makefile - Futuraway M1 compositor + demo (host builds)
# SPDX-License-Identifier: MPL-2.0

CC ?= gcc

ROOT := ../../..
BUILD_DIR := $(ROOT)/build
OBJ_DIR := $(BUILD_DIR)/obj/user/futurawayd
BIN_DIR := $(BUILD_DIR)/bin/user
LIB_DIR := $(BUILD_DIR)/lib

LIBFIPC_HOST := $(LIB_DIR)/libfipc_host.a

INCLUDES := -I$(ROOT)/include -I$(ROOT)/src/user
CFLAGS := -std=c2x -Wall -Wextra -Werror -g -O2 $(INCLUDES)
LDFLAGS := -pthread

COMMON_OBJS := \
	$(OBJ_DIR)/svc_registryd_registry_client.o

FUTURAWAYD_OBJS := \
	$(OBJ_DIR)/futurawayd.o \
	$(OBJ_DIR)/fb_host.o \
	$(OBJ_DIR)/main.o \
	$(OBJ_DIR)/sys_fipc_sys_pub_futuraway.o \
	$(COMMON_OBJS)

FW_DEMO_OBJS := \
	$(OBJ_DIR)/fw_demo.o \
	$(OBJ_DIR)/fw_demo_main.o \
	$(COMMON_OBJS)

TARGETS := $(BIN_DIR)/futurawayd $(BIN_DIR)/fw_demo

.PHONY: all clean

all: $(TARGETS)

$(BIN_DIR)/futurawayd: $(FUTURAWAYD_OBJS) $(LIBFIPC_HOST) | $(BIN_DIR)
	@echo "LD $@"
	@$(CC) $(CFLAGS) -o $@ $(FUTURAWAYD_OBJS) $(LIBFIPC_HOST) $(LDFLAGS)

$(BIN_DIR)/fw_demo: $(FW_DEMO_OBJS) $(LIBFIPC_HOST) | $(BIN_DIR)
	@echo "LD $@"
	@$(CC) $(CFLAGS) -o $@ $(FW_DEMO_OBJS) $(LIBFIPC_HOST) $(LDFLAGS)

$(OBJ_DIR)/%.o: %.c | $(OBJ_DIR)
	@echo "CC $<"
	@$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/svc_registryd_registry_client.o: ../svc_registryd/registry_client.c | $(OBJ_DIR)
	@echo "CC $<"
	@$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/sys_fipc_sys_pub_futuraway.o: ../sys/fipc_sys_pub_futuraway.c | $(OBJ_DIR)
	@echo "CC $<"
	@$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR):
	@mkdir -p $(OBJ_DIR)

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

$(LIBFIPC_HOST):
	@$(MAKE) -C $(ROOT)/host/transport

clean:
	@rm -rf $(OBJ_DIR) $(TARGETS)
