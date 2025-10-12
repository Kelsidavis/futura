# Makefile - Host test suite
# SPDX-License-Identifier: MPL-2.0

CC := gcc

ROOT := ..
BUILD_DIR := $(ROOT)/build
OBJ_DIR := $(BUILD_DIR)/obj/tests
BIN_DIR := $(BUILD_DIR)/tests
LIB_DIR := $(BUILD_DIR)/lib

LIBFIPC_HOST := $(LIB_DIR)/libfipc_host.a

INCLUDES := -I$(ROOT)/include -I$(ROOT) -I$(ROOT)/src/user/netd -I$(ROOT)/src/user/svc_registryd
CFLAGS := -std=c2x -Wall -Wextra -Werror -g -O2 $(INCLUDES)
LDFLAGS := -pthread -no-pie

TESTS := fipc_remote_loopback fipc_remote_discovery fipc_remote_capability fipc_remote_autodiscover

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

# === FIPC remote discovery test (links registry & netd directly) ===
FIPC_DISCOVERY_SRCS := fipc_remote_discovery.c \
	$(ROOT)/src/user/netd/netd_core.c \
	$(ROOT)/src/user/svc_registryd/registry_server.c \
	$(ROOT)/src/user/svc_registryd/registry_client.c

$(BIN_DIR)/fipc_remote_discovery: $(FIPC_DISCOVERY_SRCS) $(LIBFIPC_HOST) | $(BIN_DIR)
	@echo "CC $@"
	@$(CC) $(CFLAGS) -o $@ $(FIPC_DISCOVERY_SRCS) $(LIBFIPC_HOST) $(LDFLAGS)

# === Capability enforcement test ===
FIPC_CAP_SRCS := fipc_remote_capability.c \
	$(ROOT)/src/user/netd/netd_core.c \
	$(ROOT)/src/user/svc_registryd/registry_server.c \
	$(ROOT)/src/user/svc_registryd/registry_client.c

$(BIN_DIR)/fipc_remote_capability: $(FIPC_CAP_SRCS) $(LIBFIPC_HOST) | $(BIN_DIR)
	@echo "CC $@"
	@$(CC) $(CFLAGS) -o $@ $(FIPC_CAP_SRCS) $(LIBFIPC_HOST) $(LDFLAGS)

# === Auto-discovery test ===
FIPC_AUTO_SRCS := fipc_remote_autodiscover.c \
	$(ROOT)/src/user/netd/netd_core.c \
	$(ROOT)/src/user/svc_registryd/registry_server.c \
	$(ROOT)/src/user/svc_registryd/registry_client.c

$(BIN_DIR)/fipc_remote_autodiscover: $(FIPC_AUTO_SRCS) $(LIBFIPC_HOST) | $(BIN_DIR)
	@echo "CC $@"
	@$(CC) $(CFLAGS) -o $@ $(FIPC_AUTO_SRCS) $(LIBFIPC_HOST) $(LDFLAGS)

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

clean:
	@rm -rf $(OBJ_DIR) $(BIN_DIR)
