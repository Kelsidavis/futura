# Makefile - Host test suite
# SPDX-License-Identifier: MPL-2.0

CC := gcc

ROOT := ..
BUILD_DIR := $(ROOT)/build
OBJ_DIR := $(BUILD_DIR)/obj/tests
BIN_DIR := $(BUILD_DIR)/tests
LIB_DIR := $(BUILD_DIR)/lib

LIBFIPC_HOST := $(LIB_DIR)/libfipc_host.a

INCLUDES := -I$(ROOT)/include -I$(ROOT) -I$(ROOT)/src/user/netd -I$(ROOT)/src/user/svc_registryd -I$(ROOT)/src/user/sys
CFLAGS := -std=c2x -Wall -Wextra -Werror -g -O2 $(INCLUDES)
LDFLAGS := -pthread -no-pie

TESTS := fipc_remote_loopback \
	fipc_remote_discovery \
	fipc_remote_capability \
	fipc_remote_autodiscover \
	fipc_remote_metrics \
	fipc_remote_header_v1 \
	fipc_sys_metrics_subscriber

.PHONY: all clean $(TESTS)

all: $(addprefix $(BIN_DIR)/,$(TESTS))

$(TESTS): %: $(BIN_DIR)/%

$(LIBFIPC_HOST):
	@$(MAKE) -C $(ROOT)/host/transport

$(BIN_DIR)/fipc_remote_loopback: fipc_remote_loopback.c $(LIBFIPC_HOST) | $(BIN_DIR)
	@echo "CC $@"
	@$(CC) $(CFLAGS) -o $@ fipc_remote_loopback.c \
		$(ROOT)/src/user/netd/netd_core.c \
		$(ROOT)/src/user/sys/fipc_sys_pub.c \
		$(ROOT)/src/user/svc_registryd/registry_client.c \
		$(LIBFIPC_HOST) $(LDFLAGS)

# === FIPC remote discovery test (links registry & netd directly) ===
FIPC_DISCOVERY_SRCS := fipc_remote_discovery.c \
	$(ROOT)/src/user/netd/netd_core.c \
	$(ROOT)/src/user/sys/fipc_sys_pub.c \
	$(ROOT)/src/user/svc_registryd/registry_server.c \
	$(ROOT)/src/user/svc_registryd/registry_client.c

$(BIN_DIR)/fipc_remote_discovery: $(FIPC_DISCOVERY_SRCS) $(LIBFIPC_HOST) | $(BIN_DIR)
	@echo "CC $@"
	@$(CC) $(CFLAGS) -o $@ $(FIPC_DISCOVERY_SRCS) $(LIBFIPC_HOST) $(LDFLAGS)

# === Capability enforcement test ===
FIPC_CAP_SRCS := fipc_remote_capability.c \
	$(ROOT)/src/user/netd/netd_core.c \
	$(ROOT)/src/user/sys/fipc_sys_pub.c \
	$(ROOT)/src/user/svc_registryd/registry_server.c \
	$(ROOT)/src/user/svc_registryd/registry_client.c

$(BIN_DIR)/fipc_remote_capability: $(FIPC_CAP_SRCS) $(LIBFIPC_HOST) | $(BIN_DIR)
	@echo "CC $@"
	@$(CC) $(CFLAGS) -o $@ $(FIPC_CAP_SRCS) $(LIBFIPC_HOST) $(LDFLAGS)

# === Auto-discovery test ===
FIPC_AUTO_SRCS := fipc_remote_autodiscover.c \
	$(ROOT)/src/user/netd/netd_core.c \
	$(ROOT)/src/user/sys/fipc_sys_pub.c \
	$(ROOT)/src/user/svc_registryd/registry_server.c \
	$(ROOT)/src/user/svc_registryd/registry_client.c

$(BIN_DIR)/fipc_remote_autodiscover: $(FIPC_AUTO_SRCS) $(LIBFIPC_HOST) | $(BIN_DIR)
	@echo "CC $@"
	@$(CC) $(CFLAGS) -o $@ $(FIPC_AUTO_SRCS) $(LIBFIPC_HOST) $(LDFLAGS)

# === FIPC netd metrics test ===
FIPC_MET_SRCS := fipc_remote_metrics.c \
	$(ROOT)/src/user/netd/netd_core.c \
	$(ROOT)/src/user/sys/fipc_sys_pub.c \
	$(ROOT)/src/user/svc_registryd/registry_server.c \
	$(ROOT)/src/user/svc_registryd/registry_client.c

$(BIN_DIR)/fipc_remote_metrics: $(FIPC_MET_SRCS) $(LIBFIPC_HOST) | $(BIN_DIR)
	@echo "CC $@"
	@$(CC) $(CFLAGS) -o $@ $(FIPC_MET_SRCS) $(LIBFIPC_HOST) $(LDFLAGS)

# === FIPC header v1 test ===
FIPC_HDRV1_SRCS := fipc_remote_header_v1.c \
	$(ROOT)/src/user/netd/netd_core.c \
	$(ROOT)/src/user/sys/fipc_sys_pub.c \
	$(ROOT)/src/user/svc_registryd/registry_server.c \
	$(ROOT)/src/user/svc_registryd/registry_client.c

$(BIN_DIR)/fipc_remote_header_v1: $(FIPC_HDRV1_SRCS) $(LIBFIPC_HOST) | $(BIN_DIR)
	@echo "CC $@"
	@$(CC) $(CFLAGS) -o $@ $(FIPC_HDRV1_SRCS) $(LIBFIPC_HOST) $(LDFLAGS)

# === System metrics subscriber test ===
FIPC_SYSMET_SRCS := fipc_sys_metrics_subscriber.c \
	$(ROOT)/src/user/netd/netd_core.c \
	$(ROOT)/src/user/sys/fipc_sys_pub.c \
	$(ROOT)/src/user/sys/fipc_sys_sub.c \
	$(ROOT)/src/user/svc_registryd/registry_client.c

$(BIN_DIR)/fipc_sys_metrics_subscriber: $(FIPC_SYSMET_SRCS) $(LIBFIPC_HOST) | $(BIN_DIR)
	@echo "CC $@"
	@$(CC) $(CFLAGS) -o $@ $(FIPC_SYSMET_SRCS) $(LIBFIPC_HOST) $(LDFLAGS)

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

clean:
	@rm -rf $(OBJ_DIR) $(BIN_DIR)
