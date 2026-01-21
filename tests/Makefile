# Makefile - Host test suite
#
# Copyright (c) 2025 Kelsi Davis
# Licensed under the MPL v2.0 — see LICENSE for details.

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
	fipc_sys_metrics_subscriber \
	fipc_sys_kernel_metrics \
	fipc_sys_futuraway_metrics \
	fipc_sys_vfs_metrics \
	fipc_kernel_flowcontrol \
	fipc_kernel_caps_quota \
	fipc_kernel_vecsend \
	fipc_timer_deadline \
	fipc_reply_pi \
	fipc_cap_revoke \
	fipc_rate_limit \
	fipc_ring_wrap \
	fipc_ring_prop \
	fipc_admin_ops \
	fipc_batch_recv \
	fipc_big_send_stage \
	futuraway_smoke \
	futuraway_m2_smoke \
	futuraway_m2_bench \
	registry_auth


.PHONY: all clean $(TESTS)

.PHONY: fipc_syswatch_smoke
fipc_syswatch_smoke: $(BIN_DIR)/fipc_syswatch_smoke

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
	$(ROOT)/src/user/svc_registryd/registry_server.c \
	$(ROOT)/src/user/svc_registryd/registry_client.c

$(BIN_DIR)/fipc_sys_metrics_subscriber: $(FIPC_SYSMET_SRCS) $(LIBFIPC_HOST) | $(BIN_DIR)
	@echo "CC $@"
	@$(CC) $(CFLAGS) -o $@ $(FIPC_SYSMET_SRCS) $(LIBFIPC_HOST) $(LDFLAGS)

# === Kernel + netd system metrics test ===
FIPC_SYSK_SRCS := fipc_sys_kernel_metrics.c \
	$(ROOT)/src/user/netd/netd_core.c \
	$(ROOT)/src/user/sys/fipc_sys_pub.c \
	$(ROOT)/src/user/svc_registryd/registry_client.c

$(BIN_DIR)/fipc_sys_kernel_metrics: $(FIPC_SYSK_SRCS) $(LIBFIPC_HOST) | $(BIN_DIR)
	@echo "CC $@"
	@$(CC) $(CFLAGS) -o $@ $(FIPC_SYSK_SRCS) $(LIBFIPC_HOST) $(LDFLAGS)

# === FuturaWay compositor metrics test ===
FIPC_FWAY_SRCS := fipc_sys_futuraway_metrics.c \
	$(ROOT)/src/user/sys/fipc_sys_pub_futuraway.c

$(BIN_DIR)/fipc_sys_futuraway_metrics: $(FIPC_FWAY_SRCS) $(LIBFIPC_HOST) | $(BIN_DIR)
	@echo "CC $@"
	@$(CC) $(CFLAGS) -o $@ $(FIPC_FWAY_SRCS) $(LIBFIPC_HOST) $(LDFLAGS)

# === VFS metrics test ===
FIPC_VFS_SRCS := fipc_sys_vfs_metrics.c \
	$(ROOT)/src/user/sys/fipc_sys_pub_vfs.c

$(BIN_DIR)/fipc_sys_vfs_metrics: $(FIPC_VFS_SRCS) $(LIBFIPC_HOST) | $(BIN_DIR)
	@echo "CC $@"
	@$(CC) $(CFLAGS) -o $@ $(FIPC_VFS_SRCS) $(LIBFIPC_HOST) $(LDFLAGS)

$(BIN_DIR)/fipc_kernel_flowcontrol: fipc_kernel_flowcontrol.c $(LIBFIPC_HOST) | $(BIN_DIR)
	@echo "CC $@"
	@$(CC) $(CFLAGS) -o $@ fipc_kernel_flowcontrol.c $(LIBFIPC_HOST) $(LDFLAGS)

$(BIN_DIR)/fipc_kernel_caps_quota: fipc_kernel_caps_quota.c $(LIBFIPC_HOST) | $(BIN_DIR)
	@echo "CC $@"
	@$(CC) $(CFLAGS) -o $@ fipc_kernel_caps_quota.c $(LIBFIPC_HOST) $(LDFLAGS)

$(BIN_DIR)/fipc_kernel_vecsend: fipc_kernel_vecsend.c $(LIBFIPC_HOST) | $(BIN_DIR)
	@echo "CC $@"
	@$(CC) $(CFLAGS) -o $@ fipc_kernel_vecsend.c $(LIBFIPC_HOST) $(LDFLAGS)

$(BIN_DIR)/fipc_timer_deadline: fipc_timer_deadline.c $(LIBFIPC_HOST) | $(BIN_DIR)
	@echo "CC $@"
	@$(CC) $(CFLAGS) -o $@ fipc_timer_deadline.c $(LIBFIPC_HOST) $(LDFLAGS)

$(BIN_DIR)/fipc_reply_pi: fipc_reply_pi.c $(LIBFIPC_HOST) | $(BIN_DIR)
	@echo "CC $@"
	@$(CC) $(CFLAGS) -o $@ fipc_reply_pi.c $(LIBFIPC_HOST) $(LDFLAGS)

$(BIN_DIR)/fipc_cap_revoke: fipc_cap_revoke.c $(LIBFIPC_HOST) | $(BIN_DIR)
	@echo "CC $@"
	@$(CC) $(CFLAGS) -o $@ fipc_cap_revoke.c $(LIBFIPC_HOST) $(LDFLAGS)

$(BIN_DIR)/fipc_rate_limit: fipc_rate_limit.c $(LIBFIPC_HOST) | $(BIN_DIR)
	@echo "CC $@"
	@$(CC) $(CFLAGS) -o $@ fipc_rate_limit.c $(LIBFIPC_HOST) $(LDFLAGS)

$(BIN_DIR)/fipc_ring_wrap: fipc_ring_wrap.c $(LIBFIPC_HOST) | $(BIN_DIR)
	@echo "CC $@"
	@$(CC) $(CFLAGS) -o $@ fipc_ring_wrap.c $(LIBFIPC_HOST) $(LDFLAGS)

$(BIN_DIR)/fipc_ring_prop: fipc_ring_prop.c ring_model.h $(LIBFIPC_HOST) | $(BIN_DIR)
	@echo "CC $@"
	@$(CC) $(CFLAGS) -o $@ fipc_ring_prop.c $(LIBFIPC_HOST) $(LDFLAGS)

$(BIN_DIR)/fipc_admin_ops: fipc_admin_ops.c $(LIBFIPC_HOST) | $(BIN_DIR)
	@echo "CC $@"
	@$(CC) $(CFLAGS) -o $@ fipc_admin_ops.c $(LIBFIPC_HOST) $(LDFLAGS)

$(BIN_DIR)/fipc_batch_recv: fipc_batch_recv.c $(LIBFIPC_HOST) | $(BIN_DIR)
	@echo "CC $@"
	@$(CC) $(CFLAGS) -o $@ fipc_batch_recv.c $(LIBFIPC_HOST) $(LDFLAGS)

$(BIN_DIR)/fipc_big_send_stage: fipc_big_send_stage.c $(LIBFIPC_HOST) | $(BIN_DIR)
	@echo "CC $@"
	@$(CC) $(CFLAGS) -o $@ fipc_big_send_stage.c $(LIBFIPC_HOST) $(LDFLAGS)

FUTURAWAY_COMMON_SRCS := \
	$(ROOT)/src/user/futurawayd/futurawayd.c \
	$(ROOT)/src/user/futurawayd/fb_host.c \
	$(ROOT)/src/user/futurawayd/fb_hw.c \
	$(ROOT)/src/user/sys/fipc_sys_pub_futuraway.c \
	$(ROOT)/src/user/svc_registryd/registry_server.c \
	$(ROOT)/src/user/svc_registryd/registry_client.c

FUTURAWAY_SMOKE_SRCS := futuraway_smoke.c \
	$(ROOT)/src/user/futurawayd/fw_demo.c \
	$(FUTURAWAY_COMMON_SRCS)

$(BIN_DIR)/futuraway_smoke: $(FUTURAWAY_SMOKE_SRCS) $(LIBFIPC_HOST) | $(BIN_DIR)
	@echo "CC $@"
	@$(CC) $(CFLAGS) -o $@ $(FUTURAWAY_SMOKE_SRCS) $(LIBFIPC_HOST) $(LDFLAGS)

FUTURAWAY_M2_SMOKE_SRCS := futuraway_m2_smoke.c \
	$(ROOT)/src/user/futurawayd/fw_demo.c \
	$(FUTURAWAY_COMMON_SRCS)

$(BIN_DIR)/futuraway_m2_smoke: $(FUTURAWAY_M2_SMOKE_SRCS) $(LIBFIPC_HOST) | $(BIN_DIR)
	@echo "CC $@"
	@$(CC) $(CFLAGS) -o $@ $(FUTURAWAY_M2_SMOKE_SRCS) $(LIBFIPC_HOST) $(LDFLAGS)

FUTURAWAY_M2_BENCH_SRCS := futuraway_m2_bench.c

$(BIN_DIR)/futuraway_m2_bench: $(FUTURAWAY_M2_BENCH_SRCS) $(LIBFIPC_HOST) | $(BIN_DIR)
	@echo "CC $@"
	@$(CC) $(CFLAGS) -o $@ $(FUTURAWAY_M2_BENCH_SRCS) $(LIBFIPC_HOST) $(LDFLAGS)

$(BIN_DIR)/registry_auth: registry_auth.c \
	$(ROOT)/src/user/svc_registryd/registry_server.c \
	$(ROOT)/src/user/svc_registryd/registry_client.c \
	$(LIBFIPC_HOST) | $(BIN_DIR)
	@echo "CC $@"
	@$(CC) $(CFLAGS) -o $@ registry_auth.c \
		$(ROOT)/src/user/svc_registryd/registry_server.c \
		$(ROOT)/src/user/svc_registryd/registry_client.c \
		$(LIBFIPC_HOST) $(LDFLAGS)

# === syswatch smoke helper ===
$(BIN_DIR)/fipc_syswatch_smoke: fipc_syswatch_smoke.c \
	$(ROOT)/src/user/sys/fipc_sys_pub.c \
	$(ROOT)/src/user/sys/fipc_sys_pub_futuraway.c \
	$(ROOT)/src/user/sys/fipc_sys_pub_vfs.c \
	$(ROOT)/src/user/netd/netd_core.c \
	$(ROOT)/src/user/svc_registryd/registry_client.c \
	$(LIBFIPC_HOST) | $(BIN_DIR)
	@echo "CC $@"
	@$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

clean:
	@rm -rf $(OBJ_DIR) $(BIN_DIR)
