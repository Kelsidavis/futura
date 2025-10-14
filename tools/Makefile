ROOT := ..
BUILD_DIR ?= build
ABS_BUILD_DIR := $(ROOT)/$(BUILD_DIR)
INCLUDES := -I$(ROOT)/include -I$(ROOT) -I$(ROOT)/src/user/sys -I$(ROOT)/src/user/netd
CFLAGS := -std=c2x -Wall -Wextra -Werror -g -O2 $(INCLUDES)
CFLAGS += $(REPRO_CFLAGS)
LDFLAGS += $(REPRO_LDFLAGS)
LIBFIPC_HOST := $(ABS_BUILD_DIR)/lib/libfipc_host.a
BIN_DIR := $(ABS_BUILD_DIR)/tools

TOOLS := syswatch ctltool mkfutfs fsck.futfs

all: $(addprefix $(BIN_DIR)/,$(TOOLS))

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

$(LIBFIPC_HOST):
	@$(MAKE) -C $(ROOT)/host/transport

$(BIN_DIR)/syswatch: syswatch.c \
	$(ROOT)/src/user/sys/fipc_sys_sub.c \
	$(LIBFIPC_HOST) | $(BIN_DIR)
	@echo "CC $@"
	@$(CC) $(CFLAGS) -o $@ $^ $(LIBFIPC_HOST) $(LDFLAGS)

$(BIN_DIR)/ctltool: ctltool.c $(LIBFIPC_HOST) | $(BIN_DIR)
	@echo "CC $@"
	@$(CC) $(CFLAGS) -o $@ ctltool.c $(LIBFIPC_HOST) $(LDFLAGS)

$(BIN_DIR)/mkfutfs: mkfutfs.c | $(BIN_DIR)
	@echo "CC $@"
	@$(CC) $(CFLAGS) -o $@ mkfutfs.c $(LDFLAGS)

$(BIN_DIR)/fsck.futfs: fsck.futfs.c | $(BIN_DIR)
	@echo "CC $@"
	@$(CC) $(CFLAGS) -o $@ fsck.futfs.c $(LDFLAGS)

.PHONY: all
