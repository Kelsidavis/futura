ROOT := ..
INCLUDES := -I$(ROOT)/include -I$(ROOT) -I$(ROOT)/src/user/sys -I$(ROOT)/src/user/netd
CFLAGS := -std=c2x -Wall -Wextra -Werror -g -O2 $(INCLUDES)
LDFLAGS :=
LIBFIPC_HOST := $(ROOT)/build/lib/libfipc_host.a
BIN_DIR := $(ROOT)/build/tools

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
