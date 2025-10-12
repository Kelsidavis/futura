ROOT := ..
INCLUDES := -I$(ROOT)/include -I$(ROOT) -I$(ROOT)/src/user/sys -I$(ROOT)/src/user/netd -I$(ROOT)/subsystems/futura_fs
CFLAGS := -std=c2x -Wall -Wextra -Werror -g -O2 $(INCLUDES)
LDFLAGS :=
LIBFIPC_HOST := $(ROOT)/build/lib/libfipc_host.a
LIBFUTFS := $(ROOT)/build/lib/libfutfs.a
BIN_DIR := $(ROOT)/build/tools

TOOLS := syswatch ctltool mkfutfs

all: $(addprefix $(BIN_DIR)/,$(TOOLS))

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

$(LIBFIPC_HOST):
	@$(MAKE) -C $(ROOT)/host/transport

$(LIBFUTFS):
	@$(MAKE) -C $(ROOT)/subsystems/futura_fs

$(BIN_DIR)/syswatch: syswatch.c \
	$(ROOT)/src/user/sys/fipc_sys_sub.c \
	$(LIBFIPC_HOST) | $(BIN_DIR)
	@echo "CC $@"
	@$(CC) $(CFLAGS) -o $@ $^ $(LIBFIPC_HOST) $(LDFLAGS)

$(BIN_DIR)/ctltool: ctltool.c $(LIBFIPC_HOST) | $(BIN_DIR)
	@echo "CC $@"
	@$(CC) $(CFLAGS) -o $@ ctltool.c $(LIBFIPC_HOST) $(LDFLAGS)

$(BIN_DIR)/mkfutfs: mkfutfs.c $(LIBFUTFS) | $(BIN_DIR)
	@echo "CC $@"
	@$(CC) $(CFLAGS) -o $@ mkfutfs.c $(LIBFUTFS) $(LDFLAGS)

.PHONY: all
