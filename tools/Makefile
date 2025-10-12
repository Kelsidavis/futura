ROOT := ..
INCLUDES := -I$(ROOT)/include -I$(ROOT) -I$(ROOT)/src/user/sys -I$(ROOT)/src/user/netd
CFLAGS := -std=c2x -Wall -Wextra -Werror -g -O2 $(INCLUDES)
LDFLAGS :=
LIBFIPC_HOST := $(ROOT)/build/lib/libfipc_host.a
BIN_DIR := $(ROOT)/build/tools

TOOLS := syswatch

all: $(addprefix $(BIN_DIR)/,$(TOOLS))

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)


$(BIN_DIR)/syswatch: syswatch.c \
	$(ROOT)/src/user/sys/fipc_sys_sub.c | $(BIN_DIR)
	@echo "CC $@"
	@$(CC) $(CFLAGS) -o $@ $^ $(LIBFIPC_HOST) $(LDFLAGS)

.PHONY: all
