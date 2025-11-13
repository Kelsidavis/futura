# Makefile for Futura Service Registry Daemon (svc_registryd)
# SPDX-License-Identifier: MPL-2.0

# Toolchain (use platform-specific compiler from main Makefile)
CC ?= gcc
LD ?= ld
AR ?= ar

# Directories
BUILD_DIR := ../../../build
OBJ_DIR := $(BUILD_DIR)/obj/user/svc_registryd
BIN_DIR := $(BUILD_DIR)/bin/user

# Includes
INCLUDES := -I../../../include

# Compiler flags
CFLAGS := -std=c99 -fPIC -Wall -Wextra -Werror
CFLAGS += -g -O2
CFLAGS += $(INCLUDES)

# Linker flags
LDFLAGS := -nostdlib -static

# Libfutura paths
CRT0 := $(BUILD_DIR)/lib/crt0.o
LIBFUTURA := $(BUILD_DIR)/lib/libfutura.a

# Source files
SRCS := registry_server.c registry_client.c
OBJS := $(SRCS:%.c=$(OBJ_DIR)/%.o)

# Target binary
TARGET := $(BIN_DIR)/svc_registryd

# Build rules
.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS) $(CRT0) $(LIBFUTURA) | $(BIN_DIR)
	$(LD) $(LDFLAGS) -o $@ $(CRT0) $(OBJS) $(LIBFUTURA)
	@echo "Built svc_registryd: $@"

$(OBJ_DIR)/%.o: %.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR):
	@mkdir -p $(OBJ_DIR)

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

clean:
	rm -rf $(OBJ_DIR) $(TARGET)

# Dependencies
$(OBJ_DIR)/registry_server.o: registry_server.c registry_common.h registry_server.h ../../../include/kernel/fut_hmac.h
$(OBJ_DIR)/registry_client.o: registry_client.c registry_common.h
