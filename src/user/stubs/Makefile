# SPDX-License-Identifier: MPL-2.0
#
# Simple user-space stubs used by kernel exec regression tests.

ROOT := ../../..
BUILD_ROOT := $(ROOT)/build
OBJ_DIR := $(BUILD_ROOT)/obj/user/stubs
BIN_DIR := $(BUILD_ROOT)/bin/user
LIB_DIR := $(BUILD_ROOT)/lib

CC := gcc
LD := ld

CFLAGS := -std=c2x -ffreestanding -nostdlib -fno-builtin -fno-stack-protector
CFLAGS += -Wall -Wextra -Werror -g -O2
CFLAGS += -I$(ROOT)/include

LDSCRIPT := ../libfutura/userland.ld
CRT0 := $(LIB_DIR)/crt0.o
LIBFUTURA := $(LIB_DIR)/libfutura.a

TARGETS := $(BIN_DIR)/init_stub $(BIN_DIR)/second

OBJS := \
	$(OBJ_DIR)/init_stub.o \
	$(OBJ_DIR)/second.o

.PHONY: all clean

all: $(TARGETS)

$(BIN_DIR)/init_stub: $(OBJ_DIR)/init_stub.o $(CRT0) $(LIBFUTURA) | $(BIN_DIR)
	@echo "LD $@"
	@$(LD) -nostdlib -T $(LDSCRIPT) --unresolved-symbols=ignore-all -o $@ $(CRT0) $(OBJ_DIR)/init_stub.o $(LIBFUTURA)

$(BIN_DIR)/second: $(OBJ_DIR)/second.o $(CRT0) $(LIBFUTURA) | $(BIN_DIR)
	@echo "LD $@"
	@$(LD) -nostdlib -T $(LDSCRIPT) --unresolved-symbols=ignore-all -o $@ $(CRT0) $(OBJ_DIR)/second.o $(LIBFUTURA)

$(OBJ_DIR)/init_stub.o: init_stub.c | $(OBJ_DIR)
	@echo "CC $<"
	@$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/second.o: second.c | $(OBJ_DIR)
	@echo "CC $<"
	@$(CC) $(CFLAGS) -c $< -o $@

$(CRT0):
	@$(MAKE) -C ../libfutura all

$(LIBFUTURA):
	@$(MAKE) -C ../libfutura all

$(OBJ_DIR):
	@mkdir -p $@

$(BIN_DIR):
	@mkdir -p $@

clean:
	@rm -rf $(OBJ_DIR)
	@rm -f $(TARGETS)
