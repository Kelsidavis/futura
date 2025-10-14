# SPDX-License-Identifier: MPL-2.0
#
# Makefile for winstub client application

CC := gcc
LD := ld

ROOT := ../../../..
BUILD_DIR := $(ROOT)/build
OBJ_DIR := $(BUILD_DIR)/obj/user/apps/winstub
BIN_DIR := $(BUILD_DIR)/bin/user
LIB_DIR := $(BUILD_DIR)/lib

INCLUDES := -I$(ROOT)/include -I. -I../../services/winsrv

CFLAGS := -std=c2x -ffreestanding -nostdlib -fno-builtin -fno-stack-protector
CFLAGS += -Wall -Wextra -Werror
CFLAGS += -g -O2
CFLAGS += $(INCLUDES)

LDSCRIPT := ../../libfutura/userland.ld
CRT0 := $(LIB_DIR)/crt0.o
LIBFUTURA := $(LIB_DIR)/libfutura.a

TARGET := $(BIN_DIR)/winstub
OBJS := $(OBJ_DIR)/main.o $(OBJ_DIR)/win_proto.o

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS) $(CRT0) $(LIBFUTURA) | $(BIN_DIR)
	$(LD) -nostdlib -T $(LDSCRIPT) --unresolved-symbols=ignore-all -o $@ $(CRT0) $(OBJS) $(LIBFUTURA)
	@echo "Built winstub: $@"

$(OBJ_DIR)/main.o: main.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/win_proto.o: ../../services/winsrv/win_proto.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(CRT0):
	@$(MAKE) -C ../../libfutura all

$(LIBFUTURA):
	@$(MAKE) -C ../../libfutura all

$(OBJ_DIR):
	@mkdir -p $(OBJ_DIR)

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

clean:
	@rm -rf $(OBJ_DIR) $(TARGET)
