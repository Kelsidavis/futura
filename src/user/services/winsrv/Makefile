# SPDX-License-Identifier: MPL-2.0
#
# Makefile for winsrv user service

CC := gcc
LD := ld

ROOT := ../../../..
PLATFORM ?= x86_64
BUILD_DIR := $(ROOT)/build
OBJ_DIR := $(BUILD_DIR)/obj/user/services/winsrv
BIN_DIR := $(BUILD_DIR)/bin/user
LIB_DIR := $(BUILD_DIR)/lib/$(PLATFORM)

INCLUDES := -I$(ROOT)/include -I.. -I.

CFLAGS := -std=c2x -ffreestanding -nostdlib -fno-builtin -fno-stack-protector
CFLAGS += -Wall -Wextra -Werror
CFLAGS += -g -O2
CFLAGS += $(INCLUDES)

ifeq ($(DEBUG_WINSRV),1)
CFLAGS += -DDEBUG_WINSRV
endif

LDSCRIPT := ../../libfutura/userland.ld
CRT0 := $(LIB_DIR)/crt0.o
LIBFUTURA := $(LIB_DIR)/libfutura.a

SRCS := main.c compositor.c win_proto.c
OBJS := $(SRCS:%.c=$(OBJ_DIR)/%.o)

TARGET := $(BIN_DIR)/winsrv

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS) $(CRT0) $(LIBFUTURA) | $(BIN_DIR)
	$(LD) -nostdlib -T $(LDSCRIPT) --unresolved-symbols=ignore-all -o $@ $(CRT0) $(OBJS) $(LIBFUTURA)
	@echo "Built winsrv: $@"

$(OBJ_DIR)/%.o: %.c | $(OBJ_DIR)
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
