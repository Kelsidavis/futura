# Makefile for shell user program

CC := gcc
LD := ld

BUILD_DIR := ../../../build
OBJ_DIR := $(BUILD_DIR)/obj/user/shell
BIN_DIR := $(BUILD_DIR)/bin/user
LIB_DIR := $(BUILD_DIR)/lib

INCLUDES := -I../../../include

CFLAGS := -std=c2x -ffreestanding -nostdlib -fno-builtin -fno-stack-protector
CFLAGS += -Wall -Wextra -Werror
CFLAGS += -g -O2
CFLAGS += $(INCLUDES)

LDSCRIPT := ../libfutura/userland.ld
CRT0 := $(LIB_DIR)/crt0.o
LIBFUTURA := $(LIB_DIR)/libfutura.a

SRCS := main.c
OBJS := $(SRCS:%.c=$(OBJ_DIR)/%.o)

TARGET := $(BIN_DIR)/shell

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS) $(CRT0) $(LIBFUTURA) | $(BIN_DIR)
	$(LD) -nostdlib -T $(LDSCRIPT) -o $@ $(CRT0) $(OBJS) $(LIBFUTURA)
	@echo "Built shell: $@"

$(OBJ_DIR)/%.o: %.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(CRT0):
	@$(MAKE) -C ../libfutura all

$(LIBFUTURA):
	@$(MAKE) -C ../libfutura all

$(OBJ_DIR):
	@mkdir -p $(OBJ_DIR)

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

clean:
	@rm -rf $(OBJ_DIR) $(TARGET)
