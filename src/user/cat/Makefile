# Makefile for cat utility

TARGET = cat
OBJS = main.o

CC = gcc
CFLAGS = -std=c2x -ffreestanding -nostdlib -fno-builtin -fno-stack-protector \
         -Wall -Wextra -Werror -g -O2 -I../../../include

LD = ld
LDFLAGS = -nostdlib -T ../libfutura/userland.ld

BUILD_DIR = ../../../build
OBJ_DIR = $(BUILD_DIR)/obj/user/$(TARGET)
BIN_DIR = $(BUILD_DIR)/bin/user
LIB_DIR = $(BUILD_DIR)/lib

all: $(BIN_DIR)/$(TARGET)

$(OBJ_DIR)/%.o: %.c
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BIN_DIR)/$(TARGET): $(addprefix $(OBJ_DIR)/, $(OBJS))
	@mkdir -p $(BIN_DIR)
	$(LD) $(LDFLAGS) -o $@ $(LIB_DIR)/crt0.o $^ $(LIB_DIR)/libfutura.a
	@echo "Built $(TARGET): $@"

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)/$(TARGET)

.PHONY: all clean
