ROOT := ../..
BUILD_DIR := $(ROOT)/build
OBJ_DIR := $(BUILD_DIR)/obj/subsystems/futura_fs
LIB_DIR := $(BUILD_DIR)/lib

CC ?= gcc
AR ?= ar

CFLAGS ?= -std=c2x -Wall -Wextra -Werror -g -O2
CFLAGS += -I$(ROOT)/include -I$(ROOT)/subsystems/futura_fs -I$(ROOT)

SRCS := logfs.c
OBJS := $(SRCS:%.c=$(OBJ_DIR)/%.o)

LIB := $(LIB_DIR)/libfutfs.a

.PHONY: all clean

all: $(LIB)

$(OBJ_DIR):
	@mkdir -p $(OBJ_DIR)

$(LIB_DIR):
	@mkdir -p $(LIB_DIR)

$(OBJ_DIR)/%.o: %.c | $(OBJ_DIR)
	@echo "CC $<"
	@$(CC) $(CFLAGS) -c $< -o $@

$(LIB): $(OBJS) | $(LIB_DIR)
	@echo "AR $@"
	@$(AR) rcs $@ $(OBJS)

clean:
	@rm -f $(OBJS) $(LIB)
