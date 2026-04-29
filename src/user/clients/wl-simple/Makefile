# wl-simple - Wayland terminal emulator
#
# Same source builds for x86_64 and aarch64-elf Futura.

PLATFORM ?= x86_64

ROOT := ../../../..
BUILD_ROOT := $(ROOT)/build
OBJ_DIR := $(BUILD_ROOT)/obj/$(PLATFORM)/user/clients/wl-simple
BIN_DIR := $(BUILD_ROOT)/bin/$(PLATFORM)/user

# Toolchain
ifeq ($(PLATFORM),arm64)
    ifeq ($(shell uname -s),Darwin)
        CROSS_COMPILE ?= /opt/homebrew/bin/aarch64-elf-
    else
        CROSS_COMPILE ?= aarch64-linux-gnu-
    endif
    CC := $(CROSS_COMPILE)gcc
    LD := $(CROSS_COMPILE)ld
    AR := $(CROSS_COMPILE)ar
    ARCH_CFLAGS := -march=armv8-a -mtune=cortex-a53 -mno-outline-atomics
else
    CC := gcc
    LD := ld
    AR := ar
    ARCH_CFLAGS := -m64
endif

# wayland-scanner is always the host build
WAYLAND_HOST_PREFIX := $(ROOT)/build/third_party/wayland/install-host
WAYLAND_SCANNER     := $(WAYLAND_HOST_PREFIX)/bin/wayland-scanner

include $(ROOT)/mk/wayland.mk

.DEFAULT_GOAL := all

TARGET := $(BIN_DIR)/wl-simple
SRCS := main.c
OUT ?= $(BUILD_ROOT)/generated/wayland
$(eval $(call wayland_proto_client,$(ROOT)/protocols/xdg-shell.xml,client))

WAYLAND_GEN_SRCS := $(OUT)/client/xdg-shell-protocol.c
WAYLAND_GEN_HDRS := $(OUT)/client/xdg-shell-client-protocol.h

OBJS := $(SRCS:%.c=$(OBJ_DIR)/%.o)
OBJS += $(OBJ_DIR)/xdg-shell-protocol.o

# Target-arch wayland + libffi
WAYLAND_PREFIX := $(ROOT)/build/third_party/wayland/install-$(PLATFORM)
WAYLAND_INCLUDEDIR := $(WAYLAND_PREFIX)/include
WAYLAND_LIBDIR := $(WAYLAND_PREFIX)/lib
LIBFFI_PREFIX := $(ROOT)/build/third_party/libffi/install-$(PLATFORM)

WAYLAND_CFLAGS := -I$(WAYLAND_INCLUDEDIR) -I$(LIBFFI_PREFIX)/include
WAYLAND_LDFLAGS := -L$(WAYLAND_LIBDIR) -L$(LIBFFI_PREFIX)/lib
ifeq ($(PLATFORM),arm64)
WAYLAND_LIBS := -lwayland-client -lffi
else
WAYLAND_LIBS := -lwayland-client -lffi -lpthread -lm -lrt
endif

LDSCRIPT := ../../libfutura/userland_$(PLATFORM).ld
CRT0     := $(BUILD_ROOT)/lib/$(PLATFORM)/crt0.o
LIBFUTURA := $(BUILD_ROOT)/lib/$(PLATFORM)/libfutura.a

ifeq ($(PLATFORM),arm64)
LIBGCC := $(shell $(CC) -print-libgcc-file-name)
else
LIBGCC :=
endif

CFLAGS := -std=c2x -ffreestanding -nostdlib -fno-builtin -fno-stack-protector
CFLAGS += -Wall -Wextra -Werror -g -O2 -Wno-attributes
CFLAGS += $(ARCH_CFLAGS)
CFLAGS += -I$(ROOT)/include -I$(ROOT)/include/user
CFLAGS += -I$(OUT)/client $(WAYLAND_CFLAGS)

ifeq ($(DEBUG_WAYLAND),1)
CFLAGS += -DDEBUG_WAYLAND
endif

LDFLAGS := -nostdlib -static -T $(LDSCRIPT) $(WAYLAND_LDFLAGS)
LDLIBS := $(WAYLAND_LIBS) $(LIBFUTURA) $(LIBGCC)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS) | $(BIN_DIR) $(CRT0) $(LIBFUTURA)
	@echo "LD $@"
	$(CC) $(LDFLAGS) $(CRT0) $(OBJS) $(LDLIBS) -o $@

$(OBJ_DIR)/%.o: %.c $(WAYLAND_GEN_HDRS) | $(OBJ_DIR)
	@echo "CC $<"
	@$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/xdg-shell-protocol.o: $(OUT)/client/xdg-shell-protocol.c $(WAYLAND_GEN_HDRS) | $(OBJ_DIR)
	@echo "CC $<"
	@$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR):
	@mkdir -p $@

$(BIN_DIR):
	@mkdir -p $@

$(CRT0):
	@$(MAKE) -C ../../libfutura PLATFORM=$(PLATFORM) all

$(LIBFUTURA):
	@$(MAKE) -C ../../libfutura PLATFORM=$(PLATFORM) all

clean:
	@rm -rf $(OBJ_DIR) $(TARGET)
