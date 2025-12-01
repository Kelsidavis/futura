# Makefile for forktest

PLATFORM ?= x86_64

ifeq ($(PLATFORM),arm64)
    # On macOS, use the cross-compiler from Homebrew
    ifeq ($(shell uname -s),Darwin)
        CROSS_COMPILE_ARM64 ?= /opt/homebrew/bin/aarch64-elf-
        CC = $(CROSS_COMPILE_ARM64)gcc
        LD = $(CROSS_COMPILE_ARM64)ld
        OBJCOPY = $(CROSS_COMPILE_ARM64)objcopy
    else
        CC = aarch64-elf-gcc
        LD = aarch64-elf-ld
        OBJCOPY = aarch64-elf-objcopy
    endif
    CFLAGS = -std=c23 -ffreestanding -nostdlib -fno-builtin \
             -Wall -Wextra -O2 -g \
             -I../../../include \
             -fno-stack-protector \
             -fno-pic -fno-pie \
             -mcmodel=large \
             -march=armv8-a
    LDFLAGS = -nostdlib -static --build-id=none -T ../libfutura/userland_arm64.ld
    LIBFUTURA = ../../../build/lib/arm64/libfutura.a
    CRT0 = ../../../build/lib/arm64/crt0.o
    OBJDIR = ../../../build/obj/arm64/user/forktest
    TARGET = ../../../build/bin/arm64/user/forktest
else
    CC = gcc
    LD = ld
    OBJCOPY = objcopy
    CFLAGS = -std=c23 -ffreestanding -nostdlib -nostdinc -fno-builtin \
             -Wall -Wextra -O2 -g \
             -I../../../include \
             -m64 -mno-red-zone -mcmodel=kernel -mno-sse -mno-sse2
    LDFLAGS = -nostdlib -static --build-id=none -T ../libfutura/userland_x86_64.ld
    LIBFUTURA = ../../../build/lib/libfutura.a
    CRT0 = ../../../build/lib/crt0.o
    OBJDIR = ../../../build/obj/user/forktest
    TARGET = ../../../build/bin/user/forktest
endif

LIBGCC = $(shell $(CC) $(CFLAGS) -print-libgcc-file-name)

SOURCES = main.c
OBJECTS = $(SOURCES:%.c=$(OBJDIR)/%.o)

all: $(TARGET)

$(OBJDIR):
	@mkdir -p $(OBJDIR)

$(OBJDIR)/%.o: %.c | $(OBJDIR)
	@echo "CC $<"
	@$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJECTS) $(CRT0) $(LIBFUTURA)
	@echo "LD $@"
	@$(LD) $(LDFLAGS) -o $@ $(CRT0) $(OBJECTS) $(LIBFUTURA) $(LIBGCC)

clean:
	rm -rf $(OBJDIR) $(TARGET)

.PHONY: all clean
