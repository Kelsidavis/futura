CROSS_COMPILE ?= $(shell command -v aarch64-elf-gcc >/dev/null 2>&1 && echo "aarch64-elf-" || echo "aarch64-linux-gnu-")
CC      := $(CROSS_COMPILE)gcc
LD      := $(CROSS_COMPILE)ld

CFLAGS  := -std=c2x -O2 -g -Wall -Wextra -Werror \
           -Wno-unterminated-string-initialization \
           -ffreestanding -nostdlib -I../../../include \
           -fno-stack-protector -fno-pic -fno-pie \
           -march=armv8-a -mno-outline-atomics

LDFLAGS := -nostdlib -static --build-id=none \
           -T ../libfutura/userland_arm64.ld

LIBFUTURA := ../../../build/lib/arm64/libfutura.a
CRT0      := ../../../build/lib/arm64/crt0.o
LIBGCC    := $(shell $(CC) -print-libgcc-file-name 2>/dev/null)

TARGET := ../../../build/bin/arm64/user/nano

all: $(TARGET)

$(TARGET): main.o
	$(LD) $(LDFLAGS) -o $@ $(CRT0) main.o $(LIBFUTURA) $(LIBGCC)

main.o: main.c
	$(CC) $(CFLAGS) -c main.c -o main.o

clean:
	rm -f main.o $(TARGET)

.PHONY: all clean
