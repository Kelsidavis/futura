# Auto-detect cross compiler: try aarch64-elf-gcc (macOS), then aarch64-linux-gnu-gcc-14 (CI), then aarch64-linux-gnu-gcc
CROSS_COMPILE ?= $(shell \
  if command -v aarch64-elf-gcc >/dev/null 2>&1; then echo "aarch64-elf-"; \
  elif command -v aarch64-linux-gnu-gcc-14 >/dev/null 2>&1; then echo "aarch64-linux-gnu-"; \
  else echo "aarch64-linux-gnu-"; fi)
CC_SUFFIX ?= $(shell command -v $(CROSS_COMPILE)gcc >/dev/null 2>&1 && echo "" || echo "-14")
CC      := $(CROSS_COMPILE)gcc$(CC_SUFFIX)
LD      := $(CROSS_COMPILE)ld

CFLAGS  := -std=c2x -O2 -g -Wall -Wextra -Werror \
           -Wno-unterminated-string-initialization \
           -ffreestanding -nostdlib -I../../../include \
           -fno-stack-protector -fno-pic -fno-pie \
           -march=armv8-a -mno-outline-atomics -mstrict-align

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
