CC      := /opt/homebrew/bin/aarch64-elf-gcc
LD      := /opt/homebrew/bin/aarch64-elf-ld
OBJDUMP := /opt/homebrew/bin/aarch64-elf-objdump

CFLAGS  := -std=c23 -O2 -g -Wall -Wextra -Werror \
           -ffreestanding -nostdlib -I../../../include \
           -fno-stack-protector -fno-pic -fno-pie \
           -mcmodel=large -march=armv8-a -mno-outline-atomics

LDFLAGS := -nostdlib -static --build-id=none \
           -T ../libfutura/userland_arm64.ld

LIBFUTURA := ../../../build/lib/arm64/libfutura.a
CRT0      := ../../../build/lib/arm64/crt0.o
LIBGCC    := /opt/homebrew/Cellar/aarch64-elf-gcc/15.2.0/lib/gcc/aarch64-elf/15.2.0/libgcc.a

TARGET := ../../../build/bin/arm64/user/nano

all: $(TARGET)

$(TARGET): main.o
	$(LD) $(LDFLAGS) -o $@ $(CRT0) main.o $(LIBFUTURA) $(LIBGCC)

main.o: main.c
	$(CC) $(CFLAGS) -c main.c -o main.o

clean:
	rm -f main.o $(TARGET)

.PHONY: all clean
