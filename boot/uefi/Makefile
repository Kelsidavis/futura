# Futura OS UEFI Bootloader Makefile
#
# Copyright (c) 2025 Kelsi Davis
# Licensed under the MPL v2.0 — see LICENSE for details.

BUILD_DIR := ../../build
UEFI_EFI := $(BUILD_DIR)/BOOTX64.EFI
UEFI_SO := $(BUILD_DIR)/bootx64.so
UEFI_O := $(BUILD_DIR)/uefi_loader.o

CC := gcc
LD := ld
OBJCOPY := objcopy

CFLAGS := -ffreestanding -fno-stack-protector -fpic -fshort-wchar \
          -mno-red-zone -maccumulate-outgoing-args \
          -Wall -Wextra -Werror \
          -DGNU_EFI_USE_MS_ABI -D__MAKEWITH_GNUEFI \
          -I. -O2

LDFLAGS := -nostdlib -znocombreloc -T link.ld -shared -Bsymbolic

.PHONY: all clean

all: $(UEFI_EFI)

$(UEFI_O): uefi_loader.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(UEFI_SO): $(UEFI_O) link.ld | $(BUILD_DIR)
	$(LD) $(LDFLAGS) $< -o $@

$(UEFI_EFI): $(UEFI_SO) | $(BUILD_DIR)
	$(OBJCOPY) -j .text -j .sdata -j .data \
	           -j .dynamic -j .dynsym -j .rel \
	           -j .rela -j .rel.* -j .rela.* -j .reloc \
	           --target=efi-app-x86_64 --subsystem=10 $< $@
	@echo "UEFI bootloader created: $@"
	@ls -lh $@

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

clean:
	rm -f $(UEFI_O) $(UEFI_SO) $(UEFI_EFI)
