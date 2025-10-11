
# UEFI Boot Stub
UEFI_STUB := $(BUILD_DIR)/uefi_boot.efi
UEFI_OBJ := $(OBJ_DIR)/uefi_boot.o

.PHONY: uefi
uefi: $(UEFI_STUB)

$(UEFI_OBJ): platform/x86_64/uefi_boot.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -ffreestanding -fno-stack-protector -fpic -fshort-wchar \
		-mno-red-zone -DEFI_FUNCTION_WRAPPER -c $< -o $@

$(UEFI_STUB): $(UEFI_OBJ) | $(BUILD_DIR)
	$(LD) -shared -Bsymbolic -nostdlib -znocombreloc \
		-T platform/x86_64/uefi_stub.lds $< -o $(BUILD_DIR)/uefi_boot.so
	objcopy -j .text -j .sdata -j .data -j .dynamic -j .dynsym -j .rel \
		-j .rela -j .reloc --target=efi-app-x86_64 $(BUILD_DIR)/uefi_boot.so $@
	@echo "UEFI stub created: $@"
