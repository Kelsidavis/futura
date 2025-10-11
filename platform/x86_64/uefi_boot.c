/*
 * Futura OS - UEFI Bootloader Stub
 * Copyright (C) 2025 Futura OS Project
 *
 * Minimal UEFI application that loads the Futura kernel
 */

#include <stdint.h>
#include <stddef.h>

/* UEFI Types */
typedef uint64_t UINTN;
typedef uint64_t EFI_STATUS;
typedef uint16_t CHAR16;
typedef void *EFI_HANDLE;

#define EFI_SUCCESS 0
#define EFI_ERROR_MASK 0x8000000000000000ULL

/* UEFI GUID */
typedef struct {
    uint32_t Data1;
    uint16_t Data2;
    uint16_t Data3;
    uint8_t  Data4[8];
} EFI_GUID;

/* UEFI Table Header */
typedef struct {
    uint64_t Signature;
    uint32_t Revision;
    uint32_t HeaderSize;
    uint32_t CRC32;
    uint32_t Reserved;
} EFI_TABLE_HEADER;

/* UEFI Simple Text Output Protocol */
typedef struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL;

typedef EFI_STATUS (*EFI_TEXT_STRING)(
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This,
    CHAR16 *String
);

typedef EFI_STATUS (*EFI_TEXT_CLEAR_SCREEN)(
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This
);

struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL {
    void *Reset;
    EFI_TEXT_STRING OutputString;
    void *TestString;
    void *QueryMode;
    void *SetMode;
    void *SetAttribute;
    EFI_TEXT_CLEAR_SCREEN ClearScreen;
    void *SetCursorPosition;
    void *EnableCursor;
    void *Mode;
};

/* UEFI System Table */
typedef struct {
    EFI_TABLE_HEADER Hdr;
    CHAR16 *FirmwareVendor;
    uint32_t FirmwareRevision;
    EFI_HANDLE ConsoleInHandle;
    void *ConIn;
    EFI_HANDLE ConsoleOutHandle;
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *ConOut;
    EFI_HANDLE StandardErrorHandle;
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *StdErr;
    void *RuntimeServices;
    void *BootServices;
    UINTN NumberOfTableEntries;
    void *ConfigurationTable;
} EFI_SYSTEM_TABLE;

/* Kernel entry point type */
typedef void (*kernel_entry_t)(void);

/* Global System Table */
static EFI_SYSTEM_TABLE *ST;

/* UEFI Entry Point */
EFI_STATUS efi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable) {
    (void)ImageHandle;
    ST = SystemTable;

    /* Clear screen */
    ST->ConOut->ClearScreen(ST->ConOut);

    /* Print boot message */
    ST->ConOut->OutputString(ST->ConOut, L"Futura OS UEFI Bootloader\r\n");
    ST->ConOut->OutputString(ST->ConOut, L"Loading kernel...\r\n");

    /*
     * In a real implementation, we would:
     * 1. Use UEFI file system protocol to load kernel ELF
     * 2. Parse ELF headers and load segments
     * 3. Set up page tables for higher-half kernel
     * 4. Exit UEFI boot services
     * 5. Jump to kernel entry point
     *
     * For now, we'll jump directly to the kernel which is already loaded
     * by QEMU at 0x100000 (our multiboot address).
     */

    ST->ConOut->OutputString(ST->ConOut, L"Jumping to kernel at 0x100030...\r\n");

    /* Jump to kernel entry point */
    kernel_entry_t kernel_entry = (kernel_entry_t)0x100030;
    kernel_entry();

    /* Should never return */
    ST->ConOut->OutputString(ST->ConOut, L"ERROR: Kernel returned!\r\n");
    while (1) {
        __asm__ volatile("hlt");
    }

    return EFI_SUCCESS;
}
