/* Minimal UEFI Hello World */
#include <stdint.h>

typedef uint64_t UINTN;
typedef uint64_t EFI_STATUS;
typedef uint16_t CHAR16;
typedef void *EFI_HANDLE;

#define EFI_SUCCESS 0

typedef struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL {
    void *Reset;
    EFI_STATUS (*OutputString)(struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This, CHAR16 *String);
    void *TestString;
    void *QueryMode;
    void *SetMode;
    void *SetAttribute;
    void *ClearScreen;
    void *SetCursorPosition;
    void *EnableCursor;
    void *Mode;
} EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL;

typedef struct {
    char Signature[8];
    uint32_t Revision;
    uint32_t HeaderSize;
    uint32_t CRC32;
    uint32_t Reserved;
    void *FirmwareVendor;
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

EFI_STATUS efi_main(EFI_HANDLE ImageHandle __attribute__((unused)), EFI_SYSTEM_TABLE *SystemTable) {
    SystemTable->ConOut->OutputString(SystemTable->ConOut, L"Hello from UEFI!\r\n");

    /* Hang so we can see the output */
    while (1) {
        __asm__ volatile("hlt");
    }

    return EFI_SUCCESS;
}
