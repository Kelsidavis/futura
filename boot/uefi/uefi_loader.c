/*
 * Futura OS - UEFI Bootloader
 * Copyright (C) 2025 Futura OS Project
 *
 * Loads and boots the Futura kernel from UEFI
 */

#include <stdint.h>
#include <stddef.h>

typedef uint64_t UINTN;
typedef uint64_t EFI_STATUS;
typedef uint16_t CHAR16;
typedef void *EFI_HANDLE;
typedef void *EFI_EVENT;

#define EFI_SUCCESS 0
#define EFI_LOAD_ERROR 0x8000000000000001ULL
#define EFI_INVALID_PARAMETER 0x8000000000000002ULL
#define EFI_NOT_FOUND 0x8000000000000005ULL

/* EFI Memory Types */
#define EfiLoaderCode 1
#define EfiLoaderData 2
#define EfiBootServicesCode 3
#define EfiBootServicesData 4
#define EfiConventionalMemory 7

/* UEFI GUID */
typedef struct {
    uint32_t Data1;
    uint16_t Data2;
    uint16_t Data3;
    uint8_t Data4[8];
} EFI_GUID;

/* Memory Descriptor */
typedef struct {
    uint32_t Type;
    uint64_t PhysicalStart;
    uint64_t VirtualStart;
    uint64_t NumberOfPages;
    uint64_t Attribute;
} EFI_MEMORY_DESCRIPTOR;

/* Simple Text Output */
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

/* Boot Services */
typedef EFI_STATUS (*EFI_ALLOCATE_PAGES)(
    uint32_t Type,
    uint32_t MemoryType,
    UINTN Pages,
    uint64_t *Memory
);

typedef EFI_STATUS (*EFI_FREE_PAGES)(
    uint64_t Memory,
    UINTN Pages
);

typedef EFI_STATUS (*EFI_GET_MEMORY_MAP)(
    UINTN *MemoryMapSize,
    EFI_MEMORY_DESCRIPTOR *MemoryMap,
    UINTN *MapKey,
    UINTN *DescriptorSize,
    uint32_t *DescriptorVersion
);

typedef EFI_STATUS (*EFI_EXIT_BOOT_SERVICES)(
    EFI_HANDLE ImageHandle,
    UINTN MapKey
);

typedef struct {
    char _pad[24]; // Skip table header

    void *RaiseTPL;
    void *RestoreTPL;

    EFI_ALLOCATE_PAGES AllocatePages;
    EFI_FREE_PAGES FreePages;
    EFI_GET_MEMORY_MAP GetMemoryMap;
    void *AllocatePool;
    void *FreePool;

    void *CreateEvent;
    void *SetTimer;
    void *WaitForEvent;
    void *SignalEvent;
    void *CloseEvent;
    void *CheckEvent;

    void *InstallProtocolInterface;
    void *ReinstallProtocolInterface;
    void *UninstallProtocolInterface;
    void *HandleProtocol;
    void *Reserved;
    void *RegisterProtocolNotify;
    void *LocateHandle;
    void *LocateDevicePath;
    void *InstallConfigurationTable;

    void *LoadImage;
    void *StartImage;
    void *Exit;
    void *UnloadImage;
    EFI_EXIT_BOOT_SERVICES ExitBootServices;

    // ... more functions we don't need
} EFI_BOOT_SERVICES;

/* System Table */
typedef struct {
    char Signature[8];
    uint32_t Revision;
    uint32_t HeaderSize;
    uint32_t CRC32;
    uint32_t Reserved;

    CHAR16 *FirmwareVendor;
    uint32_t FirmwareRevision;
    EFI_HANDLE ConsoleInHandle;
    void *ConIn;
    EFI_HANDLE ConsoleOutHandle;
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *ConOut;
    EFI_HANDLE StandardErrorHandle;
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *StdErr;
    void *RuntimeServices;
    EFI_BOOT_SERVICES *BootServices;
    UINTN NumberOfTableEntries;
    void *ConfigurationTable;
} EFI_SYSTEM_TABLE;

/* Kernel entry point */
typedef void (*kernel_entry_fn)(void);

/* Globals */
static EFI_SYSTEM_TABLE *ST;
static EFI_BOOT_SERVICES *BS;
static EFI_HANDLE ImageHandle;

/* Helper functions */
static void print(const CHAR16 *str) {
    ST->ConOut->OutputString(ST->ConOut, (CHAR16 *)str);
}

static void *memcpy_local(void *dest, const void *src, UINTN n) __attribute__((unused));
static void *memcpy_local(void *dest, const void *src, UINTN n) {
    uint8_t *d = dest;
    const uint8_t *s = src;
    while (n--) *d++ = *s++;
    return dest;
}

static void *memset_local(void *s, int c, UINTN n) __attribute__((unused));
static void *memset_local(void *s, int c, UINTN n) {
    uint8_t *p = s;
    while (n--) *p++ = (uint8_t)c;
    return s;
}

/* Load kernel at fixed address 0x100000 (1MB) */
#define KERNEL_LOAD_ADDR 0x100000
#define KERNEL_ENTRY_ADDR 0x100030

/*
 * For this minimal implementation, we'll just:
 * 1. Set up identity paging for low 4GB
 * 2. Exit boot services
 * 3. Jump to kernel at 0x100030
 *
 * The kernel is already in the ESP image at a known location.
 */

EFI_STATUS efi_main(EFI_HANDLE Handle, EFI_SYSTEM_TABLE *SystemTable) {
    ImageHandle = Handle;
    ST = SystemTable;
    BS = ST->BootServices;

    /* Clear screen */
    ST->ConOut->ClearScreen(ST->ConOut);

    print(L"Futura OS UEFI Bootloader\r\n");
    print(L"=========================\r\n\r\n");

    /*
     * In a full implementation, we would:
     * 1. Use EFI_SIMPLE_FILE_SYSTEM_PROTOCOL to open the kernel file
     * 2. Parse ELF64 headers
     * 3. Allocate pages and load segments
     * 4. Set up page tables for higher-half kernel
     *
     * For now, we assume QEMU loads the kernel at 0x100000 via -kernel option
     */

    print(L"Setting up memory...\r\n");

    /* Get memory map */
    UINTN MemoryMapSize = 0;
    EFI_MEMORY_DESCRIPTOR *MemoryMap = NULL;
    UINTN MapKey = 0;
    UINTN DescriptorSize = 0;
    uint32_t DescriptorVersion = 0;

    /* First call to get size */
    EFI_STATUS status = BS->GetMemoryMap(&MemoryMapSize, MemoryMap, &MapKey,
                                          &DescriptorSize, &DescriptorVersion);

    /* Allocate space for memory map (add extra space for new descriptors) */
    MemoryMapSize += 10 * DescriptorSize;

    uint64_t buffer;
    UINTN pages = (MemoryMapSize + 4095) / 4096;
    status = BS->AllocatePages(2, EfiLoaderData, pages, &buffer);
    if (status != EFI_SUCCESS) {
        print(L"ERROR: Cannot allocate memory map buffer\r\n");
        return status;
    }

    MemoryMap = (EFI_MEMORY_DESCRIPTOR *)buffer;

    /* Get actual memory map */
    status = BS->GetMemoryMap(&MemoryMapSize, MemoryMap, &MapKey,
                              &DescriptorSize, &DescriptorVersion);
    if (status != EFI_SUCCESS) {
        print(L"ERROR: Cannot get memory map\r\n");
        return status;
    }

    print(L"Exiting boot services...\r\n");

    /* Exit boot services */
    status = BS->ExitBootServices(ImageHandle, MapKey);
    if (status != EFI_SUCCESS) {
        /* Retry once - memory map may have changed */
        BS->GetMemoryMap(&MemoryMapSize, MemoryMap, &MapKey,
                        &DescriptorSize, &DescriptorVersion);
        status = BS->ExitBootServices(ImageHandle, MapKey);

        if (status != EFI_SUCCESS) {
            print(L"ERROR: Cannot exit boot services\r\n");
            return status;
        }
    }

    /*
     * We're now running without UEFI services
     * Jump to kernel entry point
     */

    kernel_entry_fn kernel_entry = (kernel_entry_fn)KERNEL_ENTRY_ADDR;
    kernel_entry();

    /* Should never return */
    while (1) {
        __asm__ volatile("hlt");
    }

    return EFI_SUCCESS;
}
