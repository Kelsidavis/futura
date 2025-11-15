/*
 * Futura OS - ARM64 Linker Script
 * Copyright (C) 2025 Futura OS Project
 *
 * Linker script for ARM64 kernel targeting QEMU virt machine.
 */

/* Entry point */
ENTRY(_start)

/* Memory layout for QEMU virt machine
 * Note: No MEMORY directive - we use AT() for physical addresses
 * and location counter (.) for virtual addresses
 */

/* Program headers for proper memory permissions */
PHDRS
{
    text PT_LOAD FLAGS(5);    /* R+E: Read + Execute */
    rodata PT_LOAD FLAGS(4);  /* R: Read only */
    data PT_LOAD FLAGS(6);    /* R+W: Read + Write */
}

/* Sections */
SECTIONS
{
    /* Virtual address in high half (TTBR1_EL1 region)
     * Physical load address remains 0x40000000
     * This enables proper kernel/user address space separation:
     * - TTBR0_EL1: User space (0x0000000000000000 - 0x0000007FFFFFFFFF)
     * - TTBR1_EL1: Kernel space (0xFFFFFF8000000000 - 0xFFFFFFFFFFFFFFFF)
     *
     * With TCR T1SZ=25, TTBR1 covers 39-bit VA starting from 0xFFFFFF8000000000
     * So kernel must be linked at or above this address.
     */
    . = 0xFFFFFF8040000000;

    /* Boot code (must be first)
     * AT() specifies physical load address (ELF metadata, not actual QEMU load addr!)
     * Virtual address is from . = 0xFFFFFF8040000000 above
     * QEMU virt ignores AT() and loads at 0x40200000 (reserves 0x40000000-0x40200000 for DTB)
     * Page tables handle the actual mapping: VA 0xFFFFFF8040000000 → PA 0x40200000
     */
    .text.boot : AT(0x40000000) {
        *(.text.boot)
    } :text

    /* Text section (code) */
    .text : ALIGN(4096) {
        *(.text)
        *(.text.*)
    } :text

    /* Read-only data */
    .rodata : ALIGN(4096) {
        *(.rodata)
        *(.rodata.*)
    } :rodata

    /* Data section (initialized data) */
    .data : ALIGN(4096) {
        *(.data)
        *(.data.*)
    } :data

    /* BSS section (uninitialized data) */
    .bss : ALIGN(4096) {
        _bss_start = .;
        *(.bss)
        *(.bss.*)
        *(COMMON)
        _bss_end = .;
    } :data

    /* Kernel end marker */
    _kernel_end = .;

    /* Kernel stack (32 KB, grows downward) */
    . = ALIGN(16);  /* Ensure 16-byte alignment for AArch64 ABI */
    _stack_start = .;
    . += 0x10000;   /* 64 KB stack (increased from 32 KB, reasonable size) */
    . = ALIGN(16);
    _stack_top = .;

    /* Discard sections */
    /DISCARD/ : {
        *(.comment)
        *(.gnu*)
        *(.note*)
        *(.eh_frame*)
    }
}
