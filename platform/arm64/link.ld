/*
 * Futura OS - ARM64 Linker Script
 * Copyright (C) 2025 Futura OS Project
 *
 * Linker script for ARM64 kernel targeting QEMU virt machine.
 */

/* Entry point */
ENTRY(_start)

/* Memory layout for QEMU virt machine */
MEMORY
{
    /* QEMU virt machine loads kernel at 0x40000000 */
    RAM : ORIGIN = 0x40000000, LENGTH = 128M
}

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
    /* Start address */
    . = 0x40000000;

    /* Boot code (must be first) */
    .text.boot : {
        *(.text.boot)
    } > RAM :text

    /* Text section (code) */
    .text : ALIGN(4096) {
        *(.text)
        *(.text.*)
    } > RAM :text

    /* Read-only data */
    .rodata : ALIGN(4096) {
        *(.rodata)
        *(.rodata.*)
    } > RAM :rodata

    /* Data section (initialized data) */
    .data : ALIGN(4096) {
        *(.data)
        *(.data.*)
    } > RAM :data

    /* BSS section (uninitialized data) */
    .bss : ALIGN(4096) {
        _bss_start = .;
        *(.bss)
        *(.bss.*)
        *(COMMON)
        _bss_end = .;
    } > RAM :data

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
