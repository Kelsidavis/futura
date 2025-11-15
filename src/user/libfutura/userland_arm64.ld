/* userland_arm64.ld - Linker Script for Futura OS Userland Programs (ARM64)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

OUTPUT_FORMAT("elf64-littleaarch64")
OUTPUT_ARCH(aarch64)
ENTRY(_start)

/* Program headers for proper memory permissions */
PHDRS
{
    text PT_LOAD FLAGS(5);    /* R+E: Read + Execute */
    rodata PT_LOAD FLAGS(4);  /* R: Read only */
    data PT_LOAD FLAGS(6);    /* R+W: Read + Write */
}

SECTIONS
{
    /* User programs typically start at 0x400000 (4MB) */
    . = 0x400000;

    /* Text (code) section */
    .text : {
        *(.text._start)
        *(.text .text.*)
    } :text

    /* Read-only data */
    .rodata : ALIGN(4096) {
        *(.rodata .rodata.*)
    } :rodata

    /* Initialized data */
    .data : ALIGN(4096) {
        *(.data .data.*)
    } :data

    /* Uninitialized data (BSS) */
    .bss : ALIGN(4096) {
        *(.bss .bss.*)
        *(COMMON)
    } :data

    /* Heap starts after BSS */
    . = ALIGN(16);
    _heap_start = .;
    . += 16M;  /* Reserve 16MB for heap */
    _heap_end = .;

    /* Stack grows down from top of user address space */
    /* Set by kernel when creating process */
}
