/* userland_x86_64.ld - Linker Script for Futura OS Userland Programs (x86-64)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

/* Program headers with proper permissions to avoid RWX warnings */
PHDRS
{
    text PT_LOAD FLAGS(5);   /* Read + Execute (no write) */
    data PT_LOAD FLAGS(6);   /* Read + Write (no execute) */
}

SECTIONS
{
    /* User programs typically start at 0x400000 (4MB) */
    . = 0x400000;

    /* Build ID / note sections - keep in text segment to avoid PT_LOAD overlap */
    .note : {
        *(.note.gnu.build-id)
        *(.note.*)
    } :text

    /* Text (code) section - read-only executable */
    .text : {
        *(.text._start)
        *(.text .text.*)
    } :text

    /* Read-only data - also in text segment */
    .rodata : {
        *(.rodata .rodata.*)
    } :text

    /* Align to page boundary before data section */
    . = ALIGN(4096);

    /* Initialized data - read-write */
    .data : {
        *(.data .data.*)
    } :data

    /* Uninitialized data (BSS) - also in data segment */
    .bss : {
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
