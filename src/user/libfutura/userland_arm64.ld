/* userland_arm64.ld - Linker Script for Futura OS ARM64 Userland Programs
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

OUTPUT_FORMAT("elf64-littleaarch64")
OUTPUT_ARCH(aarch64)
ENTRY(_start)

SECTIONS
{
    /* User programs typically start at 0x400000 (4MB) */
    . = 0x400000;

    /* Text (code) section */
    .text : {
        *(.text._start)
        *(.text .text.*)
    }

    /* Read-only data */
    .rodata : {
        *(.rodata .rodata.*)
    }

    /* Initialized data */
    .data : {
        *(.data .data.*)
    }

    /* Uninitialized data (BSS) */
    .bss : {
        *(.bss .bss.*)
        *(COMMON)
    }

    /* Heap starts after BSS */
    . = ALIGN(16);
    _heap_start = .;
    . += 16M;  /* Reserve 16MB for heap */
    _heap_end = .;

    /* Stack grows down from top of user address space */
    /* Set by kernel when creating process */
}
