/* Linker script for Raspberry Pi ARM64 kernel
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Memory layout for RPi boot:
 * - RPi3: 0x00000000 - 0x40000000 (1GB RAM)
 * - RPi4: 0x00000000 - 0xC0000000 (4GB or 8GB RAM)
 * - RPi5: 0x00000000 - 0x100000000 or more (4GB or 8GB RAM)
 *
 * Bootloader places kernel at 0x80000 (RPi3) or higher (RPi4/5)
 */

MEMORY
{
    /* Kernel text section: typically loaded at 0x80000 by firmware */
    KERNEL (rwx) : ORIGIN = 0x80000, LENGTH = 32M

    /* Kernel BSS and heap grow upward */
    HEAP (rwx) : ORIGIN = 0x2080000, LENGTH = 224M
}

SECTIONS
{
    .text : {
        *(.text.start)
        *(.text .text.*)
        . = ALIGN(0x1000);
    } > KERNEL

    .rodata : {
        *(.rodata .rodata.*)
    } > KERNEL

    .data : {
        *(.data .data.*)
        . = ALIGN(0x1000);
    } > KERNEL

    .bss : {
        *(.bss .bss.*)
        . = ALIGN(0x1000);
    } > KERNEL

    /* Discard non-essential sections */
    /DISCARD/ : {
        *(.note .note.*)
        *(.comment)
    }
}
