/* link.ld - Futura OS x86_64 Linker Script
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * ELF64 linker script for x86_64 higher-half kernel.
 */

OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

/* Virtual base address for higher-half kernel */
KERNEL_VIRTUAL_BASE = 0xFFFFFFFF80000000;

/* Physical load address (1MB mark for multiboot2) */
KERNEL_PHYSICAL_BASE = 0x100000;

/* Page size (4KB) */
PAGE_SIZE = 0x1000;

SECTIONS
{
    /* ============================================================
     *   Boot Section (Physical Addressing)
     * ============================================================
     * The boot code runs before paging is enabled, so it must be
     * identity-mapped at low physical addresses. We place the
     * multiboot2 header and boot code at 1MB physical.
     */
    . = KERNEL_PHYSICAL_BASE;

    .boot ALIGN(PAGE_SIZE) : AT(ADDR(.boot))
    {
        _boot_start = .;
        *(.multiboot)           /* Multiboot2 header (must be in first 8KB) */
        *(.boot.text)           /* Boot code (boot.S) */
        *(.boot.data)           /* Small boot data (GDT only) */
        . = ALIGN(PAGE_SIZE);
        _boot_end = .;
    }

    /* Boot BSS (page tables, stack) - after the 8KB boot limit */
    .boot.bss ALIGN(PAGE_SIZE) : AT(ADDR(.boot.bss))
    {
        _boot_bss_start = .;
        *(.boot.bss)            /* Page tables and boot stack */
        . = ALIGN(PAGE_SIZE);
        _boot_bss_end = .;
    }

    /* ============================================================
     *   Kernel Sections (Virtual Addressing)
     * ============================================================
     * The rest of the kernel runs in higher-half virtual address space.
     * We use AT() to specify physical load addresses while running at
     * virtual addresses.
     */
    . = KERNEL_VIRTUAL_BASE + SIZEOF(.boot) + SIZEOF(.boot.bss);

    .text ALIGN(PAGE_SIZE) : AT(ADDR(.text) - KERNEL_VIRTUAL_BASE)
    {
        _text_start = .;
        *(.text.entry)          /* Kernel entry point (after paging enabled) */
        *(.text .text.*)        /* Code sections */
        . = ALIGN(PAGE_SIZE);
        _text_end = .;
    }

    .rodata ALIGN(PAGE_SIZE) : AT(ADDR(.rodata) - KERNEL_VIRTUAL_BASE)
    {
        _rodata_start = .;
        *(.rodata .rodata.*)    /* Read-only data */
        *(.note.*)              /* ELF notes */
        . = ALIGN(PAGE_SIZE);
        _rodata_end = .;
    }

    .data ALIGN(PAGE_SIZE) : AT(ADDR(.data) - KERNEL_VIRTUAL_BASE)
    {
        _data_start = .;
        *(.data .data.*)        /* Initialized data */
        . = ALIGN(8);           /* Align for pointers */
        _data_end = .;
    }

    /* ============================================================
     *   Global Descriptor Table (GDT)
     * ============================================================ */
    .gdt ALIGN(8) : AT(ADDR(.gdt) - KERNEL_VIRTUAL_BASE)
    {
        _gdt_start = .;
        *(.gdt)
        *(.gdt.*)
        . = ALIGN(8);
        _gdt_end = .;
    }

    /* ============================================================
     *   Interrupt Descriptor Table (IDT)
     * ============================================================ */
    .idt ALIGN(8) : AT(ADDR(.idt) - KERNEL_VIRTUAL_BASE)
    {
        _idt_start = .;
        *(.idt)
        *(.idt.*)
        . = ALIGN(8);
        _idt_end = .;
    }

    /* ============================================================
     *   Task State Segment (TSS)
     * ============================================================ */
    .tss ALIGN(8) : AT(ADDR(.tss) - KERNEL_VIRTUAL_BASE)
    {
        _tss_start = .;
        *(.tss)
        *(.tss.*)
        . = ALIGN(8);
        _tss_end = .;
    }

    /* ============================================================
     *   BSS Section (Uninitialized Data)
     * ============================================================ */
    .bss ALIGN(PAGE_SIZE) : AT(ADDR(.bss) - KERNEL_VIRTUAL_BASE)
    {
        _bss_start = .;
        *(.bss .bss.*)          /* Uninitialized data */
        *(COMMON)               /* Common symbols */
        . = ALIGN(PAGE_SIZE);
        _bss_end = .;
    }

    /* ============================================================
     *   Kernel Stack
     * ============================================================ */
    .stack ALIGN(PAGE_SIZE) : AT(ADDR(.stack) - KERNEL_VIRTUAL_BASE)
    {
        _stack_bottom = .;
        . += 0x4000;            /* 16KB kernel stack */
        . = ALIGN(16);          /* Stack must be 16-byte aligned */
        _stack_top = .;
    }

    /* ============================================================
     *   Kernel End Marker
     * ============================================================ */
    . = ALIGN(PAGE_SIZE);
    _kernel_end = .;
    _kernel_physical_end = . - KERNEL_VIRTUAL_BASE;

    /* ============================================================
     *   Kernel Size Calculations
     * ============================================================ */
    _kernel_size = _kernel_end - KERNEL_VIRTUAL_BASE;
    _text_size = _text_end - _text_start;
    _rodata_size = _rodata_end - _rodata_start;
    _data_size = _data_end - _data_start;
    _bss_size = _bss_end - _bss_start;

    /* ============================================================
     *   Discard Sections
     * ============================================================
     * Remove sections we don't need in the kernel binary.
     */
    /DISCARD/ :
    {
        *(.comment)             /* Compiler comments */
        *(.eh_frame)            /* Exception handling frames */
        *(.eh_frame_hdr)        /* Exception handling header */
        *(.note.GNU-stack)      /* GNU stack note */
        *(.gcc_except_table)    /* GCC exception tables */
        *(.rel.*)               /* Relocation sections */
        *(.rela.*)              /* Relocation with addends */
    }
}

/* ============================================================
 *   Section Alignment Assertions
 * ============================================================
 * Ensure all sections are properly page-aligned for memory protection.
 */
ASSERT(_text_start % PAGE_SIZE == 0, ".text section not page-aligned")
ASSERT(_rodata_start % PAGE_SIZE == 0, ".rodata section not page-aligned")
ASSERT(_data_start % PAGE_SIZE == 0, ".data section not page-aligned")
ASSERT(_bss_start % PAGE_SIZE == 0, ".bss section not page-aligned")
ASSERT(_stack_bottom % PAGE_SIZE == 0, ".stack section not page-aligned")

/* ============================================================
 *   Stack Alignment Assertion
 * ============================================================
 * x86_64 ABI requires 16-byte stack alignment.
 */
ASSERT(_stack_top % 16 == 0, "Stack top not 16-byte aligned")

/* ============================================================
 *   Kernel Size Assertion
 * ============================================================
 * Ensure kernel fits in reasonable memory (e.g., 16MB limit).
 */
ASSERT(_kernel_size < 0x1000000, "Kernel exceeds 16MB size limit")

/* ============================================================
 *   Multiboot2 Assertion
 * ============================================================
 * Multiboot2 header must be in first 8KB of binary.
 */
ASSERT(_boot_end - _boot_start <= 0x2000, "Boot section exceeds 8KB (multiboot2 requirement)")
