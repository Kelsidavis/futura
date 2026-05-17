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
    /* Virtual address in high half (TTBR1_EL1 region).
     * Physical load address: 0x40200000 on QEMU virt (m1n1 may drop
     * the image elsewhere on real Apple hardware; boot.S handles the
     * relocation via g_kernel_load_pa).
     *
     * boot.S programs T0SZ = T1SZ = 16 (48-bit VA), so:
     * - TTBR0_EL1: User space  (0x0000000000000000 - 0x0000FFFFFFFFFFFF)
     * - TTBR1_EL1: Kernel space (0xFFFF000000000000 - 0xFFFFFFFFFFFFFFFF)
     *
     * The kernel link base 0xFFFFFF8040000000 sits inside that
     * kernel-half range (L0 index 511, L1 index 1).  This same value
     * also happens to be valid under the older 39-bit VA layout, so
     * the link script doesn't need to change between the two — the
     * mapping in boot.S does.
     */
    . = 0xFFFFFF8040000000;

    /* Boot code (must be first)
     * AT() specifies physical load address (ELF metadata, not actual QEMU load addr!)
     * Virtual address is from . = 0xFFFFFF8040000000 above
     * QEMU virt ignores AT() and loads at 0x40200000 (reserves 0x40000000-0x40200000 for DTB)
     * Page tables handle the actual mapping: VA 0xFFFFFF8040000000 → PA 0x40200000
     */
    .text.boot : AT(0x40200000) {
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

    /* Kernel stack (64 KB, grows downward).  Must be BEFORE
     * _kernel_end so the ARM64 Linux header's image_size field
     * (computed as _kernel_end - _start in boot.S) reserves space
     * for the stack too.  m1n1 honours image_size when placing the
     * kernel in DRAM and may put other state immediately after the
     * reserved region — if the stack lived past _kernel_end the
     * first stack push would silently corrupt whatever m1n1 dropped
     * there. */
    . = ALIGN(16);  /* Ensure 16-byte alignment for AArch64 ABI */
    _stack_start = .;
    . += 0x10000;   /* 64 KB stack (increased from 32 KB, reasonable size) */
    . = ALIGN(16);
    _stack_top = .;

    /* Kernel end marker — placed AFTER the stack so image_size
     * covers everything the kernel actually uses. */
    _kernel_end = .;

    /* Discard sections */
    /DISCARD/ : {
        *(.comment)
        *(.gnu*)
        *(.note*)
        *(.eh_frame*)
    }
}
