/*
 * Futura OS - ARM64 Boot Code
 * Copyright (C) 2025 Futura OS Project
 *
 * Early boot code for ARM64 architecture.
 * Configures the CPU and jumps to platform initialization.
 *
 * Linux ARM64 Image Header
 * ------------------------
 * This header makes the kernel compatible with m1n1 and other
 * ARM64 bootloaders that expect the Linux ARM64 boot image format.
 *
 * Reference: Documentation/arm64/booting.txt in Linux kernel
 */

.section .text.boot

/*
 * Linux ARM64 Image Header (64 bytes)
 *
 * Offset | Field         | Size | Description
 * -------+---------------+------+-------------------------------------
 * 0x00   | code0         | 4    | Branch instruction to _start
 * 0x04   | code1         | 4    | Branch instruction (part 2)
 * 0x08   | text_offset   | 8    | Image load offset (0 = load anywhere)
 * 0x10   | image_size    | 8    | Effective kernel image size
 * 0x18   | flags         | 8    | Kernel flags
 * 0x20   | res2          | 8    | Reserved
 * 0x28   | res3          | 8    | Reserved
 * 0x30   | res4          | 8    | Reserved
 * 0x38   | magic         | 4    | Magic: 0x644d5241 ("ARM\x64")
 * 0x3c   | res5          | 4    | Reserved
 */
.global _start
_start:
    /* 0x00: Branch to kernel entry point (skip header) */
    b       _kernel_entry           /* code0: branch to actual entry */
    .long   0                       /* code1: reserved */

    /* 0x08: text_offset - Image load offset from start of RAM */
    .quad   0                       /* 0 = can be loaded anywhere */

    /* 0x10: image_size - Effective size of kernel image */
    .quad   _kernel_end - _start    /* Total kernel size */

    /* 0x18: flags - Kernel flags */
    .quad   0                       /* bit 0: LE=0, bits 1-2: 4K pages */

    /* 0x20-0x30: Reserved fields */
    .quad   0                       /* res2 */
    .quad   0                       /* res3 */
    .quad   0                       /* res4 */

    /* 0x38: magic - ARM64 Linux magic number */
    .long   0x644d5241              /* "ARM\x64" in little-endian */

    /* 0x3c: res5 */
    .long   0

/*
 * _kernel_entry - Actual ARM64 boot entry point (after header)
 *
 * Called by bootloader with:
 *   x0 = device tree blob address (or 0)
 *   x1 = 0
 *   x2 = 0
 *   x3 = 0
 */
.global _kernel_entry
_kernel_entry:
    /* Save device tree address */
    mov     x20, x0

    /* Check current exception level */
    mrs     x0, CurrentEL
    and     x0, x0, #(3 << 2)
    cmp     x0, #(1 << 2)             /* Check if EL1 */
    beq     setup_el1

    /* If EL2 or EL3, drop to EL1 */
    cmp     x0, #(2 << 2)             /* Check if EL2 */
    beq     el2_to_el1

    cmp     x0, #(3 << 2)             /* Check if EL3 */
    beq     el3_to_el2

    /* Unknown EL, halt */
    b       .

el3_to_el2:
    /* Configure EL3 to drop to EL2 */
    mov     x0, #0x5b1                /* RES1 bits + EL2h */
    msr     scr_el3, x0

    mov     x0, #0x3c9                /* EL2h with interrupts masked */
    msr     spsr_el3, x0

    adr     x0, el2_to_el1
    msr     elr_el3, x0

    eret

el2_to_el1:
    /* Configure HCR_EL2 for EL1 execution */
    mov     x0, #(1 << 31)            /* RW=1: EL1 is AArch64 */
    msr     hcr_el2, x0

    /* Disable FP/SIMD trapping from EL1 to EL2 */
    mrs     x0, cptr_el2
    bic     x0, x0, #(1 << 10)        /* Clear TFP bit: don't trap FP/SIMD */
    msr     cptr_el2, x0

    /* Configure SPSR_EL2 for EL1h mode */
    mov     x0, #0x3c5                /* EL1h with interrupts masked */
    msr     spsr_el2, x0

    /* Set ELR_EL2 to setup_el1 */
    adr     x0, setup_el1
    msr     elr_el2, x0

    eret

setup_el1:
    /* We're now at EL1 */

    /* Set up exception vector table */
    adr     x0, exception_vectors
    msr     vbar_el1, x0

    /* Enable FP/SIMD - required for varargs functions */
    mov     x0, #(3 << 20)            /* FPEN = 11b: No trap to EL1 */
    msr     cpacr_el1, x0
    isb

    /* Configure SCTLR_EL1 */
    mrs     x0, sctlr_el1
    bic     x0, x0, #(1 << 0)         /* Disable MMU */
    bic     x0, x0, #(1 << 2)         /* Disable data cache */
    bic     x0, x0, #(1 << 12)        /* Disable instruction cache */
    bic     x0, x0, #(1 << 1)         /* Disable alignment checking */
    bic     x0, x0, #(1 << 3)         /* Disable stack alignment check for now */
    msr     sctlr_el1, x0
    isb

    /* Set up stack pointer */
    adrp    x0, _stack_top
    add     x0, x0, :lo12:_stack_top
    mov     sp, x0

    /* Clear BSS */
    adrp    x0, _bss_start
    add     x0, x0, :lo12:_bss_start
    adrp    x1, _bss_end
    add     x1, x1, :lo12:_bss_end
clear_bss:
    cmp     x0, x1
    bge     bss_cleared
    str     xzr, [x0], #8
    b       clear_bss

bss_cleared:
    /* Early debug: Write 'A' to UART before MMU (proves kernel started) */
    movz    x10, #0x0900, lsl #16     /* UART0 base = 0x09000000 */
    mov     x11, #0x41                /* ASCII 'A' */
    strb    w11, [x10]                /* Write to UART data register */

    /* ========================================
     *   MMU Initialization
     * ======================================== */

    /* Setup identity mapping for first 1GB of RAM
     * QEMU virt machine has DRAM at 0x40000000-0x80000000
     * We'll use 2MB block mappings at level 2 for simplicity
     */

    /* Get base address of boot page tables
     * NOTE: For 39-bit VA (T0SZ=25), we start at Level 1, NOT Level 0!
     * ARM64 page table walk starts at different levels based on VA size:
     *   48-bit VA: L0  (T0SZ=16)
     *   39-bit VA: L1  (T0SZ=25) ← We use this
     *   30-bit VA: L2  (T0SZ=34)
     */
    adrp    x0, boot_l1_table
    add     x0, x0, :lo12:boot_l1_table

    /* Zero out all page tables first */
    mov     x1, #0
    mov     x2, #(4096 * 3 / 8)       /* 3 tables: L1, L2_peripherals, L2_dram */
1:  str     xzr, [x0, x1, lsl #3]
    add     x1, x1, #1
    cmp     x1, x2
    blt     1b

    /* Debug: Tables zeroed */
    movz    x10, #0x0900, lsl #16
    mov     x11, #0x31                /* '1' */
    strb    w11, [x10]

    /* Setup L1 table (this is the root table for 39-bit VA)
     * L1 entry 0 (VA 0x00000000-0x3FFFFFFF): Point to L2_peripherals
     * L1 entry 1 (VA 0x40000000-0x7FFFFFFF): Point to L2_dram
     */
    adrp    x0, boot_l1_table
    add     x0, x0, :lo12:boot_l1_table

    /* L1[0] -> L2_peripherals (for VA 0x00000000-0x3FFFFFFF) */
    adrp    x1, boot_l2_table_peripherals
    add     x1, x1, :lo12:boot_l2_table_peripherals
    orr     x1, x1, #3                /* Valid table descriptor */
    str     x1, [x0, #0]

    /* L1[1] -> L2_dram (for VA 0x40000000-0x7FFFFFFF) */
    adrp    x1, boot_l2_table_dram
    add     x1, x1, :lo12:boot_l2_table_dram
    orr     x1, x1, #3                /* Valid table descriptor */
    str     x1, [x0, #8]

    /* L1[256] -> PCIe ECAM 1GB block (for VA 0x4000000000-0x403FFFFFFF) */
    /* 1GB block base PA = 0x4000000000 (maps ECAM at 0x4010000000 via offset) */
    movz    x1, #0x40, lsl #32        /* PA = 0x4000000000 (1GB block base) */
    mov     x2, #0x405                /* Valid | Block | AttrIndx=1 (device) | AF */
    orr     x2, x2, #(2 << 8)         /* SH=10: Outer Shareable */
    orr     x1, x1, x2                /* Combine PA with flags */
    str     x1, [x0, #(256 * 8)]      /* L1[256] */

    /* Debug: L1 table configured */
    movz    x10, #0x0900, lsl #16
    mov     x11, #0x32                /* '2' */
    strb    w11, [x10]

    /* Setup L2_peripherals: 256 x 2MB blocks for 0x00000000-0x20000000 (512MB peripherals)
     * Each 2MB block, device memory
     * NOTE: UART at 0x09000000, virtio-mmio at 0x0a000000, PCI MMIO at 0x10000000-0x3EFF0000
     */
    adrp    x0, boot_l2_table_peripherals
    add     x0, x0, :lo12:boot_l2_table_peripherals
    mov     x1, #0x00000000           /* Start PA */
    mov     x3, #256                  /* Map 512MB to include PCI MMIO window */
    movz    x5, #0x0020, lsl #16      /* 2MB block size = 0x200000 */
2:  mov     x2, #0x405                /* Valid (bit 0) | Block (bit 1=0) | AttrIndx=1 (bit 2) | AF (bit 10) */
    orr     x2, x2, #(2 << 8)         /* SH=10: Outer Shareable */
    orr     x2, x1, x2                /* Combine PA with flags */
    str     x2, [x0], #8              /* Store entry and advance pointer */
    add     x1, x1, x5                /* Next 2MB block */
    subs    x3, x3, #1
    bne     2b

    /* Debug: L2 peripherals configured */
    movz    x10, #0x0900, lsl #16
    mov     x11, #0x33                /* '3' */
    strb    w11, [x10]

    /* Setup L2_dram: 512 x 2MB blocks for 0x40000000-0x80000000 (1GB DRAM)
     * Each 2MB block, normal memory
     */
    adrp    x0, boot_l2_table_dram
    add     x0, x0, :lo12:boot_l2_table_dram
    movz    x1, #0x4000, lsl #16      /* Start PA = 0x40000000 */
    mov     x3, #512                  /* 512 entries = 1GB */
    movz    x5, #0x0020, lsl #16      /* 2MB block size = 0x200000 */
3:  mov     x2, #0x401                /* Valid (bit 0) | Block (bit 1=0) | AttrIndx=0 | AF (bit 10) */
    orr     x2, x2, #(3 << 8)         /* SH=11: Inner Shareable */
    orr     x2, x1, x2                /* Combine PA with flags */
    str     x2, [x0], #8              /* Store entry and advance pointer */
    add     x1, x1, x5                /* Next 2MB block */
    subs    x3, x3, #1
    bne     3b

    /* Debug: L2 DRAM configured */
    movz    x10, #0x0900, lsl #16
    mov     x11, #0x34                /* '4' */
    strb    w11, [x10]

    /* ========================================
     *   Setup Kernel Page Tables (TTBR1_EL1)
     *   Maps high VA to same physical addresses as boot tables
     * ======================================== */

    /* Zero out kernel page tables */
    adrp    x0, kernel_l1_table
    add     x0, x0, :lo12:kernel_l1_table
    mov     x1, #0
    mov     x2, #(4096 * 3 / 8)       /* 3 tables: L1, L2_peripherals, L2_dram */
4:  str     xzr, [x0, x1, lsl #3]
    add     x1, x1, #1
    cmp     x1, x2
    blt     4b

    /* Setup kernel_l1_table for high VA
     * L1[0] (VA 0xFFFF000000000000) -> kernel_l2_table_peripherals
     * L1[1] (VA 0xFFFF000040000000) -> kernel_l2_table_dram
     */
    adrp    x0, kernel_l1_table
    add     x0, x0, :lo12:kernel_l1_table

    /* kernel_l1[0] -> kernel_l2_table_peripherals */
    adrp    x1, kernel_l2_table_peripherals
    add     x1, x1, :lo12:kernel_l2_table_peripherals
    orr     x1, x1, #3                /* Valid table descriptor */
    str     x1, [x0, #0]

    /* kernel_l1[1] -> kernel_l2_table_dram */
    adrp    x1, kernel_l2_table_dram
    add     x1, x1, :lo12:kernel_l2_table_dram
    orr     x1, x1, #3                /* Valid table descriptor */
    str     x1, [x0, #8]

    /* Setup kernel_l2_table_peripherals: Same as boot, but for high VA */
    adrp    x0, kernel_l2_table_peripherals
    add     x0, x0, :lo12:kernel_l2_table_peripherals
    mov     x1, #0x00000000           /* Start PA */
    mov     x3, #256                  /* 256 x 2MB = 512MB */
    movz    x5, #0x0020, lsl #16      /* 2MB block size */
5:  mov     x2, #0x405                /* Valid | Block | AttrIndx=1 (device) | AF */
    orr     x2, x2, #(2 << 8)         /* SH=10: Outer Shareable */
    orr     x2, x1, x2                /* Combine PA with flags */
    str     x2, [x0], #8              /* Store and advance */
    add     x1, x1, x5                /* Next 2MB block */
    subs    x3, x3, #1
    bne     5b

    /* Setup kernel_l2_table_dram: Same as boot, but for high VA */
    adrp    x0, kernel_l2_table_dram
    add     x0, x0, :lo12:kernel_l2_table_dram
    movz    x1, #0x4000, lsl #16      /* Start PA = 0x40000000 */
    mov     x3, #512                  /* 512 x 2MB = 1GB */
    movz    x5, #0x0020, lsl #16      /* 2MB block size */
6:  mov     x2, #0x401                /* Valid | Block | AttrIndx=0 (normal) | AF */
    orr     x2, x2, #(3 << 8)         /* SH=11: Inner Shareable */
    orr     x2, x1, x2                /* Combine PA with flags */
    str     x2, [x0], #8              /* Store and advance */
    add     x1, x1, x5                /* Next 2MB block */
    subs    x3, x3, #1
    bne     6b

    /* Debug: Kernel tables configured */
    movz    x10, #0x0900, lsl #16
    mov     x11, #0x4B                /* 'K' for Kernel */
    strb    w11, [x10]

    /* Configure MAIR_EL1 (Memory Attribute Indirection Register)
     * Attr0 = 0xFF (Normal memory, Inner/Outer Write-Back Cacheable)
     * Attr1 = 0x00 (Device-nGnRnE - for UART, GIC, etc.)
     * Attr5 = 0xFF (Normal memory - used by user stack pages)
     * Combined value: 0xFF000000_000000FF
     */
    movz    x0, #0x00FF               /* Attr0=0xFF (normal), Attr1=0x00 (device) */
    movk    x0, #0xFF00, lsl #32      /* Attr5=0xFF (normal for user pages) */
    msr     mair_el1, x0

    /* Debug: MAIR configured */
    movz    x10, #0x0900, lsl #16
    mov     x11, #0x35                /* '5' */
    strb    w11, [x10]

    /* Configure TCR_EL1 (Translation Control Register)
     * T0SZ = 25 (bits 5:0): VA size = 64 - 25 = 39 bits
     * T1SZ = 25 (bits 21:16): VA size = 39 bits
     * TG0 = 00 (bits 15:14): 4KB granule for TTBR0
     * TG1 = 10 (bits 31:30): 4KB granule for TTBR1 (different encoding!)
     * SH0 = 11 (bits 13:12): Inner shareable for TTBR0
     * SH1 = 11 (bits 29:28): Inner shareable for TTBR1
     * ORGN0/IRGN0 = 01 (bits 11:10, 9:8): Normal, WB RA WA
     * ORGN1/IRGN1 = 01 (bits 27:26, 25:24): Normal, WB RA WA
     * IPS = 001 (bits 34:32): 36-bit PA space
     */
    /* Build TCR_EL1 value carefully to ensure TG0=00 for 4KB granule */
    /* Start with T0SZ=25, IRGN0=01, ORGN0=01, SH0=11 */
    movz    x0, #0x3519               /* Bits [15:0]: T0SZ=25, IRGN0=01, ORGN0=01, SH0=11, TG0=00 */
    /* Set T1SZ=25, IRGN1=01, ORGN1=01, SH1=11, TG1=10 */
    movk    x0, #0xB519, lsl #16     /* Bits [31:16]: T1SZ=25, IRGN1=01, ORGN1=01, SH1=11, TG1=10 */
    /* Set IPS=010 (40-bit PA) */
    movk    x0, #2, lsl #32           /* Bits [34:32]: IPS=010 */
    msr     tcr_el1, x0

    /* Debug: TCR configured */
    movz    x10, #0x0900, lsl #16
    mov     x11, #0x36                /* '6' */
    strb    w11, [x10]

    /* Set TTBR0_EL1 to boot table (identity mapping for early boot) */
    adrp    x0, boot_l1_table
    add     x0, x0, :lo12:boot_l1_table
    msr     ttbr0_el1, x0

    /* Set TTBR1_EL1 to kernel table (high VA mapping for kernel) */
    adrp    x0, kernel_l1_table
    add     x0, x0, :lo12:kernel_l1_table
    msr     ttbr1_el1, x0

    /* Debug: TTBR configured */
    movz    x10, #0x0900, lsl #16
    mov     x11, #0x37                /* '7' */
    strb    w11, [x10]

    /* Verify L2_dram[0] descriptor (debug) */
    adrp    x0, boot_l2_table_dram
    add     x0, x0, :lo12:boot_l2_table_dram
    ldr     x1, [x0, #0]              /* Load first L2 entry */
    /* Expected: 0x40000701 - we'll continue regardless */

    /* Invalidate TLBs and caches before enabling MMU */
    tlbi    vmalle1                   /* Invalidate all TLB entries for EL1 */
    ic      iallu                     /* Invalidate all instruction caches to PoU */
    dsb     sy                        /* Ensure all invalidations complete */
    isb                               /* Synchronize instruction stream */

    /* Debug: About to enable MMU */
    movz    x10, #0x0900, lsl #16
    mov     x11, #0x38                /* '8' */
    strb    w11, [x10]

    /* Enable MMU (2025-11-05: Fixed page table level bug!)
     *
     * Previous attempts failed because we used L0 as root table,
     * but for 39-bit VA (T0SZ=25), ARM64 starts at Level 1!
     *
     * Corrected structure:
     * - TTBR0/TTBR1 → L1 table (root for 39-bit VA)
     * - L1[0] → L2_peripherals (80 x 2MB = 160MB for UART/GIC)
     * - L1[1] → L2_dram (512 x 2MB = 1GB for kernel)
     */
    mrs     x0, sctlr_el1
    orr     x0, x0, #(1 << 0)    /* M: Enable MMU */
    orr     x0, x0, #(1 << 2)    /* C: Enable data cache */
    orr     x0, x0, #(1 << 12)   /* I: Enable instruction cache */
    msr     sctlr_el1, x0
    isb

    /* Debug: Write 'B' to UART after MMU enable (proves MMU worked!) */
    movz    x10, #0x0900, lsl #16     /* UART0 base = 0x09000000 */
    mov     x11, #0x42                /* ASCII 'B' */
    strb    w11, [x10]                /* Write to UART data register */

    /* Jump to high VA kernel address
     * Currently executing at low VA (identity mapped via TTBR0)
     * Need to switch to high VA (mapped via TTBR1)
     *
     * Strategy: Get PC-relative address of target, then set high VA bits
     * We're linked at 0xFFFFFF8040000000 but executing at 0x40000000
     * Need to set the high bits to create 0xFFFFFF8000000000
     */
    adr     x0, .Lhigh_va_entry       /* Get low VA address (PC-relative, ~0x400xxx) */
    movz    x1, #0xFFFF, lsl #48      /* Load high VA prefix (0xFFFF000000000000) */
    movk    x1, #0xFF80, lsl #32      /* Add middle bits (0xFFFFFF8000000000) */
    orr     x0, x0, x1                /* Set high VA bits: x0 |= 0xFFFFFF8000000000 */
    br      x0                        /* Jump to high VA */

.Lhigh_va_entry:
    /* Now executing at high VA! All addresses from here on are high VA */

    /* Debug: Write 'H' to UART (now at high VA)
     * UART at PA 0x09000000 is mapped at VA 0xFFFFFF8009000000
     * (kernel_l1[0] -> peripherals at 0xFFFFFF8000000000+)
     */
    movz    x10, #0xFFFF, lsl #48     /* High VA base (0xFFFF000000000000) */
    movk    x10, #0xFF80, lsl #32     /* Add kernel offset (0xFFFFFF8000000000) */
    movk    x10, #0x0900, lsl #16     /* Add UART offset (0x09000000) */
    mov     x11, #0x48                /* ASCII 'H' for High VA */
    strb    w11, [x10]

    /* Update VBAR_EL1 to high VA exception vectors
     * The exception vector table is now at high VA, so update VBAR
     */
    adrp    x0, exception_vectors
    add     x0, x0, :lo12:exception_vectors
    msr     vbar_el1, x0
    isb

    /* Debug: VBAR updated */
    movz    x10, #0xFFFF, lsl #48
    movk    x10, #0xFF80, lsl #32
    movk    x10, #0x0900, lsl #16
    mov     x11, #0x56                /* 'V' for VBAR */
    strb    w11, [x10]

    /* Clear TTBR0_EL1 now that we're running at high VA
     * User processes will set their own TTBR0 page tables later
     */
    mov     x0, #0
    msr     ttbr0_el1, x0
    isb

    /* Debug: TTBR0 cleared */
    movz    x10, #0xFFFF, lsl #48
    movk    x10, #0xFF80, lsl #32
    movk    x10, #0x0900, lsl #16
    mov     x11, #0x54                /* 'T' for TTBR0 cleared */
    strb    w11, [x10]

    /* Restore device tree address and call platform init */
    mov     x0, #0                    /* boot_magic = 0 */
    mov     x1, x20                   /* boot_info = device tree address */

    /* Debug: Write 'C' before calling platform_init */
    movz    x10, #0xFFFF, lsl #48     /* High VA base */
    movk    x10, #0xFF80, lsl #32     /* Add kernel offset */
    movk    x10, #0x0900, lsl #16     /* Add UART offset */
    mov     x11, #0x43                /* ASCII 'C' */
    strb    w11, [x10]

    bl      fut_platform_init

    /* Should never return */
    b       .

/*
 * Exception vector table
 * ARM64 has 16 exception vectors (4 types × 4 exception levels)
 */
.align 11
.global exception_vectors
exception_vectors:
    /* Current EL with SP0 */
    .align 7
    b       sync_sp0_handler
    .align 7
    b       irq_sp0_handler
    .align 7
    b       fiq_sp0_handler
    .align 7
    b       serror_sp0_handler

    /* Current EL with SPx */
    .align 7
    b       sync_spx_handler
    .align 7
    b       irq_spx_handler
    .align 7
    b       fiq_spx_handler
    .align 7
    b       serror_spx_handler

    /* Lower EL using AArch64 */
    .align 7
    b       sync_aarch64_handler
    .align 7
    b       irq_aarch64_handler
    .align 7
    b       fiq_aarch64_handler
    .align 7
    b       serror_aarch64_handler

    /* Lower EL using AArch32 */
    .align 7
    b       sync_aarch32_handler
    .align 7
    b       irq_aarch32_handler
    .align 7
    b       fiq_aarch32_handler
    .align 7
    b       serror_aarch32_handler

/*
 * Exception handlers
 */

/* Synchronous exception from current EL with SP0 */
sync_sp0_handler:
    b       sync_exception_entry

/* IRQ from current EL with SP0 */
irq_sp0_handler:
    b       irq_handler_entry

/* FIQ from current EL with SP0 */
fiq_sp0_handler:
    b       generic_exception_handler

/* SError from current EL with SP0 */
serror_sp0_handler:
    b       generic_exception_handler

/* Synchronous exception from current EL with SPx */
sync_spx_handler:
    b       sync_exception_entry

/* IRQ from current EL with SPx */
irq_spx_handler:
    b       irq_handler_entry

/* FIQ from current EL with SPx */
fiq_spx_handler:
    b       generic_exception_handler

/* SError from current EL with SPx */
serror_spx_handler:
    b       generic_exception_handler

/* Synchronous exception from lower EL (AArch64) */
sync_aarch64_handler:
    b       sync_exception_entry

/* IRQ from lower EL (AArch64) */
irq_aarch64_handler:
    b       irq_handler_entry

/* FIQ from lower EL (AArch64) */
fiq_aarch64_handler:
    b       generic_exception_handler

/* SError from lower EL (AArch64) */
serror_aarch64_handler:
    b       generic_exception_handler

/* Synchronous exception from lower EL (AArch32) */
sync_aarch32_handler:
    b       sync_exception_entry

/* IRQ from lower EL (AArch32) */
irq_aarch32_handler:
    b       irq_handler_entry

/* FIQ from lower EL (AArch32) */
fiq_aarch32_handler:
    b       generic_exception_handler

/* SError from lower EL (AArch32) */
serror_aarch32_handler:
    b       generic_exception_handler

/*
 * Generic exception handler
 */
.align 4
generic_exception_handler:
    /* Save all registers for debugging */
    stp     x0, x1, [sp, #-16]!
    stp     x2, x3, [sp, #-16]!
    stp     x4, x5, [sp, #-16]!
    stp     x6, x7, [sp, #-16]!
    stp     x8, x9, [sp, #-16]!
    stp     x10, x11, [sp, #-16]!
    stp     x12, x13, [sp, #-16]!
    stp     x14, x15, [sp, #-16]!
    stp     x16, x17, [sp, #-16]!
    stp     x18, x19, [sp, #-16]!
    stp     x20, x21, [sp, #-16]!
    stp     x22, x23, [sp, #-16]!
    stp     x24, x25, [sp, #-16]!
    stp     x26, x27, [sp, #-16]!
    stp     x28, x29, [sp, #-16]!
    stp     x30, xzr, [sp, #-16]!

    /* Print exception message */
    adr     x0, exception_msg
    bl      fut_serial_puts

    /* Print ESR_EL1 (Exception Syndrome Register) */
    adr     x0, esr_msg
    bl      fut_serial_puts
    mrs     x0, esr_el1
    bl      print_hex64

    /* Print FAR_EL1 (Fault Address Register) */
    adr     x0, far_msg
    bl      fut_serial_puts
    mrs     x0, far_el1
    bl      print_hex64

    /* Print ELR_EL1 (Exception Link Register - return address) */
    adr     x0, elr_msg
    bl      fut_serial_puts
    mrs     x0, elr_el1
    bl      print_hex64

    /* Print SP */
    adr     x0, sp_msg
    bl      fut_serial_puts
    mov     x0, sp
    bl      print_hex64

    /* Halt */
1:  wfi
    b       1b

exception_msg:
    .asciz  "\n[EXCEPTION] ARM64 exception occurred!\n"
esr_msg:
    .asciz  "ESR_EL1: 0x"
far_msg:
    .asciz  "\nFAR_EL1: 0x"
elr_msg:
    .asciz  "\nELR_EL1: 0x"
sp_msg:
    .asciz  "\nSP:      0x"

/* Helper function to print 64-bit hex value */
.align 4
print_hex64:
    stp     x29, x30, [sp, #-16]!
    stp     x19, x20, [sp, #-16]!

    mov     x19, x0               /* Save value */
    mov     x20, #60              /* Start with highest nibble (15 * 4 = 60) */

1:  /* Print each nibble */
    lsr     x0, x19, x20          /* Shift right by bit position */
    and     x0, x0, #0xf          /* Mask to get 4 bits */

    /* Convert to hex character */
    cmp     x0, #10
    blt     2f
    add     x0, x0, #('a' - 10)
    b       3f
2:  add     x0, x0, #'0'
3:
    bl      fut_serial_putc

    /* Next nibble */
    subs    x20, x20, #4
    bge     1b

    /* Print newline */
    mov     x0, #'\n'
    bl      fut_serial_putc

    ldp     x19, x20, [sp], #16
    ldp     x29, x30, [sp], #16
    ret

/*
 * IRQ handler entry point
 */
.align 4
irq_handler_entry:
    /* Save all registers */
    stp     x0, x1, [sp, #-16]!
    stp     x2, x3, [sp, #-16]!
    stp     x4, x5, [sp, #-16]!
    stp     x6, x7, [sp, #-16]!
    stp     x8, x9, [sp, #-16]!
    stp     x10, x11, [sp, #-16]!
    stp     x12, x13, [sp, #-16]!
    stp     x14, x15, [sp, #-16]!
    stp     x16, x17, [sp, #-16]!
    stp     x18, x19, [sp, #-16]!
    stp     x20, x21, [sp, #-16]!
    stp     x22, x23, [sp, #-16]!
    stp     x24, x25, [sp, #-16]!
    stp     x26, x27, [sp, #-16]!
    stp     x28, x29, [sp, #-16]!
    stp     x30, xzr, [sp, #-16]!

    /* Call IRQ handler */
    bl      fut_irq_handler

    /* Restore all registers */
    ldp     x30, xzr, [sp], #16
    ldp     x28, x29, [sp], #16
    ldp     x26, x27, [sp], #16
    ldp     x24, x25, [sp], #16
    ldp     x22, x23, [sp], #16
    ldp     x20, x21, [sp], #16
    ldp     x18, x19, [sp], #16
    ldp     x16, x17, [sp], #16
    ldp     x14, x15, [sp], #16
    ldp     x12, x13, [sp], #16
    ldp     x10, x11, [sp], #16
    ldp     x8, x9, [sp], #16
    ldp     x6, x7, [sp], #16
    ldp     x4, x5, [sp], #16
    ldp     x2, x3, [sp], #16
    ldp     x0, x1, [sp], #16

    eret

/*
 * IRQ handler (C function)
 *
 * Simplified handler that only dispatches timer IRQs properly.
 * Other IRQs (like UART) are handled via registered handlers in arm64_irq.c,
 * but require proper interrupt frame setup which is currently simplified.
 *
 * Handler Dispatch Implementation Plan:
 *
 * Phase 1 (Current): Timer-only dispatch
 * - Timer IRQ (30) routed to dedicated handler with full frame context
 * - All other IRQs: acknowledge and return (no dispatch framework)
 * - Rationale: Timer is critical for scheduler; other IRQs not yet needed
 * - Status: Functional but limited
 *
 * Phase 2 (Planned): Registered handler framework
 * - Build IRQ dispatch table indexed by IRQ number
 * - For each IRQ: save full context frame, dispatch to registered handler
 * - Handlers registered via arm64_irq_register_handler(irq, fn)
 * - Frame structure passed to handler function (like exception handlers)
 * - EOI sent after handler returns (unless handler defers it)
 * - Rationale: Enables UART, virtio, PCI, and device driver interrupts
 * - Requirements: Handler table allocation, handler function signature
 *
 * Phase 3 (Future): Context-preserving dispatch with return values
 * - Handlers can modify interrupt frame (like signal delivery)
 * - Handler return value indicates: handled, deferred, error
 * - Integrate with scheduler for handler preemption
 * - Nested interrupt support with interrupt stack
 * - Rationale: Complex interrupt handling scenarios
 * - Requirements: Handler priority levels, nested interrupt stacks
 *
 * Current Limitations:
 * - No IRQ handler dispatch for devices (UART, VirtIO, etc.)
 * - Each device must work around this or be timer-polled
 * - No mechanism to register device-specific handlers
 * - Devices that need interrupts are not yet supported on ARM64
 *
 * Handler Frame Structure (to be used in Phase 2):
 * - Identical to exception frame from arm64_exception_entry.S
 * - Registers X0-X30 preserved for handler inspection
 * - X0-X7 available for handler arguments/return values
 * - Handler can modify PC (similar to signal delivery)
 * - SP, PSTATE preserved for correct return-to-interrupted context
 *
 * UART Interrupt Example (Phase 2):
 * 1. UART IRQ asserted (IRQ 33 on virt machine)
 * 2. CPU vectors to IRQ handler, saves context
 * 3. fut_irq_handler reads GIC, gets IRQ 33
 * 4. Dispatch table[33] = uart_irq_handler
 * 5. Call uart_irq_handler(frame) with full context
 * 6. Handler processes UART FIFO, signals reading task
 * 7. Return and send EOI to GIC
 * 8. Check reschedule flag (like timer does)
 * 9. ERET returns to interrupted context
 *
 * VirtIO Block/Net Example (Phase 2):
 * 1. Device completion interrupt asserted
 * 2. fut_irq_handler routes to registered virtio_handler
 * 3. Handler processes completion descriptors
 * 4. Wakes up blocked I/O waiters
 * 5. EOI sent, context restored
 * 6. I/O tasks scheduled if needed
 *
 * Design Decision (Current):
 * - Keep Phase 1 simple: only timer works
 * - No partial device interrupt support
 * - Better to have working timer than broken device interrupts
 * - Phase 2 requires design decisions: priority levels, handler contexts
 * - Wait for real device usage to drive requirements
 */
.type fut_irq_handler, @function
fut_irq_handler:
    /* Get interrupt number from GIC */
    bl      fut_irq_acknowledge
    mov     x19, x0                   /* Save IRQ number */

    /* Check if timer interrupt (IRQ 30) */
    cmp     x19, #30
    beq     handle_timer_irq

    /* For non-timer IRQs, just acknowledge and return */
    /* Phase 1: No registered handler dispatch framework yet (see above) */
    mov     x0, x19
    bl      fut_irq_send_eoi
    ret

handle_timer_irq:
    /* Call timer handler */
    bl      fut_timer_irq_handler

    /* Send EOI */
    mov     x0, #30
    bl      fut_irq_send_eoi

    /* Check if reschedule needed */
    bl      fut_reschedule_pending
    cbz     x0, no_reschedule

    /* Clear reschedule flag */
    bl      fut_clear_reschedule

    /* Trigger scheduler */
    bl      fut_thread_yield

no_reschedule:
    ret

/*
 * External symbols defined by linker script
 */
.extern _stack_top
.extern _bss_start
.extern _bss_end
.extern fut_in_interrupt

/* ============================================================
 *   Boot Page Tables (in BSS)
 * ============================================================ */

.section .bss
.align 12                         /* 4KB alignment required for page tables */

/* Page tables for 39-bit VA space (T0SZ=25)
 * For 39-bit VA, ARM64 starts page table walk at Level 1 (not L0)
 * Each L1 entry covers 1GB, each L2 entry covers 2MB
 */

/* Boot page tables - TTBR0_EL1 (identity mapping for early boot) */
.global boot_l1_table
boot_l1_table:
    .space 4096                   /* Level 1 (root table, 512 x 1GB per entry) */

boot_l2_table_peripherals:
    .space 4096                   /* Level 2 for peripherals (512 x 2MB = 1GB) */

boot_l2_table_dram:
    .space 4096                   /* Level 2 for DRAM (512 x 2MB = 1GB) */

/* Kernel page tables - TTBR1_EL1 (high VA mapping for kernel)
 * Maps high VA 0xFFFF000000000000+ to physical addresses
 * This allows kernel to run at high VA while user space uses low VA
 */
.global kernel_l1_table
kernel_l1_table:
    .space 4096                   /* Level 1 for high VA */

kernel_l2_table_peripherals:
    .space 4096                   /* Level 2 for high VA peripherals */

kernel_l2_table_dram:
    .space 4096                   /* Level 2 for high VA kernel */
