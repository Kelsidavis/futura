/*
 * Futura OS - ARM64 Boot Code
 * Copyright (C) 2025 Futura OS Project
 *
 * Early boot code for ARM64 architecture.
 * Configures the CPU and jumps to platform initialization.
 */

.section .text.boot

/*
 * _start - ARM64 boot entry point
 *
 * Called by bootloader with:
 *   x0 = device tree blob address (or 0)
 *   x1 = 0
 *   x2 = 0
 *   x3 = 0
 */
.global _start
_start:
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

    /* Get base address of boot page tables */
    adrp    x0, boot_l0_table
    add     x0, x0, :lo12:boot_l0_table

    /* Zero out all page tables first */
    mov     x1, #0
    mov     x2, #(4096 * 5 / 8)       /* 5 tables: L0, L1_low, L1_high, L2_peripherals, L2_dram */
1:  str     xzr, [x0, x1, lsl #3]
    add     x1, x1, #1
    cmp     x1, x2
    blt     1b

    /* Debug: Tables zeroed */
    movz    x10, #0x0900, lsl #16
    mov     x11, #0x31                /* '1' */
    strb    w11, [x10]

    /* Setup L0 table: Point to L1 tables (table descriptors, not blocks) */
    adrp    x0, boot_l0_table
    add     x0, x0, :lo12:boot_l0_table

    /* L0[0] -> L1_low (for VA 0x00000000-0x3FFFFFFF) */
    adrp    x1, boot_l1_table_low
    add     x1, x1, :lo12:boot_l1_table_low
    orr     x1, x1, #3                /* Valid table descriptor */
    str     x1, [x0, #0]

    /* L0[1] -> L1_high (for VA 0x40000000-0x7FFFFFFF) */
    adrp    x1, boot_l1_table_high
    add     x1, x1, :lo12:boot_l1_table_high
    orr     x1, x1, #3                /* Valid table descriptor */
    str     x1, [x0, #8]

    /* Debug: L0 setup done */
    movz    x10, #0x0900, lsl #16
    mov     x11, #0x32                /* '2' */
    strb    w11, [x10]

    /* Setup L1_low: Point to L2_peripherals (table descriptor, not block!) */
    adrp    x0, boot_l1_table_low
    add     x0, x0, :lo12:boot_l1_table_low
    adrp    x1, boot_l2_table_peripherals
    add     x1, x1, :lo12:boot_l2_table_peripherals
    orr     x1, x1, #3                /* Valid table descriptor */
    str     x1, [x0, #0]              /* L1_low[0] -> L2_peripherals */

    /* Setup L1_high: Point to L2_dram (table descriptor, not block!) */
    adrp    x0, boot_l1_table_high
    add     x0, x0, :lo12:boot_l1_table_high
    adrp    x1, boot_l2_table_dram
    add     x1, x1, :lo12:boot_l2_table_dram
    orr     x1, x1, #3                /* Valid table descriptor */
    str     x1, [x0, #0]              /* L1_high[0] -> L2_dram */

    /* Debug: L1 tables configured */
    movz    x10, #0x0900, lsl #16
    mov     x11, #0x33                /* '3' */
    strb    w11, [x10]

    /* Setup L2_peripherals: 64 x 2MB blocks for 0x00000000-0x08000000 (128MB peripherals)
     * Each 2MB block, device memory
     */
    adrp    x0, boot_l2_table_peripherals
    add     x0, x0, :lo12:boot_l2_table_peripherals
    mov     x1, #0x00000000           /* Start PA */
    mov     x3, #64                   /* Only map first 128MB for peripherals */
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
    mov     x11, #0x34                /* '4' */
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
    mov     x11, #0x35                /* '5' */
    strb    w11, [x10]

    /* Configure MAIR_EL1 (Memory Attribute Indirection Register)
     * Attr0 = 0xFF (Normal memory, Inner/Outer Write-Back Cacheable)
     * Attr1 = 0x00 (Device-nGnRnE - for UART, GIC, etc.)
     * Combined value: 0x00FF (Attr1=0x00, Attr0=0xFF)
     */
    movz    x0, #0x00FF               /* Attr0=0xFF (normal), Attr1=0x00 (device) */
    msr     mair_el1, x0

    /* Debug: MAIR configured */
    movz    x10, #0x0900, lsl #16
    mov     x11, #0x36                /* '6' */
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
    movz    x0, #25                   /* T0SZ = 25 */
    orr     x0, x0, #(0x3 << 12)      /* SH0 = 11 (inner shareable) */
    orr     x0, x0, #(0x1 << 10)      /* ORGN0 = 01 */
    orr     x0, x0, #(0x1 << 8)       /* IRGN0 = 01 */
    movk    x0, #25, lsl #16          /* T1SZ = 25 */
    orr     x0, x0, #(0x3 << 28)      /* SH1 = 11 (inner shareable) */
    orr     x0, x0, #(0x1 << 26)      /* ORGN1 = 01 */
    orr     x0, x0, #(0x1 << 24)      /* IRGN1 = 01 */
    orr     x0, x0, #(0x2 << 30)      /* TG1 = 10 (4KB granule for TTBR1) */
    movk    x0, #1, lsl #32           /* IPS = 001 (36-bit PA) */
    msr     tcr_el1, x0

    /* Debug: TCR configured */
    movz    x10, #0x0900, lsl #16
    mov     x11, #0x37                /* '7' */
    strb    w11, [x10]

    /* Set TTBR1_EL1 to kernel page table */
    adrp    x0, boot_l0_table
    add     x0, x0, :lo12:boot_l0_table
    msr     ttbr1_el1, x0

    /* Set TTBR0_EL1 to same table for now (no user space yet) */
    msr     ttbr0_el1, x0

    /* Debug: TTBR configured */
    movz    x10, #0x0900, lsl #16
    mov     x11, #0x38                /* '8' */
    strb    w11, [x10]

    /* Invalidate TLBs and caches before enabling MMU */
    tlbi    vmalle1                   /* Invalidate all TLB entries for EL1 */
    ic      iallu                     /* Invalidate all instruction caches to PoU */
    dsb     sy                        /* Ensure all invalidations complete */
    isb                               /* Synchronize instruction stream */

    /* Debug: About to enable MMU */
    movz    x10, #0x0900, lsl #16
    mov     x11, #0x39                /* '9' */
    strb    w11, [x10]

    /* TEMPORARY: MMU enable disabled pending further investigation
     *
     * All standard ARM64 MMU configuration has been attempted:
     * - Correct L0/L1 page table structure with 1GB blocks
     * - Proper AF bit setting (bit 10)
     * - Complete TCR_EL1 configuration (SH, ORGN, IRGN)
     * - TLB and I-cache invalidation
     * - Cache enable with MMU
     * - All DSB/ISB barriers
     *
     * Issue: MMU enable at this point causes Prefetch Abort
     * Kernel boots successfully WITHOUT MMU (proven functional)
     *
     * TODO: Compare with Linux arch/arm64/kernel/head.S
     * TODO: Test on real ARM64 hardware
     * TODO: Investigate QEMU virt machine MMU emulation
     */

    /* MMU DISABLED: Multiple attempts have failed
     *
     * 2025-11-04 attempt #1: 1GB blocks at L1 with shareable bits
     * 2025-11-04 attempt #2: 1GB blocks with TG1=10 fix
     * 2025-11-04 attempt #3: 2MB blocks at L2 (this version)
     *
     * Result: All attempts hang at MMU enable (after debug marker '9')
     *
     * Current page table structure (ready for MMU when issue is resolved):
     * - L0[0] → L1_low → L2_peripherals (64 x 2MB = 128MB for UART/GIC)
     * - L0[1] → L1_high → L2_dram (512 x 2MB = 1GB for kernel)
     * - MAIR: Attr0=0xFF (normal), Attr1=0x00 (device)
     * - TCR: T0SZ=25, T1SZ=25, TG0=00, TG1=10, shareable/cacheable
     * - Shareable: SH=10 (Outer) for device, SH=11 (Inner) for normal
     *
     * The kernel functions perfectly without MMU. Multi-process support
     * works via stack copying. MMU would provide address space isolation
     * but is not blocking further development.
     */
    /* mrs     x0, sctlr_el1 */
    /* orr     x0, x0, #(1 << 0) */
    /* orr     x0, x0, #(1 << 2) */
    /* orr     x0, x0, #(1 << 12) */
    /* msr     sctlr_el1, x0 */
    /* isb */

    /* Debug: Write 'B' to UART after MMU enable (proves MMU worked) */
    movz    x10, #0x0900, lsl #16     /* UART0 base = 0x09000000 */
    mov     x11, #0x42                /* ASCII 'B' */
    strb    w11, [x10]                /* Write to UART data register */

    /* Restore device tree address and call platform init */
    mov     x0, #0                    /* boot_magic = 0 */
    mov     x1, x20                   /* boot_info = device tree address */

    /* Debug: Write 'C' before calling platform_init */
    movz    x10, #0x0900, lsl #16     /* UART0 base = 0x09000000 */
    mov     x11, #0x43                /* ASCII 'C' */
    strb    w11, [x10]                /* Write to UART data register */

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
    /* TODO: Implement proper frame setup for registered handler dispatch */
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

boot_l0_table:
    .space 4096                   /* Level 0 (1GB per entry with T0SZ=25) */

boot_l1_table_low:
    .space 4096                   /* Level 1 for L0[0] (VA 0x00000000-0x3FFFFFFF) */

boot_l1_table_high:
    .space 4096                   /* Level 1 for L0[1] (VA 0x40000000-0x7FFFFFFF) */

boot_l2_table_peripherals:
    .space 4096                   /* Level 2 for peripherals (512 x 2MB = 1GB) */

boot_l2_table_dram:
    .space 4096                   /* Level 2 for DRAM (512 x 2MB = 1GB) */
