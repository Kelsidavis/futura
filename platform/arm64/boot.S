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

    /* Configure SCTLR_EL1 */
    mrs     x0, sctlr_el1
    bic     x0, x0, #(1 << 0)         /* Disable MMU */
    bic     x0, x0, #(1 << 2)         /* Disable data cache */
    bic     x0, x0, #(1 << 12)        /* Disable instruction cache */
    bic     x0, x0, #(1 << 1)         /* Disable alignment checking */
    orr     x0, x0, #(1 << 3)         /* Enable stack alignment check */
    msr     sctlr_el1, x0
    isb

    /* Set up stack pointer */
    adr     x0, _stack_top
    mov     sp, x0

    /* Clear BSS */
    adr     x0, _bss_start
    adr     x1, _bss_end
clear_bss:
    cmp     x0, x1
    bge     bss_cleared
    str     xzr, [x0], #8
    b       clear_bss

bss_cleared:
    /* Restore device tree address and call platform init */
    mov     x0, #0                    /* boot_magic = 0 */
    mov     x1, x20                   /* boot_info = device tree address */
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
    b       generic_exception_handler

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
    b       generic_exception_handler

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
    b       generic_exception_handler

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
    b       generic_exception_handler

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
generic_exception_handler:
    /* Save minimal context */
    stp     x0, x1, [sp, #-16]!
    stp     x2, x3, [sp, #-16]!

    /* Print exception message */
    adr     x0, exception_msg
    bl      fut_serial_puts

    /* Halt */
1:  wfi
    b       1b

exception_msg:
    .asciz  "[EXCEPTION] ARM64 exception occurred!\n"

/*
 * IRQ handler entry point
 */
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
 */
.type fut_irq_handler, @function
fut_irq_handler:
    /* Get interrupt number from GIC */
    bl      fut_irq_acknowledge
    mov     x19, x0                   /* Save IRQ number */

    /* Check if timer interrupt (IRQ 30) */
    cmp     x19, #30
    beq     handle_timer_irq

    /* Generic IRQ handling */
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
 * BSS and stack section
 */
.section .bss
.align 16
.global _stack_bottom
_stack_bottom:
    .space 16384                      /* 16 KB initial stack */
.global _stack_top
_stack_top:

.global _bss_start
.global _bss_end
