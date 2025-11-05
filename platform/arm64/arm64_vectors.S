/* arm64_vectors.S - ARM64 Exception Vector Table
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * ARM64 requires a properly aligned exception vector table with 16 entries.
 * Each entry can be up to 32 instructions (128 bytes) and handles a specific
 * exception type from a specific exception level.
 *
 * Vector table layout (each entry is 0x80 bytes apart):
 * - +0x000: Synchronous from current EL with SP0
 * - +0x080: IRQ from current EL with SP0
 * - +0x100: FIQ from current EL with SP0
 * - +0x180: SError from current EL with SP0
 * - +0x200: Synchronous from current EL with SPx
 * - +0x280: IRQ from current EL with SPx
 * - +0x300: FIQ from current EL with SPx
 * - +0x380: SError from current EL with SPx
 * - +0x400: Synchronous from lower EL (AArch64)
 * - +0x480: IRQ from lower EL (AArch64)
 * - +0x500: FIQ from lower EL (AArch64)
 * - +0x580: SError from lower EL (AArch64)
 * - +0x600: Synchronous from lower EL (AArch32)
 * - +0x680: IRQ from lower EL (AArch32)
 * - +0x700: FIQ from lower EL (AArch32)
 * - +0x780: SError from lower EL (AArch32)
 */

.text
.align 11  /* Vector table must be 2KB aligned (2^11 = 2048) */

.global arm64_exception_vectors
arm64_exception_vectors:

/* ============================================================
 *   Current EL with SP0 (not used - kernel always uses SPx)
 * ============================================================ */

/* +0x000: Synchronous from current EL with SP0 */
.align 7
curr_el_sp0_sync:
    b       sync_exception_entry

/* +0x080: IRQ from current EL with SP0 */
.align 7
curr_el_sp0_irq:
    b       irq_exception_entry

/* +0x100: FIQ from current EL with SP0 */
.align 7
curr_el_sp0_fiq:
    b       fiq_exception_entry

/* +0x180: SError from current EL with SP0 */
.align 7
curr_el_sp0_serror:
    b       serror_exception_entry

/* ============================================================
 *   Current EL with SPx (kernel mode)
 * ============================================================ */

/* +0x200: Synchronous from current EL with SPx */
.align 7
curr_el_spx_sync:
    b       sync_exception_entry

/* +0x280: IRQ from current EL with SPx */
.align 7
curr_el_spx_irq:
    b       irq_exception_entry

/* +0x300: FIQ from current EL with SPx */
.align 7
curr_el_spx_fiq:
    b       fiq_exception_entry

/* +0x380: SError from current EL with SPx */
.align 7
curr_el_spx_serror:
    b       serror_exception_entry

/* ============================================================
 *   Lower EL (AArch64) - userspace
 * ============================================================ */

/* +0x400: Synchronous from lower EL (AArch64) */
.align 7
lower_el_aarch64_sync:
    b       sync_exception_entry

/* +0x480: IRQ from lower EL (AArch64) */
.align 7
lower_el_aarch64_irq:
    b       irq_exception_entry

/* +0x500: FIQ from lower EL (AArch64) */
.align 7
lower_el_aarch64_fiq:
    b       fiq_exception_entry

/* +0x580: SError from lower EL (AArch64) */
.align 7
lower_el_aarch64_serror:
    b       serror_exception_entry

/* ============================================================
 *   Lower EL (AArch32) - not supported
 * ============================================================ */

/* +0x600: Synchronous from lower EL (AArch32) */
.align 7
lower_el_aarch32_sync:
    b       aarch32_not_supported

/* +0x680: IRQ from lower EL (AArch32) */
.align 7
lower_el_aarch32_irq:
    b       aarch32_not_supported

/* +0x700: FIQ from lower EL (AArch32) */
.align 7
lower_el_aarch32_fiq:
    b       aarch32_not_supported

/* +0x780: SError from lower EL (AArch32) */
.align 7
lower_el_aarch32_serror:
    b       aarch32_not_supported

/* ============================================================
 *   Exception Entry Stubs
 * ============================================================ */

/* IRQ Exception Entry - saves state and calls C handler */
irq_exception_entry:
    /* Save minimal context */
    sub     sp, sp, #880
    stp     x0, x1, [sp, #0]
    stp     x2, x3, [sp, #16]
    stp     x29, x30, [sp, #224]

    /* Call C IRQ handler */
    mov     x0, sp
    bl      arm64_handle_irq

    /* Restore context */
    ldp     x29, x30, [sp, #224]
    ldp     x2, x3, [sp, #16]
    ldp     x0, x1, [sp, #0]
    add     sp, sp, #880
    eret

/* FIQ Exception Entry - currently not used */
fiq_exception_entry:
    eret

/* SError Exception Entry - system error */
serror_exception_entry:
    /* Save minimal context and call handler */
    sub     sp, sp, #880
    stp     x0, x1, [sp, #0]
    mov     x0, sp
    bl      arm64_handle_serror
    ldp     x0, x1, [sp, #0]
    add     sp, sp, #880
    eret

/* AArch32 not supported */
aarch32_not_supported:
    /* Halt - AArch32 mode not supported */
1:  wfi
    b       1b

/* ============================================================
 *   Vector Table Installation Function
 * ============================================================ */

.global arm64_install_exception_vectors
.type arm64_install_exception_vectors, %function
arm64_install_exception_vectors:
    adrp    x0, arm64_exception_vectors
    add     x0, x0, :lo12:arm64_exception_vectors
    msr     vbar_el1, x0
    isb
    ret

.end
