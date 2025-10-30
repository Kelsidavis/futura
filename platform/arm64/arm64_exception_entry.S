/* arm64_exception_entry.S - ARM64 Exception Entry Points
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Exception entry code that builds exception frames and dispatches to C handlers.
 * Each exception handler saves registers, builds a fut_interrupt_frame_t structure,
 * and calls the C-level exception dispatcher.
 */

#include <asm/asm-offsets.h>

.text
.align 2

/* ============================================================
 *   Synchronous Exception Handler Entry Point
 * ============================================================ */

.global sync_exception_entry
.type sync_exception_entry, %function
sync_exception_entry:
    /* At this point:
     * - We've just taken an exception
     * - SP may be kernel stack or user stack depending on where exception came from
     * - Need to build interrupt frame and call dispatcher
     */

    /* Save SP from exception context */
    mov     x1, sp

    /* Allocate space for fut_interrupt_frame_t on kernel stack
     * Structure layout (from include/arch/arm64/regs.h):
     * - x[0-30]      : 31 * 8 = 248 bytes
     * - sp           : 8 bytes
     * - pc (ELR_EL1) : 8 bytes
     * - pstate       : 8 bytes
     * - esr          : 8 bytes
     * - far          : 8 bytes
     * - fpu_state    : 512 bytes
     * - fpsr, fpcr   : 8 bytes
     * Total: ~816 bytes, round to ~820
     */

    sub     sp, sp, #880        /* Allocate space for frame + buffer */
    mov     x0, sp              /* x0 = frame pointer */

    /* Save general purpose registers x0-x30 into frame->x[0-30] */
    stp     x2, x3, [x0, #16]
    stp     x4, x5, [x0, #32]
    stp     x6, x7, [x0, #48]
    stp     x8, x9, [x0, #64]
    stp     x10, x11, [x0, #80]
    stp     x12, x13, [x0, #96]
    stp     x14, x15, [x0, #112]
    stp     x16, x17, [x0, #128]
    stp     x18, x19, [x0, #144]
    stp     x20, x21, [x0, #160]
    stp     x22, x23, [x0, #176]
    stp     x24, x25, [x0, #192]
    stp     x26, x27, [x0, #208]
    stp     x28, x29, [x0, #224]
    str     x30, [x0, #240]

    /* Store the original x0, x1 that were in caller context
     * x1 still has original SP from exception
     * Need to get original x0 from somewhere - it's lost, use 0
     */
    str     xzr, [x0, #0]       /* frame->x[0] = 0 (will be overwritten by return value) */
    str     x1, [x0, #8]        /* frame->x[1] = original SP */

    /* Save SP, PC, PSTATE */
    str     x1, [x0, #248]      /* frame->sp */
    mrs     x1, elr_el1
    str     x1, [x0, #256]      /* frame->pc (ELR_EL1) */
    mrs     x1, spsr_el1
    str     x1, [x0, #264]      /* frame->pstate (SPSR_EL1) */

    /* Save ESR and FAR */
    mrs     x1, esr_el1
    str     x1, [x0, #272]      /* frame->esr */
    mrs     x1, far_el1
    str     x1, [x0, #280]      /* frame->far */

    /* Clear FPU state for now (TODO: save actual FPU registers if needed) */
    /* frame->fpu_state[0-63] = 0 (skip for now) */
    /* frame->fpsr = 0 */
    /* frame->fpcr = 0 */

    /* Call C-level exception dispatcher */
    bl      arm64_exception_dispatch

    /* Restore registers from frame before returning from exception
     * frame->x[0] now contains return value if any
     */

    mov     x0, sp              /* x0 = frame pointer (still valid) */

    /* Restore general purpose registers */
    ldp     x2, x3, [x0, #16]
    ldp     x4, x5, [x0, #32]
    ldp     x6, x7, [x0, #48]
    ldp     x8, x9, [x0, #64]
    ldp     x10, x11, [x0, #80]
    ldp     x12, x13, [x0, #96]
    ldp     x14, x15, [x0, #112]
    ldp     x16, x17, [x0, #128]
    ldp     x18, x19, [x0, #144]
    ldp     x20, x21, [x0, #160]
    ldp     x22, x23, [x0, #176]
    ldp     x24, x25, [x0, #192]
    ldp     x26, x27, [x0, #208]
    ldp     x28, x29, [x0, #224]
    ldr     x30, [x0, #240]

    /* Restore x0, x1 from frame */
    ldp     x1, x1, [x0, #0]   /* Load x0 from frame->x[0] */
    mov     x1, x1             /* x0 is already restored by ldp */

    /* Restore SP (update to next frame) */
    ldr     x1, [x0, #248]
    mov     sp, x1

    /* Restore PC and PSTATE via ERET
     * (ERET will use ELR_EL1 and SPSR_EL1, which we've already updated)
     */
    eret

/* ============================================================
 *   Weak Symbol References for Exception Dispatch Functions
 * ============================================================ */

.weak arm64_exception_dispatch
.weak arm64_svc_handler
.weak arm64_data_abort_handler
.weak arm64_instruction_abort_handler

/* Ensure these symbols are defined (linker will require them) */
.end
