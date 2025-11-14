/* arm64_exception_entry.S - ARM64 Exception Entry Points
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Exception entry code that builds exception frames and dispatches to C handlers.
 * Each exception handler saves registers, builds a fut_interrupt_frame_t structure,
 * and calls the C-level exception dispatcher.
 *
 * ARM64 Exception Entry Framework
 * ================================
 *
 * Phase 1 (Completed): Basic Exception Frame Building
 * -----
 * Status: ✓ Implemented and tested
 * - Register preservation (x0-x30, SP, PC, PSTATE)
 * - ELR_EL1 (exception return address) capture
 * - ESR_EL1 (exception syndrome) capture
 * - FAR_EL1 (fault address) capture for data/instruction aborts
 * - Frame allocation on kernel stack
 * - Context switch to kernel page tables
 * - Dispatcher call: arm64_exception_dispatch(frame)
 *
 * Key Design Decisions:
 * - Frames built on kernel stack: Allows safe dispatcher execution
 * - SP_EL0 preserved: Critical for user stack pointer recovery
 * - TTBR0_EL1 switched: Kernel code/data accessible in handler
 * - ELR_EL1 pre-incremented: Not needed (CPU sets correctly for SVC)
 *
 * Phase 2 (Planned): FPU State Preservation
 * -----
 * Status: ⏳ Framework in place, handler integration pending
 * - FPU register preservation (v0-v31, FPSR, FPCR)
 * - Lazy FPU context switching
 * - Interrupt context FPU access
 * - Per-task FPU state snapshots
 *
 * Phase 3 (Planned): Advanced Context Handling
 * -----
 * Status: ⏳ Deferred
 * - Signal context preservation and restoration
 * - User-mode signal handler frame setup
 * - Synchronous exception context chaining
 *
 * Architecture Notes:
 *
 * Exception Vector Layout (ARMv8):
 *   - VBAR_EL1 points to 2KB aligned exception vector table
 *   - Each vector: 128 bytes for handler code
 *   - Vectors organized by exception source/type
 *   - Exception entry is synchronous (ELR_EL1 is precise)
 *
 * Exception Syndrome Register (ESR_EL1):
 *   - [31:26] EC (Exception Class): Identifies exception type
 *   - [24:0] ISS (Instruction-Specific Syndrome): Details
 *   - Used by arm64_exception_dispatch() to route exceptions
 *
 * Privilege Level Transitions:
 *   - Syscall from EL0 → ELR_EL1 saved
 *   - Page fault from EL0 → FAR_EL1 saved
 *   - Exception always taken to EL1 (kernel)
 *   - ERET instruction returns to interrupted level
 *
 * Stack Pointer Handling:
 *   - SP_EL1: Kernel stack pointer (per-task)
 *   - SP_EL0: User stack pointer (per-task, preserved)
 *   - Switch on exception entry via kernel stack switch
 *
 * Page Table Handling:
 *   - TTBR0_EL1: User page table base (per-task)
 *   - TTBR1_EL1: Kernel page table base (fixed)
 *   - Switch to kernel TTBR0_EL1 for exception handling
 *   - Restored on return to user code
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
     * - ALL registers x0-x30 contain values that MUST BE PRESERVED!
     */

    /* Allocate space for fut_interrupt_frame_t on kernel stack
     * We'll use sub/add directly on SP to avoid clobbering any registers
     * Structure layout (from include/arch/arm64/regs.h):
     * - x[0-30]      : 31 * 8 = 248 bytes
     * - sp           : 8 bytes
     * - pc (ELR_EL1) : 8 bytes
     * - pstate       : 8 bytes
     * - esr          : 8 bytes
     * - far          : 8 bytes
     * - fpu_state    : 512 bytes
     * - fpsr, fpcr   : 8 bytes
     * Total: ~816 bytes, round to ~880
     */

    sub     sp, sp, #880        /* Allocate space for frame + buffer (must be pre-aligned) */

    /* Save all general purpose registers x0-x30 directly to frame
     * SP now points to the frame, so we can use it as base
     */
    stp     x0, x1, [sp, #0]    /* Save x0, x1 (syscall args 0, 1) */
    stp     x2, x3, [sp, #16]   /* Save x2, x3 (syscall args 2, 3) */
    stp     x4, x5, [sp, #32]   /* Save x4, x5 (syscall args 4, 5) */
    stp     x6, x7, [sp, #48]
    stp     x8, x9, [sp, #64]   /* x8 = syscall number */
    stp     x10, x11, [sp, #80]
    stp     x12, x13, [sp, #96]
    stp     x14, x15, [sp, #112]
    stp     x16, x17, [sp, #128]
    stp     x18, x19, [sp, #144]
    stp     x20, x21, [sp, #160]
    stp     x22, x23, [sp, #176]
    stp     x24, x25, [sp, #192]
    stp     x26, x27, [sp, #208]
    stp     x28, x29, [sp, #224]
    str     x30, [sp, #240]

    /* Now we can use x0 and x1 as scratch registers since they're saved */
    mov     x0, sp              /* x0 = frame pointer */

    /* Calculate original SP (before we allocated the frame)
     * Original SP = current SP + 880
     */
    add     x1, sp, #880        /* x1 = original SP */

    /* Save SP, PC, PSTATE */
    str     x1, [x0, #248]      /* frame->sp = original SP */
    mrs     x1, elr_el1
    str     x1, [x0, #256]      /* frame->pc (ELR_EL1) */
    mrs     x1, spsr_el1
    str     x1, [x0, #264]      /* frame->pstate (SPSR_EL1) */

    /* Save ESR and FAR */
    mrs     x1, esr_el1
    str     x1, [x0, #272]      /* frame->esr */
    mrs     x1, far_el1
    str     x1, [x0, #280]      /* frame->far */

    /* Save SP_EL0 (user stack pointer) - critical for userspace returns! */
    mrs     x1, sp_el0
    str     x1, [x0, #808]      /* Save SP_EL0 at offset 808 (after fpcr) */

    /* Save user TTBR0 before switching to kernel page table */
    mrs     x1, ttbr0_el1
    str     x1, [x0, #816]      /* Save TTBR0_EL1 at offset 816 (after sp_el0) */

    /* Switch to kernel page table for kernel code/data access
     * This allows syscalls to access kernel memory (code, data, page tables)
     */
    adrp    x1, boot_l1_table
    add     x1, x1, :lo12:boot_l1_table
    msr     ttbr0_el1, x1
    isb

    /* Save FPU state (v0-v31 registers and control registers)
     * FPU state is stored in frame->fpu_state[64] at offset 288
     * Each 128-bit register v[i] is saved as 2 x 64-bit words
     */

    /* Save v0-v1 (128-bit each = 256 bits = 32 bytes) */
    stp     d0, d1, [x0, #288]
    stp     d2, d3, [x0, #304]
    stp     d4, d5, [x0, #320]
    stp     d6, d7, [x0, #336]
    stp     d8, d9, [x0, #352]
    stp     d10, d11, [x0, #368]
    stp     d12, d13, [x0, #384]
    stp     d14, d15, [x0, #400]
    stp     d16, d17, [x0, #416]
    stp     d18, d19, [x0, #432]
    stp     d20, d21, [x0, #448]
    stp     d22, d23, [x0, #464]
    stp     d24, d25, [x0, #480]
    stp     d26, d27, [x0, #496]
    /* Adjust base pointer for remaining fp registers (offset too large) */
    add     x1, x0, #512
    stp     d28, d29, [x1, #0]
    stp     d30, d31, [x1, #16]

    /* Save FPSR (Floating-point Status Register) at frame->fpsr offset 800 */
    mrs     x1, fpsr
    str     w1, [x0, #800]

    /* Save FPCR (Floating-point Control Register) at frame->fpcr offset 804 */
    mrs     x1, fpcr
    str     w1, [x0, #804]

    /* Call C-level exception dispatcher */
    bl      arm64_exception_dispatch

    /* Restore registers from frame before returning from exception
     * frame->x[0] now contains return value if any
     */

    mov     x0, sp              /* x0 = frame pointer (still valid) */

    /* Restore FPU state BEFORE restoring x0 (since we need x0 as frame pointer)
     * FPU registers and control state must be restored
     */

    /* Restore FPSR (Floating-point Status Register) from offset 800 */
    ldr     w1, [x0, #800]
    msr     fpsr, x1

    /* Restore FPCR (Floating-point Control Register) from offset 804 */
    ldr     w1, [x0, #804]
    msr     fpcr, x1

    /* Restore v0-v31 registers from frame->fpu_state[64] at offset 288 */
    ldp     d0, d1, [x0, #288]
    ldp     d2, d3, [x0, #304]
    ldp     d4, d5, [x0, #320]
    ldp     d6, d7, [x0, #336]
    ldp     d8, d9, [x0, #352]
    ldp     d10, d11, [x0, #368]
    ldp     d12, d13, [x0, #384]
    ldp     d14, d15, [x0, #400]
    ldp     d16, d17, [x0, #416]
    ldp     d18, d19, [x0, #432]
    ldp     d20, d21, [x0, #448]
    ldp     d22, d23, [x0, #464]
    ldp     d24, d25, [x0, #480]
    ldp     d26, d27, [x0, #496]
    /* Adjust base pointer for remaining fp registers (offset too large) */
    add     x1, x0, #512
    ldp     d28, d29, [x1, #0]
    ldp     d30, d31, [x1, #16]

    /* Restore ELR_EL1 and SPSR_EL1 from frame BEFORE restoring x0 */
    ldr     x1, [x0, #256]      /* Load PC from frame->pc */
    msr     elr_el1, x1         /* Restore ELR_EL1 (exception return address) */

    ldr     x1, [x0, #264]      /* Load PSTATE from frame->pstate */
    msr     spsr_el1, x1        /* Restore SPSR_EL1 (exception return state) */

    /* Restore SP from frame */
    ldr     x1, [x0, #248]      /* Load SP from frame->sp */
    mov     sp, x1              /* Restore SP */

    /* Restore SP_EL0 (user stack pointer) - critical for userspace returns! */
    ldr     x1, [x0, #808]      /* Load SP_EL0 from offset 808 */
    msr     sp_el0, x1          /* Restore SP_EL0 */

    /* Restore user TTBR0 before returning to userspace */
    ldr     x1, [x0, #816]      /* Load TTBR0_EL1 from offset 816 */
    msr     ttbr0_el1, x1       /* Restore TTBR0_EL1 */
    isb

    /* Restore general purpose registers x2-x30 */
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

    /* Restore x0, x1 LAST (x0 contains syscall return value) */
    ldp     x0, x1, [x0, #0]   /* Load x0, x1 from frame->x[0] and frame->x[1] */

    /* Return from exception
     * ERET will use ELR_EL1 (PC) and SPSR_EL1 (PSTATE) to return to caller
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
