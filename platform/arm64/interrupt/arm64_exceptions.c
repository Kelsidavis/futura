/* arm64_exceptions.c - ARM64 Exception Handling
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Exception dispatch router for ARM64 synchronous exceptions.
 * Handles data aborts, instruction aborts, and system calls.
 *
 * ARM64 Exception Handling Framework
 * ===================================
 *
 * Phase 1 (Completed): Synchronous Exception Dispatch Router
 * -----
 * Status: ✓ Implemented and tested
 * - Exception syndrome register (ESR_EL1) examination
 * - Exception class (EC) extraction from ESR[31:26]
 * - Switch-based routing to specialized handlers
 * - Support for:
 *   - SVC (0x15): Supervisor calls from AArch64
 *   - Data aborts (0x24-0x25): Page faults, permission issues
 *   - Instruction aborts (0x20-0x21): TLB misses, permission issues
 *   - Unknown exceptions (0x00)
 *   - WFI/WFE traps (0x01)
 *   - Illegal execution states (0x0E)
 *
 * Key Features:
 * - C-level dispatcher called from assembly exception entry
 * - Exception context (fut_interrupt_frame_t) provided to handlers
 * - Flexible architecture for handler registration
 * - Diagnostic output for exception classification
 *
 * Phase 2 (In Progress): Data Abort Handler Enhancements
 * -----
 * Status: ⏳ Page fault handling framework in place
 * - Page fault detection and classification
 * - TLB miss vs permission fault distinction
 * - Access flag fault handling
 * - Translation fault handling (L0-L3)
 * - Alignment fault detection
 * - Signal delivery for unhandled aborts (SIGSEGV)
 * - Fault address register (FAR) examination
 *
 * Phase 3 (Planned): Instruction Abort Handler
 * -----
 * Status: ⏳ Deferred
 * - Instruction TLB miss handling
 * - Instruction access permission faults
 * - Instruction prefetch aborts
 * - Userspace instruction validation
 *
 * Phase 4 (Planned): Advanced Exception Handling
 * -----
 * Status: ⏳ Deferred
 * - Breakpoint/watchpoint exceptions (0x30-0x36)
 * - Trapped MSR/MRS instructions (0x18)
 * - PAC (Pointer Authentication Code) failures
 * - BTI (Branch Target Identification) violations
 * - Asynchronous abort handling (SError)
 *
 * Exception Syndrome Register (ESR_EL1)
 * ======================================
 *
 * Structure:
 *   [31:26] EC (Exception Class): Type of exception
 *   [24:0]  ISS (Instruction-Specific Syndrome): Details
 *
 * Exception Classes (EC):
 *   0x00 = Unknown exception
 *   0x01 = WFI/WFE instruction trapped
 *   0x03 = MCR/MRC instruction trapped (AArch32)
 *   0x04 = MCRR/MRRC instruction trapped (AArch32)
 *   0x05 = MCR/MRC instruction trapped (AArch32)
 *   0x06 = LDC/STC instruction trapped (AArch32)
 *   0x07 = SVE instruction trapped
 *   0x0A = LD64B/ST64B instruction trapped
 *   0x0C = MRRS/MSRR instruction trapped (AArch32)
 *   0x0E = Illegal execution state
 *   0x11 = SVC instruction from AArch32
 *   0x12 = HVC instruction (EL2)
 *   0x13 = SMC instruction (secure)
 *   0x15 = SVC instruction from AArch64
 *   0x18 = MSR/MRS/System instruction trapped
 *   0x19 = SVE instruction trapped
 *   0x1A = ERET/ERETAA/ERETAB instructions
 *   0x1B = FPAC instruction
 *   0x1C = Pointer Authentication instruction
 *   0x20 = Instruction abort from lower EL (userspace)
 *   0x21 = Instruction abort from current EL
 *   0x22 = PC alignment fault
 *   0x24 = Data abort from lower EL (userspace)
 *   0x25 = Data abort from current EL
 *   0x26 = SP alignment fault
 *   0x28 = Floating-point exception
 *   0x2C = Floating-point trap
 *   0x2F = SError (asynchronous abort)
 *   0x30-0x36 = Breakpoint exceptions
 *   0x38-0x39 = Software step exceptions
 *   0x3A = Watchpoint exceptions
 *
 * Data Fault Status Code (DFSC) in ISS[5:0]
 * ===========================================
 *
 * Translation faults (TF) - TLB entry not found:
 *   0x04 = Translation fault at L0
 *   0x05 = Translation fault at L1
 *   0x06 = Translation fault at L2
 *   0x07 = Translation fault at L3
 *
 * Access flag faults (AF) - Access flag bit not set:
 *   0x09 = Access flag fault at L1
 *   0x0A = Access flag fault at L2
 *   0x0B = Access flag fault at L3
 *
 * Permission faults (PF) - AP/XN bits restrict access:
 *   0x0D = Permission fault at L1
 *   0x0E = Permission fault at L2
 *   0x0F = Permission fault at L3
 *
 * Other faults:
 *   0x01 = Alignment fault
 *   0x10 = Synchronous external abort
 *   0x18 = Synchronous parity error
 *   0x11-0x1F = External abort variants
 *
 * Handler Organization
 * ====================
 *
 * arm64_exception_dispatch():
 *   - Entry point for all exceptions from assembly vector
 *   - Examines ESR_EL1 to extract exception class
 *   - Dispatches to appropriate handler based on EC
 *   - Fallback for unrecognized exceptions
 *
 * arm64_svc_handler():
 *   - Handles SVC (0x15) - system calls from EL0
 *   - Extracts syscall number and arguments
 *   - Dispatches to kernel syscall table
 *   - Manages signal delivery before return
 *
 * arm64_data_abort_handler():
 *   - Handles data aborts (0x24-0x25)
 *   - Attempts page fault handling via fut_trap_handle_page_fault()
 *   - Sends SIGSEGV for unhandled aborts
 *   - Examines FAR for fault address
 *
 * arm64_instruction_abort_handler():
 *   - Handles instruction aborts (0x20-0x21)
 *   - Currently calls handle_unknown() (Phase 3 placeholder)
 *   - Will distinguish TLB vs permission faults
 *   - Will handle instruction validation for userspace
 *
 * Signal Delivery Integration
 * ============================
 *
 * Unhandled faults trigger signal delivery:
 *   - SIGSEGV: Data or instruction abort at invalid address
 *   - SIGBUS: Alignment faults, external aborts
 *   - SIGILL: Illegal execution state
 *   - SIGTRAP: Breakpoint, watchpoint, step exceptions
 *
 * Process:
 *   1. Exception occurs in userspace (EL0)
 *   2. Exception vector saves frame (arm64_exception_entry.S)
 *   3. Dispatcher routes to handler (arm64_exception_dispatch)
 *   4. Handler processes exception
 *   5. If unhandled: fut_task_signal_exit(signal) called
 *   6. Signal context delivered at next userspace entry
 */

#include "../../include/platform/arm64/regs.h"
#include "../../include/platform/arm64/memory/paging.h"
#include "../../include/kernel/trap.h"
#include "../../include/kernel/signal.h"
#include "../../include/kernel/fut_task.h"

extern void fut_printf(const char *fmt, ...);

/* ============================================================
 *   Exception Dispatch Router
 * ============================================================ */

/**
 * Main exception dispatch function.
 * Called from exception vector handlers in boot.S.
 *
 * This function examines the ESR (Exception Syndrome Register)
 * to determine exception type and routes to appropriate handler.
 */
void arm64_exception_dispatch(fut_interrupt_frame_t *frame) {
    if (!frame) {
        fut_printf("[EXCEPTION-ARM64] NULL frame pointer\n");
        return;
    }

    uint64_t esr = frame->esr;
    uint32_t ec = (esr >> 26) & 0x3F;  /* Exception Class [31:26] */

    fut_printf("[EXCEPTION] EC=0x%02x PC=0x%llx ESR=0x%llx\n", ec, frame->pc, esr);

    /* Dispatch by exception type */
    switch (ec) {
        /* Synchronous exceptions */
        case 0x00:  /* Unknown exception */
            fut_printf("[EXCEPTION-ARM64] Unknown exception at 0x%llx\n", frame->pc);
            break;

        case 0x15:  /* SVC instruction (AArch64 system call) */
            arm64_svc_handler(frame);
            break;

        case 0x20:  /* Instruction abort from lower EL */
        case 0x21:  /* Instruction abort from current EL */
            arm64_instruction_abort_handler(frame);
            break;

        case 0x24:  /* Data abort from lower EL */
        case 0x25:  /* Data abort from current EL */
            arm64_data_abort_handler(frame);
            break;

        /* IRQ/FIQ - should not reach here (handled separately) */
        case 0x01:  /* WFI/WFE instruction */
            fut_printf("[EXCEPTION-ARM64] WFI/WFE at 0x%llx\n", frame->pc);
            break;

        default:
            fut_printf("[EXCEPTION-ARM64] Unhandled exception EC=0x%02x ESR=0x%llx PC=0x%llx\n",
                       ec, esr, frame->pc);
            break;
    }
}

/* ============================================================
 *   SVC (System Call) Handler
 * ============================================================ */

/**
 * Handle SVC (Supervisor Call) instruction - ARM64 system call.
 *
 * ARM64 Linux syscall calling convention:
 *   x8: syscall number
 *   x0-x6: syscall arguments
 *   x0: return value
 *
 * Note: SVC instruction immediate is always 0 (SVC #0)
 */
void arm64_svc_handler(fut_interrupt_frame_t *frame) {
    if (!frame) {
        return;
    }

    /* Extract syscall number from X8 (standard Linux ARM64 convention) */
    uint64_t syscall_num = frame->x[8];

    /* Arguments are in x0-x6 (frame->x[0-6]) */
    uint64_t arg1 = frame->x[0];
    uint64_t arg2 = frame->x[1];
    uint64_t arg3 = frame->x[2];
    uint64_t arg4 = frame->x[3];
    uint64_t arg5 = frame->x[4];
    uint64_t arg6 = frame->x[5];

    fut_printf("[SVC] syscall=%llu fd=%llu buf=%llx len=%llu\n", syscall_num, arg1, arg2, arg3);

    /* Call syscall dispatcher */
    extern int64_t posix_syscall_dispatch(uint64_t syscall_num,
                                          uint64_t arg1, uint64_t arg2, uint64_t arg3,
                                          uint64_t arg4, uint64_t arg5, uint64_t arg6);

    int64_t result = posix_syscall_dispatch(syscall_num, arg1, arg2, arg3, arg4, arg5, arg6);

    /* Store return value in x0 */
    frame->x[0] = (uint64_t)result;

    /* Advance PC past the SVC instruction (4 bytes) */
    frame->pc += 4;
}

/* ============================================================
 *   Data Abort Handler
 * ============================================================ */

/**
 * Handle data abort (page fault, permission fault, etc).
 * Routes to generic page fault handler or signals task.
 */
void arm64_data_abort_handler(fut_interrupt_frame_t *frame) {
    if (!frame) {
        return;
    }

    /* Debug: Read TTBR0_EL1, TTBR1_EL1, TCR_EL1 at exception time */
    uint64_t ttbr0, ttbr1, tcr;
    __asm__ volatile("mrs %0, ttbr0_el1" : "=r"(ttbr0));
    __asm__ volatile("mrs %0, ttbr1_el1" : "=r"(ttbr1));
    __asm__ volatile("mrs %0, tcr_el1" : "=r"(tcr));
    fut_printf("[EXCEPTION-DEBUG] TTBR0_EL1=0x%llx TTBR1_EL1=0x%llx TCR_EL1=0x%llx\n",
               (unsigned long long)ttbr0, (unsigned long long)ttbr1, (unsigned long long)tcr);

    /* Try to handle as page fault */
    if (fut_trap_handle_page_fault(frame)) {
        return;  /* Handled successfully */
    }

    /* Unhandled data abort - signal task */
    uint64_t esr = frame->esr;
    uint64_t far = frame->far;  /* Fault address */
    uint32_t fsc = esr & 0x3F;  /* Fault status code */

    fut_printf("[DATA-ABORT-ARM64] Unhandled abort at VA=0x%llx PC=0x%llx FSC=0x%02x\n",
               far, frame->pc, fsc);

    /* Signal task with segmentation fault
     * Data aborts typically indicate memory access violations */
    fut_task_signal_exit(SIGSEGV);
}

/* ============================================================
 *   Instruction Abort Handler
 * ============================================================ */

/**
 * Handle instruction abort (prefetch abort).
 * Usually indicates invalid instruction memory or permission fault.
 */
void arm64_instruction_abort_handler(fut_interrupt_frame_t *frame) {
    if (!frame) {
        return;
    }

    uint64_t esr = frame->esr;
    uint64_t far = frame->far;  /* Fault address */
    uint32_t fsc = esr & 0x3F;  /* Fault status code */

    fut_printf("[INSTR-ABORT-ARM64] Instruction abort at VA=0x%llx PC=0x%llx FSC=0x%02x\n",
               far, frame->pc, fsc);

    /* Instruction aborts typically indicate:
     * - Permission fault (execute never)
     * - Translation fault (page not mapped)
     * - Access fault (not marked accessible)
     *
     * Signal task with illegal instruction signal. This covers permission
     * violations (execute-never) and covers invalid instruction fetches
     * with the same signal used for actual illegal instructions.
     */
    fut_task_signal_exit(SIGILL);
}

/* ============================================================
 *   Forward Declarations (implemented in kernel/trap/)
 * ============================================================ */

/**
 * Page fault handler - returns true if handled, false if unhandled.
 * Defined in kernel/trap/page_fault.c
 */
extern bool fut_trap_handle_page_fault(fut_interrupt_frame_t *frame);
