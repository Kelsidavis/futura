/* arm64_exceptions.c - ARM64 Exception Handling
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Exception dispatch router for ARM64 synchronous exceptions.
 * Handles data aborts, instruction aborts, and system calls.
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
