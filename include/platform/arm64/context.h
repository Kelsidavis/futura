/* context.h - ARM64 Context Switching and Thread Support
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * ARM64 (AArch64) context switching primitives for cooperative multi-threading.
 */

#pragma once

#include <platform/arm64/regs.h>

/* ============================================================
 *   Context Switching Primitives
 * ============================================================ */

/**
 * Save current CPU context (callee-saved registers).
 * Used for cooperative context switches.
 * @param ctx Pointer to fut_cpu_context_t to save context
 */
#define fut_save_context(ctx) \
    __asm__ volatile( \
        "stp x19, x20, [%0, #0]\n\t" \
        "stp x21, x22, [%0, #16]\n\t" \
        "stp x23, x24, [%0, #32]\n\t" \
        "stp x25, x26, [%0, #48]\n\t" \
        "stp x27, x28, [%0, #64]\n\t" \
        "stp x29, x30, [%0, #80]\n\t" \
        "mov x1, sp\n\t" \
        "str x1, [%0, #96]\n\t" \
        : \
        : "r"(ctx) \
        : "x1", "memory" \
    )

/**
 * Restore CPU context (callee-saved registers).
 * Used for cooperative context switches.
 * @param ctx Pointer to fut_cpu_context_t to restore from
 */
#define fut_restore_context(ctx) \
    __asm__ volatile( \
        "ldp x19, x20, [%0, #0]\n\t" \
        "ldp x21, x22, [%0, #16]\n\t" \
        "ldp x23, x24, [%0, #32]\n\t" \
        "ldp x25, x26, [%0, #48]\n\t" \
        "ldp x27, x28, [%0, #64]\n\t" \
        "ldp x29, x30, [%0, #80]\n\t" \
        "ldr x1, [%0, #96]\n\t" \
        "mov sp, x1\n\t" \
        : \
        : "r"(ctx) \
        : "x1", "memory" \
    )

/**
 * Switch from one thread to another (cooperative).
 * Implemented as assembly function in context_switch.S
 * @param prev Pointer to old thread
 * @param next Pointer to new thread
 */
/* Note: Actual implementation is in context_switch.S as a function.
   The macro version is commented out since the assembly implementation handles
   all the necessary context switching operations. */

/* ============================================================
 *   Thread Entry Point
 * ============================================================ */

/**
 * Initialize a new thread context for execution.
 * Sets up registers for a new thread to start execution.
 * @param ctx Pointer to fut_cpu_context_t to initialize
 * @param entry Entry point function for new thread
 * @param arg Argument to pass to entry point
 * @param stack_ptr Stack pointer (top of stack)
 */
static inline void fut_init_thread_context(fut_cpu_context_t *ctx,
                                           void (*entry)(void *),
                                           void *arg,
                                           void *stack_ptr) {
    /* Clear context */
    __builtin_memset(ctx, 0, sizeof(fut_cpu_context_t));

    /* Set x0 with argument (return value for new thread) */
    ctx->x0 = (uint64_t)arg;

    /* Set stack pointer */
    ctx->sp = (uint64_t)stack_ptr;

    /* Set program counter to entry point */
    ctx->pc = (uint64_t)entry;

    /* Set processor state: EL1h, interrupts enabled */
    ctx->pstate = PSTATE_MODE_EL1h;

    /* Set frame pointer */
    ctx->x29_fp = (uint64_t)stack_ptr;
}

/* ============================================================
 *   Barrier and Synchronization Primitives
 * ============================================================ */

/**
 * Data memory barrier - ensure all memory operations complete.
 */
static inline void fut_dmb(void) {
    __asm__ volatile("dmb sy" ::: "memory");
}

/**
 * Data synchronization barrier - ensure all memory operations complete.
 */
static inline void fut_dsb(void) {
    __asm__ volatile("dsb sy" ::: "memory");
}

/**
 * Instruction synchronization barrier.
 */
static inline void fut_isb(void) {
    __asm__ volatile("isb" ::: "memory");
}

/* ============================================================
 *   Atomic Operations
 * ============================================================ */

/**
 * Atomic compare and swap (CAS) on 64-bit value.
 * @param addr Address of value to compare and swap
 * @param expected Expected current value
 * @param new_val Value to swap in if match
 * @return true if swap succeeded, false if value didn't match
 */
static inline bool fut_atomic_cas_64(uint64_t *addr, uint64_t expected, uint64_t new_val) {
    uint64_t result;
    uint64_t tmp;

    __asm__ volatile(
        "1:\n\t"
        "ldxr %0, [%3]\n\t"              /* Load exclusive */
        "cmp %0, %4\n\t"                 /* Compare */
        "bne 2f\n\t"                     /* Branch if not equal */
        "stxr %w1, %2, [%3]\n\t"         /* Store exclusive */
        "cbnz %w1, 1b\n\t"               /* Retry if failed */
        "2:\n\t"
        : "=&r"(result), "=&r"(tmp)
        : "r"(new_val), "r"(addr), "r"(expected)
        : "cc", "memory"
    );

    return result == expected;
}

/**
 * Atomic load acquire (load with acquire semantics).
 * @param addr Address to load from
 * @return Loaded value
 */
static inline uint64_t fut_atomic_load_acq(uint64_t *addr) {
    uint64_t result;
    __asm__ volatile(
        "ldar %0, [%1]"
        : "=r"(result)
        : "r"(addr)
        : "memory"
    );
    return result;
}

/**
 * Atomic store release (store with release semantics).
 * @param addr Address to store to
 * @param val Value to store
 */
static inline void fut_atomic_store_rel(uint64_t *addr, uint64_t val) {
    __asm__ volatile(
        "stlr %0, [%1]"
        :
        : "r"(val), "r"(addr)
        : "memory"
    );
}

/* ============================================================
 *   CPU and System Information
 * ============================================================ */

/**
 * Read CPU ID (MPIDR_EL1).
 * Returns the multiprocessor affinity register.
 * @return CPU ID
 */
static inline uint64_t fut_get_cpu_id(void) {
    uint64_t mpidr;
    __asm__ volatile("mrs %0, mpidr_el1" : "=r"(mpidr));
    return mpidr & 0xFF;  /* CPU ID in bits 0-7 */
}

/**
 * Get current exception level.
 * @return Exception level (0-3)
 */
static inline int fut_get_exception_level(void) {
    uint64_t el;
    __asm__ volatile("mrs %0, CurrentEL" : "=r"(el));
    return (el >> 2) & 0x3;
}

/**
 * Yield to scheduler (generate context switch request).
 * Uses software interrupt.
 */
static inline void fut_yield(void) {
    __asm__ volatile("svc #0" ::: "memory");
}

/**
 * Halt the CPU (wait for interrupt).
 */
static inline void fut_halt(void) {
    __asm__ volatile("wfi");
}
