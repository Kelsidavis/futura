/* fut_thread.h - Futura OS Thread Subsystem (C23)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Modern multi-threaded kernel with preemptive scheduling.
 * Freestanding implementation with no libc dependencies.
 */

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "fut_stats.h"
#include <arch/x86_64/regs.h>

/* Forward declarations */
typedef struct fut_task fut_task_t;
typedef struct fut_thread fut_thread_t;

/* ============================================================
 *   CPU Context and Interrupt Frame
 * ============================================================ */

/* CPU context and interrupt frame structures are defined in
 * arch/x86_64/regs.h for platform-specific implementation.
 *
 * - fut_cpu_context_t: For cooperative context switching
 * - fut_interrupt_frame_t: For interrupt-based context switching
 *
 * These structures are tightly coupled with the assembly code in
 * platform/x86_64/context_switch.S and platform/x86_64/isr_stubs.S
 */

/* ============================================================
 *   Thread States
 * ============================================================ */

enum fut_thread_state {
    FUT_THREAD_READY,        // Ready to run
    FUT_THREAD_RUNNING,      // Currently executing
    FUT_THREAD_SLEEPING,     // Waiting for timer
    FUT_THREAD_BLOCKED,      // Waiting for resource
    FUT_THREAD_TERMINATED    // Exited
};

/* ============================================================
 *   Thread Structure
 * ============================================================ */

struct fut_thread {
    uint64_t tid;                         // Thread ID (64-bit)
    fut_task_t *task;                     // Parent task

    void *stack_base;                     // Stack allocation
    size_t stack_size;                    // Stack size in bytes

    fut_cpu_context_t context;            // Saved CPU context (64-bit)
    fut_interrupt_frame_t *irq_frame;     // Saved interrupt frame (for IRQ context switches)
    enum fut_thread_state state;          // Current state
    int priority;                         // Effective priority (0-255, higher = higher priority)
    int base_priority;                    // Base priority (restored after PI)
    int pi_saved_priority;                // Saved priority when boosted
    bool pi_boosted;                      // Priority inheritance active
    uint64_t deadline_tick;               // Absolute deadline tick (0 = none)

    uint64_t wake_time;                   // Wake tick for sleeping threads

    fut_thread_stats_t stats;             // Performance instrumentation data

    fut_thread_t *next;                   // Next in queue
    fut_thread_t *prev;                   // Previous in queue
    fut_thread_t *wait_next;              // Next in wait queue
};

/* ============================================================
 *   Thread API
 * ============================================================ */

/**
 * Create a new thread within a task.
 *
 * @param task         Parent task
 * @param entry        Thread entry point function
 * @param arg          Argument passed to entry function
 * @param stack_size   Stack size in bytes (page-aligned)
 * @param priority     Priority level (0-255)
 * @return Thread handle, or nullptr on failure
 */
[[nodiscard]] fut_thread_t *fut_thread_create(
    fut_task_t *task,
    void (*entry)(void *),
    void *arg,
    size_t stack_size,
    int priority
);

/**
 * Voluntarily yield CPU to another thread.
 */
void fut_thread_yield(void);

/**
 * Exit the current thread (does not return).
 */
[[noreturn]] void fut_thread_exit(void);

/**
 * Sleep for specified milliseconds.
 *
 * @param millis  Milliseconds to sleep
 */
void fut_thread_sleep(uint64_t millis);

/**
 * Get current running thread.
 *
 * @return Current thread, or nullptr if none
 */
fut_thread_t *fut_thread_current(void);

/**
 * Set current thread (internal scheduler use only).
 *
 * @param thread  Thread to set as current
 */
void fut_thread_set_current(fut_thread_t *thread);

fut_thread_t *fut_thread_find(uint64_t tid);
void fut_thread_set_deadline(uint64_t abs_tick);
uint64_t fut_thread_get_deadline(void);
int fut_thread_priority_raise(fut_thread_t *thread, int new_priority);
int fut_thread_priority_restore(fut_thread_t *thread);

/* ============================================================
 *   Field Offset Verification (for assembly code)
 * ============================================================ */

/* These macros provide compile-time verification that assembly code
 * offsets match the actual C structure layout. */

#define FUT_THREAD_OFFSETOF_CONTEXT    (offsetof(fut_thread_t, context))
#define FUT_THREAD_OFFSETOF_IRQ_FRAME  (offsetof(fut_thread_t, irq_frame))

/* Context structure offsets (64-bit) - see arch/x86_64/regs.h */
#define FUT_CONTEXT_OFFSETOF_RBX       (0)
#define FUT_CONTEXT_OFFSETOF_RBP       (8)
#define FUT_CONTEXT_OFFSETOF_R12       (16)
#define FUT_CONTEXT_OFFSETOF_R13       (24)
#define FUT_CONTEXT_OFFSETOF_R14       (32)
#define FUT_CONTEXT_OFFSETOF_R15       (40)
#define FUT_CONTEXT_OFFSETOF_RSP       (48)
#define FUT_CONTEXT_OFFSETOF_RIP       (56)
#define FUT_CONTEXT_OFFSETOF_RFLAGS    (64)
#define FUT_CONTEXT_OFFSETOF_CS        (72)
#define FUT_CONTEXT_OFFSETOF_SS        (80)
#define FUT_CONTEXT_OFFSETOF_FPU_STATE (88)
