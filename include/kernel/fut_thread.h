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
#if defined(__x86_64__)
#include <platform/x86_64/regs.h>
#elif defined(__aarch64__)
#include <platform/arm64/regs.h>
#endif

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
    void *alloc_base;                     // Original malloc pointer (for proper free)
    uint64_t _padding;                    // Padding to align context to 16 bytes

    fut_cpu_context_t context;            // Saved CPU context (64-bit, 16-byte aligned)
    fut_interrupt_frame_t *irq_frame;     // Saved interrupt frame (for IRQ context switches)
    enum fut_thread_state state;          // Current state
    int priority;                         // Effective priority (0-255, higher = higher priority)
    int base_priority;                    // Base priority (restored after PI)
    int pi_saved_priority;                // Saved priority when boosted
    bool pi_boosted;                      // Priority inheritance active
    uint64_t deadline_tick;               // Absolute deadline tick (0 = none)

    uint64_t wake_time;                   // Wake tick for sleeping threads

    /* CPU Affinity Configuration */
    uint64_t cpu_affinity_mask;           // Bitmask of allowed CPUs (bit 0 = CPU 0, etc)
    uint32_t preferred_cpu;               // Primary CPU preference (within allowed mask)
    bool hard_affinity;                   // Hard pin (true) vs soft preference (false)

    fut_thread_stats_t stats;             // Performance instrumentation data

    fut_thread_t *next;                   // Next in scheduler ready queue
    fut_thread_t *prev;                   // Previous in scheduler ready queue
    fut_thread_t *wait_next;              // Next in wait queue
    fut_thread_t *global_next;            // Next in global thread list
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
 * Mark per-CPU data as safe to access (called after initialization).
 */
void fut_thread_mark_percpu_safe(void);

/**
 * Set current thread (internal scheduler use only).
 *
 * @param thread  Thread to set as current
 */
void fut_thread_set_current(fut_thread_t *thread);

/**
 * Initialize a bootstrap kernel thread/task so early subsystems that rely on
 * fut_task_current() (e.g., VFS) can operate before the scheduler runs.
 * Safe to call multiple times; subsequent calls become no-ops.
 */
void fut_thread_init_bootstrap(void);

fut_thread_t *fut_thread_find(uint64_t tid);
void fut_thread_set_deadline(uint64_t abs_tick);
uint64_t fut_thread_get_deadline(void);
int fut_thread_priority_raise(fut_thread_t *thread, int new_priority);
int fut_thread_priority_restore(fut_thread_t *thread);

/* ============================================================
 *   CPU Affinity API
 * ============================================================ */

/**
 * Set CPU affinity to a single CPU (hard pin).
 * Thread will only run on the specified CPU.
 *
 * @param thread   Thread to configure
 * @param cpu_id   CPU ID to pin to (0-63)
 * @return 0 on success, -1 if invalid CPU
 */
int fut_thread_set_affinity(fut_thread_t *thread, uint32_t cpu_id);

/**
 * Set CPU affinity mask (soft preference).
 * Thread can run on any CPU in the mask, will prefer one.
 *
 * @param thread   Thread to configure
 * @param mask     Bitmask of allowed CPUs (bit N = CPU N)
 * @return 0 on success, -1 if mask is invalid
 */
int fut_thread_set_affinity_mask(fut_thread_t *thread, uint64_t mask);

/**
 * Get current CPU affinity mask for a thread.
 *
 * @param thread   Thread to query
 * @return Bitmask of allowed CPUs (or 0 if unrestricted)
 */
uint64_t fut_thread_get_affinity_mask(fut_thread_t *thread);

/**
 * Get preferred CPU for a thread.
 *
 * @param thread   Thread to query
 * @return Preferred CPU ID
 */
uint32_t fut_thread_get_preferred_cpu(fut_thread_t *thread);

/**
 * Set hard affinity mode (pin vs soft preference).
 *
 * @param thread    Thread to configure
 * @param hard_pin  true = hard pin (must run on affinity CPU),
 *                  false = soft preference (prefer but allow others)
 */
void fut_thread_set_hard_affinity(fut_thread_t *thread, bool hard_pin);

/**
 * Check if thread has hard affinity enforced.
 *
 * @param thread   Thread to query
 * @return true if hard-pinned, false if soft preference
 */
bool fut_thread_is_hard_affinity(fut_thread_t *thread);

/* ============================================================
 *   Field Offset Verification (for assembly code)
 * ============================================================ */

/* These macros provide compile-time verification that assembly code
 * offsets match the actual C structure layout. */

#define FUT_THREAD_OFFSETOF_CONTEXT    (offsetof(fut_thread_t, context))
#define FUT_THREAD_OFFSETOF_IRQ_FRAME  (offsetof(fut_thread_t, irq_frame))

/* Context structure offsets (64-bit) - see arch/x86_64/regs.h */
#define FUT_CONTEXT_OFFSETOF_R15       (0)
#define FUT_CONTEXT_OFFSETOF_R14       (8)
#define FUT_CONTEXT_OFFSETOF_R13       (16)
#define FUT_CONTEXT_OFFSETOF_R12       (24)
#define FUT_CONTEXT_OFFSETOF_RBX       (32)
#define FUT_CONTEXT_OFFSETOF_RBP       (40)
#define FUT_CONTEXT_OFFSETOF_RIP       (48)
#define FUT_CONTEXT_OFFSETOF_RSP       (56)
#define FUT_CONTEXT_OFFSETOF_RFLAGS    (64)
#define FUT_CONTEXT_OFFSETOF_CS        (72)
#define FUT_CONTEXT_OFFSETOF_SS        (80)
#define FUT_CONTEXT_OFFSETOF_RDI       (88)
#define FUT_CONTEXT_OFFSETOF_RSI       (96)
#define FUT_CONTEXT_OFFSETOF_RDX       (104)
#define FUT_CONTEXT_OFFSETOF_RCX       (112)
#define FUT_CONTEXT_OFFSETOF_RAX       (120)
#define FUT_CONTEXT_OFFSETOF_FX        (128)
