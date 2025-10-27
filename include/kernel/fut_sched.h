/* fut_sched.h - Futura OS Scheduler (C23)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Preemptive, priority-based round-robin scheduler.
 * SMP-ready design with per-CPU current thread tracking.
 */

#pragma once

#include <stdint.h>
#include <stdatomic.h>
#include "fut_thread.h"

/* ============================================================
 *   Scheduler Constants
 * ============================================================ */

#define FUT_MAX_PRIORITY 256            // Priority levels: 0-255
#define FUT_DEFAULT_PRIORITY 128        // Default thread priority
#define FUT_IDLE_PRIORITY 0             // Idle thread priority

/* ============================================================
 *   Spinlock (SMP Placeholder)
 * ============================================================ */

/**
 * Spinlock for SMP synchronization (stubbed for single CPU).
 */
typedef struct {
    _Atomic uint64_t locked;
} fut_spinlock_t;

/**
 * Initialize a spinlock.
 *
 * @param lock  Spinlock to initialize
 */
static inline void fut_spinlock_init(fut_spinlock_t *lock) {
    atomic_store_explicit(&lock->locked, 0, memory_order_relaxed);
}

/**
 * Acquire a spinlock.
 *
 * @param lock  Spinlock to acquire
 */
static inline void fut_spinlock_acquire(fut_spinlock_t *lock) {
    // Spin until we successfully acquire the lock
    uint64_t expected = 0;
    while (!atomic_compare_exchange_weak_explicit(&lock->locked, &expected, 1,
                                                    memory_order_acquire,
                                                    memory_order_relaxed)) {
        expected = 0;
        // Hint to CPU that we're spinning
        #if defined(__x86_64__)
        __asm__ volatile("pause" ::: "memory");
        #elif defined(__aarch64__)
        __asm__ volatile("yield" ::: "memory");
        #endif
    }
}

/**
 * Release a spinlock.
 *
 * @param lock  Spinlock to release
 */
static inline void fut_spinlock_release(fut_spinlock_t *lock) {
    atomic_store_explicit(&lock->locked, 0, memory_order_release);
}

/* ============================================================
 *   Scheduler API
 * ============================================================ */

/**
 * Initialize the scheduler subsystem (for BSP).
 *
 * Sets up ready queues and creates idle thread for boot processor.
 */
void fut_sched_init(void);

/**
 * Initialize scheduler for a specific CPU (for APs).
 *
 * Creates idle thread for this application processor.
 */
void fut_sched_init_cpu(void);

/**
 * Schedule next thread to run.
 *
 * Selects highest priority READY thread and context switches to it.
 * Called from timer interrupt or explicit yield.
 */
void fut_schedule(void);

/**
 * Scheduler tick handler - called from timer interrupt.
 *
 * Handles timer-driven scheduling (preemption).
 * This function is called by fut_timer_tick().
 */
void fut_sched_tick(void);

/**
 * Add a thread to the ready queue.
 *
 * @param thread  Thread to add (must be in READY state)
 */
void fut_sched_add_thread(fut_thread_t *thread);

/**
 * Remove a thread from the ready queue.
 *
 * @param thread  Thread to remove
 */
void fut_sched_remove_thread(fut_thread_t *thread);

/**
 * Get scheduler statistics.
 *
 * @param ready_count    Output: number of ready threads
 * @param running_count  Output: number of running threads
 */
void fut_sched_stats(uint64_t *ready_count, uint64_t *running_count);
