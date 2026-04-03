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
 * ARM64 requires 8-byte alignment for 64-bit atomic operations.
 */
typedef struct {
    _Atomic uint64_t locked;
} __attribute__((aligned(8))) fut_spinlock_t;

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
 * Try to acquire a spinlock without blocking.
 *
 * @param lock  Spinlock to try
 * @return true if lock acquired, false if already held
 */
static inline bool fut_spinlock_trylock(fut_spinlock_t *lock) {
    uint64_t expected = 0;
    return atomic_compare_exchange_strong_explicit(&lock->locked, &expected, 1,
                                                   memory_order_acquire,
                                                   memory_order_relaxed);
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
 * Start the scheduler, enabling preemptive context switches.
 *
 * Must be called after all kernel initialization is complete.
 * Before this is called, timer interrupts won't cause context switches.
 */
void fut_sched_start(void);

/**
 * Check if scheduler has been started.
 */
bool fut_sched_is_started(void);

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
 * Check RLIMIT_CPU limits for a task and send signals if exceeded.
 * Exposed for unit testing from the kernel self-test suite.
 */
void fut_sched_check_rlimit_cpu(struct fut_task *task);

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
 * Compute time slice (in scheduler ticks at FUT_TIMER_HZ=100) from a nice value.
 *
 * Nice -20 (highest priority) -> 10 ticks (100ms)
 * Nice   0 (default)          ->  2 ticks  (20ms)
 * Nice  19 (lowest priority)  ->  1 tick   (10ms minimum quantum)
 *
 * Formula: max(1, 10 - (nice / 2))
 *
 * @param nice  Nice value (-20 to 19)
 * @return Time slice in ticks (1 to 10)
 */
int fut_sched_nice_to_slice(int nice);

/**
 * Compute time slice (in scheduler ticks at FUT_TIMER_HZ=100) from a nice value.
 *
 * Nice -20 (highest priority) -> 10 ticks (100ms)
 * Nice   0 (default)          ->  2 ticks  (20ms)
 * Nice  19 (lowest priority)  ->  1 tick   (10ms minimum quantum)
 *
 * Formula: max(1, 10 - (nice / 2))
 *
 * @param nice  Nice value (-20 to 19)
 * @return Time slice in ticks (1 to 10)
 */
int fut_sched_nice_to_slice(int nice);

/**
 * Get scheduler statistics.
 *
 * @param ready_count    Output: number of ready threads
 * @param running_count  Output: number of running threads
 */
void fut_sched_stats(uint64_t *ready_count, uint64_t *running_count);
