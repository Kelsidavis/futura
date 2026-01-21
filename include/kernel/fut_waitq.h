// SPDX-License-Identifier: MPL-2.0
/*
 * fut_waitq.h - Kernel wait queue primitives
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Lightweight sleep/wakeup queues used by the scheduler to block threads
 * until an event occurs. These helpers build on the existing fut_sched
 * infrastructure and ensure we never spin while waiting for child exit or
 * timer events.
 *
 * Wait queues provide a mechanism for threads to sleep until a condition
 * becomes true, avoiding busy-waiting which wastes CPU cycles. Common
 * use cases include:
 *   - Waiting for child process exit (waitpid)
 *   - Waiting for I/O completion
 *   - Waiting for locks/semaphores
 *   - Waiting for timer events
 *
 * Usage pattern:
 *   1. Initialize wait queue with fut_waitq_init()
 *   2. Thread calls fut_waitq_sleep_locked() to sleep
 *   3. Another thread/interrupt calls fut_waitq_wake_one/all() to wake
 *   4. Woken thread continues execution
 *
 * Thread safety:
 *   Wait queues have internal spinlocks for thread-safe operations.
 *   The sleep function takes an external lock parameter to support
 *   the common "check condition, then sleep" pattern atomically.
 */

#pragma once

#include <kernel/fut_sched.h>
#include <kernel/fut_thread.h>

/**
 * Wait queue structure.
 *
 * A simple linked list of sleeping threads with head/tail pointers
 * for O(1) append operations. Protected by an internal spinlock.
 */
typedef struct fut_waitq {
    fut_thread_t *head;     /**< First thread in the queue (NULL if empty) */
    fut_thread_t *tail;     /**< Last thread in the queue (NULL if empty) */
    fut_spinlock_t lock;    /**< Spinlock protecting queue operations */
} fut_waitq_t;

/**
 * Initialize a wait queue.
 *
 * Must be called before any other wait queue operations. Sets the
 * queue to empty state with unlocked spinlock.
 *
 * @param q  Pointer to wait queue to initialize
 *
 * Example:
 *   fut_waitq_t my_waitq;
 *   fut_waitq_init(&my_waitq);
 */
void fut_waitq_init(fut_waitq_t *q);

/**
 * Sleep on a wait queue while holding an external lock.
 *
 * Atomically releases the external lock and puts the current thread
 * to sleep on the wait queue. The external lock is released BEFORE
 * the thread is added to the queue, preventing deadlock.
 *
 * This function does NOT return until the thread is woken by
 * fut_waitq_wake_one() or fut_waitq_wake_all().
 *
 * @param q             Wait queue to sleep on
 * @param released_lock External lock to release before sleeping (must be held)
 * @param state         Thread state to set (typically FUT_THREAD_BLOCKED)
 *
 * Common usage pattern for condition waiting:
 *   fut_spinlock_acquire(&my_lock);
 *   while (!condition) {
 *       fut_waitq_sleep_locked(&waitq, &my_lock, FUT_THREAD_BLOCKED);
 *       // Re-acquire lock on wakeup
 *       fut_spinlock_acquire(&my_lock);
 *   }
 *   // Condition is true, proceed
 *   fut_spinlock_release(&my_lock);
 */
void fut_waitq_sleep_locked(fut_waitq_t *q, fut_spinlock_t *released_lock,
                            enum fut_thread_state state);

/**
 * Wake one thread sleeping on the wait queue.
 *
 * Removes the first thread from the wait queue and makes it runnable.
 * If the queue is empty, this function does nothing.
 *
 * Use this for single-waiter scenarios or when only one thread should
 * handle the event (e.g., mutex release, single resource available).
 *
 * @param q  Wait queue to wake a thread from
 *
 * Example:
 *   // Producer thread
 *   produce_item();
 *   fut_waitq_wake_one(&consumer_waitq);
 */
void fut_waitq_wake_one(fut_waitq_t *q);

/**
 * Wake all threads sleeping on the wait queue.
 *
 * Removes all threads from the wait queue and makes them all runnable.
 * If the queue is empty, this function does nothing.
 *
 * Use this for broadcast scenarios where all waiters should be notified
 * (e.g., child process exit, condition variable broadcast, shutdown).
 *
 * @param q  Wait queue to wake all threads from
 *
 * Example:
 *   // Parent process notification
 *   child_process_exit();
 *   fut_waitq_wake_all(&parent->child_waiters);
 */
void fut_waitq_wake_all(fut_waitq_t *q);

/**
 * Remove a specific thread from a wait queue.
 *
 * Searches the wait queue for the given thread and removes it if found.
 * The thread is NOT automatically made runnable; the caller must handle
 * the thread's state transition.
 *
 * This is typically used for timeout handling or cancellation scenarios
 * where a thread needs to be removed from a wait queue before it would
 * normally be woken.
 *
 * @param q       Wait queue to search
 * @param thread  Thread to remove from the queue
 * @return true if thread was found and removed, false if not in queue
 *
 * Example:
 *   // Timeout handler
 *   if (fut_waitq_remove_thread(&waitq, timed_out_thread)) {
 *       // Thread was waiting, handle timeout
 *       timed_out_thread->state = FUT_THREAD_READY;
 *       fut_sched_add_thread(timed_out_thread);
 *   }
 */
bool fut_waitq_remove_thread(fut_waitq_t *q, fut_thread_t *thread);
