/* kernel/scheduler/fut_waitq.c - Wait queue primitives
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements wait queues for blocking thread operations (waitpid, futex, timers, I/O).
 */

#include "../../include/kernel/fut_waitq.h"
#include <stdbool.h>

void fut_waitq_init(fut_waitq_t *q) {
    if (!q) {
        return;
    }
    q->head = NULL;
    q->tail = NULL;
    fut_spinlock_init(&q->lock);
}

static void fut_waitq_enqueue(fut_waitq_t *q, fut_thread_t *thread) {
    thread->wait_next = NULL;
    if (q->tail) {
        q->tail->wait_next = thread;
    } else {
        q->head = thread;
    }
    q->tail = thread;
}

void fut_waitq_sleep_locked(fut_waitq_t *q, fut_spinlock_t *released_lock,
                            enum fut_thread_state state) {
    if (!q) {
        if (released_lock) {
            fut_spinlock_release(released_lock);
        }
        return;
    }

    fut_thread_t *thread = fut_thread_current();
    if (!thread) {
        if (released_lock) {
            fut_spinlock_release(released_lock);
        }
        return;
    }

    if (state == FUT_THREAD_RUNNING) {
        state = FUT_THREAD_BLOCKED;
    }
    thread->state = state;
    thread->blocked_waitq = q;

    // Check if released_lock is the same as q->lock to avoid double-acquire deadlock
    // This can happen when caller already holds the wait queue lock
    int lock_already_held = (released_lock == &q->lock);

    if (!lock_already_held) {
        fut_spinlock_acquire(&q->lock);
    }
    fut_waitq_enqueue(q, thread);
    if (!lock_already_held) {
        fut_spinlock_release(&q->lock);
    }

    if (released_lock) {
        fut_spinlock_release(released_lock);
    }

    fut_schedule();
}

static fut_thread_t *fut_waitq_dequeue(fut_waitq_t *q) {
    fut_thread_t *thread = q->head;
    if (!thread) {
        return NULL;
    }
    q->head = thread->wait_next;
    if (!q->head) {
        q->tail = NULL;
    }
    thread->wait_next = NULL;
    return thread;
}

static void fut_waitq_make_ready(fut_thread_t *thread) {
    if (!thread) {
        return;
    }
    thread->blocked_waitq = NULL;
    thread->state = FUT_THREAD_READY;
    fut_sched_add_thread(thread);
}

void fut_waitq_wake_one(fut_waitq_t *q) {
    if (!q) {
        return;
    }
    fut_spinlock_acquire(&q->lock);
    fut_thread_t *thread = fut_waitq_dequeue(q);
    fut_spinlock_release(&q->lock);
    fut_waitq_make_ready(thread);
}

void fut_waitq_wake_all(fut_waitq_t *q) {
    if (!q) {
        return;
    }
    fut_spinlock_acquire(&q->lock);
    fut_thread_t *thread = q->head;
    q->head = NULL;
    q->tail = NULL;
    fut_spinlock_release(&q->lock);

    while (thread) {
        fut_thread_t *next = thread->wait_next;
        thread->wait_next = NULL;
        fut_waitq_make_ready(thread);
        thread = next;
    }
}

bool fut_waitq_remove_thread(fut_waitq_t *q, fut_thread_t *thread) {
    if (!q || !thread) {
        return false;
    }

    bool removed = false;
    fut_spinlock_acquire(&q->lock);
    fut_thread_t *prev = NULL;
    fut_thread_t *curr = q->head;
    while (curr) {
        if (curr == thread) {
            if (prev) {
                prev->wait_next = curr->wait_next;
            } else {
                q->head = curr->wait_next;
            }
            if (q->tail == curr) {
                q->tail = prev;
            }
            curr->wait_next = NULL;
            removed = true;
            break;
        }
        prev = curr;
        curr = curr->wait_next;
    }
    fut_spinlock_release(&q->lock);
    return removed;
}

/**
 * Sleep on a wait queue with a timer-based timeout.
 *
 * This solves the lost-wakeup race: adds the thread to the wait queue BEFORE
 * starting the timer, so the timer callback always finds the thread on the
 * queue.  Without this ordering, a preemption between fut_timer_start() and
 * fut_waitq_sleep_locked() causes the timer to fire and find an empty queue,
 * leaving the thread blocked forever.
 *
 * @param q              Wait queue to sleep on
 * @param timeout_ticks  Timer expiry in ticks (0 = no timeout, block forever)
 * @param released_lock  Optional lock to release after enqueuing
 */
/* Context passed to the timer callback so it can both signal that the
 * timer fired AND wake threads on the queue. */
struct timed_wakeup_ctx {
    fut_waitq_t *q;
    volatile int fired;   /* set to 1 by callback — checked after CLI */
};

static void timed_wakeup_cb(void *arg) {
    struct timed_wakeup_ctx *ctx = (struct timed_wakeup_ctx *)arg;
    if (!ctx) return;
    ctx->fired = 1;
    if (ctx->q) {
        fut_waitq_wake_all(ctx->q);
    }
}

void fut_waitq_sleep_timed(fut_waitq_t *q, uint64_t timeout_ticks,
                           fut_spinlock_t *released_lock) {
    if (!q) {
        if (released_lock)
            fut_spinlock_release(released_lock);
        return;
    }

    fut_thread_t *thread = fut_thread_current();
    if (!thread) {
        if (released_lock)
            fut_spinlock_release(released_lock);
        return;
    }

    /* Use a stack-local context so the timer callback can set a flag
     * indicating it already fired.  This closes the lost-timer race
     * without requiring interrupts to be disabled during fut_timer_start
     * (which does heap allocation and can deadlock on single-CPU). */
    struct timed_wakeup_ctx ctx = { .q = q, .fired = 0 };

    /* Step 1: Start the timer with interrupts ENABLED.  fut_timer_start
     * calls fut_malloc, which may spin on the heap lock — this is safe
     * only with interrupts enabled so preempted lock holders can run. */
    if (timeout_ticks > 0) {
        extern int fut_timer_start(uint64_t ticks, void (*cb)(void *), void *arg);
        fut_timer_start(timeout_ticks, timed_wakeup_cb, &ctx);
    }

    /* Step 2: Disable interrupts for the enqueue sequence. */
#if defined(__x86_64__)
    unsigned long flags;
    __asm__ volatile("pushfq; popq %0; cli" : "=r"(flags) :: "memory");
#elif defined(__aarch64__)
    unsigned long flags;
    __asm__ volatile("mrs %0, daif; msr daifset, #2" : "=r"(flags) :: "memory");
#else
    unsigned long flags = 0;
#endif

    /* Step 3: Check if the timer already fired between step 1 and step 2.
     * If so, skip blocking — the wakeup already happened. */
    if (timeout_ticks > 0 && ctx.fired) {
#if defined(__x86_64__)
        __asm__ volatile("pushq %0; popfq" :: "r"(flags) : "memory", "cc");
#elif defined(__aarch64__)
        __asm__ volatile("msr daif, %0" :: "r"(flags) : "memory");
#endif
        if (released_lock)
            fut_spinlock_release(released_lock);
        /* Timer already removed from list by process_timer_events. */
        return;
    }

    /* Step 4: Set BLOCKED + enqueue atomically (IRQs off, timer can't
     * fire until we re-enable).  The timer callback will find the thread
     * on the queue when it eventually fires. */
    thread->state = FUT_THREAD_BLOCKED;
    thread->blocked_waitq = q;

    int lock_already_held = (released_lock == &q->lock);
    if (!lock_already_held)
        fut_spinlock_acquire(&q->lock);
    fut_waitq_enqueue(q, thread);
    if (!lock_already_held)
        fut_spinlock_release(&q->lock);

    if (released_lock)
        fut_spinlock_release(released_lock);

    /* Step 5: Re-enable interrupts and schedule.  When the timer fires
     * it will find the thread on the waitqueue and wake it. */
#if defined(__x86_64__)
    __asm__ volatile("pushq %0; popfq" :: "r"(flags) : "memory", "cc");
#elif defined(__aarch64__)
    __asm__ volatile("msr daif, %0" :: "r"(flags) : "memory");
#endif

    fut_schedule();

    /* Step 6: Cancel the timer (harmless no-op if already fired). */
    if (timeout_ticks > 0) {
        extern int fut_timer_cancel(void (*cb)(void *), void *arg);
        fut_timer_cancel(timed_wakeup_cb, &ctx);
    }
}
