/* kernel/scheduler/fut_waitq.c - Wait queue primitives
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements wait queues for blocking thread operations (waitpid, futex, timers, I/O).
 */

#include "../../include/kernel/fut_waitq.h"
#include <stdbool.h>

/* ── IRQ-safe lock helpers ─────────────────────────────────────────
 * q->lock is acquired from both thread context AND IRQ context
 * (timer callbacks call fut_waitq_wake_all).  On single-CPU, if a
 * thread is preempted while holding q->lock and another thread later
 * disables interrupts and tries to acquire the same lock, the system
 * deadlocks.  By always disabling IRQs before acquiring q->lock, no
 * thread can be preempted while holding it, eliminating the deadlock.
 */
static inline unsigned long wq_irq_save(void) {
    unsigned long flags;
#if defined(__x86_64__)
    __asm__ volatile("pushfq; popq %0; cli" : "=r"(flags) :: "memory");
#elif defined(__aarch64__)
    __asm__ volatile("mrs %0, daif; msr daifset, #2" : "=r"(flags) :: "memory");
#else
    flags = 0;
#endif
    return flags;
}

static inline void wq_irq_restore(unsigned long flags) {
#if defined(__x86_64__)
    __asm__ volatile("pushq %0; popfq" :: "r"(flags) : "memory", "cc");
#elif defined(__aarch64__)
    __asm__ volatile("msr daif, %0" :: "r"(flags) : "memory");
#else
    (void)flags;
#endif
}

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

    int lock_already_held = (released_lock == &q->lock);

    unsigned long flags = wq_irq_save();
    if (!lock_already_held) {
        fut_spinlock_acquire(&q->lock);
    }
    fut_waitq_enqueue(q, thread);
    if (!lock_already_held) {
        fut_spinlock_release(&q->lock);
    }

    /* Release the caller's lock BEFORE restoring IRQs.  This prevents a
     * deadlock: if we restored IRQs first, a timer ISR could fire and
     * spin on released_lock (still held by this thread) → deadlock.
     * With this ordering, released_lock is free before any ISR can run. */
    if (released_lock) {
        fut_spinlock_release(released_lock);
    }
    wq_irq_restore(flags);

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
    unsigned long flags = wq_irq_save();
    fut_spinlock_acquire(&q->lock);
    fut_thread_t *thread = fut_waitq_dequeue(q);
    fut_spinlock_release(&q->lock);
    wq_irq_restore(flags);
    fut_waitq_make_ready(thread);
}

void fut_waitq_wake_all(fut_waitq_t *q) {
    if (!q) {
        return;
    }
    unsigned long flags = wq_irq_save();
    fut_spinlock_acquire(&q->lock);
    fut_thread_t *thread = q->head;
    q->head = NULL;
    q->tail = NULL;
    fut_spinlock_release(&q->lock);
    wq_irq_restore(flags);

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
    unsigned long flags = wq_irq_save();
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
    wq_irq_restore(flags);
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
     * only with interrupts enabled so preempted lock holders can run.
     * If the timer allocation fails (-ENOMEM), bail out immediately —
     * without a timer, the thread would sleep forever on the waitqueue. */
    int timer_ok = 0;
    if (timeout_ticks > 0) {
        extern int fut_timer_start(uint64_t ticks, void (*cb)(void *), void *arg);
        timer_ok = fut_timer_start(timeout_ticks, timed_wakeup_cb, &ctx);
        if (timer_ok != 0) {
            /* Timer allocation failed — don't block, return immediately */
            if (released_lock)
                fut_spinlock_release(released_lock);
            return;
        }
    }

    /* Step 2: Acquire q->lock with IRQ-safe locking, then check the
     * fired flag and enqueue atomically.  IRQ-safe locking prevents
     * deadlock: no thread can be preempted while holding q->lock. */
    thread->state = FUT_THREAD_BLOCKED;
    thread->blocked_waitq = q;

    int lock_already_held = (released_lock == &q->lock);
    unsigned long flags = wq_irq_save();
    if (!lock_already_held)
        fut_spinlock_acquire(&q->lock);

    /* Step 3: Check if the timer already fired before we got the lock.
     * If so, undo the BLOCKED state and bail out. */
    if (timeout_ticks > 0 && ctx.fired) {
        thread->state = FUT_THREAD_RUNNING;
        thread->blocked_waitq = NULL;
        if (!lock_already_held)
            fut_spinlock_release(&q->lock);
        wq_irq_restore(flags);
        if (released_lock)
            fut_spinlock_release(released_lock);
        return;
    }

    /* Step 4: Enqueue (still holding lock with IRQs off). */
    fut_waitq_enqueue(q, thread);
    if (!lock_already_held)
        fut_spinlock_release(&q->lock);
    wq_irq_restore(flags);

    if (released_lock)
        fut_spinlock_release(released_lock);

    /* Step 5: Schedule away.  When the timer fires it will find the
     * thread on the waitqueue and wake it. */
    fut_schedule();

    /* Step 6: Cancel the timer (harmless no-op if already fired). */
    if (timeout_ticks > 0) {
        extern int fut_timer_cancel(void (*cb)(void *), void *arg);
        fut_timer_cancel(timed_wakeup_cb, &ctx);
    }
}
