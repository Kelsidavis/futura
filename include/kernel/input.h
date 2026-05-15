// SPDX-License-Identifier: MPL-2.0
/*
 * input.h - Kernel input helper structures
 *
 * Provides simple ring buffers and helper functions used by the PS/2
 * keyboard and mouse drivers.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include <kernel/chrdev.h>
#include <kernel/errno.h>
#include <kernel/fut_sched.h>
#include <kernel/fut_waitq.h>
#include <kernel/uaccess.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_timer.h>
#include <kernel/fut_vfs.h>
#include <kernel/fut_task.h>
#include <futura/input_event.h>

#define FUT_INPUT_QUEUE_SIZE 128u
#define FUT_INPUT_QUEUE_MASK (FUT_INPUT_QUEUE_SIZE - 1u)

typedef struct fut_input_queue {
    struct fut_input_event events[FUT_INPUT_QUEUE_SIZE];
    uint32_t head;
    uint32_t tail;
    fut_spinlock_t lock;
    fut_waitq_t wait;
    /* Pending-wake flag for deferred mouse-move wakes.  See the wake
     * policy comment in fut_input_queue_push. */
    volatile int wake_pending;
} fut_input_queue_t;

static inline void fut_input_queue_init(fut_input_queue_t *q) {
    if (!q) {
        return;
    }
    q->head = 0;
    q->tail = 0;
    q->wake_pending = 0;
    fut_spinlock_init(&q->lock);
    fut_waitq_init(&q->wait);
}

static inline bool fut_input_queue_empty(const fut_input_queue_t *q) {
    return q->head == q->tail;
}

/* Timer-tick drain hook: deliver any deferred mouse-move wake.  Called
 * from fut_timer_tick at 100 Hz on x86_64.  Cheap when no wake is
 * pending or the waitq has no sleepers.  wake_pending is NOT cleared
 * here — only the read path clears it once the queue empties.  The
 * reason: the compositor may be running (not on the waitq) at the
 * moment we fire, so wake_one wakes nobody and returns; clearing the
 * flag here would lose the wake permanently if the compositor then
 * blocks before the next event.  Letting each tick retry the wake is
 * effectively free if there is no sleeper. */
static inline void fut_input_queue_drain_wake(fut_input_queue_t *q) {
    if (!q) return;
    if (__atomic_load_n(&q->wake_pending, __ATOMIC_ACQUIRE)) {
        fut_waitq_wake_one(&q->wait);
    }
}

/* IRQ-safe lock helpers for the input queue lock.  This lock is acquired
 * from both IRQ context (keyboard/mouse ISR calling push) and thread
 * context (compositor calling read).  Without IRQ-safe locking, a
 * keyboard IRQ firing while a thread holds the lock causes a deadlock
 * on single-CPU systems. */
static inline unsigned long _input_irq_save(void) {
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

static inline void _input_irq_restore(unsigned long flags) {
#if defined(__x86_64__)
    __asm__ volatile("pushq %0; popfq" :: "r"(flags) : "memory", "cc");
#elif defined(__aarch64__)
    __asm__ volatile("msr daif, %0" :: "r"(flags) : "memory");
#else
    (void)flags;
#endif
}

static inline void fut_input_queue_push(fut_input_queue_t *q,
                                        const struct fut_input_event *ev) {
    if (!q || !ev) {
        return;
    }
    unsigned long flags = _input_irq_save();
    fut_spinlock_acquire(&q->lock);
    bool was_empty = (q->head == q->tail);

    /* Coalesce consecutive MOUSE_MOVE events on the same axis.  At
     * Synaptics-grade ~80 pkts/sec the parser produces ~100-200 raw
     * REL_X/REL_Y events/sec; the compositor only renders the cursor
     * at the framebuffer's refresh rate, so summing the deltas instead
     * of queuing each report:
     *   - Cuts wake density to roughly the compositor's read rate.
     *   - Cuts context-switch density that triggers the known
     *     scheduler caller-saved register race on L490.
     *   - Loses zero information -- the compositor wants net dx, dy.
     * Only coalesce if the last queued event is the same type+axis
     * AND we haven't crossed an axis or event-type boundary (so a
     * MOUSE_BTN between two MOVEs still flushes the queue properly
     * for click-while-dragging). */
    if (ev->type == FUT_EV_MOUSE_MOVE && !was_empty) {
        uint32_t last_idx = (q->tail - 1u) & FUT_INPUT_QUEUE_MASK;
        struct fut_input_event *last = &q->events[last_idx];
        if (last->type == FUT_EV_MOUSE_MOVE && last->code == ev->code) {
            last->value += ev->value;
            last->ts_ns = ev->ts_ns;
            fut_spinlock_release(&q->lock);
            _input_irq_restore(flags);
            /* No queue-state change → no wake.  The existing pending
             * wake (or the next non-MOVE event) will deliver the
             * accumulated delta. */
            return;
        }
    }

    uint32_t next = (q->tail + 1u) & FUT_INPUT_QUEUE_MASK;
    if (next == q->head) {
        /* Drop oldest entry to keep queue bounded. */
        q->head = (q->head + 1u) & FUT_INPUT_QUEUE_MASK;
    }
    q->events[q->tail] = *ev;
    q->tail = next;
    fut_spinlock_release(&q->lock);
    _input_irq_restore(flags);

    /* Wake policy.  Direct wake from a PS/2 mouse IRQ at 80-200
     * reports/sec destabilises the L490 scheduler — the wake adds the
     * compositor to the ready queue and the resulting context-switch
     * churn locks the whole machine (clock stops).  So:
     *   - non-MOUSE_MOVE events (keys, buttons): wake immediately.
     *   - MOUSE_MOVE on a previously empty queue: wake immediately
     *     so a sleeping compositor never waits up to one tick for
     *     the first event of a motion burst.
     *   - MOUSE_MOVE on a non-empty queue: defer to the next 100 Hz
     *     timer tick via wake_pending, capping wake rate. */
    if (ev->type != FUT_EV_MOUSE_MOVE || was_empty) {
        fut_waitq_wake_one(&q->wait);
    } else {
        __atomic_store_n(&q->wake_pending, 1, __ATOMIC_RELEASE);
    }
}

static inline ssize_t fut_input_queue_read(fut_input_queue_t *q,
                                           int flags,
                                           void *u_buf,
                                           size_t nbytes) {
    if (!q || !u_buf) {
        return -EINVAL;
    }

    const size_t ev_size = sizeof(struct fut_input_event);
    size_t capacity = nbytes / ev_size;
    if (capacity == 0) {
        return -EINVAL;
    }

    size_t copied = 0;
    struct fut_input_event ev;

    while (copied < capacity) {
        unsigned long irqflags = _input_irq_save();
        fut_spinlock_acquire(&q->lock);
        while (fut_input_queue_empty(q)) {
            if (copied > 0) {
                fut_spinlock_release(&q->lock);
                _input_irq_restore(irqflags);
                return (ssize_t)(copied * ev_size);
            }
            if (flags & O_NONBLOCK) {
                fut_spinlock_release(&q->lock);
                _input_irq_restore(irqflags);
                return -EAGAIN;
            }
            /* Check for pending unblocked signals → EINTR */
            fut_task_t *_t = fut_task_current();
            if (_t) {
                uint64_t _p = __atomic_load_n(&_t->pending_signals, __ATOMIC_ACQUIRE);
                if (_p & ~_t->signal_mask) {
                    fut_spinlock_release(&q->lock);
                    _input_irq_restore(irqflags);
                    return -EINTR;
                }
            }
            /* CRITICAL: hold q->lock through sleep_locked. sleep_locked will
             * release q->lock atomically with the enqueue+state-transition,
             * closing the lost-wakeup race window. If we released the lock
             * first, a wake could fire between release and sleep_locked,
             * find the waitq empty, and the event would be queued with no
             * sleeper to wake until the NEXT event arrives. */
            fut_waitq_sleep_locked(&q->wait, &q->lock, FUT_THREAD_BLOCKED);
            irqflags = _input_irq_save();
            fut_spinlock_acquire(&q->lock);
        }

        ev = q->events[q->head];
        q->head = (q->head + 1u) & FUT_INPUT_QUEUE_MASK;
        fut_spinlock_release(&q->lock);
        _input_irq_restore(irqflags);

        /* Note: u_buf is a kernel buffer (from sys_read's fut_malloc), not userspace.
         * The VFS layer handles the final copy to userspace, so we use memcpy here. */
        void *dest = (uint8_t *)u_buf + copied * ev_size;
        __builtin_memcpy(dest, &ev, ev_size);
        copied++;

        if (fut_input_queue_empty(q)) {
            /* Queue fully drained — clear wake_pending so the timer
             * tick stops issuing no-op wakes until the next event
             * arrives. */
            __atomic_store_n(&q->wake_pending, 0, __ATOMIC_RELEASE);
            break;
        }
    }

    return (ssize_t)(copied * ev_size);
}

static inline uint64_t fut_input_now_ns(void) {
    return fut_get_ticks() * 10000000ull;
}

#if defined(__x86_64__)
int fut_input_hw_init(bool want_keyboard, bool want_mouse);
#else
/* ARM64: virtio-input driver handles keyboard and mouse */
#include <kernel/virtio_input.h>
static inline int fut_input_hw_init(bool want_keyboard, bool want_mouse) {
    (void)want_keyboard;
    (void)want_mouse;
    return virtio_input_hw_init();
}
#endif
