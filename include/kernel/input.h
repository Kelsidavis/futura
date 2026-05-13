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

/* Called from timer tick to deliver deferred mouse-move wakes. */
static inline void fut_input_queue_drain_wake(fut_input_queue_t *q) {
    if (!q) return;
    if (__atomic_exchange_n(&q->wake_pending, 0, __ATOMIC_ACQ_REL)) {
        fut_waitq_wake_one(&q->wait);
    }
}

static inline bool fut_input_queue_empty(const fut_input_queue_t *q) {
    return q->head == q->tail;
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
    uint32_t next = (q->tail + 1u) & FUT_INPUT_QUEUE_MASK;
    if (next == q->head) {
        /* Drop oldest entry to keep queue bounded. */
        q->head = (q->head + 1u) & FUT_INPUT_QUEUE_MASK;
    }
    q->events[q->tail] = *ev;
    q->tail = next;
    fut_spinlock_release(&q->lock);
    _input_irq_restore(flags);

    /* Defer mouse-move wakes: calling fut_waitq_wake_one from the PS/2
     * mouse IRQ handler causes a freeze on L490 (confirmed by disabling
     * wake entirely — no freeze). The wake adds the compositor to the
     * ready queue and triggers a context-switch cycle that, at 80-200
     * reports/sec from a Synaptics touchpad, destabilizes the scheduler.
     *
     * Instead of waking immediately, set a per-queue flag and let the
     * timer tick (100Hz, in fut_timer_tick) call the deferred wakes.
     * This bounds wake rate to timer frequency and moves the wake out
     * of the mouse-ISR call chain. Button/non-mouse events still wake
     * immediately. */
    if (ev->type == FUT_EV_MOUSE_MOVE) {
        __atomic_store_n(&q->wake_pending, 1, __ATOMIC_RELEASE);
    } else {
        fut_waitq_wake_one(&q->wait);
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
            fut_spinlock_release(&q->lock);
            _input_irq_restore(irqflags);
            if (copied > 0) {
                return (ssize_t)(copied * ev_size);
            }
            if (flags & O_NONBLOCK) {
                return -EAGAIN;
            }
            /* Check for pending unblocked signals → EINTR */
            fut_task_t *_t = fut_task_current();
            if (_t) {
                uint64_t _p = __atomic_load_n(&_t->pending_signals, __ATOMIC_ACQUIRE);
                if (_p & ~_t->signal_mask)
                    return -EINTR;
            }
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
