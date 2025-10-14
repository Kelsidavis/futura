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
#include <futura/input_event.h>

#define FUT_INPUT_QUEUE_SIZE 128u
#define FUT_INPUT_QUEUE_MASK (FUT_INPUT_QUEUE_SIZE - 1u)

typedef struct fut_input_queue {
    struct fut_input_event events[FUT_INPUT_QUEUE_SIZE];
    uint32_t head;
    uint32_t tail;
    fut_spinlock_t lock;
    fut_waitq_t wait;
} fut_input_queue_t;

static inline void fut_input_queue_init(fut_input_queue_t *q) {
    if (!q) {
        return;
    }
    q->head = 0;
    q->tail = 0;
    fut_spinlock_init(&q->lock);
    fut_waitq_init(&q->wait);
}

static inline bool fut_input_queue_empty(const fut_input_queue_t *q) {
    return q->head == q->tail;
}

static inline void fut_input_queue_push(fut_input_queue_t *q,
                                        const struct fut_input_event *ev) {
    if (!q || !ev) {
        return;
    }
    fut_spinlock_acquire(&q->lock);
    uint32_t next = (q->tail + 1u) & FUT_INPUT_QUEUE_MASK;
    if (next == q->head) {
        /* Drop oldest entry to keep queue bounded. */
        q->head = (q->head + 1u) & FUT_INPUT_QUEUE_MASK;
    }
    q->events[q->tail] = *ev;
    q->tail = next;
    fut_spinlock_release(&q->lock);
    fut_waitq_wake_one(&q->wait);
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
        fut_spinlock_acquire(&q->lock);
        while (fut_input_queue_empty(q)) {
            fut_spinlock_release(&q->lock);
            if (copied > 0) {
                return (ssize_t)(copied * ev_size);
            }
            if (flags & O_NONBLOCK) {
                return -EAGAIN;
            }
            fut_waitq_sleep_locked(&q->wait, &q->lock, FUT_THREAD_BLOCKED);
            fut_spinlock_acquire(&q->lock);
        }

        ev = q->events[q->head];
        q->head = (q->head + 1u) & FUT_INPUT_QUEUE_MASK;
        fut_spinlock_release(&q->lock);

        int rc = fut_copy_to_user((uint8_t *)u_buf + copied * ev_size, &ev, ev_size);
        if (rc != 0) {
            return (copied > 0) ? (ssize_t)(copied * ev_size) : rc;
        }
        copied++;

        if (fut_input_queue_empty(q)) {
            break;
        }
    }

    return (ssize_t)(copied * ev_size);
}

static inline uint64_t fut_input_now_ns(void) {
    return fut_get_ticks() * 1000000ull;
}

#if defined(__x86_64__)
int fut_input_hw_init(bool want_keyboard, bool want_mouse);
#else
static inline int fut_input_hw_init(bool want_keyboard, bool want_mouse) {
    (void)want_keyboard;
    (void)want_mouse;
    return -ENOTSUP;
}
#endif
