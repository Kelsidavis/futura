// SPDX-License-Identifier: MPL-2.0
/*
 * fut_waitq.c - Wait queue primitives
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

    fut_spinlock_acquire(&q->lock);
    fut_waitq_enqueue(q, thread);
    fut_spinlock_release(&q->lock);

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
