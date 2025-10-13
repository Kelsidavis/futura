// SPDX-License-Identifier: MPL-2.0
/*
 * fut_waitq.h - Kernel wait queue primitives
 *
 * Lightweight sleep/wakeup queues used by the scheduler to block threads
 * until an event occurs. These helpers build on the existing fut_sched
 * infrastructure and ensure we never spin while waiting for child exit or
 * timer events.
 */

#pragma once

#include <kernel/fut_sched.h>
#include <kernel/fut_thread.h>

typedef struct fut_waitq {
    fut_thread_t *head;
    fut_thread_t *tail;
    fut_spinlock_t lock;
} fut_waitq_t;

void fut_waitq_init(fut_waitq_t *q);
void fut_waitq_sleep_locked(fut_waitq_t *q, fut_spinlock_t *released_lock,
                            enum fut_thread_state state);
void fut_waitq_wake_one(fut_waitq_t *q);
void fut_waitq_wake_all(fut_waitq_t *q);
bool fut_waitq_remove_thread(fut_waitq_t *q, fut_thread_t *thread);
