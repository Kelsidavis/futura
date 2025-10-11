/* fut_task.c - Futura OS Task Implementation (C23)
 *
 * Copyright (c) 2025 Kelsi Davis / Licensed under the MPL v2.0 — see LICENSE for details
 *
 * Tasks are process containers that hold threads and resources.
 */

#include "../../include/kernel/fut_task.h"
#include "../../include/kernel/fut_sched.h"
#include "../../include/kernel/fut_memory.h"
#include <stdatomic.h>

/* ============================================================
 *   Task Management
 * ============================================================ */

/* Global task list */
fut_task_t *fut_task_list = nullptr;  /* Exposed for stats/debugging */
static _Atomic uint32_t next_pid = 1;

/* Task list lock */
static fut_spinlock_t task_list_lock = { .locked = 0 };

/**
 * Create a new task (process container).
 */
fut_task_t *fut_task_create(void) {
    // Allocate task structure
    auto task = (fut_task_t *)kmalloc(sizeof(fut_task_t));
    if (!task) {
        return nullptr;
    }

    // Initialize task
    *task = (fut_task_t){
        .pid = atomic_fetch_add_explicit(&next_pid, 1, memory_order_seq_cst),
        .page_table_root = 0,  // Future: allocate page table
        .threads = nullptr,
        .thread_count = 0,
        .next = nullptr
    };

    // Add to global task list
    fut_spinlock_acquire(&task_list_lock);
    task->next = fut_task_list;
    fut_task_list = task;
    fut_spinlock_release(&task_list_lock);

    return task;
}

/**
 * Add a thread to a task's thread list.
 */
void fut_task_add_thread(fut_task_t *task, fut_thread_t *thread) {
    if (!task || !thread) {
        return;
    }

    // Link thread into task's thread list
    thread->next = task->threads;
    if (task->threads) {
        task->threads->prev = thread;
    }
    thread->prev = nullptr;
    task->threads = thread;

    task->thread_count++;
}

/**
 * Remove a thread from a task's thread list.
 */
void fut_task_remove_thread(fut_task_t *task, fut_thread_t *thread) {
    if (!task || !thread) {
        return;
    }

    // Unlink thread from task's thread list
    if (thread->prev) {
        thread->prev->next = thread->next;
    } else {
        task->threads = thread->next;
    }

    if (thread->next) {
        thread->next->prev = thread->prev;
    }

    thread->next = nullptr;
    thread->prev = nullptr;

    task->thread_count--;
}

/**
 * Destroy a task and all its threads.
 */
void fut_task_destroy(fut_task_t *task) {
    if (!task) {
        return;
    }

    // Free all threads (stub - proper cleanup later)
    fut_thread_t *thread = task->threads;
    while (thread) {
        auto next = thread->next;
        kfree(thread->stack_base);
        kfree(thread);
        thread = next;
    }

    // Remove from task list
    fut_spinlock_acquire(&task_list_lock);
    if (fut_task_list == task) {
        fut_task_list = task->next;
    } else {
        fut_task_t *prev = fut_task_list;
        while (prev && prev->next != task) {
            prev = prev->next;
        }
        if (prev) {
            prev->next = task->next;
        }
    }
    fut_spinlock_release(&task_list_lock);

    // Free task structure
    kfree(task);
}
