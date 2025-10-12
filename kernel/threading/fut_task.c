/* fut_task.c - Futura OS Task Implementation (C23)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Tasks are process containers that hold threads and resources.
 * Migrated to x86-64 long mode architecture.
 */

#include "../../include/kernel/fut_task.h"
#include "../../include/kernel/fut_sched.h"
#include "../../include/kernel/fut_mm.h"
#include "../../include/kernel/fut_memory.h"
#include "../../include/kernel/errno.h"
#include <stdatomic.h>

/* ============================================================
 *   Task Management
 * ============================================================ */

/* Global task list */
fut_task_t *fut_task_list = NULL;  /* Exposed for stats/debugging */
static _Atomic uint64_t next_pid = 1;  /* 64-bit PID counter */

/* Task list lock */
static fut_spinlock_t task_list_lock = { .locked = 0 };

static void task_attach_child(fut_task_t *parent, fut_task_t *child) {
    if (!parent || !child) {
        return;
    }
    child->sibling = parent->first_child;
    parent->first_child = child;
}

static void task_detach_child(fut_task_t *parent, fut_task_t *child) {
    if (!parent || !child) {
        return;
    }
    fut_task_t **it = &parent->first_child;
    while (*it) {
        if (*it == child) {
            *it = child->sibling;
            child->sibling = NULL;
            return;
        }
        it = &(*it)->sibling;
    }
}

/**
 * Create a new task (process container).
 */
fut_task_t *fut_task_create(void) {
    fut_task_t *task = (fut_task_t *)fut_malloc(sizeof(fut_task_t));
    if (!task) {
        return NULL;
    }

    fut_task_t *parent = NULL;
    fut_thread_t *curr = fut_thread_current();
    if (curr) {
        parent = curr->task;
    }

    *task = (fut_task_t){
        .pid = atomic_fetch_add_explicit(&next_pid, 1, memory_order_seq_cst),
        .mm = NULL,
        .parent = parent,
        .first_child = NULL,
        .sibling = NULL,
        .state = FUT_TASK_RUNNING,
        .exit_code = 0,
        .term_signal = 0,
        .threads = NULL,
        .thread_count = 0,
        .next = NULL
    };

    fut_spinlock_acquire(&task_list_lock);
    if (parent) {
        task_attach_child(parent, task);
    }
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
    thread->prev = NULL;
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

    thread->next = NULL;
    thread->prev = NULL;

    task->thread_count--;
}

/**
 * Destroy a task and all its threads.
 */
void fut_task_destroy(fut_task_t *task) {
    if (!task) {
        return;
    }

    fut_thread_t *thread = task->threads;
    while (thread) {
        fut_thread_t *next = thread->next;
        fut_free(thread->stack_base);
        fut_free(thread);
        thread = next;
    }

    fut_spinlock_acquire(&task_list_lock);
    if (task->parent) {
        task_detach_child(task->parent, task);
    }
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

    if (task->mm) {
        fut_mm_release(task->mm);
        task->mm = NULL;
    }

    fut_free(task);
}

void fut_task_set_mm(fut_task_t *task, struct fut_mm *mm) {
    if (!task) {
        return;
    }
    if (task->mm == mm) {
        return;
    }

    if (mm) {
        fut_mm_retain(mm);
    }

    if (task->mm) {
        fut_mm_release(task->mm);
    }

    task->mm = mm;
}

struct fut_mm *fut_task_get_mm(const fut_task_t *task) {
    if (!task) {
        return NULL;
    }
    return task->mm;
}

fut_task_t *fut_task_current(void) {
    fut_thread_t *thread = fut_thread_current();
    return thread ? thread->task : NULL;
}

static void task_mark_exit(fut_task_t *task, int status, int signal) {
    fut_spinlock_acquire(&task_list_lock);
    task->state = FUT_TASK_ZOMBIE;
    task->exit_code = status & 0xFF;
    task->term_signal = signal & 0x7F;
    fut_spinlock_release(&task_list_lock);
}

void fut_task_exit_current(int status) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_thread_exit();
    }

    task_mark_exit(task, status, 0);

    if (task->mm) {
        fut_mm_switch(fut_mm_kernel());
        fut_mm_release(task->mm);
        task->mm = NULL;
    }

    fut_thread_exit();
}

void fut_task_signal_exit(int signal) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_thread_exit();
    }

    task_mark_exit(task, 0, signal);

    if (task->mm) {
        fut_mm_switch(fut_mm_kernel());
        fut_mm_release(task->mm);
        task->mm = NULL;
    }

    fut_thread_exit();
}

static int encode_wait_status(const fut_task_t *task) {
    if (task->term_signal) {
        return task->term_signal & 0x7F;
    }
    return (task->exit_code & 0xFF) << 8;
}

int fut_task_waitpid(int pid, int *status_out) {
    fut_task_t *parent = fut_task_current();
    if (!parent) {
        return -ECHILD;
    }

    for (;;) {
        fut_spinlock_acquire(&task_list_lock);

        bool has_children = parent->first_child != NULL;
        fut_task_t *child = parent->first_child;
        fut_task_t *match = NULL;

        while (child) {
            if ((pid <= 0) || ((int)child->pid == pid)) {
                if (child->state == FUT_TASK_ZOMBIE) {
                    match = child;
                    break;
                }
            }
            child = child->sibling;
        }

        if (!has_children) {
            fut_spinlock_release(&task_list_lock);
            return -ECHILD;
        }

        if (match) {
            int status = encode_wait_status(match);
            uint64_t child_pid = match->pid;
            task_detach_child(parent, match);
            fut_spinlock_release(&task_list_lock);

            if (status_out) {
                *status_out = status;
            }

            fut_task_destroy(match);
            return (int)child_pid;
        }

        fut_spinlock_release(&task_list_lock);
        fut_thread_yield();
    }
}
