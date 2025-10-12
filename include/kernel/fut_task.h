/* fut_task.h - Futura OS Task (Process) Subsystem (C23)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Tasks are containers for threads, representing processes.
 * Each task has its own address space (future VMM integration).
 */

#pragma once

#include <stdint.h>
#include <stddef.h>
#include "fut_thread.h"
#include "fut_waitq.h"

struct fut_mm;

/* Forward declaration */
typedef struct fut_task fut_task_t;

/* ============================================================
 *   Task Structure (Process Container)
 * ============================================================ */

struct fut_task {
    uint64_t pid;                      // Process ID (64-bit)

    struct fut_mm *mm;                 // Address space

    struct fut_task *parent;           // Parent task
    struct fut_task *first_child;      // Child list head
    struct fut_task *sibling;          // Next sibling in parent list
    fut_waitq_t child_waiters;         // Wait queue for waitpid callers

    enum {
        FUT_TASK_RUNNING = 0,
        FUT_TASK_ZOMBIE,
    } state;

    int exit_code;                     // Exit status (8-bit in low byte)
    int term_signal;                   // Terminating signal (0 if normal exit)

    fut_thread_t *threads;             // Linked list of threads
    uint64_t thread_count;             // Number of threads in task

    fut_task_t *next;                  // Next task in system list
};

/* ============================================================
 *   Task API
 * ============================================================ */

/**
 * Create a new task (process).
 *
 * @return Task handle, or nullptr on failure
 */
[[nodiscard]] fut_task_t *fut_task_create(void);

/**
 * Add a thread to a task's thread list.
 *
 * @param task    Task to add thread to
 * @param thread  Thread to add
 */
void fut_task_add_thread(fut_task_t *task, fut_thread_t *thread);

/**
 * Remove a thread from a task's thread list.
 *
 * @param task    Task to remove thread from
 * @param thread  Thread to remove
 */
void fut_task_remove_thread(fut_task_t *task, fut_thread_t *thread);

/**
 * Destroy a task and all its threads.
 *
 * @param task  Task to destroy
 */
void fut_task_destroy(fut_task_t *task);

/**
 * Assign an address space to a task.
 */
void fut_task_set_mm(fut_task_t *task, struct fut_mm *mm);

/**
 * Fetch the address space associated with a task.
 */
struct fut_mm *fut_task_get_mm(const fut_task_t *task);

fut_task_t *fut_task_current(void);
void fut_task_exit_current(int status);
int fut_task_waitpid(int pid, int *status_out);
void fut_task_signal_exit(int signal);
