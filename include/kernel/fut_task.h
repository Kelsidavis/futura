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

/* Forward declaration */
typedef struct fut_task fut_task_t;

/* ============================================================
 *   Task Structure (Process Container)
 * ============================================================ */

struct fut_task {
    uint64_t pid;                      // Process ID (64-bit)

    uintptr_t page_table_root;         // Page table root (future VMM)

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
