/* sys_fork.c - fork() syscall implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements process cloning via fork().
 */

#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
#include <kernel/fut_mm.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_vfs.h>
#include <kernel/errno.h>
#include <kernel/uaccess.h>
#include <string.h>

extern void fut_printf(const char *fmt, ...);

/* Forward declarations */
static fut_mm_t *clone_mm(fut_mm_t *parent_mm);
static fut_thread_t *clone_thread(fut_thread_t *parent_thread, fut_task_t *child_task);

/* Dummy entry point for cloned threads - should never be called */
static void dummy_entry(void *arg) {
    (void)arg;
    /* This should never be called since we override the context */
    for (;;);
}

/**
 * fork() syscall - Create a new process by duplicating the calling process.
 *
 * Returns:
 *   - Child PID in parent process
 *   - 0 in child process
 *   - -errno on error
 */
long sys_fork(void) {
    fut_thread_t *parent_thread = fut_thread_current();
    if (!parent_thread) {
        return -ESRCH;
    }

    fut_task_t *parent_task = parent_thread->task;
    if (!parent_task) {
        return -ESRCH;
    }

    /* Create new child task */
    fut_task_t *child_task = fut_task_create();
    if (!child_task) {
        return -ENOMEM;
    }

    /* Clone address space (for now, create new empty one - COW can be added later) */
    fut_mm_t *parent_mm = fut_task_get_mm(parent_task);
    fut_mm_t *child_mm = NULL;

    if (parent_mm && parent_mm != fut_mm_kernel()) {
        child_mm = clone_mm(parent_mm);
        if (!child_mm) {
            fut_task_destroy(child_task);
            return -ENOMEM;
        }
        fut_task_set_mm(child_task, child_mm);
    }

    /* Clone the current thread into the child task */
    fut_thread_t *child_thread = clone_thread(parent_thread, child_task);
    if (!child_thread) {
        if (child_mm) {
            fut_mm_release(child_mm);
        }
        fut_task_destroy(child_task);
        return -ENOMEM;
    }

    /*
     * Set return value for child to 0
     * The child will see RAX=0 when it starts running
     */
    child_thread->context.rax = 0;

    fut_printf("[FORK] Created child: parent_pid=%llu parent_tid=%llu child_pid=%llu child_tid=%llu\n",
               parent_task->pid, parent_thread->tid,
               child_task->pid, child_thread->tid);

    /* Return child PID to parent */
    return (long)child_task->pid;
}

/**
 * Clone memory management context.
 * For now, creates a new empty address space.
 * TODO: Implement copy-on-write (COW) for efficiency.
 */
static fut_mm_t *clone_mm(fut_mm_t *parent_mm) {
    if (!parent_mm) {
        return NULL;
    }

    /* For now, just create a new empty userspace MM */
    fut_mm_t *child_mm = fut_mm_create();
    if (!child_mm) {
        return NULL;
    }

    /* Copy heap settings */
    child_mm->brk_start = parent_mm->brk_start;
    child_mm->brk_current = parent_mm->brk_current;
    child_mm->heap_limit = parent_mm->heap_limit;
    child_mm->mmap_base = parent_mm->mmap_base;

    /* TODO: Clone page tables and set up COW mappings */
    /* For now, the child starts with an empty address space */
    /* This works for fork+exec pattern since exec replaces the address space anyway */

    return child_mm;
}

/**
 * Clone thread structure.
 * Creates a new thread in the child task with copied register state.
 */
static fut_thread_t *clone_thread(fut_thread_t *parent_thread, fut_task_t *child_task) {
    if (!parent_thread || !child_task) {
        return NULL;
    }

    /*
     * Create a new thread in the child task.
     * Use a dummy entry point - we'll override the context below.
     */
    fut_thread_t *child_thread = fut_thread_create(
        child_task,
        dummy_entry,
        NULL,
        parent_thread->stack_size,
        parent_thread->priority
    );

    if (!child_thread) {
        return NULL;
    }

    /* Copy the entire CPU context from parent to child */
    /* This makes the child resume execution at the same point as parent */
    memcpy(&child_thread->context, &parent_thread->context, sizeof(fut_cpu_context_t));

    /*
     * Note: We don't copy the stack contents.
     * In a proper fork(), we would:
     * 1. Copy all stack pages
     * 2. Adjust stack pointer
     * 3. Set up COW for stack
     *
     * For now, this works for fork+exec pattern where exec replaces everything.
     */

    return child_thread;
}
