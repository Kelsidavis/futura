/* syscall_helpers.h - Common syscall helper macros
 *
 * Copyright (c) 2026 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides helper macros to reduce boilerplate in syscall implementations.
 * These macros handle common patterns like task retrieval and validation.
 */

#ifndef KERNEL_SYSCALL_HELPERS_H
#define KERNEL_SYSCALL_HELPERS_H

#include <kernel/fut_task.h>
#include <kernel/errno.h>

/**
 * GET_CURRENT_TASK - Get current task with error checking
 *
 * Usage:
 *   GET_CURRENT_TASK(task);
 *   // task is now available and guaranteed non-NULL
 *
 * Expands to:
 *   fut_task_t *task = fut_task_current();
 *   if (!task) {
 *       return -ESRCH;
 *   }
 */
#define GET_CURRENT_TASK(task_var) \
    fut_task_t *task_var = fut_task_current(); \
    if (!task_var) { \
        return -ESRCH; \
    }

/**
 * VALIDATE_USER_PTR - Validate userspace pointer
 *
 * Usage:
 *   VALIDATE_USER_PTR(ptr, size);
 *
 * Returns -EFAULT if pointer is invalid.
 */
#define VALIDATE_USER_PTR(ptr, size) \
    do { \
        if (!(ptr) || fut_access_ok((ptr), (size), 0) != 0) { \
            return -EFAULT; \
        } \
    } while (0)

/**
 * VALIDATE_USER_PTR_WRITE - Validate userspace pointer with write access
 *
 * Usage:
 *   VALIDATE_USER_PTR_WRITE(ptr, size);
 *
 * Returns -EFAULT if pointer is invalid or not writable.
 */
#define VALIDATE_USER_PTR_WRITE(ptr, size) \
    do { \
        if (!(ptr) || fut_access_ok((ptr), (size), 1) != 0) { \
            return -EFAULT; \
        } \
    } while (0)

/**
 * VALIDATE_FD - Validate file descriptor
 *
 * Usage:
 *   fut_task_t *task = ...;
 *   VALIDATE_FD(task, fd);
 *
 * Returns -EBADF if fd is invalid.
 */
#define VALIDATE_FD(task_var, fd_val) \
    do { \
        if ((fd_val) < 0 || (fd_val) >= FUT_MAX_FDS || \
            !(task_var)->fd_table[(fd_val)]) { \
            return -EBADF; \
        } \
    } while (0)

/**
 * SYSCALL_PROLOGUE - Common syscall entry boilerplate
 *
 * Usage:
 *   long sys_example(void) {
 *       SYSCALL_PROLOGUE(task);
 *       // task is now available
 *   }
 *
 * Combines task retrieval and validation.
 */
#define SYSCALL_PROLOGUE(task_var) GET_CURRENT_TASK(task_var)

#endif /* KERNEL_SYSCALL_HELPERS_H */
