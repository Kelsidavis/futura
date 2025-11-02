/* sys_dup2.c - dup2() syscall implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements file descriptor duplication for I/O redirection.
 * Maintains per-task FD isolation for multi-process support.
 */

#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <kernel/fut_task.h>

extern void fut_printf(const char *fmt, ...);

/**
 * dup2() syscall - Duplicate a file descriptor to a specific number.
 *
 * @param oldfd Source file descriptor
 * @param newfd Target file descriptor number
 *
 * Returns:
 *   - newfd on success
 *   - -errno on error
 *
 * Behavior:
 *   - If oldfd is not valid, return -EBADF
 *   - If oldfd == newfd, return newfd without closing it
 *   - If newfd is open, close it first
 *   - Duplicate oldfd to newfd with per-task FD isolation
 */
long sys_dup2(int oldfd, int newfd) {
    /* Validate FD numbers */
    if (oldfd < 0 || newfd < 0) {
        return -EBADF;
    }

    /* Get current task for FD table access */
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;  /* No task context */
    }

    /* Get the file structure for oldfd from current task's FD table */
    struct fut_file *old_file = vfs_get_file_from_task(task, oldfd);
    if (!old_file) {
        return -EBADF;
    }

    /* If oldfd == newfd, just return newfd without modification */
    if (oldfd == newfd) {
        return newfd;
    }

    /* Increment reference count on the file since we're creating another reference */
    if (old_file) {
        old_file->refcount++;
    }

    /* Allocate newfd pointing to the same file in task's FD table */
    /* alloc_specific_fd_for_task handles closing existing FD if needed */
    int ret = vfs_alloc_specific_fd_for_task(task, newfd, old_file);
    if (ret < 0) {
        /* Failed to allocate, decrement ref count */
        if (old_file && old_file->refcount > 0) {
            old_file->refcount--;
        }
        return ret;
    }

    fut_printf("[DUP2] Duplicated fd %d to %d (task=%p)\n", oldfd, newfd, (void*)task);

    return newfd;
}
