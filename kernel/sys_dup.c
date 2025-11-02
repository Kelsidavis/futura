/* kernel/sys_dup.c - dup() syscall implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements file descriptor duplication using the lowest available FD.
 * Maintains per-task FD isolation for multi-process support.
 */

#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <kernel/fut_task.h>

extern void fut_printf(const char *fmt, ...);
extern struct fut_file *vfs_get_file_from_task(struct fut_task *task, int fd);

/**
 * dup() syscall - Duplicate a file descriptor to lowest available FD.
 *
 * @param oldfd Source file descriptor
 *
 * Returns:
 *   - New FD number on success
 *   - -errno on error
 *
 * Behavior:
 *   - If oldfd is not valid, return -EBADF
 *   - Allocates the lowest available FD number
 *   - New FD shares the same file structure as oldfd
 *   - Both FDs share file offset and flags
 */
long sys_dup(int oldfd) {
    /* Validate FD number */
    if (oldfd < 0) {
        return -EBADF;
    }

    /* Get current task for FD table access */
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;  /* No task context */
    }

    /* Validate FD table exists */
    if (!task->fd_table) {
        return -EBADF;
    }

    /* Get the file structure for oldfd from current task's FD table */
    struct fut_file *old_file = vfs_get_file_from_task(task, oldfd);
    if (!old_file) {
        return -EBADF;
    }

    /* Find the lowest available FD in the task's FD table */
    int newfd = -1;
    for (int i = 0; i < task->max_fds; i++) {
        if (task->fd_table[i] == NULL) {
            newfd = i;
            break;
        }
    }

    if (newfd < 0) {
        return -EMFILE;  /* Too many open files */
    }

    /* Increment reference count on the file since we're creating another reference */
    old_file->refcount++;

    /* Assign the file to the new FD */
    task->fd_table[newfd] = old_file;

    fut_printf("[DUP] Duplicated fd %d to %d (task=%p)\n", oldfd, newfd, (void*)task);

    return newfd;
}
