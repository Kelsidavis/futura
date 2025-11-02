/* kernel/sys_fsync.c - fsync() syscall implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements file synchronization syscall for data durability.
 * Currently a stub that validates the FD and returns success.
 */

#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <kernel/fut_task.h>

extern void fut_printf(const char *fmt, ...);
extern struct fut_file *vfs_get_file_from_task(struct fut_task *task, int fd);

/**
 * fsync() syscall - Synchronize a file's in-core state with storage.
 *
 * @param fd File descriptor to synchronize
 *
 * Returns:
 *   - 0 on success
 *   - -errno on error
 *
 * Behavior:
 *   - Validates that fd is a valid open file descriptor
 *   - Ensures all file data and metadata are written to storage
 *   - Does not return until the transfer is complete
 *   - Returns -EBADF if fd is not a valid file descriptor
 *   - Returns -EINVAL if fd refers to a special file that doesn't support syncing
 *   - Returns -EIO if an I/O error occurs during sync
 *
 * Note: Current implementation is a stub that validates the FD.
 *       Full sync support requires VFS backend implementation.
 */
long sys_fsync(int fd) {
    /* Validate FD number */
    if (fd < 0) {
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

    /* Get the file structure for fd from current task's FD table */
    struct fut_file *file = vfs_get_file_from_task(task, fd);
    if (!file) {
        return -EBADF;
    }

    /* fsync() not supported on character devices, pipes, or sockets */
    if (file->chr_ops) {
        return -EINVAL;
    }

    /* Check if this is a directory - directories can be synced */
    /* Regular files can also be synced */

    /* TODO: When VFS gains sync operations, call them here:
     * if (file->vnode && file->vnode->ops && file->vnode->ops->sync) {
     *     return file->vnode->ops->sync(file->vnode);
     * }
     */

    /* For now, return success as a stub implementation.
     * Most underlying operations in Futura may already be synchronous,
     * and this prevents applications from failing when they call fsync().
     */
    fut_printf("[FSYNC] fd=%d (stub: success)\n", fd);

    return 0;
}
