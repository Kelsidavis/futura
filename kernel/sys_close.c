/* kernel/sys_close.c - Close file descriptor syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements close() to close file descriptors and release resources.
 * Essential for proper resource management.
 */

#include <kernel/fut_task.h>
#include <kernel/fut_vfs.h>
#include <kernel/fut_socket.h>
#include <kernel/errno.h>

extern void fut_printf(const char *fmt, ...);
extern fut_task_t *fut_task_current(void);
extern fut_socket_t *get_socket_from_fd(int fd);
extern int release_socket_fd(int fd);

/**
 * close() - Close file descriptor
 *
 * Closes a file descriptor, so that it no longer refers to any file and
 * may be reused. Resources associated with the file descriptor are freed.
 *
 * @param fd File descriptor to close
 *
 * Returns:
 *   - 0 on success
 *   - -EBADF if fd is not a valid open file descriptor
 *   - -EIO if I/O error occurred
 *
 * Behavior:
 * - Closes file descriptor and frees resources
 * - File descriptor becomes available for reuse
 * - If last reference to file, file is closed
 * - For sockets, closes socket connection
 */
long sys_close(int fd) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Check if FD is a socket first */
    fut_socket_t *socket = get_socket_from_fd(fd);
    if (socket) {
        /* It's a socket - release it */
        fut_printf("[CLOSE] Closing socket fd %d\n", fd);
        return (long)release_socket_fd(fd);
    }

    /* Otherwise, close as a regular file descriptor */
    return (long)fut_vfs_close(fd);
}
