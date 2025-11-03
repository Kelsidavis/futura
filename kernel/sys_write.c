/* kernel/sys_write.c - Write to file descriptor syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements write() to write data to file descriptors.
 * Core I/O primitive for files, pipes, sockets, and devices.
 */

#include <kernel/fut_task.h>
#include <kernel/fut_vfs.h>
#include <kernel/fut_memory.h>
#include <kernel/uaccess.h>
#include <kernel/errno.h>
#include <stddef.h>

extern void fut_printf(const char *fmt, ...);
extern fut_task_t *fut_task_current(void);

/**
 * write() - Write data to file descriptor
 *
 * Writes up to count bytes from the buffer pointed to by buf to the file
 * descriptor fd. The file offset is advanced by the number of bytes written.
 *
 * @param fd    File descriptor to write to
 * @param buf   User buffer containing data to write
 * @param count Number of bytes to write
 *
 * Returns:
 *   - Number of bytes written (may be less than count)
 *   - -EBADF if fd is not a valid file descriptor
 *   - -EFAULT if buf points to invalid memory
 *   - -EINVAL if count is invalid
 *   - -EIO if I/O error occurred
 *   - -ENOSPC if no space left on device
 *   - -EPIPE if writing to closed pipe (generates SIGPIPE)
 *   - -EAGAIN if non-blocking and cannot write
 *
 * Behavior:
 * - Writes to current file offset
 * - Advances file offset by bytes written
 * - May write less than requested (short write)
 * - Blocks until can write (unless O_NONBLOCK)
 */
ssize_t sys_write(int fd, const void *buf, size_t count) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Empty write */
    if (count == 0) {
        return 0;
    }

    /* Validate user buffer */
    if (!buf) {
        return -EFAULT;
    }

    /* Allocate kernel buffer */
    void *kbuf = fut_malloc(count);
    if (!kbuf) {
        return -ENOMEM;
    }

    /* Copy from userspace */
    if (fut_copy_from_user(kbuf, buf, count) != 0) {
        fut_free(kbuf);
        return -EFAULT;
    }

    /* Write to VFS */
    ssize_t ret = fut_vfs_write(fd, kbuf, count);

    fut_free(kbuf);
    return ret;
}
