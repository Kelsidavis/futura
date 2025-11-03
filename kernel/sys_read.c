/* kernel/sys_read.c - Read from file descriptor syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements read() to read data from file descriptors.
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
 * read() - Read data from file descriptor
 *
 * Reads up to count bytes from file descriptor fd into the buffer pointed
 * to by buf. The file offset is advanced by the number of bytes read.
 *
 * @param fd    File descriptor to read from
 * @param buf   User buffer to store read data
 * @param count Maximum number of bytes to read
 *
 * Returns:
 *   - Number of bytes read (may be less than count)
 *   - 0 at end-of-file
 *   - -EBADF if fd is not a valid file descriptor
 *   - -EFAULT if buf points to invalid memory
 *   - -EINVAL if count is invalid
 *   - -EIO if I/O error occurred
 *   - -EISDIR if fd refers to a directory
 *   - -EAGAIN if non-blocking and no data available
 *
 * Behavior:
 * - Reads from current file offset
 * - Advances file offset by bytes read
 * - May read less than requested (short read)
 * - Returns 0 at EOF
 * - Blocks until data available (unless O_NONBLOCK)
 */
ssize_t sys_read(int fd, void *buf, size_t count) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Empty read */
    if (count == 0) {
        return 0;
    }

    /* Validate user buffer */
    if (!buf) {
        return -EFAULT;
    }

    /* Sanity check: reject unreasonably large reads */
    if (count > 1024 * 1024) {  /* 1 MB limit */
        return -EINVAL;
    }

    /* Allocate kernel buffer */
    void *kbuf = fut_malloc(count);
    if (!kbuf) {
        return -ENOMEM;
    }

    /* Read from VFS */
    ssize_t ret = fut_vfs_read(fd, kbuf, count);

    /* Copy to userspace on success */
    if (ret > 0) {
        if (fut_copy_to_user(buf, kbuf, (size_t)ret) != 0) {
            fut_free(kbuf);
            return -EFAULT;
        }
    }

    fut_free(kbuf);
    return ret;
}
