/* kernel/sys_copy_file_range.c - In-kernel file copy
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements copy_file_range() for efficient in-kernel file copying
 * without bouncing data through userspace. Falls back to read+write
 * when no filesystem-specific optimization exists.
 */

#include <kernel/fut_task.h>
#include <kernel/fut_vfs.h>
#include <kernel/fut_memory.h>
#include <kernel/uaccess.h>
#include <kernel/errno.h>
#include <stdint.h>
#include <stddef.h>

/* Maximum copy size per call (4MB) */
#define COPY_FILE_RANGE_MAX (4 * 1024 * 1024)

/**
 * sys_copy_file_range - Copy data between file descriptors
 *
 * @param fd_in:    Source file descriptor
 * @param off_in:   Source offset pointer (NULL = use file position)
 * @param fd_out:   Destination file descriptor
 * @param off_out:  Destination offset pointer (NULL = use file position)
 * @param len:      Number of bytes to copy
 * @param flags:    Reserved (must be 0)
 *
 * Returns:
 *   - Number of bytes copied on success (may be less than len)
 *   - -EBADF if fd_in or fd_out invalid
 *   - -EINVAL if flags != 0 or len == 0
 *   - -EXDEV if fds are on different filesystems (not currently checked)
 */
long sys_copy_file_range(int fd_in, int64_t *off_in,
                         int fd_out, int64_t *off_out,
                         size_t len, unsigned int flags) {
    if (flags != 0) {
        return -EINVAL;
    }

    if (len == 0) {
        return 0;
    }

    if (fd_in < 0 || fd_out < 0) {
        return -EBADF;
    }

    /* Cap to prevent excessive kernel memory allocation */
    if (len > COPY_FILE_RANGE_MAX) {
        len = COPY_FILE_RANGE_MAX;
    }

    /* Allocate kernel bounce buffer */
    size_t buf_size = (len < 65536) ? len : 65536;
    void *kbuf = fut_malloc(buf_size);
    if (!kbuf) {
        return -ENOMEM;
    }

    size_t total_copied = 0;

    while (total_copied < len) {
        size_t chunk = len - total_copied;
        if (chunk > buf_size) chunk = buf_size;

        /* Read from source */
        ssize_t nread = fut_vfs_read(fd_in, kbuf, chunk);
        if (nread <= 0) {
            break;  /* EOF or error */
        }

        /* Write to destination */
        ssize_t nwritten = fut_vfs_write(fd_out, kbuf, (size_t)nread);
        if (nwritten <= 0) {
            if (total_copied == 0) {
                fut_free(kbuf);
                return nwritten < 0 ? nwritten : -EIO;
            }
            break;  /* Partial copy */
        }

        total_copied += (size_t)nwritten;

        /* Short write means we can't continue */
        if ((size_t)nwritten < (size_t)nread) {
            break;
        }
    }

    fut_free(kbuf);

    /* Note: off_in/off_out are ignored for now (file positions are used).
     * A full implementation would save/restore positions and update the
     * offset pointers via copy_to_user. */
    (void)off_in;
    (void)off_out;

    return (long)total_copied;
}
