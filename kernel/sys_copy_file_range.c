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
#include <fcntl.h>
#include <stdint.h>
#include <stddef.h>

/* Maximum copy size per call (4MB) */
#define COPY_FILE_RANGE_MAX (4 * 1024 * 1024)

#ifndef KERNEL_VIRTUAL_BASE
#define KERNEL_VIRTUAL_BASE 0xFFFFFFFF80000000ULL
#endif
#define CFR_IS_KPTR(p) ((uintptr_t)(p) >= KERNEL_VIRTUAL_BASE)

/* Read/write an int64_t through a possibly-userspace pointer */
static int cfr_read_offset(const int64_t *ptr, int64_t *out) {
    if (CFR_IS_KPTR(ptr)) {
        *out = *ptr;
        return 0;
    }
    return fut_copy_from_user(out, ptr, sizeof(int64_t));
}

static int cfr_write_offset(int64_t *ptr, int64_t val) {
    if (CFR_IS_KPTR(ptr)) {
        *ptr = val;
        return 0;
    }
    return fut_copy_to_user(ptr, &val, sizeof(int64_t));
}

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
 * When off_in is non-NULL, data is read at *off_in (pread semantics):
 *   fd_in's file position is not changed; *off_in is updated by bytes read.
 * When off_out is non-NULL, data is written at *off_out (pwrite semantics):
 *   fd_out's file position is not changed; *off_out is updated by bytes written.
 *
 * Returns:
 *   - Number of bytes copied on success (may be less than len)
 *   - -EBADF if fd_in or fd_out invalid
 *   - -EINVAL if flags != 0 or len == 0
 *   - -EFAULT if off_in/off_out pointer is invalid
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

    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Validate fd bounds */
    if (fd_in >= task->max_fds || fd_out >= task->max_fds) {
        return -EBADF;
    }

    struct fut_file *f_in  = vfs_get_file_from_task(task, fd_in);
    struct fut_file *f_out = vfs_get_file_from_task(task, fd_out);
    if (!f_in || !f_out) {
        return -EBADF;
    }

    /* O_PATH fds cannot be used for I/O — only path-based operations */
    if ((f_in->flags & O_PATH) || (f_out->flags & O_PATH))
        return -EBADF;

    /* fd_in must be readable, fd_out must be writable */
    if ((f_in->flags & O_ACCMODE) == O_WRONLY)
        return -EBADF;
    if ((f_out->flags & O_ACCMODE) == O_RDONLY)
        return -EBADF;

    /* Read explicit offsets if provided */
    int64_t pos_in = -1, pos_out = -1;
    if (off_in) {
        if (cfr_read_offset(off_in, &pos_in) != 0) return -EFAULT;
        if (pos_in < 0) return -EINVAL;
    }
    if (off_out) {
        if (cfr_read_offset(off_out, &pos_out) != 0) return -EFAULT;
        if (pos_out < 0) return -EINVAL;
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

    /*
     * Save the fd positions that we will override (pread/pwrite semantics).
     * The fd_in/fd_out file positions are NOT changed when off_in/off_out
     * are non-NULL; instead the pointed-to values are updated.
     */
    uint64_t saved_in  = f_in->offset;
    uint64_t saved_out = f_out->offset;

    if (off_in)  f_in->offset  = (uint64_t)pos_in;
    if (off_out) f_out->offset = (uint64_t)pos_out;

    size_t total_copied = 0;

    while (total_copied < len) {
        size_t chunk = len - total_copied;
        if (chunk > buf_size) chunk = buf_size;

        /* Read from source via fd (advances f_in->offset) */
        ssize_t nread = fut_vfs_read(fd_in, kbuf, chunk);
        if (nread <= 0) {
            break;  /* EOF or error */
        }

        /* Write to destination via fd (advances f_out->offset) */
        ssize_t nwritten = fut_vfs_write(fd_out, kbuf, (size_t)nread);
        if (nwritten <= 0) {
            if (total_copied == 0) {
                fut_free(kbuf);
                /* Restore positions before returning */
                if (off_in)  f_in->offset  = saved_in;
                if (off_out) f_out->offset = saved_out;
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

    /*
     * Update caller's offset pointers with the advanced positions,
     * then restore the fd's own file position (pread/pwrite semantics:
     * the fd position is unchanged when off_in/off_out are non-NULL).
     */
    if (off_in) {
        int64_t new_off_in = (int64_t)f_in->offset;
        f_in->offset = saved_in;          /* restore fd position */
        cfr_write_offset(off_in, new_off_in);
    }
    if (off_out) {
        int64_t new_off_out = (int64_t)f_out->offset;
        f_out->offset = saved_out;        /* restore fd position */
        cfr_write_offset(off_out, new_off_out);
    }

    return (long)total_copied;
}
