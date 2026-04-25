/* kernel/sys_copy_file_range.c - In-kernel file copy
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements copy_file_range() for efficient in-kernel file copying
 * without bouncing data through userspace. Operates directly on vnode
 * ops with explicit offsets for cross-filesystem support, proper
 * O_APPEND handling, and correct partial-copy semantics.
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

#include <platform/platform.h>  /* Real KERNEL_VIRTUAL_BASE — see signalfd
                                 * note: hardcoded x86 fallback would miss
                                 * ARM64 kernel pointers. */
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
 * Supports cross-filesystem copies via a kernel bounce buffer that reads
 * from the source vnode and writes to the destination vnode directly.
 *
 * When off_in is non-NULL, data is read at *off_in (pread semantics):
 *   fd_in's file position is not changed; *off_in is updated by bytes read.
 * When off_out is non-NULL, data is written at *off_out (pwrite semantics):
 *   fd_out's file position is not changed; *off_out is updated by bytes written.
 *
 * O_APPEND on fd_out: each write chunk atomically seeks to end-of-file
 * before writing, matching POSIX append semantics.
 *
 * Returns:
 *   - Number of bytes copied on success (may be less than len)
 *   - -EBADF if fd_in or fd_out invalid
 *   - -EINVAL if flags != 0
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

    /* Both FDs must be regular files (Linux 5.3+).
     * Sockets and pipes are not supported by copy_file_range. */
    if (!f_in->vnode || f_in->vnode->type != VN_REG)
        return -EINVAL;
    if (!f_out->vnode || f_out->vnode->type != VN_REG)
        return -EINVAL;

    /* Ensure both vnodes have the required ops */
    if (!f_in->vnode->ops || !f_in->vnode->ops->read)
        return -EINVAL;
    if (!f_out->vnode->ops || !f_out->vnode->ops->write)
        return -EINVAL;

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

    /* Same-file overlap rejection: when fd_in and fd_out refer to the same
     * underlying vnode, the source and destination byte ranges must not
     * overlap. Without this check the per-chunk read/write loop can read
     * back data it just wrote (or wrote-then-overwrites unread data),
     * silently corrupting the destination. Linux returns EINVAL in this
     * case (man 2 copy_file_range). O_APPEND is treated as overlap-by-
     * extension since the write offset becomes EOF after the first write. */
    if (f_in->vnode == f_out->vnode) {
        int64_t a_start = off_in  ? pos_in  : (int64_t)f_in->offset;
        int64_t b_start = off_out ? pos_out : (int64_t)f_out->offset;
        int64_t a_end = a_start + (int64_t)len;
        int64_t b_end = b_start + (int64_t)len;
        if (a_start < b_end && b_start < a_end) {
            return -EINVAL;
        }
    }

    /* Allocate kernel bounce buffer */
    size_t buf_size = (len < 65536) ? len : 65536;
    void *kbuf = fut_malloc(buf_size);
    if (!kbuf) {
        return -ENOMEM;
    }

    /*
     * Determine effective read/write positions.
     * We operate directly on the vnodes with explicit offsets so that
     * cross-filesystem copies work (no need for same-fs restriction)
     * and so O_APPEND can be handled atomically per chunk.
     */
    int64_t read_off  = off_in  ? pos_in  : (int64_t)f_in->offset;
    int64_t write_off = off_out ? pos_out : (int64_t)f_out->offset;

    int is_append = (f_out->flags & O_APPEND) != 0;

    size_t total_copied = 0;

    while (total_copied < len) {
        size_t chunk = len - total_copied;
        if (chunk > buf_size) chunk = buf_size;

        /* Read from source vnode at explicit offset */
        ssize_t nread = f_in->vnode->ops->read(f_in->vnode, kbuf, chunk,
                                                 (uint64_t)read_off);
        if (nread <= 0) {
            break;  /* EOF or error */
        }

        /* O_APPEND: atomically seek to end-of-file before each write */
        if (is_append) {
            fut_spinlock_acquire(&f_out->vnode->write_lock);
            write_off = (int64_t)f_out->vnode->size;
        }

        /* Write to destination vnode at explicit offset */
        ssize_t nwritten = f_out->vnode->ops->write(f_out->vnode, kbuf,
                                                      (size_t)nread,
                                                      (uint64_t)write_off);

        if (is_append) {
            fut_spinlock_release(&f_out->vnode->write_lock);
        }

        if (nwritten <= 0) {
            if (total_copied == 0) {
                fut_free(kbuf);
                return nwritten < 0 ? nwritten : -EIO;
            }
            break;  /* Partial copy — return bytes copied so far */
        }

        read_off  += nwritten;
        write_off += nwritten;
        total_copied += (size_t)nwritten;

        /* Short write means we can't continue */
        if ((size_t)nwritten < (size_t)nread) {
            break;
        }
    }

    fut_free(kbuf);

    /*
     * Update file positions and caller's offset pointers.
     *
     * When off_in/off_out are NULL: update the fd's file position.
     * When off_in/off_out are non-NULL: write back the advanced offset
     * to the caller's pointer (pread/pwrite semantics — fd position unchanged).
     */
    if (off_in) {
        cfr_write_offset(off_in, read_off);
    } else {
        f_in->offset = (uint64_t)read_off;
    }

    if (off_out) {
        cfr_write_offset(off_out, write_off);
    } else {
        f_out->offset = (uint64_t)write_off;
    }

    /* POSIX/Linux: clear setuid/setgid bits on destination after successful write */
    if (total_copied > 0 && f_out->vnode) {
        uint32_t mode = f_out->vnode->mode;
        int needs_clear = 0;
        if (mode & 04000) needs_clear = 1;
        if ((mode & 02000) && (mode & 00010)) needs_clear = 1;
        if (needs_clear) {
            int has_cap_fsetid = task &&
                (task->cap_effective & (1ULL << 4 /* CAP_FSETID */));
            if (!has_cap_fsetid) {
                if (mode & 04000)
                    f_out->vnode->mode &= ~(uint32_t)04000;
                if ((mode & 02000) && (mode & 00010))
                    f_out->vnode->mode &= ~(uint32_t)02000;
            }
        }
    }

    return (long)total_copied;
}
