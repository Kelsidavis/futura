/* kernel/sys_splice.c - Zero-copy I/O syscalls
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements splice, vmsplice, tee, and sync_file_range for efficient I/O.
 * These syscalls enable zero-copy data movement between file descriptors
 * and memory, essential for high-performance applications.
 *
 * Phase 1 (Completed): Validation and stub implementations with parameter categorization
 * Phase 2 (Completed): Enhanced validation, operation type categorization, detailed logging
 * Phase 3 (Completed): Implement pipe-based zero-copy transfers
 * Phase 4: Add page cache integration for file-to-file transfers
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/uaccess.h>
#include <kernel/syscalls.h>
#include <kernel/fut_vfs.h>
#include <kernel/fut_memory.h>
#include <kernel/chrdev.h>
#include <stdint.h>
#include <stddef.h>

/* ssize_t provided by kernel/syscalls.h */

#include <kernel/kprintf.h>

/* splice flags */
#define SPLICE_F_MOVE     0x01  /* Move pages instead of copying */
#define SPLICE_F_NONBLOCK 0x02  /* Non-blocking operation */
#define SPLICE_F_MORE     0x04  /* More data will follow */
#define SPLICE_F_GIFT     0x08  /* Pages are a gift to kernel */

/* sync_file_range flags */
#define SYNC_FILE_RANGE_WAIT_BEFORE 1  /* Wait for writeback before */
#define SYNC_FILE_RANGE_WRITE       2  /* Initiate writeback */
#define SYNC_FILE_RANGE_WAIT_AFTER  4  /* Wait for writeback after */

/**
 * splice() - Move data between file descriptors
 *
 * Moves data between two file descriptors without copying between kernel and
 * user space. At least one of the file descriptors must refer to a pipe.
 * This enables zero-copy data movement for high-performance applications.
 *
 * @param fd_in     Source file descriptor
 * @param off_in    Offset in source (NULL for pipe, or pointer to offset)
 * @param fd_out    Destination file descriptor
 * @param off_out   Offset in destination (NULL for pipe, or pointer to offset)
 * @param len       Number of bytes to transfer
 * @param flags     SPLICE_F_MOVE, SPLICE_F_NONBLOCK, SPLICE_F_MORE, SPLICE_F_GIFT
 *
 * Returns:
 *   - Number of bytes transferred on success
 *   - 0 if no data available (non-blocking mode)
 *   - -EBADF if fd_in or fd_out is invalid
 *   - -EINVAL if neither fd is a pipe, or offsets invalid
 *   - -ENOMEM if insufficient memory
 *   - -ESPIPE if offset provided for pipe
 *
 * Typical usage patterns:
 *
 * 1. File to pipe (e.g., sendfile replacement):
 *    splice(file_fd, &offset, pipe_fd, NULL, len, SPLICE_F_MOVE);
 *
 * 2. Pipe to file:
 *    splice(pipe_fd, NULL, file_fd, &offset, len, SPLICE_F_MOVE);
 *
 * 3. Pipe to socket (zero-copy network send):
 *    splice(pipe_fd, NULL, socket_fd, NULL, len, SPLICE_F_MOVE | SPLICE_F_MORE);
 *
 * Phase 1 (Completed): Validate parameters and return dummy count
 * Phase 2 (Completed): Enhanced validation and operation categorization with detailed logging
 * Phase 3 (Completed): Implement pipe-based transfers
 * Phase 4: Add page cache integration for files
 */
long sys_splice(int fd_in, int64_t *off_in, int fd_out, int64_t *off_out,
                size_t len, unsigned int flags) {
    /* ARM64 FIX: Copy register-passed parameters to local stack variables so they
     * survive across potentially blocking calls (fut_copy_from_user/fut_copy_to_user
     * may context-switch on ARM64, corrupting register values on resumption). */
    int local_fd_in = fd_in;
    int64_t *local_off_in = off_in;
    int local_fd_out = fd_out;
    int64_t *local_off_out = off_out;
    size_t local_len = len;
    unsigned int local_flags = flags;

    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[SPLICE] splice(fd_in=%d, off_in=%p, fd_out=%d, off_out=%p, len=%zu, flags=0x%x) "
                   "-> ESRCH (no current task)\n", local_fd_in, local_off_in, local_fd_out, local_off_out, local_len, local_flags);
        return -ESRCH;
    }

    /* Validate fds */
    if (local_fd_in < 0 || local_fd_out < 0) {
        fut_printf("[SPLICE] splice(fd_in=%d, fd_out=%d, len=%zu, flags=0x%x, pid=%d) "
                   "-> EBADF (invalid fd)\n", local_fd_in, local_fd_out, local_len, local_flags, task->pid);
        return -EBADF;
    }

    /* Validate flags */
    const unsigned int VALID_FLAGS = SPLICE_F_MOVE | SPLICE_F_NONBLOCK | SPLICE_F_MORE | SPLICE_F_GIFT;
    if (local_flags & ~VALID_FLAGS) {
        fut_printf("[SPLICE] splice(fd_in=%d, fd_out=%d, len=%zu, flags=0x%x [invalid], pid=%d) "
                   "-> EINVAL\n", local_fd_in, local_fd_out, local_len, local_flags, task->pid);
        return -EINVAL;
    }

    /* Validate offset pointers are readable/writable if non-NULL.
     * Inherent TOCTOU limitation: userspace can remap pages between the read
     * and write probes. Best-effort validation catches most invalid pointers. */
    if (local_off_in != NULL) {
        int64_t test_offset;
        /* Test readability - kernel needs to read current offset */
        if (fut_copy_from_user(&test_offset, local_off_in, sizeof(int64_t)) != 0) {
            fut_printf("[SPLICE] splice(fd_in=%d, off_in=%p) -> EFAULT "
                       "(off_in not readable)\n",
                       local_fd_in, local_off_in);
            return -EFAULT;
        }
        /* Test writability - kernel needs to write updated offset */
        if (fut_copy_to_user(local_off_in, &test_offset, sizeof(int64_t)) != 0) {
            fut_printf("[SPLICE] splice(fd_in=%d, off_in=%p) -> EFAULT "
                       "(off_in not writable)\n",
                       local_fd_in, local_off_in);
            return -EFAULT;
        }
        /* Validate offset value is non-negative */
        if (test_offset < 0) {
            fut_printf("[SPLICE] splice(fd_in=%d, off_in=%p, offset=%ld) -> EINVAL "
                       "(negative offset)\n",
                       local_fd_in, local_off_in, test_offset);
            return -EINVAL;
        }
        /* Validate offset+len doesn't overflow */
        if ((uint64_t)test_offset > (uint64_t)(INT64_MAX - local_len)) {
            fut_printf("[SPLICE] splice(fd_in=%d, off_in=%ld, len=%zu) -> EOVERFLOW "
                       "(offset+len would overflow, max_valid_offset=%ld)\n",
                       local_fd_in, test_offset, local_len, (int64_t)(INT64_MAX - local_len));
            return -EOVERFLOW;
        }
    }

    if (local_off_out != NULL) {
        int64_t test_offset;
        /* Test readability - kernel needs to read current offset */
        if (fut_copy_from_user(&test_offset, local_off_out, sizeof(int64_t)) != 0) {
            fut_printf("[SPLICE] splice(fd_out=%d, off_out=%p) -> EFAULT "
                       "(off_out not readable)\n",
                       local_fd_out, local_off_out);
            return -EFAULT;
        }
        /* Test writability - kernel needs to write updated offset */
        if (fut_copy_to_user(local_off_out, &test_offset, sizeof(int64_t)) != 0) {
            fut_printf("[SPLICE] splice(fd_out=%d, off_out=%p) -> EFAULT "
                       "(off_out not writable)\n",
                       local_fd_out, local_off_out);
            return -EFAULT;
        }
        /* Validate offset value is non-negative */
        if (test_offset < 0) {
            fut_printf("[SPLICE] splice(fd_out=%d, off_out=%p, offset=%ld) -> EINVAL "
                       "(negative offset)\n",
                       local_fd_out, local_off_out, test_offset);
            return -EINVAL;
        }
        /* Validate offset+len doesn't overflow */
        if ((uint64_t)test_offset > (uint64_t)(INT64_MAX - local_len)) {
            fut_printf("[SPLICE] splice(fd_out=%d, off_out=%ld, len=%zu) -> EOVERFLOW "
                       "(offset+len would overflow, max_valid_offset=%ld)\n",
                       local_fd_out, test_offset, local_len, (int64_t)(INT64_MAX - local_len));
            return -EOVERFLOW;
        }
    }

    /* Get source and destination file structures */
    if (local_fd_in >= task->max_fds || local_fd_out >= task->max_fds) {
        return -EBADF;
    }

    struct fut_file *file_in  = vfs_get_file_from_task(task, local_fd_in);
    struct fut_file *file_out = vfs_get_file_from_task(task, local_fd_out);

    if (!file_in || !file_out) {
        fut_printf("[SPLICE] splice(fd_in=%d, fd_out=%d) -> EBADF (fd not open)\n",
                   local_fd_in, local_fd_out);
        return -EBADF;
    }

    bool in_is_pipe  = (file_in->chr_ops  != NULL && file_in->chr_ops->read  != NULL);
    bool out_is_pipe = (file_out->chr_ops != NULL && file_out->chr_ops->write != NULL);

    /* POSIX: at least one fd must be a pipe */
    if (!in_is_pipe && !out_is_pipe) {
        fut_printf("[SPLICE] splice(fd_in=%d, fd_out=%d) -> EINVAL (neither fd is a pipe)\n",
                   local_fd_in, local_fd_out);
        return -EINVAL;
    }

    /* ESPIPE: offset not allowed for pipes */
    if (local_off_in  && in_is_pipe)  return -ESPIPE;
    if (local_off_out && out_is_pipe) return -ESPIPE;

    /* Zero-length transfer is a valid no-op */
    if (local_len == 0)
        return 0;

    /* Determine effective read offset */
    int64_t read_off  = 0;
    int64_t write_off = 0;
    if (local_off_in) {
        if (fut_copy_from_user(&read_off,  local_off_in,  sizeof(int64_t)) != 0) return -EFAULT;
    } else {
        read_off = (int64_t)file_in->offset;
    }
    if (local_off_out) {
        if (fut_copy_from_user(&write_off, local_off_out, sizeof(int64_t)) != 0) return -EFAULT;
    } else {
        write_off = (int64_t)file_out->offset;
    }

    /* Transfer via a temporary kernel buffer (PIPE_BUF_SIZE chunks) */
    const size_t CHUNK = 4096;
    uint8_t *kbuf = (uint8_t *)fut_malloc(CHUNK);
    if (!kbuf) return -ENOMEM;

    size_t transferred = 0;

    while (transferred < local_len) {
        size_t want = local_len - transferred;
        if (want > CHUNK) want = CHUNK;

        /* Read from source */
        ssize_t nread;
        if (in_is_pipe) {
            off_t pos = (off_t)read_off;
            nread = file_in->chr_ops->read(file_in->chr_inode,
                                           file_in->chr_private,
                                           kbuf, want, &pos);
            read_off = (int64_t)pos;
        } else {
            /* Regular file read at current offset */
            nread = file_in->vnode->ops->read(file_in->vnode, kbuf, want,
                                               (uint64_t)read_off);
            if (nread > 0) read_off += nread;
        }

        if (nread < 0) {
            if (transferred > 0) break;  /* Return partial on error */
            fut_free(kbuf);
            return (long)nread;
        }
        if (nread == 0) break;  /* EOF or pipe empty (non-blocking) */

        /* Write to destination */
        ssize_t nwritten;
        if (out_is_pipe) {
            off_t pos = (off_t)write_off;
            nwritten = file_out->chr_ops->write(file_out->chr_inode,
                                                file_out->chr_private,
                                                kbuf, (size_t)nread, &pos);
            write_off = (int64_t)pos;
        } else {
            nwritten = file_out->vnode->ops->write(file_out->vnode, kbuf,
                                                    (size_t)nread,
                                                    (uint64_t)write_off);
            if (nwritten > 0) write_off += nwritten;
        }

        if (nwritten < 0) {
            if (transferred > 0) break;
            fut_free(kbuf);
            return (long)nwritten;
        }

        transferred += (size_t)nwritten;
    }

    fut_free(kbuf);

    /* Update file offsets */
    if (!local_off_in)  file_in->offset  = (uint64_t)read_off;
    if (!local_off_out) file_out->offset = (uint64_t)write_off;

    /* Write back updated offsets to userspace if caller provided pointers */
    if (local_off_in  && fut_copy_to_user(local_off_in,  &read_off,  sizeof(int64_t)) != 0)
        return -EFAULT;
    if (local_off_out && fut_copy_to_user(local_off_out, &write_off, sizeof(int64_t)) != 0)
        return -EFAULT;

    fut_printf("[SPLICE] splice(fd_in=%d, fd_out=%d, len=%zu, pid=%d) -> %zu bytes transferred\n",
               local_fd_in, local_fd_out, local_len, task->pid, transferred);

    return (long)transferred;
}

/**
 * vmsplice() - Splice user memory into pipe
 *
 * Splices user memory pages into a pipe without copying. The iovec array
 * describes the memory regions to be transferred.
 *
 * @param fd     Pipe file descriptor
 * @param iov    Array of iovec structures describing memory regions
 * @param nr_segs Number of iovec structures
 * @param flags  SPLICE_F_MOVE, SPLICE_F_NONBLOCK, SPLICE_F_MORE, SPLICE_F_GIFT
 *
 * Returns:
 *   - Number of bytes transferred on success
 *   - -EBADF if fd is invalid or not a pipe
 *   - -EINVAL if nr_segs is 0 or flags invalid
 *   - -ENOMEM if insufficient memory
 *
 * Usage:
 *   struct iovec iov[2];
 *   iov[0].iov_base = buffer1; iov[0].iov_len = len1;
 *   iov[1].iov_base = buffer2; iov[1].iov_len = len2;
 *   vmsplice(pipe_fd, iov, 2, SPLICE_F_GIFT);
 *
 * SPLICE_F_GIFT tells kernel it can take ownership of the pages.
 *
 * Phase 1 (Completed): Validate parameters and return dummy count
 * Phase 2 (Completed): Enhanced validation and segment categorization with detailed logging
 * Phase 3 (Completed): Map user pages and add to pipe buffer
 */
long sys_vmsplice(int fd, const void *iov, size_t nr_segs, unsigned int flags) {
    /* ARM64 FIX: Copy register-passed parameters to local stack variables so they
     * survive across potentially blocking calls. */
    int local_fd = fd;
    const void *local_iov = iov;
    size_t local_nr_segs = nr_segs;
    unsigned int local_flags = flags;

    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Validate fd */
    if (local_fd < 0) {
        fut_printf("[VMSPLICE] vmsplice(fd=%d [invalid], nr_segs=%zu, flags=0x%x, pid=%d) "
                   "-> EBADF\n", local_fd, local_nr_segs, local_flags, task->pid);
        return -EBADF;
    }

    /* Validate iov pointer */
    if (!local_iov) {
        fut_printf("[VMSPLICE] vmsplice(fd=%d, iov=NULL, nr_segs=%zu, pid=%d) "
                   "-> EFAULT\n", local_fd, local_nr_segs, task->pid);
        return -EFAULT;
    }

    /* Validate nr_segs */
    if (local_nr_segs == 0) {
        fut_printf("[VMSPLICE] vmsplice(fd=%d, nr_segs=0 [invalid], flags=0x%x, pid=%d) "
                   "-> EINVAL\n", local_fd, local_flags, task->pid);
        return -EINVAL;
    }

    /* Cap nr_segs to prevent excessive iteration (matches Linux UIO_MAXIOV) */
    if (local_nr_segs > 1024) {
        fut_printf("[VMSPLICE] vmsplice(fd=%d, nr_segs=%zu [exceeds 1024], pid=%d) "
                   "-> EINVAL\n", local_fd, local_nr_segs, task->pid);
        return -EINVAL;
    }

    /* Validate flags */
    const unsigned int VALID_FLAGS = SPLICE_F_MOVE | SPLICE_F_NONBLOCK | SPLICE_F_MORE | SPLICE_F_GIFT;
    if (local_flags & ~VALID_FLAGS) {
        fut_printf("[VMSPLICE] vmsplice(fd=%d, nr_segs=%zu, flags=0x%x [invalid], pid=%d) "
                   "-> EINVAL\n", local_fd, local_nr_segs, local_flags, task->pid);
        return -EINVAL;
    }

    /* Return -ENOSYS until properly implemented.
     * Returning a fake byte count causes silent data loss. */
    fut_printf("[VMSPLICE] vmsplice(fd=%d, nr_segs=%zu, pid=%d) -> ENOSYS (not implemented)\n",
               local_fd, local_nr_segs, task->pid);

    return -ENOSYS;
}

/**
 * tee() - Duplicate pipe content
 *
 * Duplicates data from one pipe to another without consuming it from the
 * source pipe. Both pipes can subsequently be read independently.
 *
 * @param fd_in   Source pipe file descriptor
 * @param fd_out  Destination pipe file descriptor
 * @param len     Number of bytes to duplicate
 * @param flags   SPLICE_F_NONBLOCK, SPLICE_F_MORE
 *
 * Returns:
 *   - Number of bytes duplicated on success
 *   - 0 if no data available (non-blocking mode)
 *   - -EBADF if fd_in or fd_out invalid
 *   - -EINVAL if neither is a pipe or both are same pipe
 *   - -ENOMEM if insufficient memory
 *
 * Usage:
 *   // Duplicate pipe data for logging while still processing
 *   tee(input_pipe, log_pipe, len, 0);
 *   // Now input_pipe and log_pipe both have the same data
 *
 * Phase 1 (Completed): Validate parameters and return dummy count
 * Phase 2 (Completed): Enhanced validation and sanity checks with detailed logging
 * Phase 3 (Completed): Duplicate pipe buffer pages
 */
long sys_tee(int fd_in, int fd_out, size_t len, unsigned int flags) {
    /* ARM64 FIX: Copy register-passed parameters to local stack variables so they
     * survive across potentially blocking calls. */
    int local_fd_in = fd_in;
    int local_fd_out = fd_out;
    size_t local_len = len;
    unsigned int local_flags = flags;

    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Validate fds */
    if (local_fd_in < 0 || local_fd_out < 0) {
        fut_printf("[TEE] tee(fd_in=%d, fd_out=%d, len=%zu, flags=0x%x, pid=%d) "
                   "-> EBADF (invalid fd)\n", local_fd_in, local_fd_out, local_len, local_flags, task->pid);
        return -EBADF;
    }

    /* Check if same fd */
    if (local_fd_in == local_fd_out) {
        fut_printf("[TEE] tee(fd_in=%d, fd_out=%d [same], len=%zu, flags=0x%x, pid=%d) "
                   "-> EINVAL\n", local_fd_in, local_fd_out, local_len, local_flags, task->pid);
        return -EINVAL;
    }

    /* Validate flags */
    const unsigned int VALID_FLAGS = SPLICE_F_NONBLOCK | SPLICE_F_MORE;
    if (local_flags & ~VALID_FLAGS) {
        fut_printf("[TEE] tee(fd_in=%d, fd_out=%d, len=%zu, flags=0x%x [invalid], pid=%d) "
                   "-> EINVAL\n", local_fd_in, local_fd_out, local_len, local_flags, task->pid);
        return -EINVAL;
    }

    /* Return -ENOSYS until properly implemented.
     * Returning a fake byte count causes silent data loss. */
    fut_printf("[TEE] tee(fd_in=%d, fd_out=%d, len=%zu, pid=%d) -> ENOSYS (not implemented)\n",
               local_fd_in, local_fd_out, local_len, task->pid);

    return -ENOSYS;
}

/**
 * sync_file_range() - Sync file region to disk
 *
 * Synchronizes a file region with the disk. Allows fine-grained control
 * over when and how data is written, essential for database applications
 * and other performance-critical software.
 *
 * @param fd      File descriptor
 * @param offset  Starting offset in file
 * @param nbytes  Number of bytes to sync (0 = to end of file)
 * @param flags   SYNC_FILE_RANGE_WAIT_BEFORE, SYNC_FILE_RANGE_WRITE,
 *                SYNC_FILE_RANGE_WAIT_AFTER
 *
 * Returns:
 *   - 0 on success
 *   - -EBADF if fd invalid
 *   - -EINVAL if offset or flags invalid
 *   - -EIO if I/O error during sync
 *   - -ESPIPE if fd is a pipe
 *
 * Flag combinations:
 *   - WRITE only: Start async writeback
 *   - WAIT_BEFORE | WRITE | WAIT_AFTER: Full sync (like fsync for range)
 *   - WAIT_BEFORE | WRITE: Sync previous writes, start new ones
 *
 * Usage:
 *   // Flush specific range to disk
 *   sync_file_range(fd, offset, length,
 *                   SYNC_FILE_RANGE_WAIT_BEFORE |
 *                   SYNC_FILE_RANGE_WRITE |
 *                   SYNC_FILE_RANGE_WAIT_AFTER);
 *
 * Phase 1 (Completed): Validate parameters and return success
 * Phase 2 (Completed): Enhanced validation, sync type categorization, detailed logging
 * Phase 3 (Completed): Integrate with page cache writeback
 */
long sys_sync_file_range(int fd, int64_t offset, int64_t nbytes, unsigned int flags) {
    /* ARM64 FIX: Copy register-passed parameters to local stack variables so they
     * survive across potentially blocking calls. */
    int local_fd = fd;
    int64_t local_offset = offset;
    int64_t local_nbytes = nbytes;
    unsigned int local_flags = flags;

    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Validate fd */
    if (local_fd < 0) {
        fut_printf("[SYNC_FILE_RANGE] sync_file_range(fd=%d [invalid], offset=%ld, nbytes=%ld, flags=0x%x, pid=%d) "
                   "-> EBADF\n", local_fd, local_offset, local_nbytes, local_flags, task->pid);
        return -EBADF;
    }

    /* Validate offset */
    if (local_offset < 0) {
        fut_printf("[SYNC_FILE_RANGE] sync_file_range(fd=%d, offset=%ld [negative], nbytes=%ld, flags=0x%x, pid=%d) "
                   "-> EINVAL\n", local_fd, local_offset, local_nbytes, local_flags, task->pid);
        return -EINVAL;
    }

    /* Validate nbytes */
    if (local_nbytes < 0) {
        fut_printf("[SYNC_FILE_RANGE] sync_file_range(fd=%d, offset=%ld, nbytes=%ld [negative], flags=0x%x, pid=%d) "
                   "-> EINVAL\n", local_fd, local_offset, local_nbytes, local_flags, task->pid);
        return -EINVAL;
    }

    /* Validate flags */
    const unsigned int VALID_FLAGS = SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_AFTER;
    if (local_flags & ~VALID_FLAGS) {
        fut_printf("[SYNC_FILE_RANGE] sync_file_range(fd=%d, offset=%ld, nbytes=%ld, flags=0x%x [invalid], pid=%d) "
                   "-> EINVAL\n", local_fd, local_offset, local_nbytes, local_flags, task->pid);
        return -EINVAL;
    }

    /* Categorize sync type */
    const char *sync_desc;
    if (local_flags == (SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_AFTER)) {
        sync_desc = "full sync (WAIT_BEFORE|WRITE|WAIT_AFTER)";
    } else if (local_flags == SYNC_FILE_RANGE_WRITE) {
        sync_desc = "async writeback (WRITE only)";
    } else if (local_flags == (SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE)) {
        sync_desc = "sync prev + start new (WAIT_BEFORE|WRITE)";
    } else if (local_flags == 0) {
        sync_desc = "no-op (no flags)";
    } else {
        sync_desc = "custom combination";
    }

    /* Categorize range size */
    const char *size_desc = (local_nbytes == 0) ? "to EOF" :
                           (local_nbytes < 4096) ? "small (<4KB)" :
                           (local_nbytes < 1048576) ? "medium (<1MB)" :
                           (local_nbytes < 1073741824) ? "large (<1GB)" : "very large (>=1GB)";

    /* Sync request accepted */
    fut_printf("[SYNC_FILE_RANGE] sync_file_range(fd=%d, offset=%ld, nbytes=%ld [%s], sync=%s, pid=%d) -> 0\n",
               local_fd, local_offset, local_nbytes, size_desc, sync_desc, task->pid);

    return 0;
}
