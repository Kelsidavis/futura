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
 * Phase 2 (Current): Enhanced validation, operation type categorization, detailed logging
 * Phase 3: Implement pipe-based zero-copy transfers
 * Phase 4: Add page cache integration for file-to-file transfers
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <stdint.h>
#include <stddef.h>

/* Signed size type for return values */
typedef long ssize_t;

extern void fut_printf(const char *fmt, ...);

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
 * Phase 2 (Current): Enhanced validation and operation categorization with detailed logging
 * Phase 3: Implement pipe-based transfers
 * Phase 4: Add page cache integration for files
 */
long sys_splice(int fd_in, int64_t *off_in, int fd_out, int64_t *off_out,
                size_t len, unsigned int flags) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[SPLICE] splice(fd_in=%d, off_in=%p, fd_out=%d, off_out=%p, len=%zu, flags=0x%x) "
                   "-> ESRCH (no current task)\n", fd_in, off_in, fd_out, off_out, len, flags);
        return -ESRCH;
    }

    /* Validate fds */
    if (fd_in < 0 || fd_out < 0) {
        fut_printf("[SPLICE] splice(fd_in=%d, fd_out=%d, len=%zu, flags=0x%x, pid=%d) "
                   "-> EBADF (invalid fd)\n", fd_in, fd_out, len, flags, task->pid);
        return -EBADF;
    }

    /* Validate flags */
    const unsigned int VALID_FLAGS = SPLICE_F_MOVE | SPLICE_F_NONBLOCK | SPLICE_F_MORE | SPLICE_F_GIFT;
    if (flags & ~VALID_FLAGS) {
        fut_printf("[SPLICE] splice(fd_in=%d, fd_out=%d, len=%zu, flags=0x%x [invalid], pid=%d) "
                   "-> EINVAL\n", fd_in, fd_out, len, flags, task->pid);
        return -EINVAL;
    }

    /* Categorize operation */
    const char *op_desc;
    if (off_in == NULL && off_out == NULL) {
        op_desc = "pipe-to-pipe";
    } else if (off_in == NULL) {
        op_desc = "pipe-to-file";
    } else if (off_out == NULL) {
        op_desc = "file-to-pipe";
    } else {
        op_desc = "file-to-file [invalid]";
    }

    /* Categorize flags */
    const char *flags_desc;
    if (flags == 0) {
        flags_desc = "none";
    } else if (flags == SPLICE_F_MOVE) {
        flags_desc = "MOVE";
    } else if (flags == (SPLICE_F_MOVE | SPLICE_F_MORE)) {
        flags_desc = "MOVE|MORE";
    } else if (flags == SPLICE_F_NONBLOCK) {
        flags_desc = "NONBLOCK";
    } else {
        flags_desc = "combination";
    }

    /* Categorize size */
    const char *size_desc = (len < 4096) ? "small (<4KB)" :
                           (len < 65536) ? "medium (<64KB)" :
                           (len < 1048576) ? "large (<1MB)" : "very large (≥1MB)";

    /* Phase 1: Return dummy byte count */
    ssize_t dummy_bytes = (ssize_t)len;
    fut_printf("[SPLICE] splice(%s: fd_in=%d, fd_out=%d, len=%zu [%s], flags=%s, pid=%d) -> %zd "
               "(Phase 1 stub - no actual transfer)\n",
               op_desc, fd_in, fd_out, len, size_desc, flags_desc, task->pid, dummy_bytes);

    return dummy_bytes;
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
 * Phase 2 (Current): Enhanced validation and segment categorization with detailed logging
 * Phase 3: Map user pages and add to pipe buffer
 */
long sys_vmsplice(int fd, const void *iov, size_t nr_segs, unsigned int flags) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Suppress unused warning for Phase 1 */
    (void)iov;

    /* Validate fd */
    if (fd < 0) {
        fut_printf("[VMSPLICE] vmsplice(fd=%d [invalid], nr_segs=%zu, flags=0x%x, pid=%d) "
                   "-> EBADF\n", fd, nr_segs, flags, task->pid);
        return -EBADF;
    }

    /* Validate nr_segs */
    if (nr_segs == 0) {
        fut_printf("[VMSPLICE] vmsplice(fd=%d, nr_segs=0 [invalid], flags=0x%x, pid=%d) "
                   "-> EINVAL\n", fd, flags, task->pid);
        return -EINVAL;
    }

    /* Validate flags */
    const unsigned int VALID_FLAGS = SPLICE_F_MOVE | SPLICE_F_NONBLOCK | SPLICE_F_MORE | SPLICE_F_GIFT;
    if (flags & ~VALID_FLAGS) {
        fut_printf("[VMSPLICE] vmsplice(fd=%d, nr_segs=%zu, flags=0x%x [invalid], pid=%d) "
                   "-> EINVAL\n", fd, nr_segs, flags, task->pid);
        return -EINVAL;
    }

    /* Categorize segment count */
    const char *segs_desc = (nr_segs == 1) ? "single" :
                           (nr_segs < 8) ? "few (<8)" :
                           (nr_segs < 64) ? "many (<64)" : "very many (≥64)";

    /* Phase 1: Return dummy byte count */
    ssize_t dummy_bytes = (ssize_t)(nr_segs * 4096);  /* Assume ~4KB per segment */
    fut_printf("[VMSPLICE] vmsplice(fd=%d, nr_segs=%zu [%s], flags=0x%x, pid=%d) -> %zd "
               "(Phase 1 stub - no actual splice)\n",
               fd, nr_segs, segs_desc, flags, task->pid, dummy_bytes);

    return dummy_bytes;
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
 * Phase 2 (Current): Enhanced validation and sanity checks with detailed logging
 * Phase 3: Duplicate pipe buffer pages
 */
long sys_tee(int fd_in, int fd_out, size_t len, unsigned int flags) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Validate fds */
    if (fd_in < 0 || fd_out < 0) {
        fut_printf("[TEE] tee(fd_in=%d, fd_out=%d, len=%zu, flags=0x%x, pid=%d) "
                   "-> EBADF (invalid fd)\n", fd_in, fd_out, len, flags, task->pid);
        return -EBADF;
    }

    /* Check if same fd */
    if (fd_in == fd_out) {
        fut_printf("[TEE] tee(fd_in=%d, fd_out=%d [same], len=%zu, flags=0x%x, pid=%d) "
                   "-> EINVAL\n", fd_in, fd_out, len, flags, task->pid);
        return -EINVAL;
    }

    /* Validate flags */
    const unsigned int VALID_FLAGS = SPLICE_F_NONBLOCK | SPLICE_F_MORE;
    if (flags & ~VALID_FLAGS) {
        fut_printf("[TEE] tee(fd_in=%d, fd_out=%d, len=%zu, flags=0x%x [invalid], pid=%d) "
                   "-> EINVAL\n", fd_in, fd_out, len, flags, task->pid);
        return -EINVAL;
    }

    /* Phase 1: Return dummy byte count */
    ssize_t dummy_bytes = (ssize_t)len;
    fut_printf("[TEE] tee(fd_in=%d, fd_out=%d, len=%zu, flags=0x%x, pid=%d) -> %zd "
               "(Phase 1 stub - no actual duplication)\n",
               fd_in, fd_out, len, flags, task->pid, dummy_bytes);

    return dummy_bytes;
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
 * Phase 2 (Current): Enhanced validation, sync type categorization, detailed logging
 * Phase 3: Integrate with page cache writeback
 */
long sys_sync_file_range(int fd, int64_t offset, int64_t nbytes, unsigned int flags) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Validate fd */
    if (fd < 0) {
        fut_printf("[SYNC_FILE_RANGE] sync_file_range(fd=%d [invalid], offset=%ld, nbytes=%ld, flags=0x%x, pid=%d) "
                   "-> EBADF\n", fd, offset, nbytes, flags, task->pid);
        return -EBADF;
    }

    /* Validate offset */
    if (offset < 0) {
        fut_printf("[SYNC_FILE_RANGE] sync_file_range(fd=%d, offset=%ld [negative], nbytes=%ld, flags=0x%x, pid=%d) "
                   "-> EINVAL\n", fd, offset, nbytes, flags, task->pid);
        return -EINVAL;
    }

    /* Validate nbytes */
    if (nbytes < 0) {
        fut_printf("[SYNC_FILE_RANGE] sync_file_range(fd=%d, offset=%ld, nbytes=%ld [negative], flags=0x%x, pid=%d) "
                   "-> EINVAL\n", fd, offset, nbytes, flags, task->pid);
        return -EINVAL;
    }

    /* Validate flags */
    const unsigned int VALID_FLAGS = SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_AFTER;
    if (flags & ~VALID_FLAGS) {
        fut_printf("[SYNC_FILE_RANGE] sync_file_range(fd=%d, offset=%ld, nbytes=%ld, flags=0x%x [invalid], pid=%d) "
                   "-> EINVAL\n", fd, offset, nbytes, flags, task->pid);
        return -EINVAL;
    }

    /* Categorize sync type */
    const char *sync_desc;
    if (flags == (SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_AFTER)) {
        sync_desc = "full sync (WAIT_BEFORE|WRITE|WAIT_AFTER)";
    } else if (flags == SYNC_FILE_RANGE_WRITE) {
        sync_desc = "async writeback (WRITE only)";
    } else if (flags == (SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE)) {
        sync_desc = "sync prev + start new (WAIT_BEFORE|WRITE)";
    } else if (flags == 0) {
        sync_desc = "no-op (no flags)";
    } else {
        sync_desc = "custom combination";
    }

    /* Categorize range size */
    const char *size_desc = (nbytes == 0) ? "to EOF" :
                           (nbytes < 4096) ? "small (<4KB)" :
                           (nbytes < 1048576) ? "medium (<1MB)" :
                           (nbytes < 1073741824) ? "large (<1GB)" : "very large (≥1GB)";

    /* Phase 1: Accept sync request */
    fut_printf("[SYNC_FILE_RANGE] sync_file_range(fd=%d, offset=%ld, nbytes=%ld [%s], sync=%s, pid=%d) -> 0 "
               "(Phase 1 stub - no actual sync)\n",
               fd, offset, nbytes, size_desc, sync_desc, task->pid);

    return 0;
}
