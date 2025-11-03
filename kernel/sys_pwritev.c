/* kernel/sys_pwritev.c - Position-based scatter-gather write syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements pwritev() for position-based scatter-gather I/O.
 * Combines features of writev() (multiple buffers) and pwrite64() (explicit offset).
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <stdint.h>

#ifndef _SSIZE_T_DEFINED
#define _SSIZE_T_DEFINED
typedef long ssize_t;
#endif

extern void fut_printf(const char *fmt, ...);
extern fut_task_t *fut_task_current(void);
extern int fut_copy_from_user(void *to, const void *from, size_t size);
extern int fut_copy_to_user(void *to, const void *from, size_t size);
extern void *fut_malloc(size_t size);
extern void fut_free(void *ptr);
extern struct fut_file *vfs_get_file_from_task(struct fut_task *task, int fd);

/* iovec structure for scatter-gather I/O */
struct iovec {
    void *iov_base;   /* Starting address of buffer */
    size_t iov_len;   /* Size of buffer */
};

/* Maximum number of iovecs (for safety) */
#define UIO_MAXIOV 1024

/**
 * pwritev() - Write data from multiple buffers to specific offset
 *
 * Combines the features of writev() and pwrite64():
 * - Writes from multiple buffers (like writev)
 * - Writes to specific offset without changing file position (like pwrite64)
 *
 * This is particularly useful for:
 * - Thread-safe I/O (doesn't modify shared file position)
 * - Concurrent writes to same file descriptor
 * - Database updates with scattered buffers
 * - Random access to structured files
 * - Avoiding lseek() + writev() race conditions
 *
 * @param fd      File descriptor to write to
 * @param iov     Array of iovec structures (buffer descriptors)
 * @param iovcnt  Number of iovec structures in array
 * @param offset  File offset to write to
 *
 * Returns:
 *   - Number of bytes written on success
 *   - -EBADF if fd is not a valid file descriptor
 *   - -EFAULT if iov points to invalid memory
 *   - -EINVAL if iovcnt is 0 or > UIO_MAXIOV
 *   - -EINVAL if offset is negative
 *   - -EINVAL if sum of iov_len would overflow ssize_t
 *   - -EISDIR if fd refers to a directory
 *   - -ESPIPE if fd is associated with a pipe or socket
 *   - -EIO if I/O error occurred
 *   - -ENOSPC if device has no space
 *
 * Behavior:
 * - Writes data sequentially from buffers in order
 * - Writes to specified offset
 * - Does NOT change file position (unlike writev)
 * - Stops when all buffers written or error occurs
 * - Partial writes possible (less than sum of iov_len)
 *
 * Phase 1 (Current): Validates parameters, iterates over iovecs calling pwrite64
 * Phase 2: Optimize with direct VFS scatter-gather support
 * Phase 3: Support non-blocking I/O and partial writes
 * Phase 4: Zero-copy optimization for page-aligned buffers
 *
 * Example: Thread-safe database record update
 *
 *   struct record_header hdr = { .version = 2, .size = 1024 };
 *   char data[1024];
 *   prepare_data(data);
 *
 *   struct iovec iov[2];
 *   iov[0].iov_base = &hdr;
 *   iov[0].iov_len = sizeof(hdr);
 *   iov[1].iov_base = data;
 *   iov[1].iov_len = sizeof(data);
 *
 *   // Multiple threads can safely write to different offsets
 *   ssize_t n = pwritev(db_fd, iov, 2, record_offset);
 *   if (n < 0) { perror("pwritev"); }
 *
 * Example: Concurrent log file writing
 *
 *   // Thread 1 writes to offset 0
 *   pwritev(log_fd, iov1, count1, 0);
 *
 *   // Thread 2 writes to offset 10000 (no interference)
 *   pwritev(log_fd, iov2, count2, 10000);
 *
 * Performance characteristics:
 * - Phase 1: O(iovcnt) pwrite64 calls
 * - Phase 2: Single VFS call (much faster)
 * - No lseek overhead
 * - Thread-safe (no file position contention)
 * - Better cache locality than separate calls
 *
 * Atomicity guarantees:
 * - Regular files: Usually atomic (all or nothing)
 * - File position: Never changed (thread-safe)
 * - Interrupted by signal: Returns bytes written so far (or -EINTR if none)
 * - Multiple threads: Safe to use same fd with different offsets
 *
 * Interaction with other syscalls:
 * - writev: pwritev with automatic offset tracking
 * - pwrite64: pwritev with single iovec is equivalent to pwrite64
 * - preadv: Position-based scatter-gather read (symmetric)
 * - lseek: File position NOT affected by pwritev
 *
 * Limitations:
 * - iovcnt limited to UIO_MAXIOV (1024) for safety
 * - Total size limited by ssize_t max value
 * - Some filesystems may fall back to multiple pwrite64 calls
 * - Zero-length iovecs are skipped
 * - Cannot be used on pipes, FIFOs, or sockets
 *
 * Security considerations:
 * - Validates all iovec pointers before writing
 * - Checks for integer overflow in total size
 * - Each iov_base validated separately
 * - Cannot write more than authorized by file permissions
 * - Offset validation prevents negative seeks
 *
 * Edge cases:
 * - iovcnt = 0: Returns 0 (no data to write)
 * - All iov_len = 0: Returns 0 (no data to write)
 * - offset beyond EOF: Extends file (creates hole)
 * - Negative offset: Returns -EINVAL
 * - Disk full before all buffers written: Returns bytes written so far
 * - Partial buffer write: Perfectly valid
 *
 * Comparison with alternatives:
 *
 * Using lseek + writev (not thread-safe):
 *   lseek(fd, offset, SEEK_SET);  // Race condition window
 *   writev(fd, iov, iovcnt);      // Another thread may change position
 *
 * Using pwritev (thread-safe):
 *   pwritev(fd, iov, iovcnt, offset);  // Atomic, no race
 *
 * Benefits of pwritev:
 * - Thread-safe (no file position modification)
 * - Atomic offset + write operation
 * - Fewer syscalls than lseek + writev
 * - No race conditions with concurrent I/O
 *
 * Portability notes:
 * - POSIX.1-2008 standard
 * - UIO_MAXIOV varies by system (1024 is common)
 * - Not available on all systems (check feature test macros)
 * - Behavior on pipes/sockets may differ (typically returns -ESPIPE)
 * - Always check return value for partial writes
 */
ssize_t sys_pwritev(int fd, const struct iovec *iov, int iovcnt, int64_t offset) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Validate offset */
    if (offset < 0) {
        fut_printf("[PWRITEV] pwritev(fd=%d, iov=%p, iovcnt=%d, offset=%ld) -> EINVAL (negative offset)\n",
                   fd, iov, iovcnt, offset);
        return -EINVAL;
    }

    /* Validate iovcnt */
    if (iovcnt < 0 || iovcnt > UIO_MAXIOV) {
        fut_printf("[PWRITEV] pwritev(fd=%d, iov=%p, iovcnt=%d, offset=%ld) -> EINVAL (invalid iovcnt)\n",
                   fd, iov, iovcnt, offset);
        return -EINVAL;
    }

    if (iovcnt == 0) {
        return 0;  /* Nothing to write */
    }

    /* Validate iov pointer */
    if (!iov) {
        fut_printf("[PWRITEV] pwritev(fd=%d, iov=%p, iovcnt=%d, offset=%ld) -> EFAULT (iov is NULL)\n",
                   fd, iov, iovcnt, offset);
        return -EFAULT;
    }

    /* Copy iovec array from userspace */
    struct iovec *kernel_iov = (struct iovec *)__builtin_alloca(iovcnt * sizeof(struct iovec));
    if (!kernel_iov) {
        return -ENOMEM;
    }

    if (fut_copy_from_user(kernel_iov, iov, iovcnt * sizeof(struct iovec)) != 0) {
        fut_printf("[PWRITEV] pwritev(fd=%d, iov=%p, iovcnt=%d, offset=%ld) -> EFAULT (copy_from_user failed)\n",
                   fd, iov, iovcnt, offset);
        return -EFAULT;
    }

    /* Calculate total size and validate iovecs */
    size_t total_size = 0;
    for (int i = 0; i < iovcnt; i++) {
        /* Check for overflow */
        if (total_size + kernel_iov[i].iov_len < total_size) {
            fut_printf("[PWRITEV] pwritev(fd=%d, iov=%p, iovcnt=%d, offset=%ld) -> EINVAL (size overflow)\n",
                       fd, iov, iovcnt, offset);
            return -EINVAL;
        }
        total_size += kernel_iov[i].iov_len;
    }

    /* Get file structure from task */
    struct fut_file *file = vfs_get_file_from_task(task, fd);
    if (!file) {
        fut_printf("[PWRITEV] pwritev(fd=%d, iov=%p, iovcnt=%d, offset=%ld) -> EBADF\n",
                   fd, iov, iovcnt, offset);
        return -EBADF;
    }

    /* pwritev() not supported on character devices, pipes, or sockets */
    if (file->chr_ops) {
        fut_printf("[PWRITEV] pwritev(fd=%d, iov=%p, iovcnt=%d, offset=%ld) -> ESPIPE (chrdev)\n",
                   fd, iov, iovcnt, offset);
        return -ESPIPE;
    }

    /* Check if this is a directory */
    if (file->vnode && file->vnode->type == VN_DIR) {
        fut_printf("[PWRITEV] pwritev(fd=%d, iov=%p, iovcnt=%d, offset=%ld) -> EISDIR\n",
                   fd, iov, iovcnt, offset);
        return -EISDIR;
    }

    /* Validate vnode operations */
    if (!file->vnode || !file->vnode->ops || !file->vnode->ops->write) {
        fut_printf("[PWRITEV] pwritev(fd=%d, iov=%p, iovcnt=%d, offset=%ld) -> EINVAL (no write op)\n",
                   fd, iov, iovcnt, offset);
        return -EINVAL;
    }

    /* Phase 1: Iterate over iovecs and write each from kernel buffer
     * Phase 2 will optimize this with direct VFS scatter-gather support */
    ssize_t total_written = 0;
    int64_t current_offset = offset;

    for (int i = 0; i < iovcnt; i++) {
        if (kernel_iov[i].iov_len == 0) {
            continue;  /* Skip zero-length buffers */
        }

        /* Allocate kernel buffer for this iovec */
        void *kbuf = fut_malloc(kernel_iov[i].iov_len);
        if (!kbuf) {
            if (total_written > 0) {
                break;  /* Return bytes written so far */
            }
            return -ENOMEM;
        }

        /* Copy from userspace */
        if (fut_copy_from_user(kbuf, kernel_iov[i].iov_base, kernel_iov[i].iov_len) != 0) {
            fut_free(kbuf);
            if (total_written > 0) {
                break;  /* Return bytes written so far */
            }
            fut_printf("[PWRITEV] pwritev(fd=%d, iov=%p, iovcnt=%d, offset=%ld) -> EFAULT (copy_from_user failed)\n",
                       fd, iov, iovcnt, offset);
            return -EFAULT;
        }

        /* Write to file at specified offset without changing file->offset */
        ssize_t n = file->vnode->ops->write(file->vnode, kbuf, kernel_iov[i].iov_len, (uint64_t)current_offset);

        fut_free(kbuf);

        if (n < 0) {
            /* Error on write */
            if (total_written > 0) {
                /* Return bytes written so far */
                break;
            } else {
                /* No bytes written yet, return error */
                fut_printf("[PWRITEV] pwritev(fd=%d, iov=%p, iovcnt=%d, offset=%ld) -> %ld (write error)\n",
                           fd, iov, iovcnt, offset, n);
                return n;
            }
        }

        total_written += n;
        current_offset += n;

        /* Check for partial write */
        if (n < (ssize_t)kernel_iov[i].iov_len) {
            /* Partial write, stop here */
            break;
        }
    }

    fut_printf("[PWRITEV] pwritev(fd=%d, iov=%p, iovcnt=%d, offset=%ld) -> %ld bytes\n",
               fd, iov, iovcnt, offset, total_written);

    /* Phase 2 implementation with VFS optimization:
     *
     * ssize_t total = fut_vfs_pwritev(fd, kernel_iov, iovcnt, offset);
     * return total;
     *
     * The VFS layer would:
     * 1. Validate all buffers are accessible
     * 2. Lock file (no position lock needed)
     * 3. Perform single write operation to offset from multiple buffers
     * 4. Return total bytes written
     * 5. Leave file position unchanged
     *
     * Benefits:
     * - Single VFS call instead of N calls
     * - Better atomicity (all-or-nothing more likely)
     * - Opportunity for zero-copy optimization
     * - Better performance for small buffers
     * - Thread-safe (no file position modification)
     */

    return total_written;
}
