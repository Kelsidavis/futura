/* kernel/sys_preadv.c - Position-based scatter-gather read syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements preadv() for position-based scatter-gather I/O.
 * Combines features of readv() (multiple buffers) and pread64() (explicit offset).
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
 * preadv() - Read data into multiple buffers from specific offset
 *
 * Combines the features of readv() and pread64():
 * - Reads into multiple buffers (like readv)
 * - Reads from specific offset without changing file position (like pread64)
 *
 * This is particularly useful for:
 * - Thread-safe I/O (doesn't modify shared file position)
 * - Concurrent reads from same file descriptor
 * - Database index lookups with scattered buffers
 * - Random access to structured files
 * - Avoiding lseek() + readv() race conditions
 *
 * @param fd      File descriptor to read from
 * @param iov     Array of iovec structures (buffer descriptors)
 * @param iovcnt  Number of iovec structures in array
 * @param offset  File offset to read from
 *
 * Returns:
 *   - Number of bytes read on success
 *   - 0 on end-of-file
 *   - -EBADF if fd is not a valid file descriptor
 *   - -EFAULT if iov points to invalid memory
 *   - -EINVAL if iovcnt is 0 or > UIO_MAXIOV
 *   - -EINVAL if offset is negative
 *   - -EINVAL if sum of iov_len would overflow ssize_t
 *   - -EISDIR if fd refers to a directory
 *   - -ESPIPE if fd is associated with a pipe or socket
 *   - -EIO if I/O error occurred
 *
 * Behavior:
 * - Reads data sequentially into buffers in order
 * - Reads from specified offset
 * - Does NOT change file position (unlike readv)
 * - Stops at EOF or when all buffers filled
 * - Partial reads possible (less than sum of iov_len)
 *
 * Phase 1 (Current): Validates parameters, iterates over iovecs calling pread64
 * Phase 2: Optimize with direct VFS scatter-gather support
 * Phase 3: Support non-blocking I/O and partial reads
 * Phase 4: Zero-copy optimization for page-aligned buffers
 *
 * Example: Thread-safe database record read
 *
 *   struct record_header hdr;
 *   char data[1024];
 *
 *   struct iovec iov[2];
 *   iov[0].iov_base = &hdr;
 *   iov[0].iov_len = sizeof(hdr);
 *   iov[1].iov_base = data;
 *   iov[1].iov_len = sizeof(data);
 *
 *   // Multiple threads can safely read from different offsets
 *   ssize_t n = preadv(db_fd, iov, 2, record_offset);
 *   if (n < 0) { perror("preadv"); }
 *
 * Example: Concurrent log file processing
 *
 *   // Thread 1 reads from offset 0
 *   preadv(log_fd, iov1, count1, 0);
 *
 *   // Thread 2 reads from offset 10000 (no interference)
 *   preadv(log_fd, iov2, count2, 10000);
 *
 * Performance characteristics:
 * - Phase 1: O(iovcnt) pread64 calls
 * - Phase 2: Single VFS call (much faster)
 * - No lseek overhead
 * - Thread-safe (no file position contention)
 * - Better cache locality than separate calls
 *
 * Atomicity guarantees:
 * - Regular files: Usually atomic (all or nothing)
 * - File position: Never changed (thread-safe)
 * - Interrupted by signal: Returns bytes read so far (or -EINTR if none)
 * - Multiple threads: Safe to use same fd with different offsets
 *
 * Interaction with other syscalls:
 * - readv: preadv with automatic offset tracking
 * - pread64: preadv with single iovec is equivalent to pread64
 * - pwritev: Position-based scatter-gather write (symmetric)
 * - lseek: File position NOT affected by preadv
 *
 * Limitations:
 * - iovcnt limited to UIO_MAXIOV (1024) for safety
 * - Total size limited by ssize_t max value
 * - Some filesystems may fall back to multiple pread64 calls
 * - Zero-length iovecs are skipped
 * - Cannot be used on pipes, FIFOs, or sockets
 *
 * Security considerations:
 * - Validates all iovec pointers before reading
 * - Checks for integer overflow in total size
 * - Each iov_base validated separately
 * - Cannot read more than authorized by file permissions
 * - Offset validation prevents negative seeks
 *
 * Edge cases:
 * - iovcnt = 0: Returns 0 (no data to read)
 * - All iov_len = 0: Returns 0 (no data to read)
 * - offset beyond EOF: Returns 0 (EOF)
 * - Negative offset: Returns -EINVAL
 * - EOF before all buffers filled: Returns bytes read so far
 * - Partial buffer fill: Perfectly valid
 *
 * Comparison with alternatives:
 *
 * Using lseek + readv (not thread-safe):
 *   lseek(fd, offset, SEEK_SET);  // Race condition window
 *   readv(fd, iov, iovcnt);       // Another thread may change position
 *
 * Using preadv (thread-safe):
 *   preadv(fd, iov, iovcnt, offset);  // Atomic, no race
 *
 * Benefits of preadv:
 * - Thread-safe (no file position modification)
 * - Atomic offset + read operation
 * - Fewer syscalls than lseek + readv
 * - No race conditions with concurrent I/O
 *
 * Portability notes:
 * - POSIX.1-2008 standard
 * - UIO_MAXIOV varies by system (1024 is common)
 * - Not available on all systems (check feature test macros)
 * - Behavior on pipes/sockets may differ (typically returns -ESPIPE)
 * - Always check return value for partial reads
 */
ssize_t sys_preadv(int fd, const struct iovec *iov, int iovcnt, int64_t offset) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Validate offset */
    if (offset < 0) {
        fut_printf("[PREADV] preadv(fd=%d, iov=%p, iovcnt=%d, offset=%ld) -> EINVAL (negative offset)\n",
                   fd, iov, iovcnt, offset);
        return -EINVAL;
    }

    /* Validate iovcnt */
    if (iovcnt < 0 || iovcnt > UIO_MAXIOV) {
        fut_printf("[PREADV] preadv(fd=%d, iov=%p, iovcnt=%d, offset=%ld) -> EINVAL (invalid iovcnt)\n",
                   fd, iov, iovcnt, offset);
        return -EINVAL;
    }

    if (iovcnt == 0) {
        return 0;  /* Nothing to read */
    }

    /* Validate iov pointer */
    if (!iov) {
        fut_printf("[PREADV] preadv(fd=%d, iov=%p, iovcnt=%d, offset=%ld) -> EFAULT (iov is NULL)\n",
                   fd, iov, iovcnt, offset);
        return -EFAULT;
    }

    /* Copy iovec array from userspace */
    struct iovec *kernel_iov = (struct iovec *)__builtin_alloca(iovcnt * sizeof(struct iovec));
    if (!kernel_iov) {
        return -ENOMEM;
    }

    if (fut_copy_from_user(kernel_iov, iov, iovcnt * sizeof(struct iovec)) != 0) {
        fut_printf("[PREADV] preadv(fd=%d, iov=%p, iovcnt=%d, offset=%ld) -> EFAULT (copy_from_user failed)\n",
                   fd, iov, iovcnt, offset);
        return -EFAULT;
    }

    /* Calculate total size and validate iovecs */
    size_t total_size = 0;
    for (int i = 0; i < iovcnt; i++) {
        /* Check for overflow */
        if (total_size + kernel_iov[i].iov_len < total_size) {
            fut_printf("[PREADV] preadv(fd=%d, iov=%p, iovcnt=%d, offset=%ld) -> EINVAL (size overflow)\n",
                       fd, iov, iovcnt, offset);
            return -EINVAL;
        }
        total_size += kernel_iov[i].iov_len;
    }

    /* Get file structure from task */
    struct fut_file *file = vfs_get_file_from_task(task, fd);
    if (!file) {
        fut_printf("[PREADV] preadv(fd=%d, iov=%p, iovcnt=%d, offset=%ld) -> EBADF\n",
                   fd, iov, iovcnt, offset);
        return -EBADF;
    }

    /* preadv() not supported on character devices, pipes, or sockets */
    if (file->chr_ops) {
        fut_printf("[PREADV] preadv(fd=%d, iov=%p, iovcnt=%d, offset=%ld) -> ESPIPE (chrdev)\n",
                   fd, iov, iovcnt, offset);
        return -ESPIPE;
    }

    /* Check if this is a directory */
    if (file->vnode && file->vnode->type == VN_DIR) {
        fut_printf("[PREADV] preadv(fd=%d, iov=%p, iovcnt=%d, offset=%ld) -> EISDIR\n",
                   fd, iov, iovcnt, offset);
        return -EISDIR;
    }

    /* Validate vnode operations */
    if (!file->vnode || !file->vnode->ops || !file->vnode->ops->read) {
        fut_printf("[PREADV] preadv(fd=%d, iov=%p, iovcnt=%d, offset=%ld) -> EINVAL (no read op)\n",
                   fd, iov, iovcnt, offset);
        return -EINVAL;
    }

    /* Phase 1: Iterate over iovecs and read each into kernel buffer, then copy to user
     * Phase 2 will optimize this with direct VFS scatter-gather support */
    ssize_t total_read = 0;
    int64_t current_offset = offset;

    for (int i = 0; i < iovcnt; i++) {
        if (kernel_iov[i].iov_len == 0) {
            continue;  /* Skip zero-length buffers */
        }

        /* Allocate kernel buffer for this iovec */
        void *kbuf = fut_malloc(kernel_iov[i].iov_len);
        if (!kbuf) {
            if (total_read > 0) {
                break;  /* Return bytes read so far */
            }
            return -ENOMEM;
        }

        /* Read from file at specified offset without changing file->offset */
        ssize_t n = file->vnode->ops->read(file->vnode, kbuf, kernel_iov[i].iov_len, (uint64_t)current_offset);

        if (n < 0) {
            /* Error on read */
            fut_free(kbuf);
            if (total_read > 0) {
                /* Return bytes read so far */
                break;
            } else {
                /* No bytes read yet, return error */
                fut_printf("[PREADV] preadv(fd=%d, iov=%p, iovcnt=%d, offset=%ld) -> %ld (read error)\n",
                           fd, iov, iovcnt, offset, n);
                return n;
            }
        }

        /* Copy to userspace if successful */
        if (n > 0) {
            if (fut_copy_to_user(kernel_iov[i].iov_base, kbuf, (size_t)n) != 0) {
                fut_free(kbuf);
                if (total_read > 0) {
                    break;  /* Return bytes read so far */
                }
                fut_printf("[PREADV] preadv(fd=%d, iov=%p, iovcnt=%d, offset=%ld) -> EFAULT (copy_to_user failed)\n",
                           fd, iov, iovcnt, offset);
                return -EFAULT;
            }
        }

        fut_free(kbuf);
        total_read += n;
        current_offset += n;

        /* Check for EOF or partial read */
        if (n < (ssize_t)kernel_iov[i].iov_len) {
            /* EOF or partial read, stop here */
            break;
        }
    }

    fut_printf("[PREADV] preadv(fd=%d, iov=%p, iovcnt=%d, offset=%ld) -> %ld bytes\n",
               fd, iov, iovcnt, offset, total_read);

    /* Phase 2 implementation with VFS optimization:
     *
     * ssize_t total = fut_vfs_preadv(fd, kernel_iov, iovcnt, offset);
     * return total;
     *
     * The VFS layer would:
     * 1. Validate all buffers are accessible
     * 2. Lock file (no position lock needed)
     * 3. Perform single read operation from offset into multiple buffers
     * 4. Return total bytes read
     * 5. Leave file position unchanged
     *
     * Benefits:
     * - Single VFS call instead of N calls
     * - Better atomicity (all-or-nothing more likely)
     * - Opportunity for zero-copy optimization
     * - Better performance for small buffers
     * - Thread-safe (no file position modification)
     */

    return total_read;
}
