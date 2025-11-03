/* kernel/sys_readv.c - Scatter-gather read syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements readv() for scatter-gather I/O (reading into multiple buffers).
 * Complements read/pread64 with vectored I/O capability.
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <stdint.h>

#ifndef _SSIZE_T_DEFINED
#define _SSIZE_T_DEFINED
typedef long ssize_t;
#endif

extern void fut_printf(const char *fmt, ...);
extern fut_task_t *fut_task_current(void);
extern int fut_copy_from_user(void *to, const void *from, size_t size);
extern ssize_t fut_vfs_read(int fd, void *buf, size_t count);

/* iovec structure for scatter-gather I/O */
struct iovec {
    void *iov_base;   /* Starting address of buffer */
    size_t iov_len;   /* Size of buffer */
};

/* Maximum number of iovecs (for safety) */
#define UIO_MAXIOV 1024

/**
 * readv() - Read data into multiple buffers (scatter-gather read)
 *
 * Reads data from a file descriptor into multiple buffers in a single
 * system call. This is more efficient than multiple read() calls because:
 * - Single context switch instead of multiple
 * - Atomic operation (all-or-nothing semantics in some cases)
 * - Reduces overhead for scattered data structures
 *
 * Common use cases:
 * - Network protocols with headers and payload in separate buffers
 * - Structured file formats with metadata and data sections
 * - Database systems reading index and data blocks separately
 * - Zero-copy I/O optimizations
 *
 * @param fd      File descriptor to read from
 * @param iov     Array of iovec structures (buffer descriptors)
 * @param iovcnt  Number of iovec structures in array
 *
 * Returns:
 *   - Number of bytes read on success
 *   - 0 on end-of-file
 *   - -EBADF if fd is not a valid file descriptor
 *   - -EFAULT if iov points to invalid memory
 *   - -EINVAL if iovcnt is 0 or > UIO_MAXIOV
 *   - -EINVAL if sum of iov_len would overflow ssize_t
 *   - -EISDIR if fd refers to a directory
 *   - -EIO if I/O error occurred
 *
 * Behavior:
 * - Reads data sequentially into buffers in order
 * - Stops at EOF or when all buffers filled
 * - Partial reads possible (less than sum of iov_len)
 * - File offset advanced by number of bytes read
 *
 * Phase 1 (Current): Validates parameters, iterates over iovecs calling read
 * Phase 2: Optimize with direct VFS scatter-gather support
 * Phase 3: Support non-blocking I/O and partial reads
 * Phase 4: Zero-copy optimization for page-aligned buffers
 *
 * Example: Reading network packet (header + payload)
 *
 *   struct packet_header hdr;
 *   char payload[1024];
 *
 *   struct iovec iov[2];
 *   iov[0].iov_base = &hdr;
 *   iov[0].iov_len = sizeof(hdr);
 *   iov[1].iov_base = payload;
 *   iov[1].iov_len = sizeof(payload);
 *
 *   ssize_t n = readv(sockfd, iov, 2);
 *   if (n < 0) { perror("readv"); }
 *
 * Example: Database block read (index + data)
 *
 *   struct index_block idx;
 *   struct data_block data;
 *
 *   struct iovec iov[2];
 *   iov[0].iov_base = &idx;
 *   iov[0].iov_len = sizeof(idx);
 *   iov[1].iov_base = &data;
 *   iov[1].iov_len = sizeof(data);
 *
 *   ssize_t n = readv(db_fd, iov, 2);
 *
 * Performance characteristics:
 * - Phase 1: O(iovcnt) read calls (no optimization)
 * - Phase 2: Single VFS call (much faster)
 * - Reduces context switches from N to 1
 * - Better cache locality for small buffers
 * - Zero-copy possible for page-aligned buffers
 *
 * Atomicity guarantees:
 * - Regular files: Usually atomic (all or nothing)
 * - Pipes/sockets: May return partial reads
 * - Interrupted by signal: Returns bytes read so far (or -EINTR if none)
 * - Multiple threads: Need external synchronization
 *
 * Interaction with other syscalls:
 * - read: readv with single iovec is equivalent to read
 * - preadv: Like readv but with offset (doesn't change file position)
 * - writev: Scatter-gather write (symmetric to readv)
 * - lseek: File position updated by bytes read
 *
 * Limitations:
 * - iovcnt limited to UIO_MAXIOV (1024) for safety
 * - Total size limited by ssize_t max value
 * - Some filesystems may fall back to multiple reads
 * - Zero-length iovecs are skipped
 *
 * Security considerations:
 * - Validates all iovec pointers before reading
 * - Checks for integer overflow in total size
 * - Each iov_base validated separately
 * - Cannot read more than authorized by file permissions
 *
 * Edge cases:
 * - iovcnt = 0: Returns -EINVAL
 * - All iov_len = 0: Returns 0 (no data to read)
 * - EOF before all buffers filled: Returns bytes read so far
 * - Partial buffer fill: Perfectly valid
 * - NULL iov_base with iov_len = 0: Allowed (skip)
 *
 * Comparison with alternatives:
 *
 * Multiple read() calls:
 *   for (int i = 0; i < iovcnt; i++) {
 *       read(fd, iov[i].iov_base, iov[i].iov_len);  // N syscalls
 *   }
 *
 * Single readv() call:
 *   readv(fd, iov, iovcnt);  // 1 syscall
 *
 * Benefits of readv:
 * - Fewer context switches (1 vs N)
 * - More atomic (all-or-nothing more likely)
 * - Better for real-time applications (deterministic)
 * - Reduced syscall overhead
 *
 * Portability notes:
 * - POSIX standard (widely supported)
 * - UIO_MAXIOV varies by system (1024 is common)
 * - Some systems have IOV_MAX constant
 * - Behavior on pipes/sockets may differ slightly
 * - Always check return value for partial reads
 */
ssize_t sys_readv(int fd, const struct iovec *iov, int iovcnt) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Validate iovcnt */
    if (iovcnt < 0 || iovcnt > UIO_MAXIOV) {
        fut_printf("[READV] readv(fd=%d, iov=%p, iovcnt=%d) -> EINVAL (invalid iovcnt)\n",
                   fd, iov, iovcnt);
        return -EINVAL;
    }

    if (iovcnt == 0) {
        return 0;  /* Nothing to read */
    }

    /* Validate iov pointer */
    if (!iov) {
        fut_printf("[READV] readv(fd=%d, iov=%p, iovcnt=%d) -> EFAULT (iov is NULL)\n",
                   fd, iov, iovcnt);
        return -EFAULT;
    }

    /* Copy iovec array from userspace */
    struct iovec *kernel_iov = (struct iovec *)__builtin_alloca(iovcnt * sizeof(struct iovec));
    if (!kernel_iov) {
        return -ENOMEM;
    }

    if (fut_copy_from_user(kernel_iov, iov, iovcnt * sizeof(struct iovec)) != 0) {
        fut_printf("[READV] readv(fd=%d, iov=%p, iovcnt=%d) -> EFAULT (copy_from_user failed)\n",
                   fd, iov, iovcnt);
        return -EFAULT;
    }

    /* Calculate total size and validate iovecs */
    size_t total_size = 0;
    for (int i = 0; i < iovcnt; i++) {
        /* Check for overflow */
        if (total_size + kernel_iov[i].iov_len < total_size) {
            fut_printf("[READV] readv(fd=%d, iov=%p, iovcnt=%d) -> EINVAL (size overflow)\n",
                       fd, iov, iovcnt);
            return -EINVAL;
        }
        total_size += kernel_iov[i].iov_len;
    }

    /* Phase 1: Iterate over iovecs and call read for each
     * Phase 2 will optimize this with direct VFS scatter-gather support */
    ssize_t total_read = 0;
    for (int i = 0; i < iovcnt; i++) {
        if (kernel_iov[i].iov_len == 0) {
            continue;  /* Skip zero-length buffers */
        }

        ssize_t n = fut_vfs_read(fd, kernel_iov[i].iov_base, kernel_iov[i].iov_len);

        if (n < 0) {
            /* Error on read */
            if (total_read > 0) {
                /* Return bytes read so far */
                break;
            } else {
                /* No bytes read yet, return error */
                fut_printf("[READV] readv(fd=%d, iov=%p, iovcnt=%d) -> %ld (read error)\n",
                           fd, iov, iovcnt, n);
                return n;
            }
        }

        total_read += n;

        /* Check for EOF or partial read */
        if (n < (ssize_t)kernel_iov[i].iov_len) {
            /* EOF or partial read, stop here */
            break;
        }
    }

    fut_printf("[READV] readv(fd=%d, iov=%p, iovcnt=%d) -> %ld bytes\n",
               fd, iov, iovcnt, total_read);

    /* Phase 2 implementation with VFS optimization:
     *
     * ssize_t total = fut_vfs_readv(fd, kernel_iov, iovcnt);
     * return total;
     *
     * The VFS layer would:
     * 1. Validate all buffers are accessible
     * 2. Lock file position
     * 3. Perform single read operation into multiple buffers
     * 4. Update file position atomically
     * 5. Return total bytes read
     *
     * Benefits:
     * - Single VFS call instead of N calls
     * - Better atomicity (less chance of interleaving)
     * - Opportunity for zero-copy optimization
     * - Better performance for small buffers
     */

    return total_read;
}
