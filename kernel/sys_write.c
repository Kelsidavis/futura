/* kernel/sys_write.c - Write to file descriptor syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements write() to write data to file descriptors.
 * Core I/O primitive for files, pipes, sockets, and devices.
 *
 * Phase 1 (Completed): Basic write with kernel buffer allocation
 * Phase 2 (Completed): Enhanced validation, size categorization, and detailed logging
 * Phase 3: Direct user-to-kernel transfer for zero-copy optimization
 * Phase 4: Advanced features (vectored I/O hints, writebehind, async I/O)
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
 * This is the fundamental output syscall for all file descriptor types.
 *
 * @param fd    File descriptor to write to
 * @param buf   User buffer containing data to write
 * @param count Number of bytes to write
 *
 * Returns:
 *   - Number of bytes written (may be less than count) on success
 *   - 0 if count is 0 (valid empty write)
 *   - -EBADF if fd is not a valid open file descriptor or not open for writing
 *   - -EFAULT if buf points to invalid memory
 *   - -EINVAL if count is invalid or exceeds limits
 *   - -EIO if I/O error occurred during write
 *   - -ENOSPC if no space left on device
 *   - -EPIPE if writing to closed pipe (generates SIGPIPE)
 *   - -EAGAIN if non-blocking and cannot write (buffer full)
 *   - -EINTR if interrupted by signal
 *   - -ENOMEM if insufficient memory for kernel buffer
 *
 * Behavior:
 *   - Writes to current file offset
 *   - Advances file offset by number of bytes actually written
 *   - May write less than requested (short write):
 *     - Disk full or quota exceeded
 *     - Interrupted by signal
 *     - Slow device (socket, pipe, terminal)
 *     - Kernel buffer constraints
 *   - Returns count on full success
 *   - Blocks until can write at least 1 byte (unless O_NONBLOCK)
 *   - Atomicity: write operation is atomic for regular files
 *
 * File descriptor types:
 *   - Regular files: Writes to inode data, advances file offset, extends file
 *   - Sockets: Writes to send buffer, may block if buffer full
 *   - Pipes: Writes to pipe buffer, blocks if full, SIGPIPE if no readers
 *   - Character devices: Device-specific semantics (TTY, console)
 *   - Block devices: Writes to device blocks
 *
 * Short write conditions:
 *   - Disk full or quota exceeded (ENOSPC)
 *   - Signal interruption (partial write may succeed)
 *   - Resource constraints (memory, buffer limits)
 *   - Socket/pipe buffer space available less than requested
 *
 * Common usage patterns:
 *
 * Write entire buffer:
 *   int fd = open("/path/to/file", O_WRONLY | O_CREAT, 0644);
 *   const char *data = "Hello, World!";
 *   ssize_t n = write(fd, data, strlen(data));
 *   if (n < 0) { perror("write"); }
 *   if (n != strlen(data)) { }  // short write
 *   close(fd);
 *
 * Write with retry (handle short writes):
 *   ssize_t total = 0;
 *   while (total < needed) {
 *       ssize_t n = write(fd, buf + total, needed - total);
 *       if (n < 0) { handle error }
 *       if (n == 0) { break; }  // cannot write anymore
 *       total += n;
 *   }
 *
 * Non-blocking write:
 *   fcntl(fd, F_SETFL, O_NONBLOCK);
 *   ssize_t n = write(fd, buf, count);
 *   if (n < 0 && errno == EAGAIN) {
 *       // Buffer full, try again later
 *   }
 *
 * Socket write:
 *   int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
 *   connect(sockfd, ...);
 *   const char *msg = "GET / HTTP/1.0\r\n\r\n";
 *   ssize_t n = write(sockfd, msg, strlen(msg));
 *   if (n < 0 && errno == EPIPE) { }  // Connection closed by peer
 *
 * Pipe write:
 *   int pipefd[2];
 *   pipe(pipefd);
 *   write(pipefd[1], "message", 7);  // Write to pipe write end
 *   close(pipefd[1]);  // Close write end (signals EOF to reader)
 *
 * Phase 1 (Completed): Basic write with kernel buffer allocation
 * Phase 2 (Completed): Size categorization and enhanced validation
 * Phase 3: Direct user-to-kernel transfer (zero-copy optimization)
 * Phase 4: Writebehind, vectored I/O hints, async I/O support
 */
ssize_t sys_write(int fd, const void *buf, size_t count) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[WRITE] write(fd=%d, count=%zu) -> ESRCH (no current task)\n", fd, count);
        return -ESRCH;
    }

    /* Phase 2: Validate fd early */
    if (fd < 0) {
        fut_printf("[WRITE] write(fd=%d, count=%zu) -> EBADF (negative fd)\n", fd, count);
        return -EBADF;
    }

    /* Phase 2: Handle empty write (valid, returns 0 immediately) */
    if (count == 0) {
        fut_printf("[WRITE] write(fd=%d, count=0) -> 0 (empty write)\n", fd);
        return 0;
    }

    /* Phase 2: Validate user buffer */
    if (!buf) {
        fut_printf("[WRITE] write(fd=%d, buf=NULL, count=%zu) -> EFAULT (NULL buffer)\n", fd, count);
        return -EFAULT;
    }

    /* Phase 2: Categorize write size */
    const char *size_category;
    if (count <= 16) {
        size_category = "tiny (≤16 bytes)";
    } else if (count <= 512) {
        size_category = "small (≤512 bytes)";
    } else if (count <= 4096) {
        size_category = "typical (≤4 KB)";
    } else if (count <= 65536) {
        size_category = "large (≤64 KB)";
    } else if (count <= 1024 * 1024) {
        size_category = "very large (≤1 MB)";
    } else {
        size_category = "excessive (>1 MB)";
    }

    /* Phase 2: Sanity check - reject unreasonably large writes */
    if (count > 1024 * 1024) {  /* 1 MB limit */
        fut_printf("[WRITE] write(fd=%d, count=%zu [%s]) -> EINVAL (exceeds 1 MB limit)\n",
                   fd, count, size_category);
        return -EINVAL;
    }

    /* Allocate kernel buffer */
    void *kbuf = fut_malloc(count);
    if (!kbuf) {
        fut_printf("[WRITE] write(fd=%d, count=%zu [%s]) -> ENOMEM (failed to allocate kernel buffer)\n",
                   fd, count, size_category);
        return -ENOMEM;
    }

    /* Copy from userspace */
    if (fut_copy_from_user(kbuf, buf, count) != 0) {
        fut_printf("[WRITE] write(fd=%d, count=%zu [%s]) -> EFAULT (copy_from_user failed)\n",
                   fd, count, size_category);
        fut_free(kbuf);
        return -EFAULT;
    }

    /* Write to VFS */
    ssize_t ret = fut_vfs_write(fd, kbuf, count);

    /* Phase 2: Handle error cases with detailed logging */
    if (ret < 0) {
        const char *error_desc;
        switch (ret) {
            case -EBADF:
                error_desc = "invalid file descriptor or not open for writing";
                break;
            case -EIO:
                error_desc = "I/O error during write";
                break;
            case -ENOSPC:
                error_desc = "no space left on device";
                break;
            case -EPIPE:
                error_desc = "broken pipe (no readers)";
                break;
            case -EAGAIN:
                error_desc = "non-blocking and cannot write (buffer full)";
                break;
            case -EINTR:
                error_desc = "interrupted by signal";
                break;
            default:
                error_desc = "unknown error";
                break;
        }
        fut_printf("[WRITE] write(fd=%d, count=%zu [%s]) -> %ld (%s)\n",
                   fd, count, size_category, ret, error_desc);
        fut_free(kbuf);
        return ret;
    }

    fut_free(kbuf);

    /* Phase 2: Categorize write completion status */
    const char *completion_status;
    if ((size_t)ret < count) {
        size_t percent = ((size_t)ret * 100) / count;
        if (percent < 25) {
            completion_status = "partial (< 25%)";
        } else if (percent < 50) {
            completion_status = "partial (< 50%)";
        } else if (percent < 75) {
            completion_status = "partial (< 75%)";
        } else {
            completion_status = "partial (≥ 75%)";
        }
    } else {
        completion_status = "complete";
    }

    /* Phase 2: Detailed success logging */
    if ((size_t)ret < count) {
        fut_printf("[WRITE] write(fd=%d, count=%zu [%s]) -> %ld (%s, short write: wrote %zu of %zu bytes, Phase 3: Direct user-to-kernel transfer)\n",
                   fd, count, size_category, ret, completion_status, (size_t)ret, count);
    } else {
        fut_printf("[WRITE] write(fd=%d, count=%zu [%s]) -> %ld (%s, Phase 3: Direct user-to-kernel transfer)\n",
                   fd, count, size_category, ret, completion_status);
    }

    return ret;
}
