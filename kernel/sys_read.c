/* kernel/sys_read.c - Read from file descriptor syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements read() to read data from file descriptors.
 * Core I/O primitive for files, pipes, sockets, and devices.
 *
 * Phase 1 (Completed): Basic read with kernel buffer allocation
 * Phase 2 (Current): Enhanced validation, size categorization, and detailed logging
 * Phase 3: Direct kernel-to-user transfer for zero-copy optimization
 * Phase 4: Advanced features (vectored I/O hints, readahead, async I/O)
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
 * This is the fundamental input syscall for all file descriptor types.
 *
 * @param fd    File descriptor to read from
 * @param buf   User buffer to store read data
 * @param count Maximum number of bytes to read
 *
 * Returns:
 *   - Number of bytes read (may be less than count) on success
 *   - 0 at end-of-file (EOF)
 *   - -EBADF if fd is not a valid open file descriptor
 *   - -EFAULT if buf points to invalid memory
 *   - -EINVAL if count is invalid or exceeds limits
 *   - -EIO if I/O error occurred during read
 *   - -EISDIR if fd refers to a directory
 *   - -EAGAIN if non-blocking and no data available
 *   - -EINTR if interrupted by signal
 *   - -ENOMEM if insufficient memory for kernel buffer
 *
 * Behavior:
 *   - Reads from current file offset
 *   - Advances file offset by number of bytes actually read
 *   - May read less than requested (short read):
 *     - End of file reached before count bytes
 *     - Interrupted by signal
 *     - Slow device (socket, pipe, terminal)
 *     - Kernel buffer constraints
 *   - Returns 0 at EOF (no more data available)
 *   - Blocks until at least 1 byte available (unless O_NONBLOCK)
 *   - Atomicity: read operation is atomic for regular files
 *
 * File descriptor types:
 *   - Regular files: Reads from inode data, advances file offset
 *   - Sockets: Reads from receive buffer, may block for data
 *   - Pipes: Reads from pipe buffer, blocks if empty
 *   - Character devices: Device-specific semantics (TTY, console)
 *   - Block devices: Reads from device blocks
 *   - Directories: Returns -EISDIR (use readdir/getdents)
 *
 * Short read conditions:
 *   - EOF reached before count bytes
 *   - Less data available than requested (sockets, pipes)
 *   - Signal interruption (partial read may succeed)
 *   - Resource constraints (memory, buffer limits)
 *
 * Common usage patterns:
 *
 * Read entire file:
 *   int fd = open("/path/to/file", O_RDONLY);
 *   char buf[4096];
 *   ssize_t n;
 *   while ((n = read(fd, buf, sizeof(buf))) > 0) {
 *       process(buf, n);
 *   }
 *   if (n < 0) { perror("read"); }
 *   close(fd);
 *
 * Read fixed amount:
 *   ssize_t total = 0;
 *   while (total < needed) {
 *       ssize_t n = read(fd, buf + total, needed - total);
 *       if (n < 0) { handle error }
 *       if (n == 0) { break; }  // EOF
 *       total += n;
 *   }
 *
 * Non-blocking read:
 *   fcntl(fd, F_SETFL, O_NONBLOCK);
 *   ssize_t n = read(fd, buf, count);
 *   if (n < 0 && errno == EAGAIN) {
 *       // No data available, try again later
 *   }
 *
 * Socket read:
 *   int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
 *   connect(sockfd, ...);
 *   ssize_t n = read(sockfd, buf, sizeof(buf));
 *   if (n == 0) { }  // Connection closed by peer
 *
 * Phase 1 (Completed): Basic read with kernel buffer allocation
 * Phase 2 (Current): Size categorization and enhanced validation
 * Phase 3: Direct kernel-to-user transfer (zero-copy optimization)
 * Phase 4: Readahead, vectored I/O hints, async I/O support
 */
ssize_t sys_read(int fd, void *buf, size_t count) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[READ] read(fd=%d, count=%zu) -> ESRCH (no current task)\n", fd, count);
        return -ESRCH;
    }

    /* Phase 2: Validate fd early */
    if (fd < 0) {
        fut_printf("[READ] read(fd=%d, count=%zu) -> EBADF (negative fd)\n", fd, count);
        return -EBADF;
    }

    /* Phase 2: Handle empty read (valid, returns 0 immediately) */
    if (count == 0) {
        fut_printf("[READ] read(fd=%d, count=0) -> 0 (empty read)\n", fd);
        return 0;
    }

    /* Phase 2: Validate user buffer */
    if (!buf) {
        fut_printf("[READ] read(fd=%d, buf=NULL, count=%zu) -> EFAULT (NULL buffer)\n", fd, count);
        return -EFAULT;
    }

    /* Phase 2: Categorize read size */
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

    /* Phase 2: Sanity check - reject unreasonably large reads */
    if (count > 1024 * 1024) {  /* 1 MB limit */
        fut_printf("[READ] read(fd=%d, count=%zu [%s]) -> EINVAL (exceeds 1 MB limit)\n",
                   fd, count, size_category);
        return -EINVAL;
    }

    /* Allocate kernel buffer */
    void *kbuf = fut_malloc(count);
    if (!kbuf) {
        fut_printf("[READ] read(fd=%d, count=%zu [%s]) -> ENOMEM (failed to allocate kernel buffer)\n",
                   fd, count, size_category);
        return -ENOMEM;
    }

    /* Read from VFS */
    ssize_t ret = fut_vfs_read(fd, kbuf, count);

    /* Phase 2: Handle error cases with detailed logging */
    if (ret < 0) {
        const char *error_desc;
        switch (ret) {
            case -EBADF:
                error_desc = "invalid file descriptor";
                break;
            case -EIO:
                error_desc = "I/O error during read";
                break;
            case -EISDIR:
                error_desc = "is a directory";
                break;
            case -EAGAIN:
                error_desc = "non-blocking and no data available";
                break;
            case -EINTR:
                error_desc = "interrupted by signal";
                break;
            default:
                error_desc = "unknown error";
                break;
        }
        fut_printf("[READ] read(fd=%d, count=%zu [%s]) -> %ld (%s)\n",
                   fd, count, size_category, ret, error_desc);
        fut_free(kbuf);
        return ret;
    }

    /* Phase 2: Handle EOF */
    if (ret == 0) {
        fut_printf("[READ] read(fd=%d, count=%zu [%s]) -> 0 (EOF)\n",
                   fd, count, size_category);
        fut_free(kbuf);
        return 0;
    }

    /* Copy to userspace on success */
    if (fut_copy_to_user(buf, kbuf, (size_t)ret) != 0) {
        fut_printf("[READ] read(fd=%d, count=%zu [%s], read=%ld) -> EFAULT (copy_to_user failed)\n",
                   fd, count, size_category, ret);
        fut_free(kbuf);
        return -EFAULT;
    }

    fut_free(kbuf);

    /* Phase 2: Categorize read completion status */
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
        fut_printf("[READ] read(fd=%d, count=%zu [%s]) -> %ld (%s, short read: got %zu of %zu bytes, Phase 2)\n",
                   fd, count, size_category, ret, completion_status, (size_t)ret, count);
    } else {
        fut_printf("[READ] read(fd=%d, count=%zu [%s]) -> %ld (%s, Phase 2)\n",
                   fd, count, size_category, ret, completion_status);
    }

    return ret;
}
