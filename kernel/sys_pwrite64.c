/* kernel/sys_pwrite64.c - Position-based write syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the pwrite64() syscall for writing to a file at a specific
 * offset without changing the file position. Essential for multithreaded I/O.
 *
 * Phase 1 (Completed): Basic positional write with VFS integration
 * Phase 2 (Current): Enhanced validation, FD/offset categorization, and detailed logging
 * Phase 3: Performance optimization (zero-copy, vectored I/O)
 * Phase 4: Advanced features (async I/O, write-behind hints)
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);
extern int fut_copy_from_user(void *to, const void *from, size_t size);
extern int fut_copy_to_user(void *to, const void *from, size_t size);
extern void *fut_malloc(size_t size);
extern void fut_free(void *ptr);
extern fut_task_t *fut_task_current(void);
extern struct fut_file *vfs_get_file_from_task(struct fut_task *task, int fd);

/**
 * pwrite64() - Write to file at specific offset
 *
 * Writes up to count bytes to file descriptor fd at offset offset from
 * the buffer buf. The file offset is not changed. This is useful for
 * multithreaded applications where multiple threads need to write to the
 * same file without interfering with each other's file positions.
 *
 * @param fd      File descriptor to write to
 * @param buf     Buffer containing data to write
 * @param count   Number of bytes to write
 * @param offset  Offset in file to write to
 *
 * Returns:
 *   - Number of bytes written on success
 *   - -EBADF if fd is not a valid file descriptor
 *   - -EFAULT if buf points to invalid memory
 *   - -EINVAL if fd is associated with an object that cannot be written or offset is negative
 *   - -EISDIR if fd refers to a directory
 *   - -ESPIPE if fd is associated with a pipe or socket
 *   - -ESRCH if no current task context
 *   - -ENOMEM if kernel buffer allocation fails
 *
 * Behavior:
 *   - Writes to specific offset without changing file position
 *   - File descriptor's offset remains unchanged
 *   - Thread-safe for concurrent writes at different offsets
 *   - Equivalent to lseek + write + lseek but atomic
 *   - Does not work on pipes, sockets, or character devices
 *   - Works only on seekable files
 *
 * Common usage patterns:
 *
 * Multithreaded write (independent positions):
 *   void *worker(void *arg) {
 *       int fd = *(int *)arg;
 *       char buf[1024];
 *       // Each thread writes different offset
 *       off_t offset = thread_id * 1024;
 *       pwrite64(fd, buf, sizeof(buf), offset);
 *       // File descriptor offset unchanged
 *   }
 *
 * Random access without seeking:
 *   int fd = open("/path/to/file", O_WRONLY);
 *   char header[100];
 *   char footer[100];
 *   pwrite64(fd, header, 100, 0);      // Write header
 *   pwrite64(fd, footer, 100, size-100); // Write footer
 *   // No lseek needed, fd offset unchanged
 *
 * Database-style fixed-record write:
 *   #define RECORD_SIZE 128
 *   void write_record(int fd, int record_id, const void *data) {
 *       off_t offset = record_id * RECORD_SIZE;
 *       pwrite64(fd, data, RECORD_SIZE, offset);
 *   }
 *
 * Atomic log entry append:
 *   // Multiple threads can append concurrently
 *   off_t offset = atomic_fetch_add(&log_offset, entry_size);
 *   pwrite64(log_fd, entry, entry_size, offset);
 *
 * Difference from write():
 *   - write(): Uses and updates fd offset
 *   - pwrite64(): Uses explicit offset, doesn't update fd offset
 *   - pwrite64(): Thread-safe for concurrent access
 *   - pwrite64(): Doesn't work on pipes/sockets
 *
 * Advantages over lseek + write:
 *   - Atomic operation (no race between lseek and write)
 *   - Thread-safe (no need for locking fd offset)
 *   - Cleaner code (one call instead of three)
 *   - Better performance (no extra syscalls)
 *
 * Related syscalls:
 *   - write(): Sequential write with offset update
 *   - pread64(): Position-based read
 *   - lseek(): Change file offset
 *   - writev()/pwritev(): Vectored write
 *
 * Phase 1 (Completed): Basic positional write with VFS integration
 * Phase 2 (Current): Enhanced validation, FD/offset categorization, detailed logging
 * Phase 3: Performance optimization (zero-copy, vectored I/O)
 * Phase 4: Advanced features (async I/O, write-behind hints)
 */
long sys_pwrite64(unsigned int fd, const void *buf, size_t count, int64_t offset) {
    /* Phase 2: Validate buffer pointer */
    if (!buf) {
        fut_printf("[PWRITE64] pwrite64(fd=%u, buf=NULL, count=%zu, offset=%ld) -> EFAULT "
                   "(NULL buffer)\n", fd, count, offset);
        return -EFAULT;
    }

    /* Phase 2: Validate offset is non-negative */
    if (offset < 0) {
        fut_printf("[PWRITE64] pwrite64(fd=%u, count=%zu, offset=%ld) -> EINVAL "
                   "(negative offset)\n", fd, count, offset);
        return -EINVAL;
    }

    /* Phase 2: Get current task for FD table access */
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[PWRITE64] pwrite64(fd=%u, count=%zu, offset=%ld) -> ESRCH "
                   "(no current task)\n", fd, count, offset);
        return -ESRCH;
    }

    /* Phase 2: Categorize FD range */
    const char *fd_category;
    if (fd <= 2) {
        fd_category = "stdio (0-2)";
    } else if (fd < 10) {
        fd_category = "low (3-9)";
    } else if (fd < 100) {
        fd_category = "normal (10-99)";
    } else if (fd < 1000) {
        fd_category = "high (100-999)";
    } else {
        fd_category = "very high (≥1000)";
    }

    /* Phase 2: Categorize count (write size) */
    const char *count_category;
    if (count == 0) {
        count_category = "zero";
    } else if (count <= 512) {
        count_category = "tiny (≤512 bytes)";
    } else if (count <= 4096) {
        count_category = "small (≤4 KB)";
    } else if (count <= 65536) {
        count_category = "medium (≤64 KB)";
    } else if (count <= 1048576) {
        count_category = "large (≤1 MB)";
    } else {
        count_category = "very large (>1 MB)";
    }

    /* Phase 2: Categorize offset */
    const char *offset_category;
    if (offset == 0) {
        offset_category = "beginning";
    } else if (offset < 4096) {
        offset_category = "near start (<4 KB)";
    } else if (offset < 1048576) {
        offset_category = "low (<1 MB)";
    } else if (offset < 1073741824) {
        offset_category = "medium (<1 GB)";
    } else {
        offset_category = "high (≥1 GB)";
    }

    /* Get file structure from FD */
    struct fut_file *file = vfs_get_file_from_task(task, (int)fd);
    if (!file) {
        fut_printf("[PWRITE64] pwrite64(fd=%u [%s], count=%zu [%s], offset=%ld [%s]) -> EBADF "
                   "(fd not open, pid=%d)\n",
                   fd, fd_category, count, count_category, offset, offset_category, task->pid);
        return -EBADF;
    }

    /* pwrite() not supported on character devices, pipes, or sockets */
    if (file->chr_ops) {
        fut_printf("[PWRITE64] pwrite64(fd=%u [%s], type=character device, count=%zu [%s], "
                   "offset=%ld [%s]) -> ESPIPE (not seekable, pid=%d)\n",
                   fd, fd_category, count, count_category, offset, offset_category, task->pid);
        return -ESPIPE;
    }

    /* Check if this is a directory */
    if (file->vnode && file->vnode->type == VN_DIR) {
        fut_printf("[PWRITE64] pwrite64(fd=%u [%s], type=directory, ino=%lu, count=%zu [%s], "
                   "offset=%ld [%s]) -> EISDIR (is directory, pid=%d)\n",
                   fd, fd_category, file->vnode->ino, count, count_category,
                   offset, offset_category, task->pid);
        return -EISDIR;
    }

    /* Phase 2: Validate vnode and write operation */
    if (!file->vnode || !file->vnode->ops || !file->vnode->ops->write) {
        fut_printf("[PWRITE64] pwrite64(fd=%u [%s], count=%zu [%s], offset=%ld [%s]) -> EINVAL "
                   "(no write operation, pid=%d)\n",
                   fd, fd_category, count, count_category, offset, offset_category, task->pid);
        return -EINVAL;
    }

    /* Allocate kernel buffer */
    void *kbuf = fut_malloc(count);
    if (!kbuf) {
        fut_printf("[PWRITE64] pwrite64(fd=%u [%s], ino=%lu, count=%zu [%s], offset=%ld [%s]) -> ENOMEM "
                   "(kernel buffer allocation failed, pid=%d)\n",
                   fd, fd_category, file->vnode->ino, count, count_category,
                   offset, offset_category, task->pid);
        return -ENOMEM;
    }

    /* Copy from userspace */
    if (fut_copy_from_user(kbuf, buf, count) != 0) {
        fut_printf("[PWRITE64] pwrite64(fd=%u [%s], ino=%lu, count=%zu [%s], offset=%ld [%s]) -> EFAULT "
                   "(copy_from_user failed, pid=%d)\n",
                   fd, fd_category, file->vnode->ino, count, count_category,
                   offset, offset_category, task->pid);
        fut_free(kbuf);
        return -EFAULT;
    }

    /* Write to file at the specified offset without changing file->offset */
    ssize_t ret = file->vnode->ops->write(file->vnode, kbuf, count, (uint64_t)offset);

    /* Phase 2: Handle write errors with detailed logging */
    if (ret < 0) {
        const char *error_desc;
        switch (ret) {
            case -EIO:
                error_desc = "I/O error during write";
                break;
            case -ENOSPC:
                error_desc = "no space left on device";
                break;
            case -EROFS:
                error_desc = "read-only filesystem";
                break;
            default:
                error_desc = "write operation failed";
                break;
        }
        fut_printf("[PWRITE64] pwrite64(fd=%u [%s], ino=%lu, count=%zu [%s], offset=%ld [%s]) -> %d "
                   "(%s, pid=%d)\n",
                   fd, fd_category, file->vnode->ino, count, count_category,
                   offset, offset_category, (int)ret, error_desc, task->pid);
        fut_free(kbuf);
        return ret;
    }

    fut_free(kbuf);

    /* Phase 2: Detailed success logging */
    fut_printf("[PWRITE64] pwrite64(fd=%u [%s], ino=%lu, count=%zu [%s], offset=%ld [%s], "
               "bytes_written=%zd) -> %zd (Phase 2)\n",
               fd, fd_category, file->vnode->ino, count, count_category,
               offset, offset_category, ret, ret);
    return ret;
}
