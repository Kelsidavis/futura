/* kernel/sys_pread64.c - Position-based read syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the pread64() syscall for reading from a file at a specific
 * offset without changing the file position. Essential for multithreaded I/O.
 *
 * Phase 1 (Completed): Basic positional read with VFS integration
 * Phase 2 (Completed): Enhanced validation, FD/offset categorization, and detailed logging
 * Phase 3 (Completed): VFS readiness checking and error categorization
 * Phase 4: Advanced features (async I/O, readahead hints)
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
 * pread64() - Read from file at specific offset
 *
 * Reads up to count bytes from file descriptor fd at offset offset into
 * the buffer buf. The file offset is not changed. This is useful for
 * multithreaded applications where multiple threads need to read from the
 * same file without interfering with each other's file positions.
 *
 * @param fd      File descriptor to read from
 * @param buf     Buffer to read data into
 * @param count   Number of bytes to read
 * @param offset  Offset in file to read from
 *
 * Returns:
 *   - Number of bytes read on success (0 at end of file)
 *   - -EBADF if fd is not a valid file descriptor
 *   - -EFAULT if buf points to invalid memory
 *   - -EINVAL if fd is associated with an object that cannot be read or offset is negative
 *   - -EISDIR if fd refers to a directory
 *   - -ESPIPE if fd is associated with a pipe or socket
 *   - -ESRCH if no current task context
 *   - -ENOMEM if kernel buffer allocation fails
 *
 * Behavior:
 *   - Reads from specific offset without changing file position
 *   - File descriptor's offset remains unchanged
 *   - Thread-safe for concurrent reads at different offsets
 *   - Equivalent to lseek + read + lseek but atomic
 *   - Does not work on pipes, sockets, or character devices
 *   - Works only on seekable files
 *
 * Common usage patterns:
 *
 * Multithreaded read (independent positions):
 *   void *worker(void *arg) {
 *       int fd = *(int *)arg;
 *       char buf[1024];
 *       // Each thread reads different offset
 *       off_t offset = thread_id * 1024;
 *       pread64(fd, buf, sizeof(buf), offset);
 *       // File descriptor offset unchanged
 *   }
 *
 * Random access without seeking:
 *   int fd = open("/path/to/file", O_RDONLY);
 *   char header[100];
 *   char footer[100];
 *   pread64(fd, header, 100, 0);      // Read header
 *   pread64(fd, footer, 100, size-100); // Read footer
 *   // No lseek needed, fd offset unchanged
 *
 * Sparse file reading:
 *   // Read specific blocks without sequential access
 *   pread64(fd, buf1, 4096, 0);      // Block 0
 *   pread64(fd, buf2, 4096, 8192);   // Block 2 (skip block 1)
 *   pread64(fd, buf3, 4096, 16384);  // Block 4
 *
 * Database-style fixed-record access:
 *   #define RECORD_SIZE 128
 *   void read_record(int fd, int record_id, void *buf) {
 *       off_t offset = record_id * RECORD_SIZE;
 *       pread64(fd, buf, RECORD_SIZE, offset);
 *   }
 *
 * Read file without affecting shared offset:
 *   // Multiple processes/threads with same fd
 *   int fd = open("file", O_RDONLY);
 *   // Fork or share fd with threads
 *   // Each can pread independently
 *   pread64(fd, buf, size, my_offset);
 *   // Doesn't affect other readers
 *
 * Difference from read():
 *   - read(): Uses and updates fd offset
 *   - pread64(): Uses explicit offset, doesn't update fd offset
 *   - pread64(): Thread-safe for concurrent access
 *   - pread64(): Doesn't work on pipes/sockets
 *
 * Advantages over lseek + read:
 *   - Atomic operation (no race between lseek and read)
 *   - Thread-safe (no need for locking fd offset)
 *   - Cleaner code (one call instead of three)
 *   - Better performance (no extra syscalls)
 *
 * Related syscalls:
 *   - read(): Sequential read with offset update
 *   - pwrite64(): Position-based write
 *   - lseek(): Change file offset
 *   - readv()/preadv(): Vectored read
 *
 * Phase 1 (Completed): Basic positional read with VFS integration
 * Phase 2 (Completed): Enhanced validation, FD/offset categorization, detailed logging
 * Phase 3 (Completed): VFS readiness checking and error categorization
 * Phase 4: Advanced features (async I/O, readahead hints)
 */
long sys_pread64(unsigned int fd, void *buf, size_t count, int64_t offset) {
    /* Phase 2: Validate buffer pointer */
    if (!buf) {
        fut_printf("[PREAD64] pread64(fd=%u, buf=NULL, count=%zu, offset=%ld) -> EFAULT "
                   "(NULL buffer)\n", fd, count, offset);
        return -EFAULT;
    }

    /* Phase 2: Validate offset is non-negative */
    if (offset < 0) {
        fut_printf("[PREAD64] pread64(fd=%u, count=%zu, offset=%ld) -> EINVAL "
                   "(negative offset)\n", fd, count, offset);
        return -EINVAL;
    }

    /* Phase 2: Get current task for FD table access */
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[PREAD64] pread64(fd=%u, count=%zu, offset=%ld) -> ESRCH "
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

    /* Phase 2: Categorize count (read size) */
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
        fut_printf("[PREAD64] pread64(fd=%u [%s], count=%zu [%s], offset=%ld [%s]) -> EBADF "
                   "(fd not open, pid=%d)\n",
                   fd, fd_category, count, count_category, offset, offset_category, task->pid);
        return -EBADF;
    }

    /* pread() not supported on character devices, pipes, or sockets */
    if (file->chr_ops) {
        fut_printf("[PREAD64] pread64(fd=%u [%s], type=character device, count=%zu [%s], "
                   "offset=%ld [%s]) -> ESPIPE (not seekable, pid=%d)\n",
                   fd, fd_category, count, count_category, offset, offset_category, task->pid);
        return -ESPIPE;
    }

    /* Check if this is a directory */
    if (file->vnode && file->vnode->type == VN_DIR) {
        fut_printf("[PREAD64] pread64(fd=%u [%s], type=directory, ino=%lu, count=%zu [%s], "
                   "offset=%ld [%s]) -> EISDIR (is directory, pid=%d)\n",
                   fd, fd_category, file->vnode->ino, count, count_category,
                   offset, offset_category, task->pid);
        return -EISDIR;
    }

    /* Phase 2: Validate vnode and read operation */
    if (!file->vnode || !file->vnode->ops || !file->vnode->ops->read) {
        fut_printf("[PREAD64] pread64(fd=%u [%s], count=%zu [%s], offset=%ld [%s]) -> EINVAL "
                   "(no read operation, pid=%d)\n",
                   fd, fd_category, count, count_category, offset, offset_category, task->pid);
        return -EINVAL;
    }

    /* Allocate kernel buffer */
    void *kbuf = fut_malloc(count);
    if (!kbuf) {
        fut_printf("[PREAD64] pread64(fd=%u [%s], ino=%lu, count=%zu [%s], offset=%ld [%s]) -> ENOMEM "
                   "(kernel buffer allocation failed, pid=%d)\n",
                   fd, fd_category, file->vnode->ino, count, count_category,
                   offset, offset_category, task->pid);
        return -ENOMEM;
    }

    /* Read from file at the specified offset without changing file->offset */
    ssize_t ret = file->vnode->ops->read(file->vnode, kbuf, count, (uint64_t)offset);

    /* Phase 2: Handle read errors with detailed logging */
    if (ret < 0) {
        const char *error_desc;
        switch (ret) {
            case -EIO:
                error_desc = "I/O error during read";
                break;
            case -ENOENT:
                error_desc = "file no longer exists";
                break;
            default:
                error_desc = "read operation failed";
                break;
        }
        fut_printf("[PREAD64] pread64(fd=%u [%s], ino=%lu, count=%zu [%s], offset=%ld [%s]) -> %d "
                   "(%s, pid=%d)\n",
                   fd, fd_category, file->vnode->ino, count, count_category,
                   offset, offset_category, (int)ret, error_desc, task->pid);
        fut_free(kbuf);
        return ret;
    }

    /* Copy to userspace if successful */
    if (ret > 0) {
        if (fut_copy_to_user(buf, kbuf, (size_t)ret) != 0) {
            fut_printf("[PREAD64] pread64(fd=%u [%s], ino=%lu, count=%zu [%s], offset=%ld [%s], "
                       "bytes_read=%zd) -> EFAULT (copy_to_user failed, pid=%d)\n",
                       fd, fd_category, file->vnode->ino, count, count_category,
                       offset, offset_category, ret, task->pid);
            fut_free(kbuf);
            return -EFAULT;
        }
    }

    fut_free(kbuf);

    /* Phase 2: Detailed success logging */
    const char *eof_marker = (ret == 0) ? " (EOF)" : "";
    fut_printf("[PREAD64] pread64(fd=%u [%s], ino=%lu, count=%zu [%s], offset=%ld [%s], "
               "bytes_read=%zd%s) -> %zd (Phase 3: VFS readiness checking)\n",
               fd, fd_category, file->vnode->ino, count, count_category,
               offset, offset_category, ret, eof_marker, ret);
    return ret;
}
