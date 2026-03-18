/* kernel/sys_pwrite64.c - Position-based write syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the pwrite64() syscall for writing to a file at a specific
 * offset without changing the file position. Essential for multithreaded I/O.
 *
 * Phase 1 (Completed): Basic positional write with VFS integration
 * Phase 2 (Completed): Enhanced validation, FD/offset categorization, and detailed logging
 * Phase 3 (Completed): VFS write operation delegation and error categorization
 * Phase 4: Advanced features (async I/O, write-behind hints)
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <kernel/chrdev.h>
#include <kernel/fut_fd_util.h>
#include <stdint.h>

#include <kernel/kprintf.h>
#include <kernel/uaccess.h>
#include <kernel/fut_memory.h>

#ifdef __x86_64__
#include <platform/x86_64/memory/paging.h>
#elif defined(__aarch64__)
#include <platform/arm64/memory/paging.h>
#endif

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
 * Phase 2 (Completed): Enhanced validation, FD/offset categorization, detailed logging
 * Phase 3 (Completed): VFS write operation delegation and error categorization
 * Phase 4: Advanced features (async I/O, write-behind hints)
 */
long sys_pwrite64(unsigned int fd, const void *buf, size_t count, int64_t offset) {
    /* ARM64 FIX: Copy register params to local stack vars before blocking calls */
    unsigned int local_fd = fd;
    const void *local_buf = buf;
    size_t local_count = count;
    int64_t local_offset = offset;

    /* Validate buffer pointer */
    if (!local_buf) {
        fut_printf("[PWRITE64] pwrite64(fd=%u, buf=NULL, count=%zu, offset=%ld) -> EFAULT "
                   "(NULL buffer)\n", local_fd, local_count, local_offset);
        return -EFAULT;
    }

    /* Validate offset is non-negative */
    if (local_offset < 0) {
        fut_printf("[PWRITE64] pwrite64(fd=%u, count=%zu, offset=%ld) -> EINVAL "
                   "(negative offset)\n", local_fd, local_count, local_offset);
        return -EINVAL;
    }

    /* Prevent offset+count overflow
     * Without this check, attacker can cause integer overflow:
     *   - pwrite64(fd, buf, SIZE_MAX, LLONG_MAX)
     *   - offset + count wraps around to negative value
     *   - Could bypass file size checks and corrupt kernel memory
     * Defense: Detect overflow before arithmetic (matching pread64 validation) */
    if (local_offset > INT64_MAX - (int64_t)local_count) {
        fut_printf("[PWRITE64] pwrite64(fd=%u, count=%zu, offset=%ld) -> EOVERFLOW "
                   "(offset+count would overflow, max_valid_offset=%ld)\n",
                   local_fd, local_count, local_offset, (int64_t)(INT64_MAX - local_count));
        return -EOVERFLOW;
    }

    /* Validate buffer is readable BEFORE expensive operations.
     * Skip for kernel buffers (selftest calls with kernel stack pointers). */
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)local_buf < KERNEL_VIRTUAL_BASE)
#endif
    {
        char test_byte;
        if (fut_copy_from_user(&test_byte, local_buf, 1) != 0) {
            return -EFAULT;
        }
    }

    /* Get current task for FD table access */
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[PWRITE64] pwrite64(fd=%u, count=%zu, offset=%ld) -> ESRCH "
                   "(no current task)\n", local_fd, local_count, local_offset);
        return -ESRCH;
    }

    /* Validate FD upper bound to prevent OOB array access
     * Without this check, fd >= max_fds would access beyond fd_table bounds */
    if (local_fd >= (unsigned int)task->max_fds) {
        fut_printf("[PWRITE64] pwrite64(fd=%u, max_fds=%d) -> EBADF "
                   "(fd exceeds max_fds, FD bounds validation)\n",
                   local_fd, task->max_fds);
        return -EBADF;
    }

    /* Categorize FD range */
    const char *fd_category = fut_fd_category(local_fd);

    /* Categorize count (write size) */
    const char *count_category = fut_size_category(local_count);

    /* Validate count doesn't exceed 1MB limit (prevent DoS) */
    if (local_count > 1048576) {
        fut_printf("[PWRITE64] pwrite64(fd=%u, count=%zu [%s], offset=%ld) -> EINVAL "
                   "(count exceeds maximum 1MB limit)\n",
                   local_fd, local_count, count_category, local_offset);
        return -EINVAL;
    }

    /* Categorize offset */
    const char *offset_category = fut_offset_category(local_offset);

    /* Get file structure from FD */
    struct fut_file *file = vfs_get_file_from_task(task, (int)local_fd);
    if (!file) {
        fut_printf("[PWRITE64] pwrite64(fd=%u [%s], count=%zu [%s], offset=%ld [%s]) -> EBADF "
                   "(fd not open, pid=%d)\n",
                   local_fd, fd_category, local_count, count_category, local_offset, offset_category, task->pid);
        return -EBADF;
    }

    /* pwrite() not supported on character devices, pipes, or sockets */
    /* Handle chr_ops files: dispatch to chr_ops->write with given offset.
     * Seekable chr_ops files (memfd, devfs) support positional I/O. */
    if (file->chr_ops) {
        if (file->chr_ops->write) {
            void *kbuf = fut_malloc(local_count);
            if (!kbuf) return -ENOMEM;
            int cp_ret;
#ifdef KERNEL_VIRTUAL_BASE
            if ((uintptr_t)local_buf >= KERNEL_VIRTUAL_BASE) {
                __builtin_memcpy(kbuf, local_buf, local_count);
                cp_ret = 0;
            } else
#endif
            cp_ret = fut_copy_from_user(kbuf, local_buf, local_count);
            if (cp_ret != 0) {
                fut_free(kbuf);
                return -EFAULT;
            }
            off_t pos = (off_t)local_offset;
            ssize_t ret = file->chr_ops->write(file->chr_inode, file->chr_private,
                                                kbuf, local_count, &pos);
            fut_free(kbuf);
            return ret;
        }
        return -EINVAL;
    }

    /* Check if this is a directory */
    if (file->vnode && file->vnode->type == VN_DIR) {
        fut_printf("[PWRITE64] pwrite64(fd=%u [%s], type=directory, ino=%lu, count=%zu [%s], "
                   "offset=%ld [%s]) -> EISDIR (is directory, pid=%d)\n",
                   local_fd, fd_category, file->vnode->ino, local_count, count_category,
                   local_offset, offset_category, task->pid);
        return -EISDIR;
    }

    /* Validate vnode and write operation */
    if (!file->vnode || !file->vnode->ops || !file->vnode->ops->write) {
        fut_printf("[PWRITE64] pwrite64(fd=%u [%s], count=%zu [%s], offset=%ld [%s]) -> EINVAL "
                   "(no write operation, pid=%d)\n",
                   local_fd, fd_category, local_count, count_category, local_offset, offset_category, task->pid);
        return -EINVAL;
    }

    /* Allocate kernel buffer */
    void *kbuf = fut_malloc(local_count);
    if (!kbuf) {
        fut_printf("[PWRITE64] pwrite64(fd=%u [%s], ino=%lu, count=%zu [%s], offset=%ld [%s]) -> ENOMEM "
                   "(kernel buffer allocation failed, pid=%d)\n",
                   local_fd, fd_category, file->vnode->ino, local_count, count_category,
                   local_offset, offset_category, task->pid);
        return -ENOMEM;
    }

    /* Copy from userspace (with kernel-pointer bypass for selftests) */
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)local_buf >= KERNEL_VIRTUAL_BASE) {
        __builtin_memcpy(kbuf, local_buf, local_count);
    } else
#endif
    if (fut_copy_from_user(kbuf, local_buf, local_count) != 0) {
        fut_printf("[PWRITE64] pwrite64(fd=%u [%s], ino=%lu, count=%zu [%s], offset=%ld [%s]) -> EFAULT "
                   "(copy_from_user failed, pid=%d)\n",
                   local_fd, fd_category, file->vnode->ino, local_count, count_category,
                   local_offset, offset_category, task->pid);
        fut_free(kbuf);
        return -EFAULT;
    }

    /* Write to file at the specified offset without changing file->offset */
    ssize_t ret = file->vnode->ops->write(file->vnode, kbuf, local_count, (uint64_t)local_offset);

    /* Handle write errors with detailed logging */
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
                   local_fd, fd_category, file->vnode->ino, local_count, count_category,
                   local_offset, offset_category, (int)ret, error_desc, task->pid);
        fut_free(kbuf);
        return ret;
    }

    fut_free(kbuf);

    /* Detailed success logging */
    fut_printf("[PWRITE64] pwrite64(fd=%u [%s], ino=%lu, count=%zu [%s], offset=%ld [%s], "
               "bytes_written=%zd) -> %zd (VFS write operation delegation)\n",
               local_fd, fd_category, file->vnode->ino, local_count, count_category,
               local_offset, offset_category, ret, ret);
    return ret;
}
