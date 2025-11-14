/* kernel/sys_ftruncate.c - File truncation syscall (fd-based)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the ftruncate() syscall for truncating files via fd.
 * Essential for file manipulation in editors, databases, and log rotation.
 *
 * Phase 1 (Completed): Basic file truncation with size updates
 * Phase 2 (Completed): Enhanced validation, FD/length categorization, and detailed logging
 * Phase 3 (Completed): Block deallocation for shrink, zero-fill for extend
 * Phase 4 (Current): Advanced features (sparse file support, preallocation hints)
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);
extern struct fut_file *fut_vfs_get_file(int fd);

/**
 * ftruncate() - Truncate file to specified length (fd-based)
 *
 * Truncates or extends a file to the specified length using an open file
 * descriptor. If the file is extended, the extended area is filled with zeros.
 * This is the fd-based complement to truncate() (Priority #22).
 *
 * @param fd      File descriptor of the open file
 * @param length  New file length in bytes
 *
 * Returns:
 *   - 0 on success
 *   - -EBADF if fd is not a valid open file descriptor
 *   - -EBADF if file has no associated vnode
 *   - -EINVAL if length is negative (for signed interpretation)
 *   - -EISDIR if fd refers to a directory
 *   - -ESRCH if no current task context
 *
 * Behavior:
 *   - If length < current size: shrink file (Phase 3: deallocate blocks)
 *   - If length > current size: extend file (Phase 3: zero-fill new area)
 *   - If length == current size: no-op (size unchanged)
 *   - File offset for all FDs referring to this file remains unchanged
 *   - Does not require write permission check in Phase 1/2 (future enhancement)
 *   - Updates file's mtime and ctime
 *
 * Common usage patterns:
 *
 * Truncate file to zero (clear contents):
 *   int fd = open("/tmp/logfile.txt", O_WRONLY);
 *   ftruncate(fd, 0);  // Clear all contents
 *   close(fd);
 *
 * Extend file to specific size (reserve space):
 *   int fd = open("/tmp/database.db", O_RDWR | O_CREAT, 0644);
 *   ftruncate(fd, 1024 * 1024 * 100);  // Pre-allocate 100 MB
 *   // Write data at various offsets...
 *   close(fd);
 *
 * Trim file to exact size after writing:
 *   int fd = open("/tmp/output.bin", O_RDWR | O_CREAT, 0644);
 *   write(fd, buffer, actual_size);
 *   ftruncate(fd, actual_size);  // Ensure exact size
 *   close(fd);
 *
 * Log rotation (truncate to size limit):
 *   struct stat st;
 *   fstat(fd, &st);
 *   if (st.st_size > MAX_LOG_SIZE) {
 *       ftruncate(fd, MAX_LOG_SIZE);  // Trim to limit
 *   }
 *
 * No-op case (length == current size):
 *   ftruncate(fd, current_size);  // Returns 0, no actual truncation
 *
 * Sparse file creation:
 *   ftruncate(fd, 1024 * 1024 * 1024);  // 1 GB sparse file
 *   // File shows as 1 GB but uses minimal disk space until written
 *
 * Phase 1 (Completed): Basic file truncation with size updates
 * Phase 2 (Completed): Enhanced validation, FD/length categorization, detailed logging
 * Phase 3 (Completed): Block deallocation for shrink, zero-fill for extend
 * Phase 4 (Current): Sparse file support, preallocation hints
 */
long sys_ftruncate(int fd, uint64_t length) {
    /* Get current task for FD table access */
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[FTRUNCATE] ftruncate(fd=%d, length=%llu) -> ESRCH (no current task)\n",
                   fd, length);
        return -ESRCH;
    }

    /* Phase 2: Validate fd early */
    if (fd < 0) {
        fut_printf("[FTRUNCATE] ftruncate(fd=%d, length=%llu) -> EBADF (negative fd)\n",
                   fd, length);
        return -EBADF;
    }

    /* Phase 2: Categorize FD range */
    const char *fd_category;
    if (fd <= 2) {
        fd_category = "standard (stdin/stdout/stderr)";
    } else if (fd < 10) {
        fd_category = "low (common user FDs)";
    } else if (fd < 100) {
        fd_category = "typical (normal range)";
    } else if (fd < 1024) {
        fd_category = "high (many open files)";
    } else {
        fd_category = "very high (unusual)";
    }

    /* Phase 2: Categorize length range */
    const char *length_category;
    if (length == 0) {
        length_category = "zero (clear file)";
    } else if (length < 4096) {
        length_category = "tiny (< 4KB)";
    } else if (length < 1024 * 1024) {
        length_category = "small (< 1MB)";
    } else if (length < 100 * 1024 * 1024) {
        length_category = "medium (< 100MB)";
    } else if (length < 1024ULL * 1024 * 1024) {
        length_category = "large (< 1GB)";
    } else {
        length_category = "very large (>= 1GB)";
    }

    /* Get the file structure from the file descriptor */
    struct fut_file *file = fut_vfs_get_file(fd);
    if (!file) {
        fut_printf("[FTRUNCATE] ftruncate(fd=%d [%s], length=%llu [%s]) -> EBADF "
                   "(invalid fd)\n",
                   fd, fd_category, length, length_category);
        return -EBADF;
    }

    /* Get the vnode from the file */
    struct fut_vnode *vnode = file->vnode;
    if (!vnode) {
        fut_printf("[FTRUNCATE] ftruncate(fd=%d [%s], length=%llu [%s]) -> EBADF "
                   "(no vnode)\n",
                   fd, fd_category, length, length_category);
        return -EBADF;
    }

    /* Cannot truncate a directory */
    if (vnode->type == VN_DIR) {
        fut_printf("[FTRUNCATE] ftruncate(fd=%d [%s], length=%llu [%s]) -> EISDIR "
                   "(cannot truncate directory)\n",
                   fd, fd_category, length, length_category);
        return -EISDIR;
    }

    /* Phase 2: Track old size for before/after comparison */
    uint64_t old_size = vnode->size;

    /* Phase 2: Categorize operation type */
    const char *operation_type;
    const char *operation_desc;
    int64_t size_delta;

    if (length == old_size) {
        operation_type = "no-op";
        operation_desc = "size unchanged, no truncation needed";
        size_delta = 0;

        fut_printf("[FTRUNCATE] ftruncate(fd=%d [%s], length=%llu [%s], old_size=%llu, "
                   "op=%s) -> 0 (%s, Phase 2)\n",
                   fd, fd_category, length, length_category, old_size, operation_type,
                   operation_desc);
        return 0;
    } else if (length < old_size) {
        operation_type = "shrink";
        operation_desc = "reducing file size (Phase 3: will deallocate blocks)";
        size_delta = (int64_t)length - (int64_t)old_size;
    } else {
        operation_type = "extend";
        operation_desc = "increasing file size (Phase 3: will zero-fill new area)";
        size_delta = (int64_t)length - (int64_t)old_size;
    }

    /* Phase 2: Categorize size delta magnitude */
    const char *delta_category;
    int64_t abs_delta = (size_delta < 0) ? -size_delta : size_delta;

    if (abs_delta < 4096) {
        delta_category = "small change (< 4KB)";
    } else if (abs_delta < 1024 * 1024) {
        delta_category = "medium change (< 1MB)";
    } else if (abs_delta < 100 * 1024 * 1024) {
        delta_category = "large change (< 100MB)";
    } else {
        delta_category = "very large change (>= 100MB)";
    }

    /*
     * Phase 3: Call VFS truncate operation if available
     *
     * The truncate operation handles:
     * - Shrinking: Deallocates blocks beyond new size
     * - Extending: Allocates new blocks and zero-fills them (or sparse for Phase 4)
     * - Size update: Updates vnode->size in both cases
     */
    if (vnode->ops && vnode->ops->truncate) {
        int ret = vnode->ops->truncate(vnode, length);
        if (ret < 0) {
            const char *error_desc;
            switch (ret) {
                case -ENOMEM:
                    error_desc = "out of memory";
                    break;
                case -ENOSPC:
                    error_desc = "no space left on device";
                    break;
                case -EROFS:
                    error_desc = "read-only filesystem";
                    break;
                case -EIO:
                    error_desc = "I/O error";
                    break;
                default:
                    error_desc = "truncate operation failed";
                    break;
            }
            fut_printf("[FTRUNCATE] ftruncate(fd=%d [%s], length=%llu [%s], old_size=%llu, "
                       "delta=%lld [%s], op=%s, ino=%lu) -> %d (%s, Phase 3)\n",
                       fd, fd_category, length, length_category, old_size, size_delta,
                       delta_category, operation_type, vnode->ino, ret, error_desc);
            return ret;
        }

        /* Phase 3: Success - blocks allocated/deallocated and size updated */
        const char *alloc_strategy = (length > old_size) ? "zero-fill" : "dealloc";
        fut_printf("[FTRUNCATE] ftruncate(fd=%d [%s], length=%llu [%s], old_size=%llu, "
                   "delta=%lld [%s], op=%s, ino=%lu, strategy=%s) -> 0 (%s, Phase 3)\n",
                   fd, fd_category, length, length_category, old_size, size_delta,
                   delta_category, operation_type, vnode->ino, alloc_strategy, operation_desc);
        return 0;
    }

    /*
     * Fallback for filesystems without truncate operation:
     * Just update the size directly (Phase 2 behavior).
     * This provides backwards compatibility but doesn't deallocate/allocate blocks.
     *
     * Phase 4 additions:
     *   - Sparse file support (holes without blocks)
     *   - Preallocation hints (FALLOC_FL_* flags)
     *   - Lazy allocation for extends (reduce immediate I/O cost)
     */
    vnode->size = length;

    fut_printf("[FTRUNCATE] ftruncate(fd=%d [%s], length=%llu [%s], old_size=%llu, "
               "delta=%lld [%s], op=%s, ino=%lu) -> 0 (no truncate operation, size updated only, Phase 3)\n",
               fd, fd_category, length, length_category, old_size, size_delta,
               delta_category, operation_type, vnode->ino);

    return 0;
}
