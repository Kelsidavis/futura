/* kernel/sys_fdatasync.c - fdatasync() syscall implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements file data synchronization syscall for data durability.
 * Essential for database systems and applications requiring data persistence.
 *
 * Phase 1 (Completed): Basic stub with FD validation
 * Phase 2 (Current): Enhanced validation, FD/file type categorization, and detailed logging
 * Phase 3: VFS backend sync operations (data-only sync hooks)
 * Phase 4: Performance optimization (selective metadata sync, async sync)
 */

#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <kernel/fut_task.h>

extern void fut_printf(const char *fmt, ...);
extern struct fut_file *vfs_get_file_from_task(struct fut_task *task, int fd);

/**
 * fdatasync() syscall - Synchronize a file's data (but not metadata) with storage.
 *
 * Similar to fsync(), but only flushes file data to storage, not necessarily
 * all metadata. This can be faster when metadata updates (like atime) are not
 * critical. Essential for database systems that need data durability without
 * full metadata sync overhead.
 *
 * @param fd File descriptor to synchronize
 *
 * Returns:
 *   - 0 on success
 *   - -EBADF if fd is not a valid file descriptor
 *   - -EINVAL if fd refers to a special file that doesn't support syncing
 *   - -ESRCH if no current task context
 *   - -EIO if an I/O error occurs during sync (Phase 3+)
 *   - -EROFS if the filesystem is read-only (Phase 3+)
 *
 * Behavior:
 *   - Validates that fd is a valid open file descriptor
 *   - Flushes file data to storage but not necessarily metadata
 *   - More efficient than fsync() when metadata sync is unnecessary
 *   - Does not return until the data transfer is complete
 *   - Blocks until device confirms transfer completion
 *
 * What gets synchronized:
 *   - Modified file contents (always)
 *   - File size changes (if needed for data retrieval)
 *   - NOT synchronized: atime, mtime (unless needed)
 *   - NOT synchronized: Permission changes
 *   - NOT synchronized: Extended attributes
 *
 * Difference from fsync():
 *   - fsync(): Flushes data and all metadata (slower but safer)
 *   - fdatasync(): Flushes data and minimal metadata (faster but less safe)
 *   - fdatasync() may skip atime updates but will sync size changes
 *   - For database/journaling apps, choose based on requirements
 *
 * File types and fdatasync:
 *   - Regular files: Sync data and critical metadata
 *   - Directories: Sync directory entries
 *   - Block devices: Flush device cache
 *   - Character devices: Not syncable (returns -EINVAL)
 *   - Pipes/FIFOs: Not syncable (returns -EINVAL)
 *   - Sockets: Not syncable (returns -EINVAL)
 *
 * Common usage patterns:
 *
 * Database transaction commit (data only):
 *   write(fd, transaction_data, size);
 *   fdatasync(fd);  // Ensure data is durable, skip atime update
 *
 * Log file append (performance):
 *   write(log_fd, log_entry, entry_size);
 *   fdatasync(log_fd);  // Faster than fsync for append-only logs
 *
 * When to use fdatasync vs fsync:
 *   - Use fdatasync: When only data durability matters
 *   - Use fsync: When metadata must also be durable
 *   - Example: Database data files → fdatasync
 *   - Example: Configuration files → fsync
 *
 * Performance considerations:
 *   - fdatasync() can be significantly faster than fsync()
 *   - Useful for high-throughput append-only workloads
 *   - Database systems often prefer fdatasync()
 *   - Still requires disk I/O, so use judiciously
 *
 * Related syscalls:
 *   - fsync(): Sync data and all metadata
 *   - sync(): Sync all filesystems
 *   - sync_file_range(): Sync specific file range
 *
 * Note: Current implementation is a stub that validates the FD.
 *       Full sync support requires VFS backend implementation.
 *
 * TODO Phase 3: Implement data-only sync in VFS:
 *   - Add datasync() operation to fut_vnode_ops
 *   - Implement in FuturaFS (log-structured, skip atime)
 *   - Implement in RamFS (no-op or minimal sync)
 *   - Fall back to full sync if datasync not available
 *
 * Phase 1 (Completed): Basic stub with FD validation
 * Phase 2 (Current): Enhanced validation, FD/file type categorization, detailed logging
 * Phase 3: VFS backend sync operations (data-only sync hooks)
 * Phase 4: Performance optimization (selective metadata sync, async sync)
 */
long sys_fdatasync(int fd) {
    /* Phase 2: Validate FD number */
    if (fd < 0) {
        fut_printf("[FDATASYNC] fdatasync(fd=%d) -> EBADF (negative fd)\n", fd);
        return -EBADF;
    }

    /* Phase 2: Get current task for FD table access */
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[FDATASYNC] fdatasync(fd=%d) -> ESRCH (no current task)\n", fd);
        return -ESRCH;
    }

    /* Phase 2: Categorize FD range */
    const char *fd_category;
    if (fd <= 2) {
        fd_category = "stdio (0-2)";
    } else if (fd < 16) {
        fd_category = "low (3-15)";
    } else if (fd < 256) {
        fd_category = "mid (16-255)";
    } else if (fd < 1024) {
        fd_category = "high (256-1023)";
    } else {
        fd_category = "very high (≥1024)";
    }

    /* Validate FD table exists */
    if (!task->fd_table) {
        fut_printf("[FDATASYNC] fdatasync(fd=%d [%s]) -> EBADF (no FD table, pid=%d)\n",
                   fd, fd_category, task->pid);
        return -EBADF;
    }

    /* Get the file structure for fd from current task's FD table */
    struct fut_file *file = vfs_get_file_from_task(task, fd);
    if (!file) {
        fut_printf("[FDATASYNC] fdatasync(fd=%d [%s]) -> EBADF (fd not open, pid=%d)\n",
                   fd, fd_category, task->pid);
        return -EBADF;
    }

    /* Phase 2: Identify file type */
    const char *file_type;
    const char *sync_scope;

    /* fdatasync() not supported on character devices, pipes, or sockets */
    if (file->chr_ops) {
        file_type = "character device";
        sync_scope = "not syncable";
        fut_printf("[FDATASYNC] fdatasync(fd=%d [%s], type=%s) -> EINVAL (%s, pid=%d)\n",
                   fd, fd_category, file_type, sync_scope, task->pid);
        return -EINVAL;
    }

    if (file->vnode) {
        switch (file->vnode->type) {
            case VN_REG:
                file_type = "regular file";
                sync_scope = "data+size";
                break;
            case VN_DIR:
                file_type = "directory";
                sync_scope = "directory entries";
                break;
            case VN_BLK:
                file_type = "block device";
                sync_scope = "device cache";
                break;
            case VN_LNK:
                file_type = "symbolic link";
                sync_scope = "link target";
                break;
            case VN_CHR:
                file_type = "character device";
                sync_scope = "not syncable";
                fut_printf("[FDATASYNC] fdatasync(fd=%d [%s], type=%s) -> EINVAL (%s, pid=%d)\n",
                           fd, fd_category, file_type, sync_scope, task->pid);
                return -EINVAL;
            case VN_FIFO:
                file_type = "FIFO/pipe";
                sync_scope = "not syncable";
                fut_printf("[FDATASYNC] fdatasync(fd=%d [%s], type=%s) -> EINVAL (%s, pid=%d)\n",
                           fd, fd_category, file_type, sync_scope, task->pid);
                return -EINVAL;
            case VN_SOCK:
                file_type = "socket";
                sync_scope = "not syncable";
                fut_printf("[FDATASYNC] fdatasync(fd=%d [%s], type=%s) -> EINVAL (%s, pid=%d)\n",
                           fd, fd_category, file_type, sync_scope, task->pid);
                return -EINVAL;
            default:
                file_type = "unknown";
                sync_scope = "not syncable";
                fut_printf("[FDATASYNC] fdatasync(fd=%d [%s], type=%s) -> EINVAL (%s, pid=%d)\n",
                           fd, fd_category, file_type, sync_scope, task->pid);
                return -EINVAL;
        }
    } else {
        file_type = "no vnode";
        sync_scope = "unknown";
    }

    /*
     * Phase 3: Use regular sync() operation as fallback for fdatasync()
     *
     * Ideally, fdatasync() would only sync data and critical metadata (size),
     * skipping atime/mtime updates for better performance. However, for Phase 3,
     * we use the regular sync() operation which syncs all metadata.
     *
     * Phase 4 will add a dedicated datasync() operation to vnode_ops for
     * selective metadata synchronization.
     */
    uint64_t ino = file->vnode ? file->vnode->ino : 0;

    if (file->vnode && file->vnode->ops && file->vnode->ops->sync) {
        int ret = file->vnode->ops->sync(file->vnode);
        if (ret < 0) {
            const char *error_desc;
            switch (ret) {
                case -EIO:
                    error_desc = "I/O error during sync";
                    break;
                case -EROFS:
                    error_desc = "read-only filesystem";
                    break;
                default:
                    error_desc = "sync operation failed";
                    break;
            }
            fut_printf("[FDATASYNC] fdatasync(fd=%d [%s], type=%s, scope=%s, ino=%lu, pid=%d) -> %d "
                       "(%s, Phase 3)\n",
                       fd, fd_category, file_type, sync_scope, ino, task->pid, ret, error_desc);
            return ret;
        }

        /* Phase 3: Success - sync completed (using full sync as fallback) */
        fut_printf("[FDATASYNC] fdatasync(fd=%d [%s], type=%s, scope=%s, ino=%lu, pid=%d) -> 0 "
                   "(sync completed via fsync fallback, Phase 3)\n",
                   fd, fd_category, file_type, sync_scope, ino, task->pid);
        return 0;
    }

    /*
     * No sync operation available - return success for backwards compatibility.
     *
     * Phase 4 additions:
     *   - Add dedicated datasync() operation to vnode_ops
     *   - Selective metadata sync (size, but not atime/mtime)
     *   - Async fdatasync for better performance
     *   - Per-filesystem datasync strategies
     */
    fut_printf("[FDATASYNC] fdatasync(fd=%d [%s], type=%s, scope=%s, ino=%lu, pid=%d) -> 0 "
               "(no sync operation, Phase 3)\n",
               fd, fd_category, file_type, sync_scope, ino, task->pid);

    return 0;
}
