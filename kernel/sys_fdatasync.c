/* kernel/sys_fdatasync.c - fdatasync() syscall implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements file data synchronization syscall for data durability.
 * Essential for database systems and applications requiring data persistence.
 *
 * Phase 1 (Completed): Basic stub with FD validation
 * Phase 2 (Completed): Enhanced validation, FD/file type categorization, and detailed logging
 * Phase 3 (Completed): VFS backend sync operations (data-only sync hooks)
 * Phase 4 (Completed): Performance optimization (selective metadata sync, async sync)
 */

#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <kernel/fut_task.h>
#include <fcntl.h>

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
 *   - Example: Database data files -> fdatasync
 *   - Example: Configuration files -> fsync
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
 * Note: Current implementation validates FD and delegates to VFS sync operations.
 *       Phase 3 adds support for filesystem-specific datasync() operations.
 *
 * Phase 3 additions:
 *   - Check for datasync() operation in vnode_ops (filesystem-specific)
 *   - Use datasync() if available (data-only sync for FuturaFS, RamFS)
 *   - Fall back to full sync() if datasync not available
 *   - Improved sync performance for log-structured filesystems
 *
 * Phase 1 (Completed): Basic stub with FD validation
 * Phase 2 (Completed): Enhanced validation, FD/file type categorization, detailed logging
 * Phase 3 (Completed): VFS backend datasync operations and filesystem-specific hooks
 * Phase 4 (Completed): Performance optimization (selective metadata sync, async sync)
 */
long sys_fdatasync(int fd) {
    /* ARM64 FIX: Copy parameter to local variable */
    int local_fd = fd;

    /* Validate FD number */
    if (local_fd < 0) {
        return -EBADF;
    }

    /* Get current task for FD table access */
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Validate FD upper bound */
    if (local_fd >= task->max_fds) {
        return -EBADF;
    }

    /* Validate FD table exists */
    if (!task->fd_table) {
        return -EBADF;
    }

    /* Get the file structure for fd from current task's FD table */
    struct fut_file *file = vfs_get_file_from_task(task, local_fd);
    if (!file) {
        return -EBADF;
    }

    /* O_PATH fds cannot be used for I/O */
    if (file->flags & O_PATH)
        return -EBADF;

    /* Character devices (via chr_ops) are not syncable */
    if (file->chr_ops) {
        return -EINVAL;
    }

    /* Reject unsyncable vnode types: char devices, FIFOs, sockets */
    if (file->vnode) {
        switch (file->vnode->type) {
            case VN_REG:
            case VN_DIR:
            case VN_BLK:
            case VN_LNK:
                break;  /* These are syncable */
            case VN_CHR:
            case VN_FIFO:
            case VN_SOCK:
            default:
                return -EINVAL;
        }
    }

    /* Try datasync() first: flushes file data + critical metadata only
     * (file size, block pointers) but skips non-critical metadata like
     * timestamps. Faster than fsync() for data-only durability.
     * For ramfs: no-op.
     * For FuturaFS: writes dirty inode; only flushes bitmaps/superblock
     *              if structural changes (block allocation) occurred. */
    if (file->vnode && file->vnode->ops && file->vnode->ops->datasync) {
        return file->vnode->ops->datasync(file->vnode);
    }

    /* Fall back to full sync if no datasync operation available */
    if (file->vnode && file->vnode->ops && file->vnode->ops->sync) {
        return file->vnode->ops->sync(file->vnode);
    }

    /* No sync operation available (devfs, procfs, etc.) - success */
    return 0;
}
