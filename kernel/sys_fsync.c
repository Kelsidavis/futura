/* kernel/sys_fsync.c - File synchronization syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements file synchronization syscall for data durability.
 * Essential for database commits, configuration updates, and ensuring
 * data persistence across system crashes.
 *
 * Phase 1 (Completed): Basic stub with minimal validation
 * Phase 2 (Completed): Enhanced validation, FD/file type categorization, and detailed logging
 * Phase 3 (Completed): VFS backend sync operations (FuturaFS, RamFS sync hooks)
 * Phase 4 (Completed): Per-filesystem sync strategies, writeback cache flushing
 */

#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <kernel/fut_task.h>
#include <fcntl.h>

/**
 * fsync() - Synchronize file's in-core state with storage
 *
 * Transfers all modified in-core data and metadata of the file referred to
 * by fd to the storage device. Does not return until the storage device
 * reports that the transfer has completed. This ensures all changed
 * information can be retrieved even after a system crash.
 *
 * @param fd File descriptor to synchronize
 *
 * Returns:
 *   - 0 on success
 *   - -EBADF if fd is not a valid open file descriptor
 *   - -EINVAL if fd refers to a special file that doesn't support syncing
 *   - -ESRCH if no task context available
 *   - -EIO if an I/O error occurs during sync (Phase 3+)
 *   - -EROFS if the filesystem is read-only (Phase 3+)
 *
 * Behavior:
 *   - Flushes file data to storage device
 *   - Flushes metadata (size, timestamps, permissions, etc.)
 *   - Blocks until device confirms transfer completion
 *   - Writes through or flushes disk caches if present
 *   - For directories: ensures directory entries are durable
 *   - Does not sync parent directory (use separate fsync on parent)
 *
 * What gets synchronized:
 *   - Modified file contents
 *   - File size changes
 *   - Modified timestamps (atime, mtime, ctime)
 *   - Permission changes
 *   - Extended attributes
 *   - Directory entries (if fd is a directory)
 *
 * File types and fsync:
 *   - Regular files: Sync data and metadata
 *   - Directories: Sync directory entries
 *   - Block devices: Flush device cache
 *   - Character devices: Not syncable (returns -EINVAL)
 *   - Pipes/FIFOs: Not syncable (returns -EINVAL)
 *   - Sockets: Not syncable (returns -EINVAL)
 *
 * Common usage patterns:
 *
 * Database commit:
 *   write(fd, transaction_data, size);
 *   fsync(fd);  // Ensure data is durable before returning to client
 *
 * Configuration file update:
 *   write(fd, config_data, size);
 *   fsync(fd);
 *   close(fd);
 *
 * Directory sync after file creation:
 *   int dir_fd = open("/path/to/dir", O_RDONLY | O_DIRECTORY);
 *   int file_fd = open("/path/to/dir/newfile", O_CREAT | O_WRONLY);
 *   write(file_fd, data, size);
 *   fsync(file_fd);      // Sync file data
 *   fsync(dir_fd);       // Sync directory entry
 *   close(file_fd);
 *   close(dir_fd);
 *
 * Log rotation:
 *   rename("app.log", "app.log.1");
 *   int dir_fd = open("/var/log", O_RDONLY | O_DIRECTORY);
 *   fsync(dir_fd);       // Ensure rename is durable
 *   close(dir_fd);
 *
 * Comparison with fdatasync:
 *   - fsync(): Flushes data and all metadata (slower but safer)
 *   - fdatasync(): Flushes data and minimal metadata (faster but less safe)
 *   - fdatasync() may skip atime updates but will sync size changes
 *   - For database/journaling apps, fsync() is preferred
 *
 * Phase 1 (Completed): Basic stub with minimal validation
 * Phase 2 (Completed): Enhanced validation, FD/file type categorization, detailed logging
 * Phase 3 (Completed): VFS backend sync operations (FuturaFS, RamFS sync hooks)
 * Phase 4 (Completed): Per-filesystem sync strategies, writeback cache flushing
 */
long sys_fsync(int fd) {
    /* ARM64 FIX: Copy parameter to local variable */
    int local_fd = fd;

    /* Get current task for FD table access */
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Validate fd range */
    if (local_fd < 0 || local_fd >= task->max_fds) {
        return -EBADF;
    }

    /* Validate FD table exists */
    if (!task->fd_table) {
        return -EBADF;
    }

    /* Get file structure from FD */
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

    /* Dispatch to filesystem-specific sync: flushes file data + all metadata
     * (timestamps, permissions, size, block pointers) to the block device.
     * For ramfs: no-op (already in memory).
     * For FuturaFS: writes dirty inode + bitmaps + superblock to disk. */
    if (file->vnode && file->vnode->ops && file->vnode->ops->sync) {
        return file->vnode->ops->sync(file->vnode);
    }

    /* No sync operation available (devfs, procfs, etc.) - success */
    return 0;
}
