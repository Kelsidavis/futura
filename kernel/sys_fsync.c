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
 * Phase 3 (Current): VFS backend sync operations (FuturaFS, RamFS sync hooks)
 * Phase 4: Per-filesystem sync strategies, writeback cache flushing
 */

#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <kernel/fut_task.h>

extern void fut_printf(const char *fmt, ...);
extern struct fut_file *vfs_get_file_from_task(struct fut_task *task, int fd);

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
 * Phase 2 (Current): Enhanced validation, FD/file type categorization, detailed logging
 * Phase 3: VFS backend sync operations (FuturaFS, RamFS sync hooks)
 * Phase 4: Per-filesystem sync strategies, writeback cache flushing
 */
long sys_fsync(int fd) {
    /* Get current task for FD table access */
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[FSYNC] fsync(fd=%d) -> ESRCH (no current task)\n", fd);
        return -ESRCH;
    }

    /* Phase 2: Validate fd early */
    if (fd < 0) {
        fut_printf("[FSYNC] fsync(fd=%d) -> EBADF (negative fd)\n", fd);
        return -EBADF;
    }

    /* Phase 2: Categorize FD range */
    const char *fd_category;
    if (fd <= 2) {
        fd_category = "standard (stdin/stdout/stderr)";
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
        fut_printf("[FSYNC] fsync(fd=%d [%s]) -> EBADF (no FD table, pid=%d)\n",
                   fd, fd_category, task->pid);
        return -EBADF;
    }

    /* Get file structure from FD */
    struct fut_file *file = vfs_get_file_from_task(task, fd);
    if (!file) {
        fut_printf("[FSYNC] fsync(fd=%d [%s]) -> EBADF (fd not open, pid=%d)\n",
                   fd, fd_category, task->pid);
        return -EBADF;
    }

    /* Phase 2: Identify file type */
    const char *file_type;
    const char *sync_scope;

    if (file->chr_ops) {
        file_type = "character device";
        sync_scope = "not syncable";

        fut_printf("[FSYNC] fsync(fd=%d [%s], type=%s) -> EINVAL (%s, pid=%d)\n",
                   fd, fd_category, file_type, sync_scope, task->pid);
        return -EINVAL;
    }

    if (file->vnode) {
        switch (file->vnode->type) {
            case VN_REG:
                file_type = "regular file";
                sync_scope = "data+metadata";
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

                fut_printf("[FSYNC] fsync(fd=%d [%s], type=%s) -> EINVAL "
                           "(%s, pid=%d)\n",
                           fd, fd_category, file_type, sync_scope, task->pid);
                return -EINVAL;
            case VN_FIFO:
                file_type = "FIFO/pipe";
                sync_scope = "not syncable";

                fut_printf("[FSYNC] fsync(fd=%d [%s], type=%s) -> EINVAL "
                           "(%s, pid=%d)\n",
                           fd, fd_category, file_type, sync_scope, task->pid);
                return -EINVAL;
            case VN_SOCK:
                file_type = "socket";
                sync_scope = "not syncable";

                fut_printf("[FSYNC] fsync(fd=%d [%s], type=%s) -> EINVAL "
                           "(%s, pid=%d)\n",
                           fd, fd_category, file_type, sync_scope, task->pid);
                return -EINVAL;
            default:
                file_type = "unknown";
                sync_scope = "not syncable";

                fut_printf("[FSYNC] fsync(fd=%d [%s], type=%s) -> EINVAL "
                           "(%s, pid=%d)\n",
                           fd, fd_category, file_type, sync_scope, task->pid);
                return -EINVAL;
        }
    } else {
        file_type = "no vnode";
        sync_scope = "unknown";
    }

    /*
     * Phase 3: Call VFS backend sync operation if available
     *
     * Each filesystem implements its own sync strategy:
     * - RamFS: No-op (already in memory)
     * - FuturaFS: Flush journal, ensure log-structured commits (Phase 4)
     * - Block devices: Flush device cache (Phase 4)
     */
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
            fut_printf("[FSYNC] fsync(fd=%d [%s], type=%s, scope=%s, pid=%d) -> %d "
                       "(%s, Phase 3)\n",
                       fd, fd_category, file_type, sync_scope, task->pid, ret, error_desc);
            return ret;
        }

        /* Phase 3: Success - sync completed */
        fut_printf("[FSYNC] fsync(fd=%d [%s], type=%s, scope=%s, pid=%d) -> 0 "
                   "(sync completed, Phase 3)\n",
                   fd, fd_category, file_type, sync_scope, task->pid);
        return 0;
    }

    /*
     * No sync operation available - return success for backwards compatibility.
     * This can happen for:
     * - Filesystems that don't implement sync (devfs, procfs)
     * - Special files that don't need syncing
     *
     * Phase 4 additions:
     *   - Writeback cache flushing (block layer integration)
     *   - Directory sync (ensure entries are durable)
     *   - Barrier operations for device caches (SCSI SYNCHRONIZE CACHE)
     */
    fut_printf("[FSYNC] fsync(fd=%d [%s], type=%s, scope=%s, pid=%d) -> 0 "
               "(no sync operation, Phase 3)\n",
               fd, fd_category, file_type, sync_scope, task->pid);

    return 0;
}
