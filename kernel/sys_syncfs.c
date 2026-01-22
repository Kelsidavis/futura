/* kernel/sys_syncfs.c - Filesystem-specific synchronization syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the syncfs() syscall for synchronizing a specific filesystem
 * to persistent storage. More efficient than sync() when only one filesystem
 * needs to be synchronized.
 *
 * Phase 1 (Completed): Basic syncfs implementation with FD validation
 * Phase 2: VFS integration with per-filesystem sync operations
 */

#include <kernel/fut_task.h>
#include <kernel/fut_vfs.h>
#include <kernel/errno.h>
#include <stdint.h>

#include <kernel/kprintf.h>
extern int fut_vfs_sync_fs(struct fut_mount *mount);

/**
 * syncfs() - Synchronize a specific filesystem to disk
 *
 * Like sync(), but only synchronizes the filesystem containing the file
 * referenced by fd. More efficient than sync() for targeted data
 * synchronization.
 *
 * @param fd  File descriptor on the filesystem to synchronize
 *
 * Returns:
 *   - 0 on success
 *   - -EBADF if fd is not a valid file descriptor
 *   - -EIO if I/O error occurred
 *
 * Behavior:
 *   - Flushes all dirty pages for the specified filesystem
 *   - Synchronizes filesystem metadata (inodes, directories, etc.)
 *   - Waits for I/O completion
 *   - Only affects filesystem containing fd
 *   - More efficient than sync() (doesn't flush all filesystems)
 *
 * Advantages over sync():
 *   - Faster: Only syncs one filesystem, not all
 *   - Less disruptive: Doesn't impact unrelated I/O
 *   - More predictable: Completion time is bounded
 *
 * Advantages over fsync():
 *   - Syncs entire filesystem, not just one file
 *   - Ensures filesystem consistency
 *   - Useful for database checkpointing
 *
 * Common usage patterns:
 *
 * Database checkpoint (sync entire database filesystem):
 *   int db_fd = open("/var/db/database.db", O_RDONLY);
 *   syncfs(db_fd);  // Sync entire /var/db filesystem
 *   close(db_fd);
 *
 * Application-level fsck preparation:
 *   int fd = open("/mnt/data/file", O_RDONLY);
 *   syncfs(fd);  // Ensure /mnt/data filesystem is consistent
 *   close(fd);
 *   run_fsck("/dev/sdb1");
 *
 * Before unmount:
 *   int fd = open("/mnt/usb/file", O_RDONLY);
 *   syncfs(fd);  // Flush /mnt/usb filesystem
 *   close(fd);
 *   umount("/mnt/usb");
 *
 * Multi-filesystem application:
 *   write(data_fd, data, size);  // /var/data
 *   write(log_fd, log, size);    // /var/log
 *   syncfs(data_fd);  // Only sync /var/data
 *   syncfs(log_fd);   // Only sync /var/log
 *   // More efficient than sync() which flushes everything
 *
 * Performance comparison:
 *
 * sync() - Flushes all filesystems:
 *   sync();  // Flushes /, /home, /var, /tmp, etc.
 *
 * syncfs() - Flushes one filesystem:
 *   int fd = open("/home/user/file", O_RDONLY);
 *   syncfs(fd);  // Only flushes /home filesystem
 *   close(fd);
 *
 * fsync() - Flushes one file:
 *   int fd = open("/home/user/file", O_WRONLY);
 *   write(fd, data, size);
 *   fsync(fd);  // Only flushes this file
 *   close(fd);
 *
 * When to use each:
 *   - sync(): System shutdown, emergency flush
 *   - syncfs(): Database checkpoints, filesystem-level consistency
 *   - fsync(): Single file durability, atomic updates
 *
 * Filesystem consistency guarantees:
 *   - After syncfs() returns, filesystem is consistent
 *   - All metadata updates are committed
 *   - Journal is flushed (if journaling filesystem)
 *   - Survives power loss
 *
 * Error handling:
 *
 * Handle I/O errors:
 *   if (syncfs(fd) < 0) {
 *       if (errno == EIO) {
 *           // Disk error - data may be lost
 *       }
 *   }
 *
 * Validate file descriptor:
 *   int fd = open("/path", O_RDONLY);
 *   if (fd < 0) {
 *       perror("open");
 *       return -1;
 *   }
 *   if (syncfs(fd) < 0) {
 *       perror("syncfs");
 *   }
 *   close(fd);
 *
 * Phase 1: Basic implementation with FD validation
 */
long sys_syncfs(int fd) {
    /* ARM64 FIX: Copy parameter to local variable */
    int local_fd = fd;

    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[SYNCFS] syncfs(fd=%d) -> ESRCH (no current task)\n", local_fd);
        return -ESRCH;
    }

    /* Validate file descriptor */
    if (local_fd < 0) {
        fut_printf("[SYNCFS] syncfs(fd=%d) -> EBADF (invalid fd)\n", local_fd);
        return -EBADF;
    }

    /* Phase 5: Validate FD upper bound to prevent OOB array access */
    if (local_fd >= task->max_fds) {
        fut_printf("[SYNCFS] syncfs(fd=%d, max_fds=%d) -> EBADF "
                   "(fd exceeds max_fds, Phase 5: FD bounds validation)\n",
                   local_fd, task->max_fds);
        return -EBADF;
    }

    /* Phase 2: Resolve FD to file and get mount point */
    struct fut_file *file = vfs_get_file_from_task(task, local_fd);
    if (!file) {
        fut_printf("[SYNCFS] syncfs(fd=%d) -> EBADF (fd not open)\n", local_fd);
        return -EBADF;
    }

    /* Get the vnode for this file */
    if (!file->vnode) {
        fut_printf("[SYNCFS] syncfs(fd=%d) -> EBADF (no vnode for fd)\n", local_fd);
        return -EBADF;
    }

    /* Get the mount point for this vnode */
    struct fut_mount *mount = file->vnode->mount;
    if (!mount) {
        fut_printf("[SYNCFS] syncfs(fd=%d) -> EINVAL (no mount point for vnode)\n", local_fd);
        return -EINVAL;
    }

    /* Phase 2: Sync the specific filesystem */
    int ret = fut_vfs_sync_fs(mount);
    if (ret < 0) {
        fut_printf("[SYNCFS] syncfs(fd=%d) -> %d (Phase 2: filesystem sync failed)\n",
                   local_fd, ret);
        return ret;
    }

    fut_printf("[SYNCFS] syncfs(fd=%d) -> 0 (Phase 2: filesystem synced successfully)\n",
               local_fd);
    return 0;
}
