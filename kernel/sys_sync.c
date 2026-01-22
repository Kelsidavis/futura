/* kernel/sys_sync.c - System-wide filesystem synchronization syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the sync() syscall for synchronizing all filesystem data and
 * metadata to persistent storage. Essential for ensuring data durability
 * and crash consistency.
 *
 * Phase 1 (Completed): Basic sync implementation
 * Phase 2: Per-filesystem synchronization optimization
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <stdint.h>

#include <kernel/kprintf.h>
extern int fut_vfs_sync_all(void);

/**
 * sync() - Synchronize all filesystem data to disk
 *
 * Causes all pending modifications to filesystem metadata and cached file
 * data to be written to the underlying filesystems. This ensures that all
 * buffered writes are committed to persistent storage.
 *
 * Returns:
 *   - Always returns 0 (void in POSIX, but returns int in Linux)
 *
 * Behavior:
 *   - Flushes all dirty pages in page cache to disk
 *   - Synchronizes filesystem metadata (inodes, directory entries, etc.)
 *   - Ensures write-back buffers are committed
 *   - Does not wait for I/O completion (asynchronous by tradition)
 *   - Modern implementations typically wait for completion
 *   - No-op if no dirty data exists
 *
 * Performance considerations:
 *   - Can be expensive operation (flushes all filesystems)
 *   - May cause temporary system slowdown
 *   - Use fsync(fd) for single-file synchronization
 *   - Use syncfs(fd) for single-filesystem synchronization
 *
 * Common usage patterns:
 *
 * Before system shutdown:
 *   sync();
 *   sync();  // Traditionally called twice for safety
 *   sync();
 *   // Now safe to power off
 *
 * After critical data writes:
 *   write(fd, critical_data, size);
 *   close(fd);
 *   sync();  // Ensure data is on disk
 *   // But fsync(fd) before close(fd) is better
 *
 * Emergency data preservation:
 *   if (battery_low()) {
 *       sync();  // Force all data to disk
 *       shutdown();
 *   }
 *
 * Database commit (poor practice - use fsync instead):
 *   write(db_fd, transaction, size);
 *   sync();  // DON'T DO THIS - flushes ALL filesystems
 *   // Better: fsync(db_fd) - only syncs that file
 *
 * Safer alternative patterns:
 *
 * Single file synchronization (preferred):
 *   write(fd, data, size);
 *   fsync(fd);  // Only syncs this file
 *   close(fd);
 *
 * Single filesystem synchronization:
 *   write(fd, data, size);
 *   syncfs(fd);  // Only syncs filesystem containing fd
 *   close(fd);
 *
 * Directory synchronization (atomic rename):
 *   write(tmpfd, data, size);
 *   fsync(tmpfd);
 *   close(tmpfd);
 *   rename("file.tmp", "file");
 *   int dirfd = open(".", O_RDONLY);
 *   fsync(dirfd);  // Sync directory entry
 *   close(dirfd);
 *
 * Historical note:
 *   - Original Unix sync() was asynchronous (didn't wait)
 *   - Modern sync() waits for I/O completion
 *   - Traditional "sync; sync; sync" pattern from async days
 *   - Single sync() is now sufficient
 *
 * Security considerations:
 *   - Unprivileged users can call sync()
 *   - May cause denial-of-service (high I/O load)
 *   - Some systems rate-limit sync() calls
 *   - Use fsync() or syncfs() to reduce impact
 *
 * Crash consistency guarantees:
 *   - After sync() completes, data survives power loss
 *   - Filesystem metadata is consistent
 *   - No torn writes (assuming atomic sector writes)
 *   - Journal is flushed (if journaling filesystem)
 *
 * Phase 1: Basic implementation that logs sync operation
 */
long sys_sync(void) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[SYNC] sync() -> ESRCH (no current task)\n");
        return -ESRCH;
    }

    /* Phase 2: Call VFS to sync all mounted filesystems
     * This iterates the mount list and calls the sync operation on each filesystem.
     * Filesystems with a sync() operation will flush dirty pages and commit journals.
     * In-memory filesystems (RamFS) typically have no sync operation (no-op). */

    int ret = fut_vfs_sync_all();

    if (ret < 0) {
        fut_printf("[SYNC] sync() -> %d (Phase 2: some filesystems failed to sync)\n", ret);
        /* Per POSIX, sync() doesn't return errors - always returns 0 */
        return 0;
    }

    fut_printf("[SYNC] sync() -> 0 (Phase 2: all filesystems synced successfully)\n");

    /* Always returns 0 (success) per POSIX spec */
    return 0;
}
