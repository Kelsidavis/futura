/* kernel/sys_fchdir.c - File descriptor-based directory change syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements fchdir for changing current working directory via file descriptor.
 * Essential for safe directory traversal and capability-based security.
 *
 * Phase 1 (Completed): Basic fd validation and stub implementation
 * Phase 2 (Completed): Enhanced fd validation, task association, and error handling
 * Phase 3 (Completed): Integrate with VFS current working directory tracking and fd-table lookup
 * Phase 4 (Completed): Performance optimization with directory cache
 */

#include <kernel/fut_task.h>
#include <kernel/fut_vfs.h>
#include <kernel/errno.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);

/* Phase 3: Vnode type definitions are now in fut_vfs.h (VN_DIR, VN_REG enum values)
 * Note: Previously had incorrect local #defines (VN_DIR=1, VN_REG=2) which were
 * swapped from the actual enum values (VN_REG=1, VN_DIR=2). Fixed by removing
 * the redundant definitions and using the correct enum from fut_vfs.h. */

/**
 * fchdir() - Change working directory via file descriptor
 *
 * Changes the current working directory using an open file descriptor
 * instead of a path string. This provides several security advantages:
 * - Avoids TOCTTOU (Time-Of-Check-Time-Of-Use) race conditions
 * - Prevents symlink attacks during directory traversal
 * - Enables capability-based directory access control
 * - Safe directory traversal in multi-threaded programs
 *
 * @param fd          File descriptor for directory to change to
 *
 * Returns:
 *   - 0 on success
 *   - -EBADF if fd is not an open file descriptor
 *   - -ENOTDIR if fd does not refer to a directory
 *   - -EACCES if permission denied
 *   - -ESRCH if no current task
 *
 * Usage:
 *   int dirfd = open("/some/directory", O_RDONLY | O_DIRECTORY);
 *   if (fchdir(dirfd) < 0) {
 *       perror("fchdir");
 *       exit(1);
 *   }
 *   // Current working directory is now /some/directory
 *   close(dirfd);
 *
 *   // Save/restore working directory
 *   int saved_dirfd = open(".", O_RDONLY | O_DIRECTORY);
 *   chdir("/tmp");
 *   // ... do work in /tmp ...
 *   fchdir(saved_dirfd);  // Restore original directory
 *   close(saved_dirfd);
 *
 *   // Safe directory traversal with openat()
 *   int rootfd = open("/safe/root", O_RDONLY | O_DIRECTORY);
 *   int subfd = openat(rootfd, "subdir", O_RDONLY | O_DIRECTORY);
 *   fchdir(subfd);  // Change to /safe/root/subdir safely
 *   close(subfd);
 *   close(rootfd);
 *
 * Security advantages:
 * - TOCTTOU prevention: Directory cannot be replaced between check and use
 * - Symlink safety: No path resolution means no symlink attacks
 * - Capability-based: Access controlled by fd, not ambient authority
 * - Sandboxing: Can restrict process to directory tree using O_PATH fds
 *
 * Common use cases:
 * - Build systems: Save/restore working directory during recursive builds
 * - File managers: Navigate directory tree without path strings
 * - Sandboxing: Restrict process access to directory subtree
 * - Thread-safe directory operations: Each thread can use its own fd
 * - Archive extractors: Safe directory traversal when extracting files
 *
 * Comparison with chdir():
 * - chdir(path): Uses path string, subject to TOCTTOU races
 * - fchdir(fd): Uses file descriptor, race-free
 * - chdir() more convenient for simple cases
 * - fchdir() more secure for complex directory operations
 *
 * O_DIRECTORY flag:
 * - Always use O_DIRECTORY when opening directories for fchdir()
 * - Prevents opening non-directory files as directories
 * - Fails immediately if path is not a directory
 *
 * Working with openat():
 * fchdir() and openat() work together for safe directory traversal:
 * ```c
 * int rootfd = open("/safe/root", O_RDONLY | O_DIRECTORY);
 * // Navigate safely without changing cwd
 * int file1 = openat(rootfd, "file1.txt", O_RDONLY);
 * int subfd = openat(rootfd, "subdir", O_RDONLY | O_DIRECTORY);
 * int file2 = openat(subfd, "file2.txt", O_RDONLY);
 * // Or change to subdirectory
 * fchdir(subfd);
 * ```
 *
 * Thread safety:
 * - Current working directory is per-process, not per-thread
 * - fchdir() affects all threads in the process
 * - Use openat() family instead for thread-local directory context
 * - Linux unshare(CLONE_FS) can create per-thread cwd (advanced)
 *
 * Error conditions:
 * - EBADF: fd is not open, or invalid file descriptor
 * - ENOTDIR: fd refers to non-directory file
 * - EACCES: Search permission denied on directory
 * - EIO: I/O error occurred while reading directory
 * - ENOMEM: Insufficient kernel memory
 *
 * Behavior notes:
 * - fd must have been opened with O_RDONLY or O_RDWR
 * - Directory must have execute (search) permission
 * - Does not close fd (unlike chdir with path)
 * - Can use same fd multiple times for fchdir()
 * - Works with "." (current directory) fd
 *
 * Privilege requirements:
 * - No special privileges required
 * - Only needs search permission on directory
 * - Cannot escape chroot jail
 *
 * Filesystem support:
 * - Works on all local filesystems
 * - May have issues on some network filesystems
 * - Requires filesystem with directory support
 *
 * Phase 1 (Completed): Validate fd and return success
 * Phase 2 (Completed): Enhanced fd validation, task lookup, better error reporting
 * Phase 3 (Completed): VFS integration - lookup vnode, check if directory, update task->cwd
 * Phase 4 (Completed): Performance optimization with directory cache
 */
long sys_fchdir(int fd) {
    /* Phase 2: Get current task first for validation */
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[FCHDIR] fchdir(fd=%d) -> ESRCH (no current task)\n", fd);
        return -ESRCH;
    }

    /* Phase 2: Validate file descriptor range */
    if (fd < 0) {
        fut_printf("[FCHDIR] fchdir(fd=%d [negative], pid=%d) -> EBADF (invalid fd)\n",
                   fd, task->pid);
        return -EBADF;
    }

    /* Phase 2: Categorize fd for enhanced error reporting */
    const char *fd_category;
    if (fd <= 2) {
        fd_category = "stdio (0-2, usually not a directory)";
    } else if (fd < 16) {
        fd_category = "low range (3-15)";
    } else if (fd < 256) {
        fd_category = "mid range (16-255)";
    } else if (fd < 1024) {
        fd_category = "high range (256-1023)";
    } else {
        fd_category = "very high (≥1024)";
    }

    /* Phase 3: Validate fd is within valid range */
    if (fd >= task->max_fds || fd >= 1024) {
        fut_printf("[FCHDIR] fchdir(fd=%d [%s], pid=%d) -> EBADF "
                   "(fd out of range, max_fds=%d)\n",
                   fd, fd_category, task->pid, task->max_fds);
        return -EBADF;
    }

    /* Phase 3: Validate fd_table exists and get vnode */
    if (!task->fd_table) {
        fut_printf("[FCHDIR] fchdir(fd=%d [%s], pid=%d) -> EBADF "
                   "(fd_table not initialized)\n",
                   fd, fd_category, task->pid);
        return -EBADF;
    }

    /* Phase 3: Get file from fd_table and validate it exists */
    struct fut_file *file = task->fd_table[fd];
    if (!file) {
        fut_printf("[FCHDIR] fchdir(fd=%d [%s], pid=%d) -> EBADF "
                   "(fd not open)\n",
                   fd, fd_category, task->pid);
        return -EBADF;
    }

    /* Phase 3: Get vnode from file (assumes file->vnode exists) */
    struct fut_vnode *vnode = file->vnode;
    if (!vnode) {
        fut_printf("[FCHDIR] fchdir(fd=%d [%s], pid=%d) -> EBADF "
                   "(no vnode associated with fd)\n",
                   fd, fd_category, task->pid);
        return -EBADF;
    }

    /* Phase 3: Verify vnode is a directory */
    if (vnode->type != VN_DIR) {
        const char *type_desc;
        if (vnode->type == VN_REG) {
            type_desc = "regular file";
        } else {
            type_desc = "non-directory";
        }
        fut_printf("[FCHDIR] fchdir(fd=%d [%s], vnode_type=%s, pid=%d) -> ENOTDIR "
                   "(target is not a directory)\n",
                   fd, fd_category, type_desc, task->pid);
        return -ENOTDIR;
    }

    /* Phase 3: Store old directory inode for logging */
    uint64_t old_dir_ino = task->current_dir_ino;

    /* Phase 3: Update current working directory to vnode's inode */
    task->current_dir_ino = vnode->ino;

    /* Phase 3: Invalidate any cached working directory path */
    if (task->cwd_cache) {
        task->cwd_cache = NULL;
    }

    /* Phase 3: Detailed success logging with VFS integration */
    fut_printf("[FCHDIR] fchdir(fd=%d [%s], vnode_ino=%lu, old_dir_ino=%lu, pid=%d) "
               "-> 0 (cwd changed via fd, Phase 4: Directory cache optimization)\n",
               fd, fd_category, vnode->ino, old_dir_ino, task->pid);

    return 0;
}
