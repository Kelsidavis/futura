/* kernel/sys_fchdir.c - File descriptor-based directory change syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements fchdir for changing current working directory via file descriptor.
 * Essential for safe directory traversal and capability-based security.
 *
 * Phase 1 (Current): Validation and stub implementation
 * Phase 2: Implement directory validation and path resolution
 * Phase 3: Integrate with VFS current working directory tracking
 * Phase 4: Performance optimization with directory cache
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);

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
 * Phase 1: Validate fd and return success
 * Phase 2: Implement directory validation
 * Phase 3: Integrate with VFS and update task->cwd
 */
long sys_fchdir(int fd) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Validate file descriptor */
    if (fd < 0) {
        fut_printf("[FCHDIR] fchdir(fd=%d [invalid], pid=%d) -> EBADF\n",
                   fd, task->pid);
        return -EBADF;
    }

    /* Categorize file descriptor for logging */
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

    /* Phase 1: Accept fd and return success */
    fut_printf("[FCHDIR] fchdir(fd=%d [%s], pid=%d) -> 0 "
               "(Phase 1 stub - no actual directory change yet)\n",
               fd, fd_category, task->pid);

    return 0;
}
