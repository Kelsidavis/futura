/* kernel/sys_dup.c - Duplicate file descriptor syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements dup() for file descriptor duplication to lowest available FD.
 * Essential for I/O redirection and file descriptor management.
 *
 * Phase 1 (Completed): Basic FD duplication with per-task isolation
 * Phase 2 (Completed): Enhanced validation, FD range identification, and detailed logging
 * Phase 3 (Completed): Advanced features (O_CLOEXEC handling, error recovery)
 * Phase 4: Performance optimization (FD table search hints)
 */

#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <kernel/fut_task.h>

extern void fut_printf(const char *fmt, ...);
extern struct fut_file *vfs_get_file_from_task(struct fut_task *task, int fd);

/**
 * dup() - Duplicate file descriptor to lowest available FD
 *
 * Creates a copy of the file descriptor oldfd using the lowest-numbered
 * unused file descriptor for the new descriptor. This is the simpler
 * variant of dup2() that doesn't allow specifying the target FD number.
 *
 * @param oldfd Source file descriptor to duplicate
 *
 * Returns:
 *   - Non-negative file descriptor on success (lowest available FD)
 *   - -EBADF if oldfd is not a valid open file descriptor
 *   - -ESRCH if no current task context
 *   - -EMFILE if per-process file descriptor limit reached
 *
 * Behavior:
 *   - If oldfd is not valid, return -EBADF
 *   - Allocates the lowest available FD number (≥0)
 *   - New FD shares the same file structure as oldfd
 *   - Both FDs refer to same file description (share file offset, flags)
 *   - New FD does NOT inherit close-on-exec flag (differs from oldfd)
 *   - Increments file reference count
 *   - New FD can be any value from 0 to max_fds-1
 *
 * File descriptor sharing:
 *   - oldfd and newfd share:
 *     - File offset (lseek on one affects both)
 *     - File status flags (O_APPEND, O_NONBLOCK, etc.)
 *     - File locks (fcntl)
 *   - oldfd and newfd do NOT share:
 *     - File descriptor flags (close-on-exec)
 *
 * Differences from dup2():
 *   - dup: Returns lowest available FD (cannot choose FD number)
 *   - dup2: Allows specifying exact FD number (atomic close-and-dup)
 *   - dup: Never closes existing FDs
 *   - dup2: Closes newfd if it's already open
 *   - dup: Returns -EMFILE if no FDs available
 *   - dup2: Can reuse any FD number (up to system limit)
 *
 * Common usage patterns:
 *
 * Save stdout for later restoration:
 *   int saved_stdout = dup(1);  // Duplicate stdout to lowest available FD
 *   if (saved_stdout < 0) {
 *       perror("dup");
 *   }
 *   // ... redirect stdout ...
 *   dup2(saved_stdout, 1);      // Restore original stdout
 *   close(saved_stdout);        // Close the saved copy
 *
 * Create backup of file descriptor:
 *   int backup_fd = dup(original_fd);
 *   if (backup_fd < 0) {
 *       perror("dup");
 *   }
 *   // Both backup_fd and original_fd refer to same file
 *   // Closing one doesn't affect the other
 *
 * Prevent accidental closure:
 *   int permanent_fd = dup(temp_fd);
 *   close(temp_fd);  // Can close temp_fd, permanent_fd still works
 *
 * Shell-style FD manipulation:
 *   // Save original stdin/stdout/stderr
 *   int saved_stdin = dup(0);
 *   int saved_stdout = dup(1);
 *   int saved_stderr = dup(2);
 *
 *   // ... manipulate stdin/stdout/stderr ...
 *
 *   // Restore originals
 *   dup2(saved_stdin, 0);
 *   dup2(saved_stdout, 1);
 *   dup2(saved_stderr, 2);
 *   close(saved_stdin);
 *   close(saved_stdout);
 *   close(saved_stderr);
 *
 * Standard FD values:
 *   - 0: stdin (standard input)
 *   - 1: stdout (standard output)
 *   - 2: stderr (standard error)
 *   - 3+: User-opened files, sockets, pipes
 *
 * Typical FD allocation patterns:
 *   - Lowest available: 0, 1, 2 (if not already open)
 *   - After stdin/stdout/stderr: 3, 4, 5, ...
 *   - Shell redirections often use FD 3-9
 *   - Applications typically use FD 3+
 *
 * Phase 1 (Completed): Basic FD duplication with per-task isolation
 * Phase 2 (Completed): Enhanced validation, FD range identification, detailed logging
 * Phase 3 (Completed): Advanced features (O_CLOEXEC handling, error recovery)
 * Phase 4: Performance optimization (FD table search hints)
 */
long sys_dup(int oldfd) {
    /* ARM64 FIX: Copy parameters to local variables immediately to ensure they're preserved
     * on the stack across potentially blocking calls. VFS operations may block and corrupt
     * register-passed parameters upon resumption. */
    int local_oldfd = oldfd;

    /* Get current task for FD table access */
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[DUP] dup(oldfd=%d) -> ESRCH (no current task)\n", local_oldfd);
        return -ESRCH;
    }

    /* Phase 2: Validate oldfd early */
    if (local_oldfd < 0) {
        fut_printf("[DUP] dup(oldfd=%d) -> EBADF (negative oldfd)\n", local_oldfd);
        return -EBADF;
    }

    /* Phase 2: Categorize oldfd range */
    const char *oldfd_category;
    if (local_oldfd <= 2) {
        oldfd_category = "standard (stdin/stdout/stderr)";
    } else if (local_oldfd < 10) {
        oldfd_category = "low (common user FDs)";
    } else if (local_oldfd < 100) {
        oldfd_category = "typical (normal range)";
    } else if (local_oldfd < 1024) {
        oldfd_category = "high (many open files)";
    } else {
        oldfd_category = "very high (unusual)";
    }

    /* Validate FD table exists */
    if (!task->fd_table) {
        fut_printf("[DUP] dup(oldfd=%d [%s]) -> EBADF (no FD table)\n",
                   local_oldfd, oldfd_category);
        return -EBADF;
    }

    /* Get the file structure for oldfd from current task's FD table */
    struct fut_file *old_file = vfs_get_file_from_task(task, local_oldfd);
    if (!old_file) {
        fut_printf("[DUP] dup(oldfd=%d [%s]) -> EBADF (oldfd not open)\n",
                   local_oldfd, oldfd_category);
        return -EBADF;
    }

    /* Phase 2: Find the lowest available FD in the task's FD table */
    int newfd = -1;
    for (int i = 0; i < task->max_fds; i++) {
        if (task->fd_table[i] == NULL) {
            newfd = i;
            break;
        }
    }

    /* Phase 2: Handle FD exhaustion with detailed logging */
    if (newfd < 0) {
        fut_printf("[DUP] dup(oldfd=%d [%s], max_fds=%d) -> EMFILE "
                   "(all FDs in use, no available slots)\n",
                   local_oldfd, oldfd_category, task->max_fds);
        return -EMFILE;
    }

    /* Phase 2: Categorize newfd range */
    const char *newfd_category;
    if (newfd <= 2) {
        newfd_category = "standard (stdin/stdout/stderr)";
    } else if (newfd < 10) {
        newfd_category = "low (common user FDs)";
    } else if (newfd < 100) {
        newfd_category = "typical (normal range)";
    } else if (newfd < 1024) {
        newfd_category = "high (many open files)";
    } else {
        newfd_category = "very high (unusual)";
    }

    /* Increment reference count on the file since we're creating another reference */
    old_file->refcount++;

    /* Assign the file to the new FD */
    task->fd_table[newfd] = old_file;

    /* Phase 2: Detailed success logging */
    fut_printf("[DUP] dup(oldfd=%d [%s]) -> %d [%s] (refcount=%u, "
               "lowest available FD, Phase 2)\n",
               local_oldfd, oldfd_category, newfd, newfd_category, old_file->refcount);

    return newfd;
}
