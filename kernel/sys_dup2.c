/* kernel/sys_dup2.c - Duplicate file descriptor to specific number syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements dup2() for file descriptor duplication to specific FD number.
 * Essential for I/O redirection in shells and process management.
 *
 * Phase 1 (Completed): Basic FD duplication with per-task isolation
 * Phase 2 (Current): Enhanced validation, operation categorization, and detailed logging
 * Phase 3: Atomic close-and-dup with proper error handling
 * Phase 4: Advanced features (O_CLOEXEC handling, dup3 support)
 */

#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <kernel/fut_task.h>

extern void fut_printf(const char *fmt, ...);

/**
 * dup2() - Duplicate file descriptor to specific number
 *
 * Creates a copy of the file descriptor oldfd using the descriptor number
 * specified by newfd. This is the primary syscall for I/O redirection in
 * shells and process management.
 *
 * @param oldfd Source file descriptor to duplicate
 * @param newfd Target file descriptor number
 *
 * Returns:
 *   - newfd on success
 *   - -EBADF if oldfd is not a valid open file descriptor
 *   - -EINVAL if newfd is outside the allowed range
 *   - -ESRCH if no current task context
 *   - -ENOMEM if insufficient memory for FD table expansion
 *
 * Behavior:
 *   - If oldfd is not valid, return -EBADF
 *   - If oldfd == newfd and oldfd is valid, return newfd (no-op)
 *   - If newfd is open, close it first (atomic close-and-dup)
 *   - Duplicate oldfd to newfd
 *   - Both FDs refer to same file description (share file offset, flags)
 *   - newfd does NOT inherit close-on-exec flag (differs from oldfd)
 *   - Increments file reference count
 *
 * File descriptor sharing:
 *   - oldfd and newfd share:
 *     - File offset (lseek on one affects both)
 *     - File status flags (O_APPEND, O_NONBLOCK, etc.)
 *     - File locks (fcntl)
 *   - oldfd and newfd do NOT share:
 *     - File descriptor flags (close-on-exec)
 *
 * Common usage patterns:
 *
 * Redirect stdout to file:
 *   int fd = open("/tmp/output.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);
 *   dup2(fd, 1);  // Make fd 1 (stdout) refer to output.log
 *   close(fd);    // Original fd no longer needed
 *   printf("This goes to output.log\n");
 *
 * Redirect stderr to stdout:
 *   dup2(1, 2);  // Make fd 2 (stderr) refer to same file as fd 1 (stdout)
 *
 * Save and restore stdout:
 *   int saved_stdout = dup(1);  // Save current stdout
 *   dup2(fd, 1);                // Redirect stdout to fd
 *   // ... do output ...
 *   dup2(saved_stdout, 1);      // Restore original stdout
 *   close(saved_stdout);
 *
 * Shell pipe implementation:
 *   int pipefd[2];
 *   pipe(pipefd);
 *   if (fork() == 0) {
 *       // Child: redirect stdout to pipe write end
 *       dup2(pipefd[1], 1);
 *       close(pipefd[0]);
 *       close(pipefd[1]);
 *       exec(...);
 *   }
 *
 * No-op case (oldfd == newfd):
 *   dup2(3, 3);  // Returns 3, validates fd 3 is open, no actual duplication
 *
 * Phase 1 (Completed): Basic FD duplication with per-task isolation
 * Phase 2 (Current): Enhanced validation, operation categorization, detailed logging
 * Phase 3: Atomic close-and-dup with proper error handling
 * Phase 4: O_CLOEXEC handling, dup3 support with flags
 */
long sys_dup2(int oldfd, int newfd) {
    /* Get current task for FD table access */
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[DUP2] dup2(oldfd=%d, newfd=%d) -> ESRCH (no current task)\n",
                   oldfd, newfd);
        return -ESRCH;
    }

    /* Phase 2: Validate oldfd early */
    if (oldfd < 0) {
        fut_printf("[DUP2] dup2(oldfd=%d, newfd=%d) -> EBADF (negative oldfd)\n",
                   oldfd, newfd);
        return -EBADF;
    }

    /* Phase 2: Validate newfd early */
    if (newfd < 0) {
        fut_printf("[DUP2] dup2(oldfd=%d, newfd=%d) -> EBADF (negative newfd)\n",
                   oldfd, newfd);
        return -EBADF;
    }

    /* Phase 2: Categorize FD range */
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

    /* Get the file structure for oldfd from current task's FD table */
    struct fut_file *old_file = vfs_get_file_from_task(task, oldfd);
    if (!old_file) {
        fut_printf("[DUP2] dup2(oldfd=%d, newfd=%d [%s]) -> EBADF (oldfd not open)\n",
                   oldfd, newfd, newfd_category);
        return -EBADF;
    }

    /* Phase 2: Categorize operation type */
    const char *operation_type;
    const char *operation_desc;

    if (oldfd == newfd) {
        operation_type = "no-op (same FD)";
        operation_desc = "validates oldfd is open, no duplication";

        fut_printf("[DUP2] dup2(oldfd=%d, newfd=%d [%s], op=%s) -> %d (%s, Phase 2)\n",
                   oldfd, newfd, newfd_category, operation_type, newfd, operation_desc);
        return newfd;
    }

    /* Check if newfd is currently open (will be closed) */
    struct fut_file *existing_file = vfs_get_file_from_task(task, newfd);
    if (existing_file) {
        operation_type = "close-and-dup";
        operation_desc = "closes existing newfd, then duplicates";
    } else {
        operation_type = "simple dup";
        operation_desc = "newfd unused, direct duplication";
    }

    /* Increment reference count on the file since we're creating another reference */
    if (old_file) {
        old_file->refcount++;
    }

    /* Allocate newfd pointing to the same file in task's FD table */
    /* alloc_specific_fd_for_task handles closing existing FD if needed */
    int ret = vfs_alloc_specific_fd_for_task(task, newfd, old_file);
    if (ret < 0) {
        /* Failed to allocate, decrement ref count */
        if (old_file && old_file->refcount > 0) {
            old_file->refcount--;
        }

        /* Phase 2: Detailed error logging */
        const char *error_desc;
        switch (ret) {
            case -EBADF:
                error_desc = "invalid file descriptor";
                break;
            case -EINVAL:
                error_desc = "newfd out of range";
                break;
            case -ENOMEM:
                error_desc = "insufficient memory for FD table";
                break;
            default:
                error_desc = "unknown error";
                break;
        }

        fut_printf("[DUP2] dup2(oldfd=%d, newfd=%d [%s], op=%s) -> %d (%s)\n",
                   oldfd, newfd, newfd_category, operation_type, ret, error_desc);
        return ret;
    }

    /* Phase 2: Detailed success logging */
    fut_printf("[DUP2] dup2(oldfd=%d, newfd=%d [%s], op=%s, refcount=%u) -> %d (%s, Phase 2)\n",
               oldfd, newfd, newfd_category, operation_type, old_file->refcount, newfd,
               operation_desc);

    return newfd;
}
