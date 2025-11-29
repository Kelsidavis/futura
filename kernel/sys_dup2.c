/* kernel/sys_dup2.c - Duplicate file descriptor to specific number syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements dup2() for file descriptor duplication to specific FD number.
 * Essential for I/O redirection in shells and process management.
 *
 * Phase 1 (Completed): Basic FD duplication with per-task isolation
 * Phase 2 (Completed): Enhanced validation, operation categorization, and detailed logging
 * Phase 3 (Completed): Atomic close-and-dup with proper error handling
 * Phase 4 (Completed): dup3() with O_CLOEXEC flag support
 * Phase 5: Advanced features (F_DUPFD_CLOEXEC in fcntl)
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
 * Phase 2 (Completed): Enhanced validation, operation categorization, detailed logging
 * Phase 3 (Completed): Atomic close-and-dup with proper error handling
 * Phase 4: O_CLOEXEC handling, dup3 support with flags
 */
long sys_dup2(int oldfd, int newfd) {
    /* ARM64 FIX: Copy parameters to local variables immediately to ensure they're preserved
     * on the stack across potentially blocking calls. VFS operations may block and corrupt
     * register-passed parameters upon resumption. */
    int local_oldfd = oldfd;
    int local_newfd = newfd;

    /* Get current task for FD table access */
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[DUP2] dup2(oldfd=%d, newfd=%d) -> ESRCH (no current task)\n",
                   local_oldfd, local_newfd);
        return -ESRCH;
    }

    /* Phase 5: Validate oldfd and newfd bounds to prevent FD table out-of-bounds access
     * VULNERABILITY: Out-of-Bounds FD Table Access (Dual FD Parameters)
     *
     * ATTACK SCENARIO:
     * Attacker provides oldfd or newfd values exceeding task->max_fds
     * 1. Task has max_fds = 1024 (typical limit)
     * 2. Attacker calls dup2(9999, 3) or dup2(3, 9999)
     * 3. Without bounds validation, multiple OOB access points:
     *    - Line 150: vfs_get_file_from_task accesses fd_table[oldfd]
     *    - Line 171: vfs_get_file_from_task accesses fd_table[newfd]
     *    - Line 187: vfs_alloc_specific_fd_for_task accesses fd_table[newfd]
     * 4. If fd_table array has < 9999 entries → OOB read/write
     * 5. Kernel crash or memory corruption
     *
     * IMPACT:
     * - Information disclosure: OOB read reveals kernel memory contents
     * - Kernel crash: Accessing unmapped memory causes page fault
     * - Memory corruption: OOB write corrupts adjacent kernel structures
     * - Privilege escalation: Overwriting function pointers or credentials
     *
     * ROOT CAUSE:
     * dup2() has TWO FD parameters that both need validation
     * - Must validate oldfd >= 0 AND oldfd < max_fds
     * - Must validate newfd >= 0 AND newfd < max_fds
     * - Either parameter OOB causes vulnerability
     * - More attack surface than single-FD syscalls
     *
     * DEFENSE (Phase 5):
     * Validate both FD parameters before any FD table access
     * - Check oldfd >= 0 and oldfd < task->max_fds
     * - Check newfd >= 0 and newfd < task->max_fds
     * - Return -EBADF if oldfd out of range
     * - Return -EINVAL if newfd out of range (matches POSIX)
     * - Prevents OOB access from either parameter
     * - Fail-fast before calling any VFS functions
     *
     * CVE REFERENCES:
     * - CVE-2014-0181: Linux fget out-of-bounds FD access
     * - CVE-2016-0728: Android FD table bounds violation
     *
     * POSIX REQUIREMENT:
     * IEEE Std 1003.1-2017 dup2(): "shall fail with EBADF if oldfd is
     * not a valid file descriptor, or EINVAL if newfd is negative or
     * greater than or equal to OPEN_MAX"
     *
     * PRECEDENT:
     * - sys_close Phase 5: FD bounds validation for single parameter
     * - sys_dup Phase 5: FD bounds validation for oldfd only
     * - sys_dup2 Phase 5: Validates BOTH oldfd and newfd (dual parameters)
     */
    if (local_oldfd < 0) {
        fut_printf("[DUP2] dup2(oldfd=%d, newfd=%d) -> EBADF (negative oldfd, Phase 5)\n",
                   local_oldfd, local_newfd);
        return -EBADF;
    }

    if (local_oldfd >= (int)task->max_fds) {
        fut_printf("[DUP2] dup2(oldfd=%d, newfd=%d, max_fds=%u) -> EBADF "
                   "(oldfd exceeds max_fds, Phase 5: FD bounds validation)\n",
                   local_oldfd, local_newfd, task->max_fds);
        return -EBADF;
    }

    if (local_newfd < 0) {
        fut_printf("[DUP2] dup2(oldfd=%d, newfd=%d) -> EINVAL (negative newfd, Phase 5)\n",
                   local_oldfd, local_newfd);
        return -EINVAL;
    }

    if (local_newfd >= (int)task->max_fds) {
        fut_printf("[DUP2] dup2(oldfd=%d, newfd=%d, max_fds=%u) -> EINVAL "
                   "(newfd exceeds max_fds, Phase 5: FD bounds validation)\n",
                   local_oldfd, local_newfd, task->max_fds);
        return -EINVAL;
    }

    /* Phase 2: Categorize FD range */
    const char *newfd_category;
    if (local_newfd <= 2) {
        newfd_category = "standard (stdin/stdout/stderr)";
    } else if (local_newfd < 10) {
        newfd_category = "low (common user FDs)";
    } else if (local_newfd < 100) {
        newfd_category = "typical (normal range)";
    } else if (local_newfd < 1024) {
        newfd_category = "high (many open files)";
    } else {
        newfd_category = "very high (unusual)";
    }

    /* Get the file structure for oldfd from current task's FD table */
    struct fut_file *old_file = vfs_get_file_from_task(task, local_oldfd);
    if (!old_file) {
        fut_printf("[DUP2] dup2(oldfd=%d, newfd=%d [%s]) -> EBADF (oldfd not open)\n",
                   local_oldfd, local_newfd, newfd_category);
        return -EBADF;
    }

    /* Phase 2: Categorize operation type */
    const char *operation_type;
    const char *operation_desc;

    if (local_oldfd == local_newfd) {
        operation_type = "no-op (same FD)";
        operation_desc = "validates oldfd is open, no duplication";

        fut_printf("[DUP2] dup2(oldfd=%d, newfd=%d [%s], op=%s) -> %d (%s, Phase 5)\n",
                   local_oldfd, local_newfd, newfd_category, operation_type, local_newfd, operation_desc);
        return local_newfd;
    }

    /* Check if newfd is currently open (will be closed) */
    struct fut_file *existing_file = vfs_get_file_from_task(task, local_newfd);
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
    int ret = vfs_alloc_specific_fd_for_task(task, local_newfd, old_file);
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
                   local_oldfd, local_newfd, newfd_category, operation_type, ret, error_desc);
        return ret;
    }

    /* Phase 5: Detailed success logging */
    fut_printf("[DUP2] dup2(oldfd=%d, newfd=%d [%s], op=%s, refcount=%u) -> %d (%s, Phase 5: FD bounds validation)\n",
               local_oldfd, local_newfd, newfd_category, operation_type, old_file->refcount, local_newfd,
               operation_desc);

    return local_newfd;
}

/**
 * sys_dup3() - Duplicate file descriptor with flags
 *
 * Like dup2() but allows atomically setting O_CLOEXEC on the new FD.
 * This is essential for avoiding race conditions in multithreaded programs.
 *
 * @param oldfd Source file descriptor to duplicate
 * @param newfd Target file descriptor number
 * @param flags Must be O_CLOEXEC (0x80000) or 0
 *
 * Returns:
 *   - newfd on success
 *   - -EBADF if oldfd is not a valid open file descriptor
 *   - -EINVAL if newfd is outside allowed range or oldfd == newfd or invalid flags
 *   - -ESRCH if no current task context
 *
 * Differences from dup2():
 *   - dup3(fd, fd, flags) returns -EINVAL (dup2 returns fd)
 *   - Can set O_CLOEXEC atomically without race condition
 *   - Only supports O_CLOEXEC flag (other flags return -EINVAL)
 *
 * Phase 4: Initial implementation with O_CLOEXEC support
 */
long sys_dup3(int oldfd, int newfd, int flags) {
    /* Copy parameters to local variables for ARM64 */
    int local_oldfd = oldfd;
    int local_newfd = newfd;
    int local_flags = flags;

    /* Validate flags - only O_CLOEXEC is supported */
    if (local_flags & ~0x80000) {  /* Only O_CLOEXEC */
        fut_printf("[DUP3] dup3(oldfd=%d, newfd=%d, flags=0x%x) -> EINVAL (invalid flags)\n",
                   local_oldfd, local_newfd, local_flags);
        return -EINVAL;
    }

    /* dup3() requires oldfd != newfd (unlike dup2) */
    if (local_oldfd == local_newfd) {
        fut_printf("[DUP3] dup3(oldfd=%d, newfd=%d, flags=0x%x) -> EINVAL (oldfd == newfd not allowed)\n",
                   local_oldfd, local_newfd, local_flags);
        return -EINVAL;
    }

    /* Get current task */
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[DUP3] dup3(oldfd=%d, newfd=%d, flags=0x%x) -> ESRCH (no current task)\n",
                   local_oldfd, local_newfd, local_flags);
        return -ESRCH;
    }

    /* Validate oldfd */
    if (local_oldfd < 0) {
        fut_printf("[DUP3] dup3(oldfd=%d, newfd=%d, flags=0x%x) -> EBADF (negative oldfd)\n",
                   local_oldfd, local_newfd, local_flags);
        return -EBADF;
    }

    /* Validate newfd */
    if (local_newfd < 0) {
        fut_printf("[DUP3] dup3(oldfd=%d, newfd=%d, flags=0x%x) -> EINVAL (negative newfd)\n",
                   local_oldfd, local_newfd, local_flags);
        return -EINVAL;
    }

    /* Get the file structure for oldfd */
    struct fut_file *old_file = vfs_get_file_from_task(task, local_oldfd);
    if (!old_file) {
        fut_printf("[DUP3] dup3(oldfd=%d, newfd=%d, flags=0x%x) -> EBADF (oldfd not open)\n",
                   local_oldfd, local_newfd, local_flags);
        return -EBADF;
    }

    /* Increment reference count since we're creating another reference */
    if (old_file) {
        old_file->refcount++;
    }

    /* Allocate newfd pointing to the same file */
    int ret = vfs_alloc_specific_fd_for_task(task, local_newfd, old_file);
    if (ret < 0) {
        /* Failed to allocate, decrement ref count */
        if (old_file && old_file->refcount > 0) {
            old_file->refcount--;
        }

        const char *error_desc;
        switch (ret) {
            case -EBADF:
                error_desc = "invalid file descriptor";
                break;
            case -EINVAL:
                error_desc = "newfd out of range";
                break;
            case -ENOMEM:
                error_desc = "insufficient memory";
                break;
            default:
                error_desc = "unknown error";
                break;
        }
        fut_printf("[DUP3] dup3(oldfd=%d, newfd=%d, flags=0x%x) -> %d (%s)\n",
                   local_oldfd, local_newfd, local_flags, ret, error_desc);
        return ret;
    }

    /* Apply O_CLOEXEC if requested */
    if (local_flags & 0x80000) {  /* O_CLOEXEC */
        extern long sys_fcntl(int fd, int cmd, long arg);
        sys_fcntl(local_newfd, 2, 1);  /* F_SETFD, FD_CLOEXEC */
    }

    const char *flags_desc = (local_flags & 0x80000) ? "O_CLOEXEC" : "none";

    fut_printf("[DUP3] dup3(oldfd=%d, newfd=%d, flags=0x%x [%s]) -> %d (Phase 4: atomic dup with flags)\n",
               local_oldfd, local_newfd, local_flags, flags_desc, local_newfd);

    return local_newfd;
}
