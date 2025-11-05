/* kernel/sys_acct.c - Process accounting syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements process accounting for tracking system resource usage.
 * Essential for system auditing, billing, and resource monitoring.
 *
 * Phase 1 (Current): Validation and stub implementation
 * Phase 2: Implement accounting record generation
 * Phase 3: Write accounting records to file
 * Phase 4: Performance optimization and filtering
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <stddef.h>

extern void fut_printf(const char *fmt, ...);

/**
 * acct() - Enable or disable process accounting
 *
 * Enables or disables the recording of process accounting information.
 * When enabled, the kernel writes an accounting record to the specified
 * file whenever a process terminates. This is used for system auditing,
 * billing, and resource usage analysis.
 *
 * @param filename  Path to accounting file, or NULL to disable accounting
 *
 * Returns:
 *   - 0 on success
 *   - -EFAULT if filename points to invalid memory
 *   - -EACCES if file is not a regular file
 *   - -EPERM if caller does not have CAP_SYS_PACCT capability
 *   - -EIO if I/O error occurs opening the file
 *   - -ENOSPC if insufficient disk space
 *   - -EROFS if filesystem is read-only
 *
 * Usage:
 *   // Enable accounting to /var/account/pacct
 *   if (acct("/var/account/pacct") < 0)
 *       perror("acct");
 *
 *   // Disable accounting
 *   acct(NULL);
 *
 * Accounting records contain:
 * - Process ID, parent PID, user/group IDs
 * - Command name (up to 16 characters)
 * - Exit status
 * - CPU time used (user and system)
 * - Memory usage
 * - I/O statistics
 * - Start and exit times
 *
 * Use cases:
 * - System administrators: Track resource usage for billing
 * - Security auditing: Monitor process execution patterns
 * - Performance analysis: Identify resource-intensive processes
 * - Capacity planning: Analyze historical usage trends
 *
 * Security considerations:
 * - Requires CAP_SYS_PACCT capability (root-equivalent)
 * - Accounting file should be protected (mode 0600)
 * - Records may contain sensitive information
 * - Can be used to detect unauthorized activity
 *
 * Phase 1: Validate parameters and accept enable/disable requests
 * Phase 2: Open accounting file and initialize record structure
 * Phase 3: Generate and write accounting records on process exit
 */
long sys_acct(const char *filename) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Check if disabling accounting */
    if (filename == NULL) {
        fut_printf("[ACCT] acct(NULL, pid=%d) -> 0 (disabling accounting - Phase 1 stub)\n",
                   task->pid);
        return 0;
    }

    /* Enabling accounting with specified file */
    fut_printf("[ACCT] acct(filename=%p, pid=%d) -> 0 "
               "(enabling accounting - Phase 1 stub, no actual recording yet)\n",
               filename, task->pid);

    return 0;
}
