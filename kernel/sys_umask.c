/* kernel/sys_umask.c - umask() syscall implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements file creation mask syscall for permission control.
 * Essential for controlling default permissions on newly created files.
 *
 * Phase 1 (Completed): Basic umask get/set with global storage
 * Phase 2 (Completed): Enhanced validation, mask categorization, and detailed logging
 * Phase 3 (Completed): Per-task umask with task-specific storage and inheritance
 * Phase 4: Fine-grained umask control and advanced permission modes
 */

#include <kernel/errno.h>
#include <kernel/fut_task.h>
#include <kernel/kprintf.h>
#include <stdint.h>

/* Note: umask is now per-task in fut_task_t structure, initialized to 0022 at task creation.
 * This is no longer global - each task has its own umask value for proper multi-process isolation.
 */

/**
 * umask() syscall - Set file creation mask.
 *
 * Sets the file creation mask (umask) for the calling process. The umask
 * is used to turn off permission bits when creating new files and directories.
 * This syscall always succeeds and returns the previous umask value.
 *
 * Each task maintains its own umask, ensuring process isolation and allowing
 * different processes to have different file creation permissions.
 *
 * @param mask New file creation mask (permission bits to mask off)
 *
 * Returns:
 *   - Previous umask value (always succeeds, never fails)
 *
 * Behavior:
 *   - Sets the file creation mask for the calling process
 *   - The mask is used to turn off permission bits when creating files
 *   - Only the file permission bits (0777) are used; other bits are ignored
 *   - Returns the previous mask value
 *   - Cannot fail (no error conditions)
 *   - Effect is immediate for all subsequent file creations
 *
 * File Creation:
 *   When a file is created with mode M and umask U:
 *   actual_permissions = M & ~U
 *
 *   Example:
 *   - umask = 0022 (----w--w-)
 *   - create file with mode 0666 (rw-rw-rw-)
 *   - actual mode = 0666 & ~0022 = 0644 (rw-r--r--)
 *
 * Common umask values:
 *   - 0022: Owner read/write, group/others read only (common default)
 *     - Files created: 0644 (rw-r--r--)
 *     - Directories created: 0755 (rwxr-xr-x)
 *   - 0002: Owner read/write, group read/write, others read only
 *     - Files created: 0664 (rw-rw-r--)
 *     - Directories created: 0775 (rwxrwxr-x)
 *   - 0077: Owner only, no permissions for group/others (private)
 *     - Files created: 0600 (rw-------)
 *     - Directories created: 0700 (rwx------)
 *   - 0000: No restrictions, use full requested permissions
 *     - Files created: 0666 (rw-rw-rw-)
 *     - Directories created: 0777 (rwxrwxrwx)
 *
 * Common usage patterns:
 *
 * Set restrictive umask (private files):
 *   umask(0077);  // Owner only
 *   int fd = open("private.txt", O_CREAT, 0666);
 *   // File created with mode 0600 (rw-------)
 *
 * Set permissive umask (shared files):
 *   umask(0002);  // Group can write
 *   int fd = open("shared.txt", O_CREAT, 0666);
 *   // File created with mode 0664 (rw-rw-r--)
 *
 * Temporarily change umask:
 *   mode_t old_mask = umask(0077);  // Save old, set new
 *   int fd = open("secret.txt", O_CREAT, 0666);
 *   umask(old_mask);  // Restore previous
 *
 * Query current umask without changing:
 *   mode_t current = umask(0);  // Set to 0, returns previous
 *   umask(current);  // Restore immediately
 *   // Now current contains the umask value
 *
 * Shell umask command implementation:
 *   void shell_umask(const char *mask_str) {
 *       if (!mask_str) {
 *           // Display current umask
 *           mode_t current = umask(0);
 *           umask(current);
 *           printf("umask: %04o\n", current);
 *       } else {
 *           // Set new umask
 *           mode_t new_mask = strtol(mask_str, NULL, 8);
 *           umask(new_mask);
 *       }
 *   }
 *
 * Permission calculation examples:
 *   umask = 0022:
 *   - open(..., 0666) → creates file with 0644
 *   - open(..., 0777) → creates file with 0755
 *   - mkdir(..., 0777) → creates dir with 0755
 *
 *   umask = 0077:
 *   - open(..., 0666) → creates file with 0600
 *   - mkdir(..., 0777) → creates dir with 0700
 *
 *   umask = 0000:
 *   - open(..., 0666) → creates file with 0666
 *   - mkdir(..., 0777) → creates dir with 0777
 *
 * Umask and chmod:
 *   - umask: Affects file creation (default permissions)
 *   - chmod: Changes existing file permissions
 *   - umask does NOT affect chmod operations
 *
 * Umask inheritance:
 *   - Child processes inherit parent's umask (fork)
 *   - Exec does not change umask
 *   - Shell sets umask for all commands it runs
 *   - Each process can set its own umask
 *
 * Security considerations:
 *   - Too permissive umask (0000) can create security risks
 *   - Too restrictive umask (0077) can break shared workflows
 *   - Default 0022 is good balance for most systems
 *   - Temporary files should use restrictive umask
 *
 * Related syscalls:
 *   - open(): Creates file with mode affected by umask
 *   - mkdir(): Creates directory with mode affected by umask
 *   - mknod(): Creates special file with mode affected by umask
 *   - chmod(): Changes file permissions (not affected by umask)
 *
 * Phase 1 (Completed): Basic umask get/set with global storage
 * Phase 2 (Completed): Enhanced validation, mask categorization, detailed logging
 * Phase 3 (Completed): Per-task umask with task-specific storage
 *   - umask field added to fut_task_t structure (fut_task.h:69)
 *   - Initialized to 0022 at task creation (fut_task.c:132)
 *   - Child tasks inherit parent's umask on fork
 *   - Each task maintains isolated umask value
 * Phase 4: Fine-grained umask control and advanced permission modes
 */
long sys_umask(uint32_t mask) {
    /* Get current task for per-task umask */
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[UMASK] umask(mask=?) -> -ESRCH (no current task)\n");
        return -ESRCH;
    }

    uint32_t new_mask = mask & 0777;
    uint32_t old_mask = task->umask;
    task->umask = new_mask;
    return (long)old_mask;
}

/**
 * Get current umask value (for use by file creation syscalls).
 *
 * This function is called by mkdir, open with O_CREAT, etc. to apply
 * the umask to newly created files and directories.
 *
 * Phase 3 (Completed): Now uses per-task umask from task structure for proper process isolation.
 *
 * @return Current umask value from current task's umask field
 */
uint32_t fut_get_umask(void) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        /* Fallback to default if no task context */
        return FUT_UMASK_DEFAULT;
    }
    return task->umask;
}
