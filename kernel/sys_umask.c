/* kernel/sys_umask.c - umask() syscall implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements file creation mask syscall for permission control.
 * Essential for controlling default permissions on newly created files.
 *
 * Phase 1 (Completed): Basic umask get/set with global storage
 * Phase 2 (Current): Enhanced validation, mask categorization, and detailed logging
 * Phase 3: Per-task umask (move to fut_task structure)
 * Phase 4: umask inheritance and fine-grained control
 */

#include <kernel/errno.h>
#include <kernel/fut_task.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);

/* Global umask value for current implementation.
 * TODO Phase 3: When per-task state is added to fut_task structure, move this
 * to a per-task umask field for proper multi-process isolation.
 */
static uint32_t global_umask = 0022;  /* Default: owner read/write, group/others read only */

/**
 * umask() syscall - Set file creation mask.
 *
 * Sets the file creation mask (umask) for the calling process. The umask
 * is used to turn off permission bits when creating new files and directories.
 * This syscall always succeeds and returns the previous umask value.
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
 * Note: Current implementation uses a global umask value.
 *       For proper per-process isolation, this should be moved to
 *       per-task state in fut_task_t when task structure is extended.
 *
 * TODO Phase 3: Move to per-task umask:
 *   - Add umask field to fut_task_t structure
 *   - Initialize from parent task on fork
 *   - Use task-local umask instead of global
 *
 * Phase 1 (Completed): Basic umask get/set with global storage
 * Phase 2 (Current): Enhanced validation, mask categorization, detailed logging
 * Phase 3: Per-task umask (move to fut_task structure)
 * Phase 4: umask inheritance and fine-grained control
 */
long sys_umask(uint32_t mask) {
    /* Phase 2: Only use the permission bits (0777 octal = 511 decimal) */
    uint32_t new_mask = mask & 0777;

    /* Phase 2: Get previous mask value */
    uint32_t old_mask = global_umask;

    /* Phase 2: Categorize old mask */
    const char *old_mask_desc;
    if (old_mask == 0022) {
        old_mask_desc = "0022 (typical default, owner rw, others r)";
    } else if (old_mask == 0002) {
        old_mask_desc = "0002 (group writable)";
    } else if (old_mask == 0077) {
        old_mask_desc = "0077 (private, owner only)";
    } else if (old_mask == 0000) {
        old_mask_desc = "0000 (permissive, no restrictions)";
    } else if (old_mask == 0027) {
        old_mask_desc = "0027 (group readable, others none)";
    } else {
        old_mask_desc = "custom";
    }

    /* Phase 2: Categorize new mask */
    const char *new_mask_desc;
    if (new_mask == 0022) {
        new_mask_desc = "0022 (typical default, owner rw, others r)";
    } else if (new_mask == 0002) {
        new_mask_desc = "0002 (group writable)";
    } else if (new_mask == 0077) {
        new_mask_desc = "0077 (private, owner only)";
    } else if (new_mask == 0000) {
        new_mask_desc = "0000 (permissive, no restrictions)";
    } else if (new_mask == 0027) {
        new_mask_desc = "0027 (group readable, others none)";
    } else {
        new_mask_desc = "custom";
    }

    /* Phase 2: Determine operation type */
    const char *operation_type;
    if (new_mask == 0 && old_mask != 0) {
        operation_type = "query (set to 0 to read)";
    } else if (new_mask == old_mask) {
        operation_type = "no change (same value)";
    } else if (new_mask > old_mask) {
        operation_type = "more restrictive";
    } else {
        operation_type = "less restrictive";
    }

    /* Phase 2: Build octal string for old mask */
    char old_octal[8];
    char *p = old_octal;
    *p++ = '0';
    if (old_mask >= 0100) {
        *p++ = '0' + ((old_mask >> 6) & 7);
    }
    *p++ = '0' + ((old_mask >> 3) & 7);
    *p++ = '0' + (old_mask & 7);
    *p = '\0';

    /* Phase 2: Build octal string for new mask */
    char new_octal[8];
    p = new_octal;
    *p++ = '0';
    if (new_mask >= 0100) {
        *p++ = '0' + ((new_mask >> 6) & 7);
    }
    *p++ = '0' + ((new_mask >> 3) & 7);
    *p++ = '0' + (new_mask & 7);
    *p = '\0';

    /* Set new mask */
    global_umask = new_mask;

    /* Phase 2: Detailed success logging */
    fut_printf("[UMASK] umask(mask=%s [%s]) -> %s [%s] (op=%s, Phase 2)\n",
               new_octal, new_mask_desc, old_octal, old_mask_desc, operation_type);

    /* Return previous mask */
    return (long)old_mask;
}

/**
 * Get current umask value (for use by file creation syscalls).
 *
 * This function is called by mkdir, open with O_CREAT, etc. to apply
 * the umask to newly created files and directories.
 *
 * @return Current umask value
 *
 * TODO Phase 3: When moving to per-task umask, this should accept
 * fut_task_t* parameter and return task->umask instead of global_umask.
 */
uint32_t fut_get_umask(void) {
    return global_umask;
}
