/* kernel/sys_umask.c - umask() syscall implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements file creation mask syscall for permission control.
 */

#include <kernel/errno.h>
#include <kernel/fut_task.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);

/* Global umask value for current implementation.
 * TODO: When per-task state is added to fut_task structure, move this
 * to a per-task umask field for proper multi-process isolation.
 */
static uint32_t global_umask = 0022;  /* Default: owner read/write, group/others read only */

/**
 * umask() syscall - Set file creation mask.
 *
 * @param mask New file creation mask (permission bits to mask off)
 *
 * Returns:
 *   - Previous umask value (always succeeds)
 *
 * Behavior:
 *   - Sets the file creation mask for the calling process
 *   - The mask is used to turn off permission bits when creating files
 *   - Only the file permission bits (0777) are used; other bits are ignored
 *   - Returns the previous mask value
 *   - Cannot fail (no error conditions)
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
 *   - 0002: Owner read/write, group read/write, others read only
 *   - 0077: Owner only, no permissions for group/others
 *
 * Note: Current implementation uses a global umask value.
 *       For proper per-process isolation, this should be moved to
 *       per-task state in fut_task_t when task structure is extended.
 */
long sys_umask(uint32_t mask) {
    /* Only use the permission bits (0777 octal = 511 decimal) */
    uint32_t new_mask = mask & 0777;

    /* Get previous mask value */
    uint32_t old_mask = global_umask;

    /* Set new mask */
    global_umask = new_mask;

    fut_printf("[UMASK] Changed from %03o to %03o\n", old_mask, new_mask);

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
 */
uint32_t fut_get_umask(void) {
    return global_umask;
}
