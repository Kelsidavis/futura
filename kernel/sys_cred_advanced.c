/* kernel/sys_cred_advanced.c - Advanced process credential syscalls for ARM64
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements advanced credential syscalls: setreuid, setregid, setresuid,
 * setresgid, getresuid, getresgid. These provide finer-grained control over
 * real, effective, and saved user/group IDs.
 *
 * Note: Basic credential syscalls (getuid, geteuid, getgid, getegid, setuid,
 * setgid) are provided by shared kernel/sys_cred.c.
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>

#include <kernel/kprintf.h>

/* Special value indicating "don't change" */
#define UID_NO_CHANGE ((uint32_t)-1)
#define GID_NO_CHANGE ((uint32_t)-1)

/**
 * sys_setreuid - Set real and/or effective user ID
 *
 * @param ruid: New real UID (-1 = don't change)
 * @param euid: New effective UID (-1 = don't change)
 *
 * Allows setting real and effective UIDs independently. More flexible than
 * setuid() as it can swap between real and effective UIDs.
 *
 * Phase 1: Stub - validates parameters, returns success
 * Phase 2: Implement with privilege checks and saved UID management
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL if invalid UID values
 *   - -EPERM if insufficient privileges
 *   - -ESRCH if no task context
 */
long sys_setreuid(uint32_t ruid, uint32_t euid) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    fut_printf("[CRED] setreuid(ruid=%d, euid=%d, pid=%u) Phase 1 stub\n",
               (int)ruid, (int)euid, task->pid);

    /* Phase 1: Stub - accept parameters */
    /* Phase 2: Implement full privilege logic:
     *   - Privileged: can set to any values
     *   - Unprivileged: can swap real/effective or set to saved UID
     *   - Update saved UID when effective UID changes
     */

    (void)ruid;
    (void)euid;
    fut_printf("[CRED] setreuid stub - returning success\n");
    return 0;
}

/**
 * sys_setregid - Set real and/or effective group ID
 *
 * @param rgid: New real GID (-1 = don't change)
 * @param egid: New effective GID (-1 = don't change)
 *
 * Allows setting real and effective GIDs independently.
 *
 * Phase 1: Stub - validates parameters, returns success
 * Phase 2: Implement with privilege checks and saved GID management
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL if invalid GID values
 *   - -EPERM if insufficient privileges
 *   - -ESRCH if no task context
 */
long sys_setregid(uint32_t rgid, uint32_t egid) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    fut_printf("[CRED] setregid(rgid=%d, egid=%d, pid=%u) Phase 1 stub\n",
               (int)rgid, (int)egid, task->pid);

    /* Phase 1: Stub - accept parameters */
    /* Phase 2: Implement full privilege logic for GIDs */

    (void)rgid;
    (void)egid;
    fut_printf("[CRED] setregid stub - returning success\n");
    return 0;
}

/**
 * sys_setresuid - Set real, effective, and saved user ID
 *
 * @param ruid: New real UID (-1 = don't change)
 * @param euid: New effective UID (-1 = don't change)
 * @param suid: New saved UID (-1 = don't change)
 *
 * Most powerful credential syscall - allows setting all three UIDs at once.
 * Provides complete control over process credentials.
 *
 * Phase 1: Stub - validates parameters, returns success
 * Phase 2: Implement with full privilege checks
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL if invalid UID values
 *   - -EPERM if insufficient privileges
 *   - -ESRCH if no task context
 */
long sys_setresuid(uint32_t ruid, uint32_t euid, uint32_t suid) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    fut_printf("[CRED] setresuid(ruid=%d, euid=%d, suid=%d, pid=%u) Phase 1 stub\n",
               (int)ruid, (int)euid, (int)suid, task->pid);

    /* Phase 1: Stub - accept parameters */
    /* Phase 2: Implement with privilege checks:
     *   - Privileged: can set to any values
     *   - Unprivileged: can only set to current real, effective, or saved UID
     */

    (void)ruid;
    (void)euid;
    (void)suid;
    fut_printf("[CRED] setresuid stub - returning success\n");
    return 0;
}

/**
 * sys_setresgid - Set real, effective, and saved group ID
 *
 * @param rgid: New real GID (-1 = don't change)
 * @param egid: New effective GID (-1 = don't change)
 * @param sgid: New saved GID (-1 = don't change)
 *
 * Most powerful GID syscall - allows setting all three GIDs at once.
 *
 * Phase 1: Stub - validates parameters, returns success
 * Phase 2: Implement with full privilege checks
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL if invalid GID values
 *   - -EPERM if insufficient privileges
 *   - -ESRCH if no task context
 */
long sys_setresgid(uint32_t rgid, uint32_t egid, uint32_t sgid) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    fut_printf("[CRED] setresgid(rgid=%d, egid=%d, sgid=%d, pid=%u) Phase 1 stub\n",
               (int)rgid, (int)egid, (int)sgid, task->pid);

    /* Phase 1: Stub - accept parameters */
    /* Phase 2: Implement with privilege checks for GIDs */

    (void)rgid;
    (void)egid;
    (void)sgid;
    fut_printf("[CRED] setresgid stub - returning success\n");
    return 0;
}

/* Note: sys_getresuid() and sys_getresgid() are implemented in kernel/sys_cred.c
 * with Phase 3 implementations that include fut_copy_to_user() for proper
 * userspace pointer handling. */
