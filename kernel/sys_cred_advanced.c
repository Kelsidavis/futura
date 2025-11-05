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

extern void fut_printf(const char *fmt, ...);
extern fut_task_t *fut_task_current(void);

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

/**
 * sys_getresuid - Get real, effective, and saved user ID
 *
 * @param ruid: Output pointer for real UID
 * @param euid: Output pointer for effective UID
 * @param suid: Output pointer for saved UID
 *
 * Returns all three UIDs at once. Useful for credential management.
 *
 * Phase 1: Stub - returns current real and effective UIDs, saved UID = effective
 * Phase 2: Return actual saved UID when implemented in task structure
 *
 * Returns:
 *   - 0 on success
 *   - -EFAULT if any pointer is invalid
 *   - -ESRCH if no task context
 */
long sys_getresuid(uint32_t *ruid, uint32_t *euid, uint32_t *suid) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Validate pointers */
    if (!ruid || !euid || !suid) {
        return -EFAULT;
    }

    /* Phase 1: Return current UIDs (saved = effective for now) */
    *ruid = task->ruid;
    *euid = task->uid;
    *suid = task->uid;  /* Phase 2: Use actual saved UID from task */

    fut_printf("[CRED] getresuid(pid=%u) -> ruid=%u, euid=%u, suid=%u (Phase 1 stub)\n",
               task->pid, *ruid, *euid, *suid);

    return 0;
}

/**
 * sys_getresgid - Get real, effective, and saved group ID
 *
 * @param rgid: Output pointer for real GID
 * @param egid: Output pointer for effective GID
 * @param sgid: Output pointer for saved GID
 *
 * Returns all three GIDs at once.
 *
 * Phase 1: Stub - returns current real and effective GIDs, saved GID = effective
 * Phase 2: Return actual saved GID when implemented in task structure
 *
 * Returns:
 *   - 0 on success
 *   - -EFAULT if any pointer is invalid
 *   - -ESRCH if no task context
 */
long sys_getresgid(uint32_t *rgid, uint32_t *egid, uint32_t *sgid) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Validate pointers */
    if (!rgid || !egid || !sgid) {
        return -EFAULT;
    }

    /* Phase 1: Return current GIDs (saved = effective for now) */
    *rgid = task->rgid;
    *egid = task->gid;
    *sgid = task->gid;  /* Phase 2: Use actual saved GID from task */

    fut_printf("[CRED] getresgid(pid=%u) -> rgid=%u, egid=%u, sgid=%u (Phase 1 stub)\n",
               task->pid, *rgid, *egid, *sgid);

    return 0;
}
