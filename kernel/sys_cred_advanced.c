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
 *
 * Phase 1 (Completed): Stub implementations
 * Phase 2 (Completed): Full implementation with privilege checks
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>

#include <kernel/kprintf.h>

/* Special value indicating "don't change" */
#define UID_NO_CHANGE ((uint32_t)-1)
#define GID_NO_CHANGE ((uint32_t)-1)

/* Root UID for privilege checks */
#define ROOT_UID 0

/**
 * cred_is_privileged - Check if task has privilege to change credentials
 *
 * A task is privileged if its effective UID is 0 (root).
 */
static inline int cred_is_privileged(fut_task_t *task) {
    return task->uid == ROOT_UID;
}

/**
 * cred_uid_valid - Check if UID value is valid for unprivileged change
 *
 * Unprivileged processes can only set UID to one of:
 * - Current real UID
 * - Current effective UID
 * - Current saved UID
 *
 * @param task  Current task
 * @param uid   UID to validate
 * @return 1 if valid, 0 if not
 */
static inline int cred_uid_valid(fut_task_t *task, uint32_t uid) {
    return uid == task->ruid || uid == task->uid || uid == task->suid;
}

/**
 * cred_gid_valid - Check if GID value is valid for unprivileged change
 *
 * @param task  Current task
 * @param gid   GID to validate
 * @return 1 if valid, 0 if not
 */
static inline int cred_gid_valid(fut_task_t *task, uint32_t gid) {
    return gid == task->rgid || gid == task->gid || gid == task->sgid;
}

/**
 * sys_setreuid - Set real and/or effective user ID
 *
 * @param ruid: New real UID (-1 = don't change)
 * @param euid: New effective UID (-1 = don't change)
 *
 * Allows setting real and effective UIDs independently. More flexible than
 * setuid() as it can swap between real and effective UIDs.
 *
 * POSIX behavior:
 * - Privileged (root): Can set to any values
 * - Unprivileged: Can only set ruid to current real/effective UID
 *                 Can only set euid to current real/effective/saved UID
 * - If real UID is changed, saved UID is set to new effective UID
 *
 * Phase 1 (Completed): Stub implementations
 * Phase 2 (Completed): Full implementation with privilege checks
 *
 * Returns:
 *   - 0 on success
 *   - -EPERM if insufficient privileges
 *   - -ESRCH if no task context
 */
long sys_setreuid(uint32_t ruid, uint32_t euid) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    int privileged = cred_is_privileged(task);

    /* Phase 2: Validate ruid (if changing) */
    if (ruid != UID_NO_CHANGE) {
        if (!privileged && ruid != task->ruid && ruid != task->uid) {
            fut_printf("[CRED] setreuid(ruid=%u, euid=%u, pid=%llu) -> EPERM "
                       "(unprivileged, ruid must be real or effective UID)\n",
                       ruid, euid, task->pid);
            return -EPERM;
        }
    }

    /* Phase 2: Validate euid (if changing) */
    if (euid != UID_NO_CHANGE) {
        if (!privileged && !cred_uid_valid(task, euid)) {
            fut_printf("[CRED] setreuid(ruid=%u, euid=%u, pid=%llu) -> EPERM "
                       "(unprivileged, euid must be real/effective/saved UID)\n",
                       ruid, euid, task->pid);
            return -EPERM;
        }
    }

    /* Store old values for logging */
    uint32_t old_ruid = task->ruid;
    uint32_t old_euid = task->uid;

    /* Phase 2: Apply changes */
    if (ruid != UID_NO_CHANGE) {
        task->ruid = ruid;
    }
    if (euid != UID_NO_CHANGE) {
        task->uid = euid;
    }

    /* POSIX: If real UID was changed, set saved UID to new effective UID */
    if (ruid != UID_NO_CHANGE) {
        task->suid = task->uid;
    }

    fut_printf("[CRED] setreuid(ruid=%u, euid=%u, pid=%llu) -> 0 "
               "(Phase 2: ruid %u->%u, euid %u->%u, suid=%u)\n",
               ruid, euid, task->pid, old_ruid, task->ruid, old_euid, task->uid, task->suid);

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
 * POSIX behavior (mirrors setreuid for GIDs):
 * - Privileged (root): Can set to any values
 * - Unprivileged: Can only set rgid to current real/effective GID
 *                 Can only set egid to current real/effective/saved GID
 * - If real GID is changed, saved GID is set to new effective GID
 *
 * Phase 1 (Completed): Stub implementations
 * Phase 2 (Completed): Full implementation with privilege checks
 *
 * Returns:
 *   - 0 on success
 *   - -EPERM if insufficient privileges
 *   - -ESRCH if no task context
 */
long sys_setregid(uint32_t rgid, uint32_t egid) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    int privileged = cred_is_privileged(task);

    /* Phase 2: Validate rgid (if changing) */
    if (rgid != GID_NO_CHANGE) {
        if (!privileged && rgid != task->rgid && rgid != task->gid) {
            fut_printf("[CRED] setregid(rgid=%u, egid=%u, pid=%llu) -> EPERM "
                       "(unprivileged, rgid must be real or effective GID)\n",
                       rgid, egid, task->pid);
            return -EPERM;
        }
    }

    /* Phase 2: Validate egid (if changing) */
    if (egid != GID_NO_CHANGE) {
        if (!privileged && !cred_gid_valid(task, egid)) {
            fut_printf("[CRED] setregid(rgid=%u, egid=%u, pid=%llu) -> EPERM "
                       "(unprivileged, egid must be real/effective/saved GID)\n",
                       rgid, egid, task->pid);
            return -EPERM;
        }
    }

    /* Store old values for logging */
    uint32_t old_rgid = task->rgid;
    uint32_t old_egid = task->gid;

    /* Phase 2: Apply changes */
    if (rgid != GID_NO_CHANGE) {
        task->rgid = rgid;
    }
    if (egid != GID_NO_CHANGE) {
        task->gid = egid;
    }

    /* POSIX: If real GID was changed, set saved GID to new effective GID */
    if (rgid != GID_NO_CHANGE) {
        task->sgid = task->gid;
    }

    fut_printf("[CRED] setregid(rgid=%u, egid=%u, pid=%llu) -> 0 "
               "(Phase 2: rgid %u->%u, egid %u->%u, sgid=%u)\n",
               rgid, egid, task->pid, old_rgid, task->rgid, old_egid, task->gid, task->sgid);

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
 * POSIX behavior:
 * - Privileged (root): Can set any UID to any value
 * - Unprivileged: Each UID can only be set to current real, effective, or saved UID
 *
 * Phase 1 (Completed): Stub implementations
 * Phase 2 (Completed): Full implementation with privilege checks
 *
 * Returns:
 *   - 0 on success
 *   - -EPERM if insufficient privileges
 *   - -ESRCH if no task context
 */
long sys_setresuid(uint32_t ruid, uint32_t euid, uint32_t suid) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    int privileged = cred_is_privileged(task);

    /* Phase 2: Validate all UIDs (if changing) - unprivileged can only set
     * to current real, effective, or saved UID */
    if (!privileged) {
        if (ruid != UID_NO_CHANGE && !cred_uid_valid(task, ruid)) {
            fut_printf("[CRED] setresuid(ruid=%u, ..., pid=%llu) -> EPERM "
                       "(unprivileged, ruid must be real/effective/saved UID)\n",
                       ruid, task->pid);
            return -EPERM;
        }
        if (euid != UID_NO_CHANGE && !cred_uid_valid(task, euid)) {
            fut_printf("[CRED] setresuid(..., euid=%u, ..., pid=%llu) -> EPERM "
                       "(unprivileged, euid must be real/effective/saved UID)\n",
                       euid, task->pid);
            return -EPERM;
        }
        if (suid != UID_NO_CHANGE && !cred_uid_valid(task, suid)) {
            fut_printf("[CRED] setresuid(..., suid=%u, pid=%llu) -> EPERM "
                       "(unprivileged, suid must be real/effective/saved UID)\n",
                       suid, task->pid);
            return -EPERM;
        }
    }

    /* Store old values for logging */
    uint32_t old_ruid = task->ruid;
    uint32_t old_euid = task->uid;
    uint32_t old_suid = task->suid;

    /* Phase 2: Apply changes */
    if (ruid != UID_NO_CHANGE) {
        task->ruid = ruid;
    }
    if (euid != UID_NO_CHANGE) {
        task->uid = euid;
    }
    if (suid != UID_NO_CHANGE) {
        task->suid = suid;
    }

    fut_printf("[CRED] setresuid(ruid=%u, euid=%u, suid=%u, pid=%llu) -> 0 "
               "(Phase 2: ruid %u->%u, euid %u->%u, suid %u->%u)\n",
               ruid, euid, suid, task->pid,
               old_ruid, task->ruid, old_euid, task->uid, old_suid, task->suid);

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
 * POSIX behavior (mirrors setresuid for GIDs):
 * - Privileged (root): Can set any GID to any value
 * - Unprivileged: Each GID can only be set to current real, effective, or saved GID
 *
 * Phase 1 (Completed): Stub implementations
 * Phase 2 (Completed): Full implementation with privilege checks
 *
 * Returns:
 *   - 0 on success
 *   - -EPERM if insufficient privileges
 *   - -ESRCH if no task context
 */
long sys_setresgid(uint32_t rgid, uint32_t egid, uint32_t sgid) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    int privileged = cred_is_privileged(task);

    /* Phase 2: Validate all GIDs (if changing) - unprivileged can only set
     * to current real, effective, or saved GID */
    if (!privileged) {
        if (rgid != GID_NO_CHANGE && !cred_gid_valid(task, rgid)) {
            fut_printf("[CRED] setresgid(rgid=%u, ..., pid=%llu) -> EPERM "
                       "(unprivileged, rgid must be real/effective/saved GID)\n",
                       rgid, task->pid);
            return -EPERM;
        }
        if (egid != GID_NO_CHANGE && !cred_gid_valid(task, egid)) {
            fut_printf("[CRED] setresgid(..., egid=%u, ..., pid=%llu) -> EPERM "
                       "(unprivileged, egid must be real/effective/saved GID)\n",
                       egid, task->pid);
            return -EPERM;
        }
        if (sgid != GID_NO_CHANGE && !cred_gid_valid(task, sgid)) {
            fut_printf("[CRED] setresgid(..., sgid=%u, pid=%llu) -> EPERM "
                       "(unprivileged, sgid must be real/effective/saved GID)\n",
                       sgid, task->pid);
            return -EPERM;
        }
    }

    /* Store old values for logging */
    uint32_t old_rgid = task->rgid;
    uint32_t old_egid = task->gid;
    uint32_t old_sgid = task->sgid;

    /* Phase 2: Apply changes */
    if (rgid != GID_NO_CHANGE) {
        task->rgid = rgid;
    }
    if (egid != GID_NO_CHANGE) {
        task->gid = egid;
    }
    if (sgid != GID_NO_CHANGE) {
        task->sgid = sgid;
    }

    fut_printf("[CRED] setresgid(rgid=%u, egid=%u, sgid=%u, pid=%llu) -> 0 "
               "(Phase 2: rgid %u->%u, egid %u->%u, sgid %u->%u)\n",
               rgid, egid, sgid, task->pid,
               old_rgid, task->rgid, old_egid, task->gid, old_sgid, task->sgid);

    return 0;
}

/* Note: sys_getresuid() and sys_getresgid() are implemented in kernel/sys_cred.c
 * with Phase 3 implementations that include fut_copy_to_user() for proper
 * userspace pointer handling. */
