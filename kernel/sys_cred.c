/* kernel/sys_cred.c - Process credential syscalls
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements syscalls for managing process user and group IDs (credentials).
 * Provides access to real, effective, and saved user/group IDs.
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);

/**
 * getuid() - Get real user ID of calling process
 *
 * Returns the real user ID (ruid) of the calling process.
 * The real UID cannot be changed by unprivileged processes.
 *
 * Returns:
 *   - Real user ID of the calling process (always succeeds)
 */
long sys_getuid(void) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        /* Default to root if no task (shouldn't happen) */
        return 0;
    }

    fut_printf("[CRED] getuid() -> ruid=%u\n", task->ruid);
    return task->ruid;
}

/**
 * geteuid() - Get effective user ID of calling process
 *
 * Returns the effective user ID (uid) of the calling process.
 * The effective UID is used for access control checks.
 * Can be different from real UID due to setuid binaries.
 *
 * Returns:
 *   - Effective user ID of the calling process (always succeeds)
 */
long sys_geteuid(void) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        /* Default to root if no task (shouldn't happen) */
        return 0;
    }

    fut_printf("[CRED] geteuid() -> uid=%u\n", task->uid);
    return task->uid;
}

/**
 * getgid() - Get real group ID of calling process
 *
 * Returns the real group ID (rgid) of the calling process.
 * The real GID cannot be changed by unprivileged processes.
 *
 * Returns:
 *   - Real group ID of the calling process (always succeeds)
 */
long sys_getgid(void) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        /* Default to root group if no task (shouldn't happen) */
        return 0;
    }

    fut_printf("[CRED] getgid() -> rgid=%u\n", task->rgid);
    return task->rgid;
}

/**
 * getegid() - Get effective group ID of calling process
 *
 * Returns the effective group ID (gid) of the calling process.
 * The effective GID is used for file access control checks.
 *
 * Returns:
 *   - Effective group ID of the calling process (always succeeds)
 */
long sys_getegid(void) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        /* Default to root group if no task (shouldn't happen) */
        return 0;
    }

    fut_printf("[CRED] getegid() -> gid=%u\n", task->gid);
    return task->gid;
}

/**
 * setuid(uid_t uid) - Set user ID
 *
 * Changes both the real and effective user IDs of the calling process.
 *
 * If the calling process has appropriate privileges (root), both IDs
 * can be set to the specified value. Otherwise, only the effective UID can be set
 * to either the real UID.
 *
 * @param uid User ID to set
 *
 * Returns:
 *   - 0 on success
 *   - -EPERM if not privileged and uid doesn't match real UID
 */
long sys_setuid(uint32_t uid) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;  /* No current task */
    }

    /* Check if process is privileged (root) */
    int is_privileged = (task->uid == 0);

    if (is_privileged) {
        /* Root can set both IDs */
        task->ruid = uid;
        task->uid = uid;
        fut_printf("[CRED] setuid(%u) -> privilege set both UIDs\n", uid);
        return 0;
    } else {
        /* Non-root can only set effective UID to real UID */
        if (uid == task->ruid) {
            task->uid = uid;
            fut_printf("[CRED] setuid(%u) -> non-privilege set uid\n", uid);
            return 0;
        } else {
            fut_printf("[CRED] setuid(%u) -> EPERM (not root, uid mismatch)\n", uid);
            return -EPERM;
        }
    }
}

/**
 * seteuid(uid_t euid) - Set effective user ID
 *
 * Changes only the effective user ID of the calling process.
 * The effective UID is used for access control checks.
 *
 * Unprivileged processes can only set euid to their real UID.
 * Privileged processes can set euid to any value.
 *
 * @param euid Effective user ID to set
 *
 * Returns:
 *   - 0 on success
 *   - -EPERM if not privileged and euid doesn't match real UID
 */
long sys_seteuid(uint32_t euid) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;  /* No current task */
    }

    int is_privileged = (task->uid == 0);

    if (is_privileged) {
        task->uid = euid;
        fut_printf("[CRED] seteuid(%u) -> privilege set uid\n", euid);
        return 0;
    } else {
        if (euid == task->ruid) {
            task->uid = euid;
            fut_printf("[CRED] seteuid(%u) -> non-privilege set uid\n", euid);
            return 0;
        } else {
            fut_printf("[CRED] seteuid(%u) -> EPERM\n", euid);
            return -EPERM;
        }
    }
}

/**
 * setgid(gid_t gid) - Set group ID
 *
 * Changes both the real and effective group IDs of the calling process.
 *
 * If the calling process has appropriate privileges (root), both IDs
 * can be set to the specified value. Otherwise, only the effective GID can be set
 * to the real GID.
 *
 * @param gid Group ID to set
 *
 * Returns:
 *   - 0 on success
 *   - -EPERM if not privileged and gid doesn't match real GID
 */
long sys_setgid(uint32_t gid) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;  /* No current task */
    }

    int is_privileged = (task->gid == 0);

    if (is_privileged) {
        /* Root can set both GIDs */
        task->rgid = gid;
        task->gid = gid;
        fut_printf("[CRED] setgid(%u) -> privilege set both GIDs\n", gid);
        return 0;
    } else {
        /* Non-root can only set effective GID to real GID */
        if (gid == task->rgid) {
            task->gid = gid;
            fut_printf("[CRED] setgid(%u) -> non-privilege set gid\n", gid);
            return 0;
        } else {
            fut_printf("[CRED] setgid(%u) -> EPERM (not root, gid mismatch)\n", gid);
            return -EPERM;
        }
    }
}

/**
 * setegid(gid_t egid) - Set effective group ID
 *
 * Changes only the effective group ID of the calling process.
 *
 * Unprivileged processes can only set egid to their real GID.
 * Privileged processes can set egid to any value.
 *
 * @param egid Effective group ID to set
 *
 * Returns:
 *   - 0 on success
 *   - -EPERM if not privileged and egid doesn't match real GID
 */
long sys_setegid(uint32_t egid) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;  /* No current task */
    }

    int is_privileged = (task->gid == 0);

    if (is_privileged) {
        task->gid = egid;
        fut_printf("[CRED] setegid(%u) -> privilege set gid\n", egid);
        return 0;
    } else {
        if (egid == task->rgid) {
            task->gid = egid;
            fut_printf("[CRED] setegid(%u) -> non-privilege set gid\n", egid);
            return 0;
        } else {
            fut_printf("[CRED] setegid(%u) -> EPERM\n", egid);
            return -EPERM;
        }
    }
}
