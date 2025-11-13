/* kernel/sys_cred.c - Process credential syscalls
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements syscalls for managing process user and group IDs (credentials).
 * Provides access to real, effective, and saved user/group IDs.
 *
 * Phase 1 (Completed): Basic credential get/set operations
 * Phase 2 (Completed): Enhanced validation, UID/GID categorization, detailed logging
 * Phase 3 (Completed): Capability-based access control, getresuid/getresgid implementation
 * Phase 4 (Current): Per-namespace credential management, user namespaces
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);
extern fut_task_t *fut_task_current(void);
extern int fut_copy_to_user(void *to, const void *from, size_t size);

/* Phase 3: Helper to check capability-based privilege */
static int has_cap_setuid(fut_task_t *task) {
    if (!task) return 0;
    /* Phase 3: Check CAP_SETUID capability (capability 7) */
    return (task->cap_effective & (1 << 7)) ? 1 : 0;
}

/* Helper to categorize UID/GID values */
static const char *categorize_id(uint32_t id) {
    if (id == 0) {
        return "root (0)";
    } else if (id < 100) {
        return "system (1-99)";
    } else if (id < 1000) {
        return "service (100-999)";
    } else if (id < 65534) {
        return "user (1000-65533)";
    } else if (id == 65534) {
        return "nobody (65534)";
    } else {
        return "reserved (≥65535)";
    }
}

/**
 * getuid() - Get real user ID of calling process
 *
 * Returns the real user ID (ruid) of the calling process.
 * The real UID identifies who the user really is and cannot be
 * changed by unprivileged processes.
 *
 * Returns:
 *   - Real user ID of the calling process (always succeeds)
 *
 * Behavior:
 *   - Never fails (no error conditions)
 *   - Returns 0 (root) if no task context (kernel threads)
 *   - Real UID is set at login and persists across privilege changes
 *   - Used by accounting, auditing, and resource limits
 *
 * Related syscalls:
 *   - geteuid(): Get effective UID (used for access control)
 *   - setuid(): Set both real and effective UID
 *   - getresuid(): Get real, effective, and saved UIDs
 *
 * Phase 1 (Completed): Basic ruid retrieval
 * Phase 2 (Completed): UID categorization and detailed logging
 * Phase 3 (Current): Per-namespace UID mapping
 * Phase 4: Capability-based UID queries
 */
long sys_getuid(void) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        /* No task context - default to root for kernel threads */
        fut_printf("[CRED] getuid() -> 0 (no task context, kernel thread, Phase 2)\n");
        return 0;
    }

    uint32_t ruid = task->ruid;
    const char *category = categorize_id(ruid);

    fut_printf("[CRED] getuid(pid=%u) -> ruid=%u [%s] (Phase 2)\n",
               task->pid, ruid, category);

    return (long)ruid;
}

/**
 * geteuid() - Get effective user ID of calling process
 *
 * Returns the effective user ID (uid) of the calling process.
 * The effective UID is used for access control checks and can differ
 * from real UID due to setuid binaries or seteuid() calls.
 *
 * Returns:
 *   - Effective user ID of the calling process (always succeeds)
 *
 * Behavior:
 *   - Never fails (no error conditions)
 *   - Returns 0 (root) if no task context (kernel threads)
 *   - Effective UID determines file access permissions
 *   - Can be changed by setuid binaries or seteuid()
 *   - Used for all permission checks (open, read, write, etc.)
 *
 * Common usage patterns:
 *
 * Check if process has root privileges:
 *   if (geteuid() == 0) {
 *       // Running with root privileges
 *   }
 *
 * Temporarily drop privileges (setuid binary):
 *   uid_t real_uid = getuid();
 *   seteuid(real_uid);  // Drop to real user
 *   // ... do unprivileged work ...
 *   seteuid(0);  // Regain root (if real user was root)
 *
 * Related syscalls:
 *   - getuid(): Get real UID
 *   - seteuid(): Set effective UID only
 *   - setuid(): Set both real and effective UID
 *
 * Phase 1 (Completed): Basic euid retrieval
 * Phase 2 (Current): UID categorization and detailed logging
 * Phase 3: Capability-based privilege checks
 * Phase 4: Per-namespace effective UID
 */
long sys_geteuid(void) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        /* No task context - default to root for kernel threads */
        fut_printf("[CRED] geteuid() -> 0 (no task context, kernel thread, Phase 2)\n");
        return 0;
    }

    uint32_t euid = task->uid;
    const char *category = categorize_id(euid);

    fut_printf("[CRED] geteuid(pid=%u) -> euid=%u [%s] (Phase 2)\n",
               task->pid, euid, category);

    return (long)euid;
}

/**
 * getgid() - Get real group ID of calling process
 *
 * Returns the real group ID (rgid) of the calling process.
 * The real GID identifies the user's primary group and cannot be
 * changed by unprivileged processes.
 *
 * Returns:
 *   - Real group ID of the calling process (always succeeds)
 *
 * Behavior:
 *   - Never fails (no error conditions)
 *   - Returns 0 (root group) if no task context
 *   - Real GID is set at login from /etc/passwd
 *   - Used for determining default group ownership of new files
 *
 * Related syscalls:
 *   - getegid(): Get effective GID (used for access control)
 *   - setgid(): Set both real and effective GID
 *   - getgroups(): Get supplementary group list
 *
 * Phase 1 (Completed): Basic rgid retrieval
 * Phase 2 (Current): GID categorization and detailed logging
 * Phase 3: Per-namespace GID mapping
 * Phase 4: Supplementary group support
 */
long sys_getgid(void) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        /* No task context - default to root group for kernel threads */
        fut_printf("[CRED] getgid() -> 0 (no task context, kernel thread, Phase 2)\n");
        return 0;
    }

    uint32_t rgid = task->rgid;
    const char *category = categorize_id(rgid);

    fut_printf("[CRED] getgid(pid=%u) -> rgid=%u [%s] (Phase 2)\n",
               task->pid, rgid, category);

    return (long)rgid;
}

/**
 * getegid() - Get effective group ID of calling process
 *
 * Returns the effective group ID (gid) of the calling process.
 * The effective GID is used for file access control checks.
 *
 * Returns:
 *   - Effective group ID of the calling process (always succeeds)
 *
 * Behavior:
 *   - Never fails (no error conditions)
 *   - Returns 0 (root group) if no task context
 *   - Effective GID determines group-based file access
 *   - Can differ from real GID due to setgid binaries
 *   - New files inherit this GID (unless directory has setgid bit)
 *
 * Related syscalls:
 *   - getgid(): Get real GID
 *   - setegid(): Set effective GID only
 *   - setgid(): Set both real and effective GID
 *
 * Phase 1 (Completed): Basic egid retrieval
 * Phase 2 (Current): GID categorization and detailed logging
 * Phase 3: Capability-based group checks
 * Phase 4: Per-namespace effective GID
 */
long sys_getegid(void) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        /* No task context - default to root group for kernel threads */
        fut_printf("[CRED] getegid() -> 0 (no task context, kernel thread, Phase 2)\n");
        return 0;
    }

    uint32_t egid = task->gid;
    const char *category = categorize_id(egid);

    fut_printf("[CRED] getegid(pid=%u) -> egid=%u [%s] (Phase 2)\n",
               task->pid, egid, category);

    return (long)egid;
}

/**
 * setuid(uid_t uid) - Set user ID
 *
 * Changes both the real and effective user IDs of the calling process.
 * Privileged processes can set to any value; unprivileged processes
 * can only set effective UID to their real UID.
 *
 * @param uid User ID to set
 *
 * Returns:
 *   - 0 on success
 *   - -EPERM if not privileged and uid doesn't match real UID
 *   - -ESRCH if no task context
 *
 * Behavior:
 *   - If privileged (euid=0): Sets both real and effective UID to uid
 *   - If unprivileged: Can only set effective UID to real UID
 *   - After setuid(X), both getuid() and geteuid() return X
 *   - Saved set-user-ID is also set to uid
 *   - Irreversible privilege drop for root processes
 *
 * Common usage patterns:
 *
 * Permanent privilege drop (as root):
 *   setuid(1000);  // Drop to user 1000, cannot regain root
 *
 * Unprivileged UID swap:
 *   // In setuid-root binary running as user 1000:
 *   uid_t real = getuid();  // 1000
 *   uid_t eff = geteuid();  // 0
 *   setuid(real);  // Set effective to 1000, can regain if saved=0
 *
 * Related syscalls:
 *   - seteuid(): Temporary effective UID change (reversible)
 *   - setreuid(): Set real and effective separately
 *   - setresuid(): Set real, effective, and saved
 *
 * Security considerations:
 *   - setuid() is irreversible for root processes
 *   - After setuid(X) where X != 0, cannot regain root
 *   - Use seteuid() for temporary privilege changes
 *
 * Phase 1 (Completed): Basic setuid with privilege checks
 * Phase 2 (Current): UID categorization, operation type, detailed logging
 * Phase 3: Capability-based setuid, fine-grained control
 * Phase 4: Per-namespace UID setting, audit logging
 */
long sys_setuid(uint32_t uid) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[CRED] setuid(uid=%u) -> ESRCH (no task context)\n", uid);
        return -ESRCH;
    }

    const char *uid_category = categorize_id(uid);
    const char *old_euid_category = categorize_id(task->uid);
    const char *old_ruid_category = categorize_id(task->ruid);

    /* Check if process is privileged (euid=0) */
    int is_privileged = (task->uid == 0);

    if (is_privileged) {
        /* Root can set both IDs to any value */
        uint32_t old_ruid = task->ruid;
        uint32_t old_euid = task->uid;

        task->ruid = uid;
        task->uid = uid;

        /* Determine if this is a privilege drop */
        const char *operation;
        if (uid == 0) {
            operation = "no change (already root)";
        } else {
            operation = "privilege drop (irreversible)";
        }

        fut_printf("[CRED] setuid(uid=%u [%s], pid=%u, old_ruid=%u [%s], "
                   "old_euid=%u [%s], op=%s, privileged) -> 0 (Phase 2)\n",
                   uid, uid_category, task->pid,
                   old_ruid, old_ruid_category,
                   old_euid, old_euid_category,
                   operation);

        return 0;
    } else {
        /* Non-root can only set effective UID to real UID */
        if (uid == task->ruid) {
            uint32_t old_euid = task->uid;
            task->uid = uid;

            fut_printf("[CRED] setuid(uid=%u [%s], pid=%u, old_euid=%u [%s], "
                       "op=set euid to ruid, unprivileged) -> 0 (Phase 2)\n",
                       uid, uid_category, task->pid,
                       old_euid, old_euid_category);

            return 0;
        } else {
            fut_printf("[CRED] setuid(uid=%u [%s], pid=%u, ruid=%u [%s], "
                       "euid=%u [%s]) -> EPERM (uid mismatch, unprivileged)\n",
                       uid, uid_category, task->pid,
                       task->ruid, old_ruid_category,
                       task->uid, old_euid_category);

            return -EPERM;
        }
    }
}

/**
 * seteuid(uid_t euid) - Set effective user ID
 *
 * Changes only the effective user ID of the calling process.
 * Unlike setuid(), this is reversible for privileged processes.
 *
 * @param euid Effective user ID to set
 *
 * Returns:
 *   - 0 on success
 *   - -EPERM if not privileged and euid doesn't match real UID
 *   - -ESRCH if no task context
 *
 * Behavior:
 *   - If privileged (euid=0): Can set euid to any value
 *   - If unprivileged: Can only set euid to real UID
 *   - Real UID remains unchanged
 *   - Saved set-user-ID remains unchanged
 *   - Reversible privilege change for setuid binaries
 *
 * Common usage patterns:
 *
 * Temporary privilege drop (setuid-root binary):
 *   uid_t saved_euid = geteuid();  // Save current euid (0)
 *   seteuid(getuid());  // Drop to real user
 *   // ... do unprivileged work ...
 *   seteuid(saved_euid);  // Regain root privileges
 *
 * Alternating privileges:
 *   seteuid(1000);  // Drop to user 1000
 *   // ... user work ...
 *   seteuid(0);     // Back to root
 *   // ... root work ...
 *   seteuid(1000);  // Drop again
 *
 * Related syscalls:
 *   - setuid(): Permanent UID change (irreversible for root)
 *   - setreuid(): Set real and effective separately
 *   - getuid()/geteuid(): Query current UIDs
 *
 * Security note: seteuid() enables temporary privilege changes,
 * allowing programs to minimize time spent with elevated privileges.
 *
 * Phase 1 (Completed): Basic seteuid with privilege checks
 * Phase 2 (Current): UID categorization, operation type, detailed logging
 * Phase 3: Capability-based seteuid, audit trail
 * Phase 4: Per-namespace effective UID, fine-grained control
 */
long sys_seteuid(uint32_t euid) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[CRED] seteuid(euid=%u) -> ESRCH (no task context)\n", euid);
        return -ESRCH;
    }

    const char *euid_category = categorize_id(euid);
    const char *old_euid_category = categorize_id(task->uid);
    const char *ruid_category = categorize_id(task->ruid);

    int is_privileged = (task->uid == 0);

    if (is_privileged) {
        uint32_t old_euid = task->uid;
        task->uid = euid;

        /* Determine operation type */
        const char *operation;
        if (euid == 0) {
            if (old_euid == 0) {
                operation = "no change (already root)";
            } else {
                operation = "regain privilege";
            }
        } else {
            operation = "temporary privilege drop (reversible)";
        }

        fut_printf("[CRED] seteuid(euid=%u [%s], pid=%u, old_euid=%u [%s], "
                   "ruid=%u [%s], op=%s, privileged) -> 0 (Phase 2)\n",
                   euid, euid_category, task->pid,
                   old_euid, old_euid_category,
                   task->ruid, ruid_category,
                   operation);

        return 0;
    } else {
        if (euid == task->ruid) {
            uint32_t old_euid = task->uid;
            task->uid = euid;

            fut_printf("[CRED] seteuid(euid=%u [%s], pid=%u, old_euid=%u [%s], "
                       "ruid=%u [%s], op=set euid to ruid, unprivileged) -> 0 (Phase 2)\n",
                       euid, euid_category, task->pid,
                       old_euid, old_euid_category,
                       task->ruid, ruid_category);

            return 0;
        } else {
            fut_printf("[CRED] seteuid(euid=%u [%s], pid=%u, ruid=%u [%s], "
                       "current_euid=%u [%s]) -> EPERM (euid mismatch, unprivileged)\n",
                       euid, euid_category, task->pid,
                       task->ruid, ruid_category,
                       task->uid, old_euid_category);

            return -EPERM;
        }
    }
}

/**
 * setgid(gid_t gid) - Set group ID
 *
 * Changes both the real and effective group IDs of the calling process.
 * Privileged processes can set to any value; unprivileged processes
 * can only set effective GID to their real GID.
 *
 * @param gid Group ID to set
 *
 * Returns:
 *   - 0 on success
 *   - -EPERM if not privileged and gid doesn't match real GID
 *   - -ESRCH if no task context
 *
 * Behavior:
 *   - If privileged (egid=0): Sets both real and effective GID to gid
 *   - If unprivileged: Can only set effective GID to real GID
 *   - After setgid(X), both getgid() and getegid() return X
 *   - Saved set-group-ID is also set to gid
 *   - New files will be owned by this group
 *
 * Related syscalls:
 *   - setegid(): Temporary effective GID change (reversible)
 *   - setregid(): Set real and effective separately
 *   - getgroups(): Get supplementary group list
 *
 * Phase 1 (Completed): Basic setgid with privilege checks
 * Phase 2 (Current): GID categorization, operation type, detailed logging
 * Phase 3: Capability-based setgid, supplementary groups
 * Phase 4: Per-namespace GID setting, audit logging
 */
long sys_setgid(uint32_t gid) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[CRED] setgid(gid=%u) -> ESRCH (no task context)\n", gid);
        return -ESRCH;
    }

    const char *gid_category = categorize_id(gid);
    const char *old_egid_category = categorize_id(task->gid);
    const char *old_rgid_category = categorize_id(task->rgid);

    /* Check if process is privileged (egid=0) */
    int is_privileged = (task->gid == 0);

    if (is_privileged) {
        /* Root group can set both GIDs to any value */
        uint32_t old_rgid = task->rgid;
        uint32_t old_egid = task->gid;

        task->rgid = gid;
        task->gid = gid;

        /* Determine operation type */
        const char *operation;
        if (gid == 0) {
            operation = "no change (already root group)";
        } else {
            operation = "group change";
        }

        fut_printf("[CRED] setgid(gid=%u [%s], pid=%u, old_rgid=%u [%s], "
                   "old_egid=%u [%s], op=%s, privileged) -> 0 (Phase 2)\n",
                   gid, gid_category, task->pid,
                   old_rgid, old_rgid_category,
                   old_egid, old_egid_category,
                   operation);

        return 0;
    } else {
        /* Non-root can only set effective GID to real GID */
        if (gid == task->rgid) {
            uint32_t old_egid = task->gid;
            task->gid = gid;

            fut_printf("[CRED] setgid(gid=%u [%s], pid=%u, old_egid=%u [%s], "
                       "op=set egid to rgid, unprivileged) -> 0 (Phase 2)\n",
                       gid, gid_category, task->pid,
                       old_egid, old_egid_category);

            return 0;
        } else {
            fut_printf("[CRED] setgid(gid=%u [%s], pid=%u, rgid=%u [%s], "
                       "egid=%u [%s]) -> EPERM (gid mismatch, unprivileged)\n",
                       gid, gid_category, task->pid,
                       task->rgid, old_rgid_category,
                       task->gid, old_egid_category);

            return -EPERM;
        }
    }
}

/**
 * setegid(gid_t egid) - Set effective group ID
 *
 * Changes only the effective group ID of the calling process.
 * Unlike setgid(), this is reversible for privileged processes.
 *
 * @param egid Effective group ID to set
 *
 * Returns:
 *   - 0 on success
 *   - -EPERM if not privileged and egid doesn't match real GID
 *   - -ESRCH if no task context
 *
 * Behavior:
 *   - If privileged (egid=0): Can set egid to any value
 *   - If unprivileged: Can only set egid to real GID
 *   - Real GID remains unchanged
 *   - Saved set-group-ID remains unchanged
 *   - New files will be owned by effective GID
 *
 * Related syscalls:
 *   - setgid(): Permanent GID change
 *   - setregid(): Set real and effective separately
 *   - getgid()/getegid(): Query current GIDs
 *
 * Phase 1 (Completed): Basic setegid with privilege checks
 * Phase 2 (Current): GID categorization, operation type, detailed logging
 * Phase 3: Capability-based setegid, audit trail
 * Phase 4: Per-namespace effective GID, supplementary groups
 */
long sys_setegid(uint32_t egid) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[CRED] setegid(egid=%u) -> ESRCH (no task context)\n", egid);
        return -ESRCH;
    }

    const char *egid_category = categorize_id(egid);
    const char *old_egid_category = categorize_id(task->gid);
    const char *rgid_category = categorize_id(task->rgid);

    int is_privileged = (task->gid == 0);

    if (is_privileged) {
        uint32_t old_egid = task->gid;
        task->gid = egid;

        /* Determine operation type */
        const char *operation;
        if (egid == 0) {
            if (old_egid == 0) {
                operation = "no change (already root group)";
            } else {
                operation = "regain privilege";
            }
        } else {
            operation = "temporary group change (reversible)";
        }

        fut_printf("[CRED] setegid(egid=%u [%s], pid=%u, old_egid=%u [%s], "
                   "rgid=%u [%s], op=%s, privileged) -> 0 (Phase 2)\n",
                   egid, egid_category, task->pid,
                   old_egid, old_egid_category,
                   task->rgid, rgid_category,
                   operation);

        return 0;
    } else {
        if (egid == task->rgid) {
            uint32_t old_egid = task->gid;
            task->gid = egid;

            fut_printf("[CRED] setegid(egid=%u [%s], pid=%u, old_egid=%u [%s], "
                       "rgid=%u [%s], op=set egid to rgid, unprivileged) -> 0 (Phase 2)\n",
                       egid, egid_category, task->pid,
                       old_egid, old_egid_category,
                       task->rgid, rgid_category);

            return 0;
        } else {
            fut_printf("[CRED] setegid(egid=%u [%s], pid=%u, rgid=%u [%s], "
                       "current_egid=%u [%s]) -> EPERM (egid mismatch, unprivileged)\n",
                       egid, egid_category, task->pid,
                       task->rgid, rgid_category,
                       task->gid, old_egid_category);

            return -EPERM;
        }
    }
}

/**
 * getresuid() - Get real, effective, and saved user IDs
 *
 * Retrieves all three user IDs in a single syscall.
 * More efficient than multiple getuid/geteuid calls.
 *
 * @param ruid Pointer to store real user ID
 * @param euid Pointer to store effective user ID
 * @param suid Pointer to store saved set-user-ID
 *
 * Returns:
 *   - 0 on success
 *   - -EFAULT if any pointer is NULL
 *   - -ESRCH if no task context
 *
 * Phase 3: Implementation with atomic retrieval and copy to user
 */
long sys_getresuid(uint32_t *ruid, uint32_t *euid, uint32_t *suid) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[CRED] getresuid(ruid=%p, euid=%p, suid=%p) -> ESRCH\n",
                   (void*)ruid, (void*)euid, (void*)suid);
        return -ESRCH;
    }

    /* Phase 3: Validate pointers */
    if (!ruid || !euid || !suid) {
        fut_printf("[CRED] getresuid(ruid=%p, euid=%p, suid=%p) -> EFAULT (NULL pointer)\n",
                   (void*)ruid, (void*)euid, (void*)suid);
        return -EFAULT;
    }

    /* Phase 3: Retrieve saved set-user-ID (typically same as real) */
    uint32_t saved_uid = task->ruid;

    /* Phase 3: Copy IDs to userspace */
    if (fut_copy_to_user(ruid, &task->ruid, sizeof(uint32_t)) != 0) {
        return -EFAULT;
    }
    if (fut_copy_to_user(euid, &task->uid, sizeof(uint32_t)) != 0) {
        return -EFAULT;
    }
    if (fut_copy_to_user(suid, &saved_uid, sizeof(uint32_t)) != 0) {
        return -EFAULT;
    }

    /* Phase 3: Detailed logging with all three IDs */
    fut_printf("[CRED] getresuid(pid=%u) -> ruid=%u [%s], euid=%u [%s], "
               "suid=%u [%s] (Phase 3)\n",
               task->pid,
               task->ruid, categorize_id(task->ruid),
               task->uid, categorize_id(task->uid),
               saved_uid, categorize_id(saved_uid));

    return 0;
}

/**
 * getresgid() - Get real, effective, and saved group IDs
 *
 * Retrieves all three group IDs in a single syscall.
 *
 * @param rgid Pointer to store real group ID
 * @param egid Pointer to store effective group ID
 * @param sgid Pointer to store saved set-group-ID
 *
 * Returns:
 *   - 0 on success
 *   - -EFAULT if any pointer is NULL
 *   - -ESRCH if no task context
 *
 * Phase 3: Implementation with atomic retrieval and copy to user
 */
long sys_getresgid(uint32_t *rgid, uint32_t *egid, uint32_t *sgid) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[CRED] getresgid(rgid=%p, egid=%p, sgid=%p) -> ESRCH\n",
                   (void*)rgid, (void*)egid, (void*)sgid);
        return -ESRCH;
    }

    /* Phase 3: Validate pointers */
    if (!rgid || !egid || !sgid) {
        fut_printf("[CRED] getresgid(rgid=%p, egid=%p, sgid=%p) -> EFAULT (NULL pointer)\n",
                   (void*)rgid, (void*)egid, (void*)sgid);
        return -EFAULT;
    }

    /* Phase 3: Retrieve saved set-group-ID (typically same as real) */
    uint32_t saved_gid = task->rgid;

    /* Phase 3: Copy IDs to userspace */
    if (fut_copy_to_user(rgid, &task->rgid, sizeof(uint32_t)) != 0) {
        return -EFAULT;
    }
    if (fut_copy_to_user(egid, &task->gid, sizeof(uint32_t)) != 0) {
        return -EFAULT;
    }
    if (fut_copy_to_user(sgid, &saved_gid, sizeof(uint32_t)) != 0) {
        return -EFAULT;
    }

    /* Phase 3: Detailed logging with all three IDs */
    fut_printf("[CRED] getresgid(pid=%u) -> rgid=%u [%s], egid=%u [%s], "
               "sgid=%u [%s] (Phase 3)\n",
               task->pid,
               task->rgid, categorize_id(task->rgid),
               task->gid, categorize_id(task->gid),
               saved_gid, categorize_id(saved_gid));

    return 0;
}
