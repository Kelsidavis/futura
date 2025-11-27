/* kernel/vfs/vfs_credentials.c - VFS Credential Management
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides credential context and permission checking for filesystem operations.
 * Ensures that all VFS operations respect process ownership and permissions.
 */

#include <kernel/fut_task.h>
#include <kernel/fut_vfs.h>
#include <kernel/errno.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);

/**
 * Get the current process's effective UID.
 * Used for permission checks in VFS operations.
 */
uint32_t vfs_get_current_uid(void) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return 0;  /* Default to root if no current task */
    }
    return task->uid;
}

/**
 * Get the current process's effective GID.
 * Used for permission checks in VFS operations.
 */
uint32_t vfs_get_current_gid(void) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return 0;  /* Default to root if no current task */
    }
    return task->gid;
}

/**
 * Get the current process's umask.
 * Used when creating files to set initial permissions.
 */
uint32_t vfs_get_current_umask(void) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return 0022;  /* Default umask */
    }
    return task->umask;
}

/**
 * Check if current process has write permission on a vnode.
 *
 * @vnode: The vnode to check
 * @return: 0 if permitted, negative error code otherwise
 *
 * Permission rules:
 * - Owner (uid matches) checks owner write bits (0200)
 * - Group (gid matches) checks group write bits (0020)
 * - Others checks other write bits (0002)
 * - Root (uid=0) always has write permission
 */
int vfs_check_write_perm(struct fut_vnode *vnode) {
    if (!vnode) {
        return -EINVAL;
    }

    uint32_t uid = vfs_get_current_uid();
    uint32_t gid = vfs_get_current_gid();
    uint32_t mode = vnode->mode;

    /* Root always has write permission */
    if (uid == 0) {
        return 0;
    }

    /* Check owner write bit */
    if (uid == vnode->uid) {
        if (mode & 0200) {  /* Owner write */
            return 0;
        }
        return -EACCES;
    }

    /* Check group write bit */
    if (gid == vnode->gid) {
        if (mode & 0020) {  /* Group write */
            return 0;
        }
        return -EACCES;
    }

    /* Check other write bit */
    if (mode & 0002) {  /* Other write */
        return 0;
    }

    return -EACCES;
}

/**
 * Check if current process has read permission on a vnode.
 *
 * @vnode: The vnode to check
 * @return: 0 if permitted, negative error code otherwise
 *
 * Permission rules:
 * - Owner (uid matches) checks owner read bits (0400)
 * - Group (gid matches) checks group read bits (0040)
 * - Others checks other read bits (0004)
 * - Root (uid=0) always has read permission
 */
int vfs_check_read_perm(struct fut_vnode *vnode) {
    if (!vnode) {
        return -EINVAL;
    }

    uint32_t uid = vfs_get_current_uid();
    uint32_t gid = vfs_get_current_gid();
    uint32_t mode = vnode->mode;

    /* Root always has read permission */
    if (uid == 0) {
        return 0;
    }

    /* Check owner read bit */
    if (uid == vnode->uid) {
        if (mode & 0400) {  /* Owner read */
            return 0;
        }
        return -EACCES;
    }

    /* Check group read bit */
    if (gid == vnode->gid) {
        if (mode & 0040) {  /* Group read */
            return 0;
        }
        return -EACCES;
    }

    /* Check other read bit */
    if (mode & 0004) {  /* Other read */
        return 0;
    }

    return -EACCES;
}

/**
 * Check if current process has execute permission on a vnode.
 * For directories, this means search permission (can look up entries).
 *
 * @vnode: The vnode to check
 * @return: 0 if permitted, negative error code otherwise
 *
 * Permission rules:
 * - Owner (uid matches) checks owner execute bits (0100)
 * - Group (gid matches) checks group execute bits (0010)
 * - Others checks other execute bits (0001)
 * - Root (uid=0) always has execute permission
 */
int vfs_check_exec_perm(struct fut_vnode *vnode) {
    if (!vnode) {
        return -EINVAL;
    }

    uint32_t uid = vfs_get_current_uid();
    uint32_t gid = vfs_get_current_gid();
    uint32_t mode = vnode->mode;

    /* Root always has execute permission */
    if (uid == 0) {
        return 0;
    }

    /* Check owner execute bit */
    if (uid == vnode->uid) {
        if (mode & 0100) {  /* Owner execute */
            return 0;
        }
        return -EACCES;
    }

    /* Check group execute bit */
    if (gid == vnode->gid) {
        if (mode & 0010) {  /* Group execute */
            return 0;
        }
        return -EACCES;
    }

    /* Check other execute bit */
    if (mode & 0001) {  /* Other execute */
        return 0;
    }

    return -EACCES;
}

/**
 * Check if current process can modify a vnode's attributes.
 * Only the owner or root can change permissions/ownership.
 *
 * @vnode: The vnode to check
 * @return: 0 if permitted, negative error code otherwise
 */
int vfs_check_modify_perm(struct fut_vnode *vnode) {
    if (!vnode) {
        return -EINVAL;
    }

    uint32_t uid = vfs_get_current_uid();

    /* Root can always modify */
    if (uid == 0) {
        return 0;
    }

    /* Only owner can modify their own file's attributes */
    if (uid == vnode->uid) {
        return 0;
    }

    return -EPERM;
}

/**
 * Calculate effective permissions after umask is applied.
 * Used when creating new files/directories.
 *
 * @mode: Requested mode (e.g., 0777)
 * @return: Effective mode after umask (e.g., 0755 if umask=0022)
 */
uint32_t vfs_apply_umask(uint32_t mode) {
    uint32_t umask = vfs_get_current_umask();
    return mode & ~umask;
}

/**
 * Initialize a newly created vnode with proper ownership.
 * Sets uid/gid/mode based on parent directory and current process.
 *
 * @vnode: The newly created vnode
 * @parent: The parent directory vnode
 * @requested_mode: The requested mode (will be masked with umask)
 */
void vfs_init_vnode_ownership(struct fut_vnode *vnode,
                               struct fut_vnode *parent,
                               uint32_t requested_mode) {
    if (!vnode) {
        return;
    }

    uint32_t uid = vfs_get_current_uid();
    uint32_t gid = vfs_get_current_gid();

    /* New files owned by creating process */
    vnode->uid = uid;

    /* Group ID inheritance from parent directory (if setgid bit set)
     * Otherwise use creating process's primary group */
    if (parent && (parent->mode & 02000)) {  /* Parent has setgid bit */
        vnode->gid = parent->gid;
    } else {
        vnode->gid = gid;
    }

    /* Apply umask to requested mode */
    vnode->mode = (requested_mode & 0777) & ~vfs_get_current_umask();

    /* Preserve special bits from requested mode */
    vnode->mode |= (requested_mode & 07000);

    fut_printf("[VFS-CRED] Initialized vnode ownership: uid=%u, gid=%u, mode=0%o\n",
               vnode->uid, vnode->gid, vnode->mode);
}
