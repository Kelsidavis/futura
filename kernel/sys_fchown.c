/* kernel/sys_fchown.c - File ownership syscall (fd-based)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the fchown() syscall for changing file ownership via fd.
 * Essential for file ownership management on open files.
 * Supports capability checks and detailed validation.
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <kernel/userns.h>
#include <kernel/fut_fd_util.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>

#include <kernel/kprintf.h>

/**
 * fchown() - Change file ownership (fd-based)
 *
 * Changes the owner (uid) and group (gid) of a file using an open file
 * descriptor. Special values:
 * - (uid_t)-1 means "don't change uid"
 * - (gid_t)-1 means "don't change gid"
 *
 * @param fd    File descriptor of the open file
 * @param uid   New user ID (or -1 to leave unchanged)
 * @param gid   New group ID (or -1 to leave unchanged)
 *
 * Returns:
 *   - 0 on success
 *   - -EBADF if fd is not a valid open file descriptor
 *   - -ENOSYS if filesystem doesn't support ownership changes
 *   - -EPERM if not permitted
 *   - -EROFS if filesystem is read-only
 */
long sys_fchown(int fd, uint32_t uid, uint32_t gid) {
    /* ARM64 FIX: Copy register parameters to local stack variables */
    int local_fd = fd;
    uint32_t local_uid = uid;
    uint32_t local_gid = gid;

    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[FCHOWN] fchown(fd=%d, uid=%u, gid=%u) -> ESRCH (no current task)\n",
                   local_fd, local_uid, local_gid);
        return -ESRCH;
    }

    /* Validate FD bounds */
    if (local_fd < 0) {
        fut_printf("[FCHOWN] fchown(fd=%d, uid=%u, gid=%u) -> EBADF (negative FD)\n",
                   local_fd, local_uid, local_gid);
        return -EBADF;
    }

    if (local_fd >= task->max_fds) {
        fut_printf("[FCHOWN] fchown(fd=%d, max_fds=%d, uid=%u, gid=%u) -> EBADF "
                   "(fd exceeds max_fds)\n",
                   local_fd, task->max_fds, local_uid, local_gid);
        return -EBADF;
    }

    /* Categorize FD */
    const char *fd_category = fut_fd_category(local_fd);

    /* Get the file structure from the file descriptor */
    struct fut_file *file = vfs_get_file_from_task(task, local_fd);
    if (!file) {
        fut_printf("[FCHOWN] fchown(fd=%d [%s], uid=%u, gid=%u) -> EBADF (file not found)\n",
                   local_fd, fd_category, local_uid, local_gid);
        return -EBADF;
    }

    /* O_PATH fds cannot be used for fchown — use fchownat instead */
    if (file->flags & O_PATH)
        return -EBADF;

    /* Get the vnode from the file */
    struct fut_vnode *vnode = file->vnode;
    if (!vnode) {
        fut_printf("[FCHOWN] fchown(fd=%d [%s], uid=%u, gid=%u) -> EBADF (no vnode)\n",
                   local_fd, fd_category, local_uid, local_gid);
        return -EBADF;
    }

    /* Categorize uid/gid */
    const char *uid_desc = (local_uid == (uint32_t)-1) ? "unchanged" :
                          (local_uid == 0) ? "root" : "user";
    const char *gid_desc = (local_gid == (uint32_t)-1) ? "unchanged" :
                          (local_gid == 0) ? "root" : "group";
    struct user_namespace *ns = task ? task->user_ns : NULL;
    uint32_t task_host_uid = userns_ns_to_host_uid(ns, task->uid);
    uint32_t task_host_gid = userns_ns_to_host_gid(ns, task->gid);
    uint32_t host_uid = local_uid;
    uint32_t host_gid = local_gid;
    if (local_uid != (uint32_t)-1) host_uid = userns_ns_to_host_uid(ns, local_uid);
    if (local_gid != (uint32_t)-1) host_gid = userns_ns_to_host_gid(ns, local_gid);

    /* Capability checks for ownership transfer */
    const char *capability_status = "none required";
    if (local_uid != (uint32_t)-1 && host_uid != vnode->uid) {
        /* Changing owner requires root, CAP_CHOWN, or being the current owner */
        if (task_host_uid != 0 &&
            !(task->cap_effective & (1ULL << 0 /* CAP_CHOWN */)) &&
            task_host_uid != vnode->uid) {
            fut_printf("[FCHOWN] fchown(fd=%d [%s], vnode_ino=%lu, uid=%u [%s], gid=%u [%s]) "
                       "-> EPERM (user %u cannot change owner from %u to %u without CAP_CHOWN)\n",
                       local_fd, fd_category, vnode->ino, local_uid, uid_desc, local_gid, gid_desc,
                       task_host_uid, vnode->uid, host_uid);
            return -EPERM;
        }
        capability_status = "CAP_CHOWN (owner transfer)";
    }

    if (local_gid != (uint32_t)-1 && host_gid != vnode->gid) {
        /* Changing group requires CAP_CHOWN, root, or: file owner
         * changing group to a group they're a member of (effective GID
         * or any supplementary group — same as the path-based sys_chown
         * fix). Without supplementary-group support a user couldn't
         * fchown to a group they joined via 'groups[]'. */
        if (task_host_uid != 0 &&
            !(task->cap_effective & (1ULL << 0 /* CAP_CHOWN */))) {
            if (task_host_uid != vnode->uid) {
                fut_printf("[FCHOWN] fchown(fd=%d [%s], vnode_ino=%lu, uid=%u [%s], gid=%u [%s]) "
                           "-> EPERM (user %u cannot change group from %u to %u)\n",
                           local_fd, fd_category, vnode->ino, local_uid, uid_desc, local_gid, gid_desc,
                           task_host_uid, vnode->gid, host_gid);
                return -EPERM;
            }
            bool member = (host_gid == task_host_gid);
            if (!member) {
                for (int gi = 0; gi < task->ngroups; gi++) {
                    if (userns_ns_to_host_gid(ns, task->groups[gi]) == host_gid) {
                        member = true;
                        break;
                    }
                }
            }
            if (!member) {
                fut_printf("[FCHOWN] fchown(fd=%d [%s], vnode_ino=%lu, uid=%u [%s], gid=%u [%s]) "
                           "-> EPERM (user %u not a member of target group %u)\n",
                           local_fd, fd_category, vnode->ino, local_uid, uid_desc, local_gid, gid_desc,
                           task_host_uid, host_gid);
                return -EPERM;
            }
        }
        if (strcmp(capability_status, "none required") == 0) {
            capability_status = "CAP_CHOWN (group transfer)";
        }
    }

    /* Check if filesystem supports ownership changes */
    if (!vnode->ops || !vnode->ops->setattr) {
        fut_printf("[FCHOWN] fchown(fd=%d [%s], vnode_ino=%lu, uid=%u [%s], gid=%u [%s]) "
                   "-> ENOSYS (filesystem doesn't support setattr)\n",
                   local_fd, fd_category, vnode->ino, local_uid, uid_desc, local_gid, gid_desc);
        return -ENOSYS;
    }

    /* Create a stat structure with the new ownership.
     * Timestamps use (uint64_t)-1 sentinel to avoid resetting them. */
    struct fut_stat stat = {0};
    stat.st_mode = (uint32_t)-1;  /* Don't change mode */
    stat.st_uid = host_uid;
    stat.st_gid = host_gid;
    stat.st_atime = (uint64_t)-1;
    stat.st_mtime = (uint64_t)-1;

    /* Save old uid/gid to detect ownership changes for S_ISUID/S_ISGID clearing */
    uint32_t old_uid = vnode->uid;
    uint32_t old_gid = vnode->gid;

    /* Call the filesystem's setattr operation */
    int ret = vnode->ops->setattr(vnode, &stat);

    if (ret < 0) {
        const char *error_desc;
        switch (ret) {
            case -EPERM:
                error_desc = "operation not permitted";
                break;
            case -EROFS:
                error_desc = "read-only filesystem";
                break;
            case -EACCES:
                error_desc = "permission denied";
                break;
            default:
                error_desc = "setattr failed";
                break;
        }

        fut_printf("[FCHOWN] fchown(fd=%d [%s], vnode_ino=%lu, uid=%u [%s], gid=%u [%s]) "
                   "-> %d (%s)\n",
                   local_fd, fd_category, vnode->ino, local_uid, uid_desc, local_gid, gid_desc,
                   ret, error_desc);
        return ret;
    }

    /* POSIX/Linux: clear S_ISUID/S_ISGID on ownership change.
     * When uid changes, both S_ISUID and S_ISGID are cleared.
     * When only gid changes, S_ISGID is cleared if S_IXGRP is set.
     * This prevents privilege escalation via chowning setuid binaries. */
    if (vnode->type == VN_REG) {
        uint32_t old_local_uid = userns_host_to_ns_uid(ns, old_uid);
        uint32_t old_local_gid = userns_host_to_ns_gid(ns, old_gid);
        int uid_changed = (local_uid != (uint32_t)-1 && local_uid != old_local_uid);
        int gid_changed = (local_gid != (uint32_t)-1 && local_gid != old_local_gid);
        if (uid_changed || gid_changed) {
            if (uid_changed) {
                vnode->mode &= ~(uint32_t)(04000 | 02000);
            } else if (gid_changed) {
                if ((vnode->mode & 02000) && (vnode->mode & 00010))
                    vnode->mode &= ~(uint32_t)02000;
            }
        }
    }

    /* Dispatch IN_ATTRIB inotify event so watchers see the ownership change */
    if (vnode->parent && vnode->name) {
        char dir_path[256];
        if (fut_vnode_build_path(vnode->parent, dir_path, sizeof(dir_path)))
            inotify_dispatch_event(dir_path, 0x00000004 /* IN_ATTRIB */, vnode->name, 0);
    }

    return 0;
}
