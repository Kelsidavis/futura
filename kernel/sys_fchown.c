/* kernel/sys_fchown.c - File ownership syscall (fd-based)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the fchown() syscall for changing file ownership via fd.
 * Essential for file ownership management on open files.
 *
 * Phase 1 (Completed): Basic ownership changing with FD lookup
 * Phase 2 (Completed): Enhanced validation, uid/gid categorization, and detailed logging
 * Phase 3 (Current): Advanced features (capability checks, quota updates)
 * Phase 4: Performance optimization (batched ownership updates)
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);
extern struct fut_file *fut_vfs_get_file(int fd);

/**
 * fchown() - Change file ownership (fd-based)
 *
 * Changes the owner (uid) and group (gid) of a file using an open file
 * descriptor. Special values:
 * - (uid_t)-1 means "don't change uid"
 * - (gid_t)-1 means "don't change gid"
 *
 * This is the fd-based complement to chown().
 *
 * In a simplified single-user OS, this is primarily a metadata operation
 * that updates the file's ownership fields without complex permission checks.
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
 *
 * Phase 1 (Completed): Basic ownership changing with FD lookup
 * Phase 2 (Current): Enhanced validation, uid/gid categorization, detailed logging
 * Phase 3: Advanced features (capability checks, quota updates)
 * Phase 4: Performance optimization (batched ownership updates)
 */
long sys_fchown(int fd, uint32_t uid, uint32_t gid) {
    /* Phase 2: Validate FD number */
    if (fd < 0) {
        fut_printf("[FCHOWN] fchown(fd=%d [invalid], uid=%u, gid=%u) -> EBADF (negative FD)\n",
                   fd, uid, gid);
        return -EBADF;
    }

    /* Phase 2: Categorize FD */
    const char *fd_category;
    if (fd == 0) {
        fd_category = "stdin";
    } else if (fd == 1) {
        fd_category = "stdout";
    } else if (fd == 2) {
        fd_category = "stderr";
    } else if (fd < 10) {
        fd_category = "low";
    } else {
        fd_category = "high";
    }

    /* Get the file structure from the file descriptor */
    struct fut_file *file = fut_vfs_get_file(fd);
    if (!file) {
        fut_printf("[FCHOWN] fchown(fd=%d [%s], uid=%u, gid=%u) -> EBADF (file not found)\n",
                   fd, fd_category, uid, gid);
        return -EBADF;
    }

    /* Get the vnode from the file */
    struct fut_vnode *vnode = file->vnode;
    if (!vnode) {
        fut_printf("[FCHOWN] fchown(fd=%d [%s], uid=%u, gid=%u) -> EBADF (no vnode)\n",
                   fd, fd_category, uid, gid);
        return -EBADF;
    }

    /* Phase 2: Categorize uid/gid */
    const char *uid_desc = (uid == (uint32_t)-1) ? "unchanged" :
                          (uid == 0) ? "root" : "user";
    const char *gid_desc = (gid == (uint32_t)-1) ? "unchanged" :
                          (gid == 0) ? "root" : "group";

    /* Check if filesystem supports ownership changes */
    if (!vnode->ops || !vnode->ops->setattr) {
        fut_printf("[FCHOWN] fchown(fd=%d [%s], vnode_ino=%lu, uid=%u [%s], gid=%u [%s]) "
                   "-> ENOSYS (filesystem doesn't support setattr)\n",
                   fd, fd_category, vnode->ino, uid, uid_desc, gid, gid_desc);
        return -ENOSYS;
    }

    /* Create a stat structure with the new ownership */
    struct fut_stat stat = {0};
    stat.st_uid = uid;
    stat.st_gid = gid;

    /* Call the filesystem's setattr operation */
    int ret = vnode->ops->setattr(vnode, &stat);

    /* Phase 2: Handle setattr errors with detailed logging */
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
                   fd, fd_category, vnode->ino, uid, uid_desc, gid, gid_desc,
                   ret, error_desc);
        return ret;
    }

    /* Phase 2: Detailed success logging */
    fut_printf("[FCHOWN] fchown(fd=%d [%s], vnode_ino=%lu, uid=%u [%s], gid=%u [%s]) "
               "-> 0 (ownership changed, Phase 2)\n",
               fd, fd_category, vnode->ino, uid, uid_desc, gid, gid_desc);

    return 0;
}
