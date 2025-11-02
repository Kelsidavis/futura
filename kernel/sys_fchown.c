/* kernel/sys_fchown.c - File ownership syscall (fd-based)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the fchown() syscall for changing file ownership via fd.
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
 * This is the fd-based complement to chown() (Priority #25).
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
 */
long sys_fchown(int fd, uint32_t uid, uint32_t gid) {
    /* Get the file structure from the file descriptor */
    struct fut_file *file = fut_vfs_get_file(fd);
    if (!file) {
        fut_printf("[FCHOWN] fchown(%d, %u, %u) -> EBADF (invalid fd)\n", fd, uid, gid);
        return -EBADF;
    }

    /* Get the vnode from the file */
    struct fut_vnode *vnode = file->vnode;
    if (!vnode) {
        fut_printf("[FCHOWN] fchown(%d, %u, %u) -> EBADF (no vnode)\n", fd, uid, gid);
        return -EBADF;
    }

    /* Check if filesystem supports ownership changes */
    if (!vnode->ops || !vnode->ops->setattr) {
        fut_printf("[FCHOWN] fchown(%d, %u, %u) -> ENOSYS (no setattr)\n", fd, uid, gid);
        return -ENOSYS;
    }

    /* Create a stat structure with the new ownership
     * Note: VFS layer doesn't currently track uid/gid on vnodes,
     * so we just pass through the values. When uid/gid is -1,
     * the filesystem backend should preserve existing values.
     */
    struct fut_stat stat = {0};
    stat.st_uid = uid;
    stat.st_gid = gid;

    /* Call the filesystem's setattr operation */
    int ret = vnode->ops->setattr(vnode, &stat);

    fut_printf("[FCHOWN] fchown(%d, %u, %u) -> %d\n", fd, uid, gid, ret);
    return ret;
}
