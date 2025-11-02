/* kernel/sys_chown.c - File ownership syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the chown() syscall for changing file ownership.
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);
extern int fut_copy_from_user(void *to, const void *from, size_t size);

/**
 * chown() - Change file ownership
 *
 * Changes the owner (uid) and group (gid) of a file. Special values:
 * - (uid_t)-1 means "don't change uid"
 * - (gid_t)-1 means "don't change gid"
 *
 * In a simplified single-user OS, this is primarily a metadata operation
 * that updates the file's ownership fields without complex permission checks.
 *
 * @param path  Path to the file
 * @param uid   New user ID (or -1 to leave unchanged)
 * @param gid   New group ID (or -1 to leave unchanged)
 *
 * Returns:
 *   - 0 on success
 *   - -EFAULT if path is inaccessible
 *   - -ENOENT if file does not exist
 *   - -EINVAL if path is empty
 *   - -ENOSYS if filesystem doesn't support ownership changes
 */
long sys_chown(const char *path, uint32_t uid, uint32_t gid) {
    if (!path) {
        return -EINVAL;
    }

    /* Copy path from userspace to kernel space */
    char path_buf[256];
    if (fut_copy_from_user(path_buf, path, sizeof(path_buf) - 1) != 0) {
        return -EFAULT;
    }
    path_buf[sizeof(path_buf) - 1] = '\0';

    /* Validate path is not empty */
    if (path_buf[0] == '\0') {
        return -EINVAL;
    }

    /* Lookup the vnode */
    struct fut_vnode *vnode = NULL;
    int ret = fut_vfs_lookup(path_buf, &vnode);
    if (ret < 0) {
        /* File doesn't exist */
        return -ENOENT;
    }

    if (!vnode) {
        return -ENOENT;
    }

    /* Check if filesystem supports ownership changes */
    if (!vnode->ops || !vnode->ops->setattr) {
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
    ret = vnode->ops->setattr(vnode, &stat);

    fut_printf("[CHOWN] chown(%s, %u, %u) -> %d\n", path_buf, uid, gid, ret);
    return ret;
}
