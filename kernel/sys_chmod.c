/* kernel/sys_chmod.c - File permission syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the chmod() syscall for changing file permissions.
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);
extern int fut_copy_from_user(void *to, const void *from, size_t size);

/**
 * chmod() - Change file permissions
 *
 * Changes the permission bits of a file. The mode parameter is a bit mask
 * containing the new permission bits (e.g., 0755 for rwxr-xr-x).
 *
 * @param path  Path to the file
 * @param mode  New permission bits (e.g., 0755, 0644, etc.)
 *
 * Returns:
 *   - 0 on success
 *   - -EFAULT if path is inaccessible
 *   - -ENOENT if file does not exist
 *   - -EINVAL if path is empty
 *   - -ENOSYS if filesystem doesn't support permission changes
 */
long sys_chmod(const char *path, uint32_t mode) {
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

    /* Check if filesystem supports permission changes */
    if (!vnode->ops || !vnode->ops->setattr) {
        return -ENOSYS;
    }

    /* Create a stat structure with the new mode */
    struct fut_stat stat = {0};
    stat.st_mode = mode;

    /* Call the filesystem's setattr operation */
    ret = vnode->ops->setattr(vnode, &stat);

    fut_printf("[CHMOD] chmod(%s, %o) -> %d\n", path_buf, mode, ret);
    return ret;
}
