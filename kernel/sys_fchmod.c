/* kernel/sys_fchmod.c - File permission syscall (fd-based)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the fchmod() syscall for changing file permissions via fd.
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);
extern struct fut_file *fut_vfs_get_file(int fd);

/**
 * fchmod() - Change file permissions (fd-based)
 *
 * Changes the permission bits of a file using an open file descriptor.
 * The mode parameter is a bit mask containing the new permission bits
 * (e.g., 0755 for rwxr-xr-x).
 *
 * This is the fd-based complement to chmod() (Priority #17).
 *
 * @param fd    File descriptor of the open file
 * @param mode  New permission bits (e.g., 0755, 0644, etc.)
 *
 * Returns:
 *   - 0 on success
 *   - -EBADF if fd is not a valid open file descriptor
 *   - -ENOSYS if filesystem doesn't support permission changes
 */
long sys_fchmod(int fd, uint32_t mode) {
    /* Get the file structure from the file descriptor */
    struct fut_file *file = fut_vfs_get_file(fd);
    if (!file) {
        fut_printf("[FCHMOD] fchmod(%d, %o) -> EBADF (invalid fd)\n", fd, mode);
        return -EBADF;
    }

    /* Get the vnode from the file */
    struct fut_vnode *vnode = file->vnode;
    if (!vnode) {
        fut_printf("[FCHMOD] fchmod(%d, %o) -> EBADF (no vnode)\n", fd, mode);
        return -EBADF;
    }

    /* Check if filesystem supports permission changes */
    if (!vnode->ops || !vnode->ops->setattr) {
        fut_printf("[FCHMOD] fchmod(%d, %o) -> ENOSYS (no setattr)\n", fd, mode);
        return -ENOSYS;
    }

    /* Create a stat structure with the new mode */
    struct fut_stat stat = {0};
    stat.st_mode = mode;

    /* Call the filesystem's setattr operation */
    int ret = vnode->ops->setattr(vnode, &stat);

    fut_printf("[FCHMOD] fchmod(%d, %o) -> %d\n", fd, mode, ret);
    return ret;
}
