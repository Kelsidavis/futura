/* kernel/sys_rename.c - File rename syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the rename() syscall for renaming/moving files and directories.
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <stdint.h>
#include <string.h>

extern void fut_printf(const char *fmt, ...);
extern int fut_copy_from_user(void *to, const void *from, size_t size);

/**
 * rename() - Rename or move a file/directory
 *
 * Renames the file at oldpath to newpath. If newpath exists, it is replaced.
 *
 * @param oldpath  Path to existing file/directory
 * @param newpath  New path for the file/directory
 *
 * Returns:
 *   - 0 on success
 *   - -EFAULT if paths are inaccessible
 *   - -ENOENT if oldpath does not exist
 *   - -EINVAL if oldpath or newpath is invalid
 *   - -ENOSYS if operation not supported by filesystem
 *
 * Note: This is a stub implementation. The VFS layer currently does not
 * support atomic rename operations. A production implementation would
 * require adding a rename() operation to the filesystem interface.
 */
long sys_rename(const char *oldpath, const char *newpath) {
    if (!oldpath || !newpath) {
        return -EINVAL;
    }

    /* Copy paths from userspace to kernel space */
    char old_buf[256];
    char new_buf[256];

    if (fut_copy_from_user(old_buf, oldpath, sizeof(old_buf) - 1) != 0) {
        return -EFAULT;
    }
    old_buf[sizeof(old_buf) - 1] = '\0';

    if (fut_copy_from_user(new_buf, newpath, sizeof(new_buf) - 1) != 0) {
        return -EFAULT;
    }
    new_buf[sizeof(new_buf) - 1] = '\0';

    /* Validate paths are not empty */
    if (old_buf[0] == '\0' || new_buf[0] == '\0') {
        return -EINVAL;
    }

    /* Check if oldpath exists */
    struct fut_vnode *old_vnode = NULL;
    int ret = fut_vfs_lookup(old_buf, &old_vnode);
    if (ret < 0) {
        /* Old path doesn't exist */
        return -ENOENT;
    }

    /* For now, return not supported since the VFS doesn't have atomic rename.
     * To properly implement this, we'd need to:
     * 1. Add a rename() operation to the filesystem interface
     * 2. Implement it in RamFS and FuturaFS
     * 3. Or implement a copy-then-unlink pattern with transaction support
     */
    fut_printf("[RENAME] sys_rename(%s, %s) - stub (not yet implemented)\n", old_buf, new_buf);
    return -ENOSYS;
}
