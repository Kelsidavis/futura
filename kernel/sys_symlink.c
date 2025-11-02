/* kernel/sys_symlink.c - Symbolic link creation syscall (stub)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the symlink() syscall stub. Full symbolic link support
 * is not yet implemented in the VFS layer, so this returns -ENOSYS.
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);

/**
 * symlink() - Create a symbolic link (stub implementation)
 *
 * Creates a symbolic link named 'linkpath' which contains the string 'target'.
 * This is currently a stub implementation that returns -ENOSYS because the VFS
 * layer does not yet have full symbolic link support.
 *
 * TODO: Implement full symbolic link support in VFS layer:
 *   - Add symlink operation to fut_vnode_ops
 *   - Implement fut_vfs_symlink() in kernel/vfs/fut_vfs.c
 *   - Add symbolic link support to RamFS
 *   - Add symbolic link support to FuturaFS
 *   - Coordinate with readlink() implementation (Priority #33)
 *
 * @param target    The target path that the symbolic link points to
 * @param linkpath  The path where the symbolic link should be created
 *
 * Returns:
 *   - 0 on success (when implemented)
 *   - -ENOSYS (not implemented) - current stub behavior
 *
 * Future error codes (when implemented):
 *   - -EFAULT if target or linkpath is inaccessible
 *   - -EINVAL if target or linkpath is empty or NULL
 *   - -EEXIST if linkpath already exists
 *   - -ENOENT if a directory component in linkpath doesn't exist
 *   - -ENOTDIR if a component of linkpath prefix is not a directory
 *   - -ENOSPC if no space available
 *   - -EROFS if filesystem is read-only
 *   - -EIO if I/O error occurred
 */
long sys_symlink(const char *target, const char *linkpath) {
    (void)target;
    (void)linkpath;

    fut_printf("[SYMLINK] symlink() -> -ENOSYS (symbolic links not yet supported)\n");
    return -ENOSYS;
}
