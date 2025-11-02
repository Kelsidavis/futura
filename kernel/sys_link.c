/* kernel/sys_link.c - Hard link creation syscall (stub)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the link() syscall stub. Full hard link support is not yet
 * implemented in the VFS layer, so this returns -ENOSYS.
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);

/**
 * link() - Create a hard link (stub implementation)
 *
 * Creates a hard link named 'newpath' which refers to the same inode as
 * 'oldpath'. Both paths then refer to the same file on disk, and the file
 * is only deleted when all links are removed. This is currently a stub
 * implementation that returns -ENOSYS because the VFS layer does not yet
 * have full hard link support.
 *
 * TODO: Implement full hard link support in VFS layer:
 *   - Add link operation to fut_vnode_ops
 *   - Implement fut_vfs_link() in kernel/vfs/fut_vfs.c
 *   - Properly track nlinks (link count) in vnode structures
 *   - Add hard link support to RamFS
 *   - Add hard link support to FuturaFS
 *   - Ensure proper reference counting for shared inodes
 *
 * @param oldpath  Path to the existing file
 * @param newpath  Path where the hard link should be created
 *
 * Returns:
 *   - 0 on success (when implemented)
 *   - -ENOSYS (not implemented) - current stub behavior
 *
 * Future error codes (when implemented):
 *   - -EFAULT if oldpath or newpath is inaccessible
 *   - -EINVAL if oldpath or newpath is empty or NULL
 *   - -EEXIST if newpath already exists
 *   - -ENOENT if oldpath doesn't exist
 *   - -ENOTDIR if a component of path prefix is not a directory
 *   - -EXDEV if oldpath and newpath are on different filesystems
 *   - -EPERM if oldpath is a directory (hard links to dirs not allowed)
 *   - -EMLINK if oldpath already has maximum number of links
 *   - -ENOSPC if no space available
 *   - -EROFS if filesystem is read-only
 *   - -EIO if I/O error occurred
 */
long sys_link(const char *oldpath, const char *newpath) {
    (void)oldpath;
    (void)newpath;

    fut_printf("[LINK] link() -> -ENOSYS (hard links not yet supported)\n");
    return -ENOSYS;
}
