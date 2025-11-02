/* kernel/sys_readlink.c - Symbolic link reading syscall (stub)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the readlink() syscall stub. Full symbolic link support
 * is not yet implemented in the VFS layer, so this returns -ENOSYS.
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);

/**
 * readlink() - Read value of a symbolic link (stub implementation)
 *
 * Reads the target path of a symbolic link. This is currently a stub
 * implementation that returns -ENOSYS because the VFS layer does not yet
 * have full symbolic link support.
 *
 * TODO: Implement full symbolic link support in VFS layer:
 *   - Add readlink operation to fut_vnode_ops
 *   - Implement fut_vfs_readlink() in kernel/vfs/fut_vfs.c
 *   - Add symbolic link support to RamFS
 *   - Add symbolic link support to FuturaFS
 *
 * @param path    Path to the symbolic link
 * @param buf     Buffer to store the link target
 * @param bufsiz  Size of the buffer
 *
 * Returns:
 *   - Number of bytes placed in buffer on success
 *   - -ENOSYS (not implemented) - current stub behavior
 *
 * Future error codes (when implemented):
 *   - -EFAULT if path or buf is inaccessible
 *   - -EINVAL if path is empty, NULL, or bufsiz <= 0
 *   - -ENOENT if symbolic link doesn't exist
 *   - -ENOTDIR if a component of path is not a directory
 *   - -EINVAL if path does not refer to a symbolic link
 *   - -EIO if I/O error occurred
 */
long sys_readlink(const char *path, char *buf, size_t bufsiz) {
    (void)path;
    (void)buf;
    (void)bufsiz;

    fut_printf("[READLINK] readlink() -> -ENOSYS (symbolic links not yet supported)\n");
    return -ENOSYS;
}
