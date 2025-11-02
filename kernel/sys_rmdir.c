/* kernel/sys_rmdir.c - Directory removal syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the rmdir() syscall for removing empty directories.
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);
extern int fut_copy_from_user(void *to, const void *from, size_t size);

/**
 * rmdir() - Remove empty directory
 *
 * Removes an empty directory from the filesystem. The directory must be
 * empty (containing only . and .. entries) for the operation to succeed.
 *
 * @param path  Path to the directory to remove
 *
 * Returns:
 *   - 0 on success
 *   - -EFAULT if path is inaccessible
 *   - -EINVAL if path is empty, NULL, or refers to . or ..
 *   - -ENOENT if directory doesn't exist
 *   - -ENOTDIR if path is not a directory
 *   - -ENOTEMPTY if directory is not empty
 *   - -EBUSY if directory is in use (e.g., cwd of a process)
 */
long sys_rmdir(const char *path) {
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

    /* Remove the directory via VFS */
    int ret = fut_vfs_rmdir(path_buf);
    if (ret < 0) {
        fut_printf("[RMDIR] rmdir(%s) -> %d (VFS error)\n", path_buf, ret);
        return ret;
    }

    fut_printf("[RMDIR] rmdir(%s) -> 0 (success)\n", path_buf);
    return 0;
}
