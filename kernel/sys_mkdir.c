/* kernel/sys_mkdir.c - Directory creation syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the mkdir() syscall for creating directories.
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);
extern int fut_copy_from_user(void *to, const void *from, size_t size);

/**
 * mkdir() - Create directory
 *
 * Creates a new directory with the specified mode. The mode parameter
 * specifies the permission bits for the new directory (e.g., 0755).
 *
 * @param path  Path to the new directory
 * @param mode  Permission bits for the directory (e.g., 0755, 0700, etc.)
 *
 * Returns:
 *   - 0 on success
 *   - -EFAULT if path is inaccessible
 *   - -EINVAL if path is empty or NULL
 *   - -EEXIST if directory already exists
 *   - -ENOENT if parent directory doesn't exist
 *   - -ENOSPC if no space available
 */
long sys_mkdir(const char *path, uint32_t mode) {
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

    /* Create the directory via VFS */
    int ret = fut_vfs_mkdir(path_buf, mode);
    if (ret < 0) {
        fut_printf("[MKDIR] mkdir(%s, %o) -> %d (VFS error)\n", path_buf, mode, ret);
        return ret;
    }

    fut_printf("[MKDIR] mkdir(%s, %o) -> 0 (success)\n", path_buf, mode);
    return 0;
}
