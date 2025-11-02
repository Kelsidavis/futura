/* kernel/sys_unlink.c - File deletion syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the unlink() syscall for deleting files and symbolic links.
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);
extern int fut_copy_from_user(void *to, const void *from, size_t size);

/**
 * unlink() - Delete a file or symbolic link
 *
 * Removes a file or symbolic link from the filesystem. If the file has
 * multiple hard links, only the specified link is removed. The file's
 * data is deleted when the last link is removed and no processes have
 * the file open.
 *
 * @param path  Path to the file or symbolic link to remove
 *
 * Returns:
 *   - 0 on success
 *   - -EFAULT if path is inaccessible
 *   - -EINVAL if path is empty or NULL
 *   - -ENOENT if file doesn't exist
 *   - -EISDIR if path refers to a directory (use rmdir instead)
 *   - -EACCES if permission denied
 *   - -EBUSY if file is in use
 */
long sys_unlink(const char *path) {
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

    /* Delete the file via VFS */
    int ret = fut_vfs_unlink(path_buf);
    if (ret < 0) {
        fut_printf("[UNLINK] unlink(%s) -> %d (VFS error)\n", path_buf, ret);
        return ret;
    }

    fut_printf("[UNLINK] unlink(%s) -> 0 (success)\n", path_buf);
    return 0;
}
