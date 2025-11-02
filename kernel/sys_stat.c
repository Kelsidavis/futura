/* kernel/sys_stat.c - File status syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the stat() syscall for retrieving file metadata.
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);
extern int fut_copy_from_user(void *to, const void *from, size_t size);
extern int fut_copy_to_user(void *to, const void *from, size_t size);

/**
 * stat() - Get file status
 *
 * Retrieves file metadata including size, mode, timestamps, and inode number.
 * This is the path-based variant of fstat() (Priority #28 candidate).
 *
 * @param path  Path to the file
 * @param statbuf  Pointer to userspace stat buffer to fill
 *
 * Returns:
 *   - 0 on success
 *   - -EFAULT if path or statbuf is inaccessible
 *   - -ENOENT if file does not exist
 *   - -EINVAL if path is empty or statbuf is NULL
 */
long sys_stat(const char *path, struct fut_stat *statbuf) {
    if (!path || !statbuf) {
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

    /* Get file metadata via VFS */
    struct fut_stat kernel_stat;
    int ret = fut_vfs_stat(path_buf, &kernel_stat);
    if (ret < 0) {
        fut_printf("[STAT] stat(%s) -> %d (VFS error)\n", path_buf, ret);
        return ret;
    }

    /* Copy stat buffer to userspace */
    if (fut_copy_to_user(statbuf, &kernel_stat, sizeof(struct fut_stat)) != 0) {
        fut_printf("[STAT] stat(%s) -> EFAULT (copy_to_user failed)\n", path_buf);
        return -EFAULT;
    }

    fut_printf("[STAT] stat(%s) -> 0 (size=%llu, mode=%o, ino=%llu)\n",
               path_buf, kernel_stat.st_size, kernel_stat.st_mode, kernel_stat.st_ino);
    return 0;
}
