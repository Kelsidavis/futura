/* kernel/sys_access.c - File accessibility check syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the access() syscall for checking file accessibility.
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);
extern int fut_copy_from_user(void *to, const void *from, size_t size);
extern fut_task_t *fut_task_current(void);

/* access() mode bits */
#define F_OK 0  /* File exists */
#define X_OK 1  /* Execute permission */
#define W_OK 2  /* Write permission */
#define R_OK 4  /* Read permission */

/**
 * access() - Check file accessibility
 *
 * Checks whether the calling process has access to the file at path.
 * The mode argument is a bitmask specifying the type of access to check:
 *   - F_OK: file exists
 *   - R_OK: file is readable
 *   - W_OK: file is writable
 *   - X_OK: file is executable
 *
 * @param path  Path to the file
 * @param mode  Accessibility mode to check (F_OK, R_OK, W_OK, X_OK)
 *
 * Returns:
 *   - 0 if file is accessible with requested permissions
 *   - -EACCES if access is denied
 *   - -EFAULT if path is inaccessible
 *   - -ENOENT if file does not exist
 *   - -EINVAL if path is empty or mode is invalid
 */
long sys_access(const char *path, int mode) {
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

    /* Validate mode contains only valid bits */
    if (mode & ~(F_OK | R_OK | W_OK | X_OK)) {
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

    /* F_OK just checks if file exists (we already verified it exists) */
    if (mode == F_OK) {
        fut_printf("[ACCESS] access(%s, F_OK) -> 0 (exists)\n", path_buf);
        return 0;
    }

    /* Get current task for permission checking */
    fut_task_t *current = fut_task_current();
    if (!current) {
        return -EACCES;
    }

    /* Check permissions based on mode bits
     *
     * For simplicity, we use a basic permission model:
     * - Owner (uid == file owner) gets rwx if any permission bits are set
     * - Others get permissions based on "other" bits in mode
     *
     * This is a simplified model since Futura OS has simplified uid/gid handling.
     */

    uint32_t file_mode = vnode->mode;

    /* Extract permission bits from file mode (st_mode follows Unix convention:
     * bits 0-8 are permissions: user(6-8), group(3-5), other(0-2) */
    uint32_t other_perms = (file_mode >> 0) & 0x7;   /* rwx for others */

    /* Simplified permission check: use "other" permissions for all users
     * A full implementation would check uid/gid against vnode ownership
     * and apply user/group/other permissions accordingly */
    uint32_t applicable_perms = other_perms;

    /* Check requested access bits */
    if ((mode & R_OK) && !(applicable_perms & 4)) {  /* Read bit */
        fut_printf("[ACCESS] access(%s, R_OK) -> EACCES\n", path_buf);
        return -EACCES;
    }

    if ((mode & W_OK) && !(applicable_perms & 2)) {  /* Write bit */
        fut_printf("[ACCESS] access(%s, W_OK) -> EACCES\n", path_buf);
        return -EACCES;
    }

    if ((mode & X_OK) && !(applicable_perms & 1)) {  /* Execute bit */
        fut_printf("[ACCESS] access(%s, X_OK) -> EACCES\n", path_buf);
        return -EACCES;
    }

    fut_printf("[ACCESS] access(%s, %d) -> 0 (accessible)\n", path_buf, mode);
    return 0;
}
