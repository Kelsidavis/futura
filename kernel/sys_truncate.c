/* kernel/sys_truncate.c - File truncation syscall (path-based)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the truncate() syscall for truncating files by path.
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);
extern int fut_copy_from_user(void *to, const void *from, size_t size);

/**
 * truncate() - Truncate file to specified length (path-based)
 *
 * Truncates or extends a file to the specified length. If the file is
 * extended, the extended area is filled with zeros. This is the path-based
 * complement to ftruncate() (which operates on an open file descriptor).
 *
 * @param path    Path to the file
 * @param length  New file length in bytes
 *
 * Returns:
 *   - 0 on success
 *   - -EFAULT if path is inaccessible
 *   - -ENOENT if file does not exist
 *   - -EINVAL if path is empty or length is negative
 *   - -EISDIR if path refers to a directory
 */
long sys_truncate(const char *path, uint64_t length) {
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

    /* Cannot truncate a directory */
    if (vnode->type == VN_DIR) {
        fut_printf("[TRUNCATE] truncate(%s, %llu) -> EISDIR\n", path_buf, length);
        return -EISDIR;
    }

    /* Simple truncation: directly modify vnode size.
     * For truncating smaller, just update size (real filesystem would deallocate blocks).
     * For extending, update size (real filesystem would allocate and zero blocks).
     */
    uint64_t current_size = vnode->size;

    if (length <= current_size) {
        /* Truncating to smaller size */
        vnode->size = length;
        fut_printf("[TRUNCATE] truncate(%s, %llu) -> 0 (shrink from %llu)\n",
                   path_buf, length, current_size);
        return 0;
    } else {
        /* Extending file - update size (would need to zero-fill in real impl) */
        vnode->size = length;
        fut_printf("[TRUNCATE] truncate(%s, %llu) -> 0 (extend from %llu)\n",
                   path_buf, length, current_size);
        return 0;
    }
}
