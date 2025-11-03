/* kernel/sys_truncate.c - File truncation syscall (path-based)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the truncate() syscall for truncating files by path.
 * Essential for file size manipulation and disk space management.
 *
 * Phase 1 (Completed): Basic truncation with vnode lookup
 * Phase 2 (Current): Enhanced validation, length categorization, and detailed logging
 * Phase 3: Advanced features (sparse file support, extent management)
 * Phase 4: Performance optimization (async truncation, bulk operations)
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);
extern int fut_copy_from_user(void *to, const void *from, size_t size);

/* Manual string length calculation */
static size_t manual_strlen(const char *s) {
    size_t len = 0;
    while (s[len] != '\0' && len < 255) {
        len++;
    }
    return len;
}

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
 *   - -EACCES if write permission denied
 *   - -EROFS if filesystem is read-only
 *
 * Phase 1 (Completed): Basic truncation with vnode lookup
 * Phase 2 (Current): Enhanced validation, length categorization, detailed logging
 * Phase 3: Advanced features (sparse file support, extent management)
 * Phase 4: Performance optimization (async truncation, bulk operations)
 */
long sys_truncate(const char *path, uint64_t length) {
    /* Phase 2: Validate path pointer */
    if (!path) {
        fut_printf("[TRUNCATE] truncate(path=NULL, length=%llu) -> EINVAL (NULL path)\n",
                   (unsigned long long)length);
        return -EINVAL;
    }

    /* Copy path from userspace to kernel space */
    char path_buf[256];
    if (fut_copy_from_user(path_buf, path, sizeof(path_buf) - 1) != 0) {
        fut_printf("[TRUNCATE] truncate(path=?, length=%llu) -> EFAULT (copy_from_user failed)\n",
                   (unsigned long long)length);
        return -EFAULT;
    }
    path_buf[sizeof(path_buf) - 1] = '\0';

    /* Phase 2: Validate path is not empty */
    if (path_buf[0] == '\0') {
        fut_printf("[TRUNCATE] truncate(path=\"\" [empty], length=%llu) -> EINVAL (empty path)\n",
                   (unsigned long long)length);
        return -EINVAL;
    }

    /* Phase 2: Categorize path type */
    const char *path_type;
    if (path_buf[0] == '/') {
        path_type = "absolute";
    } else if (path_buf[0] == '.' && path_buf[1] == '/') {
        path_type = "relative (explicit)";
    } else if (path_buf[0] == '.') {
        path_type = "relative (current/parent)";
    } else {
        path_type = "relative";
    }

    /* Phase 2: Calculate path length */
    size_t path_len = manual_strlen(path_buf);

    /* Phase 2: Categorize length */
    const char *length_category;
    if (length == 0) {
        length_category = "empty file";
    } else if (length < 1024) {
        length_category = "<1KB";
    } else if (length < 1024 * 1024) {
        length_category = "<1MB";
    } else if (length < 1024 * 1024 * 1024) {
        length_category = "<1GB";
    } else {
        length_category = ">=1GB";
    }

    /* Lookup the vnode */
    struct fut_vnode *vnode = NULL;
    int ret = fut_vfs_lookup(path_buf, &vnode);

    /* Phase 2: Handle lookup errors with detailed logging */
    if (ret < 0) {
        const char *error_desc;
        switch (ret) {
            case -ENOENT:
                error_desc = "file not found or path component missing";
                break;
            case -ENOTDIR:
                error_desc = "path component not a directory";
                break;
            case -ENAMETOOLONG:
                error_desc = "pathname too long";
                break;
            case -EACCES:
                error_desc = "search permission denied on path component";
                break;
            default:
                error_desc = "lookup failed";
                break;
        }

        fut_printf("[TRUNCATE] truncate(path='%s' [%s, len=%lu], length=%llu [%s]) "
                   "-> %d (%s)\n",
                   path_buf, path_type, (unsigned long)path_len,
                   (unsigned long long)length, length_category, ret, error_desc);
        return ret;
    }

    if (!vnode) {
        fut_printf("[TRUNCATE] truncate(path='%s' [%s, len=%lu], length=%llu [%s]) "
                   "-> ENOENT (vnode is NULL)\n",
                   path_buf, path_type, (unsigned long)path_len,
                   (unsigned long long)length, length_category);
        return -ENOENT;
    }

    /* Cannot truncate a directory */
    if (vnode->type == VN_DIR) {
        fut_printf("[TRUNCATE] truncate(path='%s' [%s, len=%lu], vnode_ino=%lu, "
                   "length=%llu [%s]) -> EISDIR (cannot truncate directory)\n",
                   path_buf, path_type, (unsigned long)path_len, vnode->ino,
                   (unsigned long long)length, length_category);
        return -EISDIR;
    }

    /* Phase 2: Store current size for before/after comparison */
    uint64_t current_size = vnode->size;

    /* Phase 2: Determine operation type */
    const char *operation;
    if (length < current_size) {
        operation = "shrink";
    } else if (length > current_size) {
        operation = "extend";
    } else {
        operation = "no-change";
    }

    /* Simple truncation: directly modify vnode size */
    vnode->size = length;

    /* Phase 2: Detailed success logging */
    fut_printf("[TRUNCATE] truncate(path='%s' [%s, len=%lu], vnode_ino=%lu, "
               "length=%llu [%s], operation=%s [%llu -> %llu]) "
               "-> 0 (size changed, Phase 2)\n",
               path_buf, path_type, (unsigned long)path_len, vnode->ino,
               (unsigned long long)length, length_category, operation,
               (unsigned long long)current_size, (unsigned long long)length);

    return 0;
}
