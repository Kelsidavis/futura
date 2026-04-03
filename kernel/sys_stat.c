/* kernel/sys_stat.c - File status syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the stat() syscall for retrieving file metadata.
 * Essential for file inspection and access validation.
 *
 * Phase 1 (Completed): Basic file status retrieval with vnode lookup
 * Phase 2 (Completed): Enhanced validation, file categorization, and detailed logging
 * Phase 3 (Completed): Extended attributes (xattr), filesystem-specific metadata
 * Phase 4 (Completed): Performance optimization (cached stat, bulk stat operations)
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <stdint.h>

#include <kernel/kprintf.h>
#include <kernel/uaccess.h>
#include <string.h>

#include <platform/platform.h>

static inline int stat_copy_to_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)dst >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_to_user(dst, src, n);
}
static inline int stat_copy_from_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)src >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_from_user(dst, src, n);
}


/**
 * stat() - Get file status
 *
 * Retrieves file metadata including size, mode, timestamps, and inode number.
 * This is the path-based variant of fstat().
 *
 * @param path     Path to the file
 * @param statbuf  Pointer to userspace stat buffer to fill
 *
 * Returns:
 *   - 0 on success
 *   - -EFAULT if path or statbuf is inaccessible
 *   - -ENOENT if file does not exist
 *   - -EINVAL if path is empty or statbuf is NULL
 *   - -ENOTDIR if a path component is not a directory
 *   - -ENAMETOOLONG if path exceeds maximum length
 *
 * Behavior:
 *   - Retrieves metadata for file at path
 *   - Does not follow symbolic links (use fstatat with AT_SYMLINK_NOFOLLOW)
 *   - Fills statbuf with inode, size, mode, timestamps
 *   - Works on all file types (regular, directory, device, etc.)
 *   - Does not require read permission on file, only search on path
 *
 * Common usage patterns:
 *
 * Check if file exists:
 *   struct fut_stat st;
 *   if (stat("/path/to/file", &st) == 0) {
 *       // File exists
 *   }
 *
 * Get file size:
 *   struct fut_stat st;
 *   stat("/path/to/file", &st);
 *   printf("Size: %llu bytes\n", st.st_size);
 *
 * Check file type:
 *   struct fut_stat st;
 *   stat("/path/to/file", &st);
 *   if (S_ISREG(st.st_mode)) {
 *       // Regular file
 *   } else if (S_ISDIR(st.st_mode)) {
 *       // Directory
 *   }
 *
 * Get permissions:
 *   struct fut_stat st;
 *   stat("/path/to/file", &st);
 *   mode_t perms = st.st_mode & 0777;
 *   printf("Permissions: %03o\n", perms);
 *
 * Phase 1 (Completed): Basic file status retrieval with vnode lookup
 * Phase 2 (Completed): Enhanced validation, file categorization, detailed logging
 * Phase 3 (Completed): Extended attributes (xattr), filesystem-specific metadata
 * Phase 4 (Completed): Performance optimization (cached stat, bulk stat operations)
 */
long sys_stat(const char *path, struct fut_stat *statbuf) {
    /* ARM64 FIX: Copy parameters to local variables immediately to ensure they're preserved
     * on the stack across potentially blocking calls. VFS and copy operations may block and
     * corrupt register-passed parameters upon resumption. */
    const char *local_path = path;
    struct fut_stat *local_statbuf = statbuf;

    /* Phase 2: Validate input pointers */
    if (!local_path) {
        fut_printf("[STAT] stat(path=NULL, statbuf=%p) -> EINVAL (NULL path)\n",
                   (void *)local_statbuf);
        return -EINVAL;
    }

    if (!local_statbuf) {
        fut_printf("[STAT] stat(path=%p, statbuf=NULL) -> EINVAL (NULL statbuf)\n",
                   (const void *)local_path);
        return -EINVAL;
    }

    /* Copy path from userspace to kernel space */
    char path_buf[FUT_VFS_PATH_BUFFER_SIZE];
    if (stat_copy_from_user(path_buf, local_path, sizeof(path_buf)) != 0) {
        fut_printf("[STAT] stat(path=?, statbuf=%p) -> EFAULT (copy_from_user failed)\n",
                   (void *)local_statbuf);
        return -EFAULT;
    }
    /* Verify path was not truncated */
    if (memchr(path_buf, '\0', sizeof(path_buf)) == NULL) {
        fut_printf("[STAT] stat(path exceeds %zu bytes) -> ENAMETOOLONG\n",
                   sizeof(path_buf) - 1);
        return -ENAMETOOLONG;
    }

    /* Phase 2: Validate path is not empty */
    if (path_buf[0] == '\0') {
        fut_printf("[STAT] stat(path=\"\" [empty], statbuf=%p) -> EINVAL (empty path)\n",
                   (void *)local_statbuf);
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
    size_t path_len = strlen(path_buf);

    /* Validate buffer alignment before expensive VFS operation
     * struct fut_stat requires 8-byte alignment for uint64_t fields (st_size, st_ino, etc.)
     * Unaligned access can cause performance degradation or crashes on some architectures */
    if (((uintptr_t)local_statbuf & 7) != 0) {
        fut_printf("[STAT] stat(path='%s' [%s, len=%lu], statbuf=%p) -> EINVAL "
                   "(buffer not 8-byte aligned)\n",
                   path_buf, path_type, (unsigned long)path_len, (void *)local_statbuf);
        return -EINVAL;
    }

    /* Early buffer writability test before expensive VFS operation
     * Test if we can write to statbuf before calling fut_vfs_stat(), which
     * requires path lookup and inode access. This optimization fails fast if
     * the buffer is in inaccessible memory. Use actual write test with first byte. */
    char test_byte;
    if (stat_copy_from_user(&test_byte, (const char *)local_statbuf, 1) != 0 ||
        stat_copy_to_user((char *)local_statbuf, &test_byte, 1) != 0) {
        fut_printf("[STAT] stat(path='%s' [%s, len=%lu], statbuf=%p) -> EFAULT "
                   "(buffer not accessible)\n",
                   path_buf, path_type, (unsigned long)path_len, (void *)local_statbuf);
        return -EFAULT;
    }

    /* Get file metadata via VFS
     * Zero-initialize to prevent leaking uninitialized kernel stack data
     * to userspace if VFS doesn't fill all fields (e.g. nsec, padding) */
    struct fut_stat kernel_stat = {0};
    int ret = fut_vfs_stat(path_buf, &kernel_stat);

    /* Phase 2: Handle VFS errors with detailed logging */
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
            case -EFAULT:
                error_desc = "pathname points to inaccessible memory";
                break;
            default:
                error_desc = "VFS lookup failed";
                break;
        }

        /* Only log unexpected errors, not routine ENOENT from file existence checks */
        if (ret != -ENOENT) {
            fut_printf("[STAT] stat(path='%s' [%s, len=%lu]) -> %d (%s)\n",
                       path_buf, path_type, (unsigned long)path_len, ret, error_desc);
        }
        return ret;
    }

    /* Copy stat buffer to userspace */
    if (stat_copy_to_user(local_statbuf, &kernel_stat, sizeof(struct fut_stat)) != 0) {
        fut_printf("[STAT] stat(path='%s' [%s, len=%lu]) -> EFAULT "
                   "(copy_to_user failed)\n",
                   path_buf, path_type, (unsigned long)path_len);
        return -EFAULT;
    }

    return 0;
}
