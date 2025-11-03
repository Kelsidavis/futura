/* kernel/sys_stat.c - File status syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the stat() syscall for retrieving file metadata.
 * Essential for file inspection and access validation.
 *
 * Phase 1 (Completed): Basic file status retrieval with vnode lookup
 * Phase 2 (Current): Enhanced validation, file categorization, and detailed logging
 * Phase 3: Extended attributes (xattr), filesystem-specific metadata
 * Phase 4: Performance optimization (cached stat, bulk stat operations)
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);
extern int fut_copy_from_user(void *to, const void *from, size_t size);
extern int fut_copy_to_user(void *to, const void *from, size_t size);

/* Manual string length calculation */
static size_t manual_strlen(const char *s) {
    size_t len = 0;
    while (s[len] != '\0' && len < 255) {
        len++;
    }
    return len;
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
 * Phase 2 (Current): Enhanced validation, file categorization, detailed logging
 * Phase 3: Extended attributes (xattr), filesystem-specific metadata
 * Phase 4: Performance optimization (cached stat, bulk stat operations)
 */
long sys_stat(const char *path, struct fut_stat *statbuf) {
    /* Phase 2: Validate input pointers */
    if (!path) {
        fut_printf("[STAT] stat(path=NULL, statbuf=%p) -> EINVAL (NULL path)\n",
                   (void *)statbuf);
        return -EINVAL;
    }

    if (!statbuf) {
        fut_printf("[STAT] stat(path=%p, statbuf=NULL) -> EINVAL (NULL statbuf)\n",
                   (const void *)path);
        return -EINVAL;
    }

    /* Copy path from userspace to kernel space */
    char path_buf[256];
    if (fut_copy_from_user(path_buf, path, sizeof(path_buf) - 1) != 0) {
        fut_printf("[STAT] stat(path=?, statbuf=%p) -> EFAULT (copy_from_user failed)\n",
                   (void *)statbuf);
        return -EFAULT;
    }
    path_buf[sizeof(path_buf) - 1] = '\0';

    /* Phase 2: Validate path is not empty */
    if (path_buf[0] == '\0') {
        fut_printf("[STAT] stat(path=\"\" [empty], statbuf=%p) -> EINVAL (empty path)\n",
                   (void *)statbuf);
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

    /* Get file metadata via VFS */
    struct fut_stat kernel_stat;
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

        fut_printf("[STAT] stat(path='%s' [%s, len=%lu], statbuf=%p) -> %d (%s)\n",
                   path_buf, path_type, (unsigned long)path_len, (void *)statbuf,
                   ret, error_desc);
        return ret;
    }

    /* Copy stat buffer to userspace */
    if (fut_copy_to_user(statbuf, &kernel_stat, sizeof(struct fut_stat)) != 0) {
        fut_printf("[STAT] stat(path='%s' [%s, len=%lu]) -> EFAULT "
                   "(copy_to_user failed)\n",
                   path_buf, path_type, (unsigned long)path_len);
        return -EFAULT;
    }

    /* Phase 2: Categorize file type */
    const char *file_type_desc;
    uint32_t mode = kernel_stat.st_mode;

    if ((mode & 0170000) == 0040000) {
        file_type_desc = "directory";
    } else if ((mode & 0170000) == 0100000) {
        file_type_desc = "regular file";
    } else if ((mode & 0170000) == 0120000) {
        file_type_desc = "symbolic link";
    } else if ((mode & 0170000) == 0020000) {
        file_type_desc = "character device";
    } else if ((mode & 0170000) == 0060000) {
        file_type_desc = "block device";
    } else if ((mode & 0170000) == 0010000) {
        file_type_desc = "FIFO/pipe";
    } else if ((mode & 0170000) == 0140000) {
        file_type_desc = "socket";
    } else {
        file_type_desc = "unknown";
    }

    /* Phase 2: Categorize file size */
    const char *size_category;
    if (kernel_stat.st_size == 0) {
        size_category = "empty";
    } else if (kernel_stat.st_size < 1024) {
        size_category = "<1KB";
    } else if (kernel_stat.st_size < 1024 * 1024) {
        size_category = "<1MB";
    } else if (kernel_stat.st_size < 1024 * 1024 * 1024) {
        size_category = "<1GB";
    } else {
        size_category = ">=1GB";
    }

    /* Phase 2: Detailed success logging */
    fut_printf("[STAT] stat(path='%s' [%s, len=%lu], type=%s, size=%llu [%s], "
               "mode=%o, ino=%llu) -> 0 (success, Phase 2)\n",
               path_buf, path_type, (unsigned long)path_len, file_type_desc,
               (unsigned long long)kernel_stat.st_size, size_category,
               kernel_stat.st_mode & 0777, (unsigned long long)kernel_stat.st_ino);

    return 0;
}
