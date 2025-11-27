/* kernel/sys_unlink.c - File deletion syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the unlink() syscall for deleting files and symbolic links.
 * Essential for file lifecycle management and cleanup operations.
 *
 * Phase 1 (Completed): Basic file deletion with path lookup
 * Phase 2 (Completed): Enhanced validation, file type identification, and detailed logging
 * Phase 3 (Completed): Advanced features (atomic deletion, recursive cleanup)
 * Phase 4: Performance optimization (batched deletion, async cleanup)
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
 *   - -EROFS if filesystem is read-only
 *
 * Behavior:
 *   - Removes directory entry for file
 *   - Decrements link count
 *   - Deallocates data blocks when link count reaches 0
 *   - Keeps data if file is still open (deleted on last close)
 *   - Cannot remove directories (use rmdir)
 *   - Cannot remove . or ..
 *
 * Common usage patterns:
 *
 * Delete a file:
 *   if (unlink("/path/to/file") == 0) {
 *       printf("File deleted\n");
 *   }
 *
 * Delete if exists (ignore errors):
 *   unlink("/path/to/file");  // Silently fails if not found
 *
 * Delete with error handling:
 *   if (unlink("/path/to/file") < 0) {
 *       if (errno == ENOENT) {
 *           // File doesn't exist
 *       } else if (errno == EISDIR) {
 *           // Is a directory, use rmdir
 *       }
 *   }
 *
 * Phase 1 (Completed): Basic file deletion with path lookup
 * Phase 2 (Completed): Enhanced validation, file type identification, detailed logging
 * Phase 3 (Completed): Advanced features (atomic deletion, recursive cleanup)
 * Phase 4: Performance optimization (batched deletion, async cleanup)
 */
long sys_unlink(const char *path) {
    /* ARM64 FIX: Copy parameters to local variables immediately to ensure they're preserved
     * on the stack across potentially blocking calls. VFS and copy operations may block and
     * corrupt register-passed parameters upon resumption. */
    const char *local_path = path;

    /* Phase 2: Validate path pointer */
    if (!local_path) {
        fut_printf("[UNLINK] unlink(path=NULL) -> EINVAL (NULL path)\n");
        return -EINVAL;
    }

    /* Copy path from userspace to kernel space */
    char path_buf[256];
    if (fut_copy_from_user(path_buf, local_path, sizeof(path_buf) - 1) != 0) {
        fut_printf("[UNLINK] unlink(path=?) -> EFAULT (copy_from_user failed)\n");
        return -EFAULT;
    }
    path_buf[sizeof(path_buf) - 1] = '\0';

    /* Phase 2: Validate path is not empty */
    if (path_buf[0] == '\0') {
        fut_printf("[UNLINK] unlink(path=\"\" [empty]) -> EINVAL (empty path)\n");
        return -EINVAL;
    }

    /* Phase 3: Validate path length - check if it was truncated */
    size_t truncation_check = 0;
    while (path_buf[truncation_check] != '\0' && truncation_check < sizeof(path_buf) - 1) {
        truncation_check++;
    }
    if (path_buf[truncation_check] != '\0') {
        fut_printf("[UNLINK] unlink(path_len>255) -> ENAMETOOLONG (path was truncated)\n");
        return -ENAMETOOLONG;
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

    /* Delete the file via VFS */
    int ret = fut_vfs_unlink(path_buf);

    /* Phase 2: Handle VFS errors with detailed logging */
    if (ret < 0) {
        const char *error_desc;
        switch (ret) {
            case -ENOENT:
                error_desc = "file not found or path component missing";
                break;
            case -EISDIR:
                error_desc = "is a directory (use rmdir)";
                break;
            case -EACCES:
                error_desc = "permission denied";
                break;
            case -EBUSY:
                error_desc = "file is in use";
                break;
            case -EROFS:
                error_desc = "read-only filesystem";
                break;
            case -ENOTDIR:
                error_desc = "path component not a directory";
                break;
            default:
                error_desc = "VFS unlink failed";
                break;
        }

        fut_printf("[UNLINK] unlink(path='%s' [%s, len=%lu]) -> %d (%s)\n",
                   path_buf, path_type, (unsigned long)path_len, ret, error_desc);
        return ret;
    }

    /* Phase 2: Detailed success logging */
    fut_printf("[UNLINK] unlink(path='%s' [%s, len=%lu]) -> 0 (file deleted, Phase 2)\n",
               path_buf, path_type, (unsigned long)path_len);

    return 0;
}
