/* kernel/sys_rmdir.c - Directory removal syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the rmdir() syscall for removing empty directories.
 * Essential for directory management and filesystem cleanup.
 *
 * Phase 1 (Completed): Basic directory removal with VFS integration
 * Phase 2 (Completed): Enhanced validation, path categorization, and detailed logging
 * Phase 3 (Completed): VFS directory removal operation
 * Phase 4: Performance optimization (batch removal, inode cache integration)
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
 * This is essential for filesystem cleanup and directory hierarchy management.
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
 *   - -EACCES if search permission denied on path component
 *   - -EPERM if operation not permitted (e.g., trying to remove /)
 *   - -EROFS if filesystem is read-only
 *
 * Behavior:
 *   - Removes empty directories only
 *   - Directory must contain only . and .. entries
 *   - Cannot remove current working directory
 *   - Cannot remove root directory (/)
 *   - Cannot remove . or .. special entries
 *   - Requires write and execute permission on parent directory
 *   - Updates parent directory's modification time
 *   - Decrements parent directory's link count
 *
 * Directory emptiness check:
 *   - Directory is empty if it contains only . and ..
 *   - Even hidden files prevent removal
 *   - Subdirectories prevent removal
 *   - Empty files prevent removal
 *
 * Common usage patterns:
 *
 * Remove empty directory:
 *   if (rmdir("/tmp/olddir") == 0) {
 *       // Directory successfully removed
 *   }
 *
 * Cleanup directory tree (must be done leaf-first):
 *   rmdir("/tmp/project/subdir1");
 *   rmdir("/tmp/project/subdir2");
 *   rmdir("/tmp/project");  // Remove parent last
 *
 * Check if directory is empty before removal:
 *   DIR *d = opendir(path);
 *   int count = 0;
 *   while (readdir(d)) count++;
 *   closedir(d);
 *   if (count == 2) {  // Only . and ..
 *       rmdir(path);
 *   }
 *
 * Safe directory removal with error handling:
 *   if (rmdir(path) < 0) {
 *       if (errno == ENOTEMPTY) {
 *           printf("Directory not empty\n");
 *       } else if (errno == EBUSY) {
 *           printf("Directory in use\n");
 *       } else if (errno == ENOTDIR) {
 *           printf("Not a directory\n");
 *       }
 *   }
 *
 * Temporary directory cleanup:
 *   char tmpdir[256];
 *   snprintf(tmpdir, sizeof(tmpdir), "/tmp/build-%d", getpid());
 *   // ... use tmpdir ...
 *   rmdir(tmpdir);  // Clean up when done
 *
 * Cannot remove patterns (will fail):
 *   - rmdir("/")              -> EPERM (root directory)
 *   - rmdir(".")              -> EINVAL (current directory)
 *   - rmdir("..")             -> EINVAL (parent directory)
 *   - rmdir("/tmp/nonempty")  -> ENOTEMPTY (has files)
 *   - rmdir("/home/user")     -> EBUSY (process cwd)
 *
 * Related syscalls:
 *   - mkdir(): Create directory
 *   - unlink(): Remove file (not directory)
 *   - rename(): Move directory
 *   - unlinkat(): Remove directory with flags (AT_REMOVEDIR)
 *
 * Security considerations:
 *   - Check write permission on parent directory
 *   - Prevent removal of directories in use
 *   - Prevent removal of root directory
 *   - Check for symbolic link attacks
 *
 * Phase 1 (Completed): Basic directory removal with VFS integration
 * Phase 2 (Completed): Enhanced validation, path categorization, detailed logging
 * Phase 3 (Completed): VFS directory removal operation
 * Phase 4: Performance optimization (batch removal, inode cache integration)
 */
long sys_rmdir(const char *path) {
    /* ARM64 FIX: Copy parameters to local variables immediately to ensure they're preserved
     * on the stack across potentially blocking calls. VFS and copy operations may block and
     * corrupt register-passed parameters upon resumption. */
    const char *local_path = path;

    /* Phase 2: Validate path pointer */
    if (!local_path) {
        fut_printf("[RMDIR] rmdir(path=NULL) -> EINVAL (NULL path)\n");
        return -EINVAL;
    }

    /* Copy path from userspace to kernel space */
    char path_buf[256];
    if (fut_copy_from_user(path_buf, local_path, sizeof(path_buf) - 1) != 0) {
        fut_printf("[RMDIR] rmdir(path=?) -> EFAULT (copy_from_user failed)\n");
        return -EFAULT;
    }
    path_buf[sizeof(path_buf) - 1] = '\0';

    /* Phase 2: Validate path is not empty */
    if (path_buf[0] == '\0') {
        fut_printf("[RMDIR] rmdir(path=\"\" [empty]) -> EINVAL (empty path)\n");
        return -EINVAL;
    }

    /* Phase 2: Categorize path type */
    const char *path_type;
    if (path_buf[0] == '/') {
        path_type = "absolute";
    } else if (path_buf[0] == '.' && path_buf[1] == '\0') {
        path_type = "current (.)";
    } else if (path_buf[0] == '.' && path_buf[1] == '.' && path_buf[2] == '\0') {
        path_type = "parent (..)";
    } else if (path_buf[0] == '.' && path_buf[1] == '/') {
        path_type = "relative (explicit)";
    } else if (path_buf[0] == '.') {
        path_type = "relative (current/parent)";
    } else {
        path_type = "relative";
    }

    /* Phase 2: Validate not attempting to remove . or .. */
    if ((path_buf[0] == '.' && path_buf[1] == '\0') ||
        (path_buf[0] == '.' && path_buf[1] == '.' && path_buf[2] == '\0')) {
        fut_printf("[RMDIR] rmdir(path='%s' [%s]) -> EINVAL (cannot remove . or ..)\n",
                   path_buf, path_type);
        return -EINVAL;
    }

    /* Phase 3: Prevent removal of root directory */
    if (path_buf[0] == '/' && path_buf[1] == '\0') {
        fut_printf("[RMDIR] rmdir(path='/' [root]) -> EPERM (cannot remove root directory)\n");
        return -EPERM;
    }

    /* Phase 2: Calculate path length for categorization */
    size_t path_len = 0;
    while (path_buf[path_len] != '\0' && path_len < 256) {
        path_len++;
    }

    /* Phase 2: Categorize path length */
    const char *length_category;
    if (path_len == 1 && path_buf[0] == '/') {
        length_category = "root (/)";
    } else if (path_len <= 16) {
        length_category = "short (≤16 chars)";
    } else if (path_len <= 64) {
        length_category = "medium (≤64 chars)";
    } else if (path_len <= 128) {
        length_category = "long (≤128 chars)";
    } else {
        length_category = "very long (>128 chars)";
    }

    /* Remove the directory via VFS */
    int ret = fut_vfs_rmdir(path_buf);

    /* Phase 2: Handle VFS errors with detailed logging */
    if (ret < 0) {
        const char *error_desc;
        switch (ret) {
            case -ENOENT:
                error_desc = "directory not found";
                break;
            case -ENOTDIR:
                error_desc = "path is not a directory";
                break;
            case -ENOTEMPTY:
                error_desc = "directory not empty";
                break;
            case -EBUSY:
                error_desc = "directory in use (cwd of process)";
                break;
            case -EACCES:
                error_desc = "permission denied";
                break;
            case -EPERM:
                error_desc = "operation not permitted";
                break;
            case -EROFS:
                error_desc = "read-only filesystem";
                break;
            case -ENAMETOOLONG:
                error_desc = "pathname too long";
                break;
            default:
                error_desc = "VFS error";
                break;
        }

        fut_printf("[RMDIR] rmdir(path='%s' [%s, %s]) -> %d (%s)\n",
                   path_buf, path_type, length_category, ret, error_desc);
        return ret;
    }

    /* Phase 3: Detailed success logging */
    fut_printf("[RMDIR] rmdir(path='%s' [%s, %s]) -> 0 (Phase 3: VFS directory removal operation)\n",
               path_buf, path_type, length_category);
    return 0;
}
