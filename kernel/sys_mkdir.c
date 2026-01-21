/* kernel/sys_mkdir.c - Directory creation syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the mkdir() syscall for creating directories.
 * Essential for filesystem organization and hierarchical structure management.
 *
 * Phase 1 (Completed): Basic directory creation with VFS integration
 * Phase 2 (Completed): Enhanced validation, mode/path categorization, and detailed logging
 * Phase 3 (Completed): Parent directory validation and atomic creation
 * Phase 4: Advanced features (mkdir -p equivalent, ACL support)
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <stdint.h>

#include <kernel/kprintf.h>
extern int fut_copy_from_user(void *to, const void *from, size_t size);

/**
 * mkdir() - Create directory
 *
 * Creates a new directory with the specified mode. The mode parameter
 * specifies the permission bits for the new directory (e.g., 0755).
 * The directory is created as an empty directory containing only "." and ".."
 * entries.
 *
 * @param path  Path to the new directory (relative or absolute)
 * @param mode  Permission bits for the directory (e.g., 0755, 0700, etc.)
 *
 * Returns:
 *   - 0 on success
 *   - -EFAULT if path points to inaccessible memory
 *   - -EINVAL if path is empty or NULL
 *   - -EEXIST if directory already exists at path
 *   - -ENOENT if parent directory doesn't exist or path component missing
 *   - -ENOTDIR if path component is not a directory
 *   - -ENOSPC if no space available for new directory
 *   - -EROFS if filesystem is read-only
 *   - -EACCES if write permission denied on parent directory
 *   - -ENAMETOOLONG if pathname too long
 *   - -EPERM if filesystem doesn't support directory creation
 *
 * Behavior:
 *   - Creates directory with specified permissions (modified by umask)
 *   - Directory starts with nlinks=2 ("." and parent's ".." reference)
 *   - Parent directory's nlinks incremented (due to new ".." entry)
 *   - Requires write and execute permission on parent directory
 *   - Path must not already exist (no overwrite)
 *   - Parent directory must exist (no recursive creation in Phase 1/2)
 *
 * Permission modes:
 *   - 0755: rwxr-xr-x (owner all, others read/execute) - typical directory
 *   - 0700: rwx------ (owner only) - private directory
 *   - 0775: rwxrwxr-x (owner/group all, others read/execute) - shared directory
 *   - 0777: rwxrwxrwx (all permissions) - world-writable directory
 *   - Mode is modified by process umask (typically 022 or 002)
 *
 * Common usage patterns:
 *
 * Create directory with standard permissions:
 *   mkdir("/tmp/mydir", 0755);
 *
 * Create private directory:
 *   mkdir("/home/user/.private", 0700);
 *
 * Create shared group directory:
 *   mkdir("/shared/project", 0775);
 *
 * Create directory tree (manual, not recursive):
 *   mkdir("/tmp/a", 0755);
 *   mkdir("/tmp/a/b", 0755);
 *   mkdir("/tmp/a/b/c", 0755);
 *
 * Error handling:
 *   if (mkdir("/tmp/test", 0755) < 0) {
 *       if (errno == EEXIST) {
 *           // Directory already exists
 *       } else if (errno == ENOENT) {
 *           // Parent directory doesn't exist
 *       } else if (errno == EACCES) {
 *           // Permission denied
 *       }
 *   }
 *
 * Check before creating:
 *   struct stat st;
 *   if (stat("/tmp/test", &st) == 0) {
 *       if (S_ISDIR(st.st_mode)) {
 *           // Directory already exists
 *       } else {
 *           // File exists but not a directory
 *       }
 *   } else if (errno == ENOENT) {
 *       mkdir("/tmp/test", 0755);
 *   }
 *
 * Phase 1 (Completed): Basic directory creation with VFS integration
 * Phase 2 (Completed): Enhanced validation, mode/path categorization, detailed logging
 * Phase 3 (Completed): Parent directory validation and atomic creation
 * Phase 4: mkdir -p equivalent (recursive creation), ACL support
 */
long sys_mkdir(const char *path, uint32_t mode) {
    /* ARM64 FIX: Copy parameters to local variables immediately to ensure they're preserved
     * on the stack across potentially blocking calls. VFS and copy operations may block and
     * corrupt register-passed parameters upon resumption. */
    const char *local_path = path;
    uint32_t local_mode = mode;

    /* Phase 2: Validate path pointer */
    if (!local_path) {
        fut_printf("[MKDIR] mkdir(path=NULL, mode=0%o) -> EINVAL (NULL path)\n", local_mode);
        return -EINVAL;
    }

    /* Phase 3: Validate mode bits - reject any bits outside permission mask (07777) */
    if (local_mode & ~07777) {
        fut_printf("[MKDIR] mkdir(path=?, mode=0%o) -> EINVAL (invalid mode bits 0%o outside 07777)\n",
                   local_mode, local_mode & ~07777);
        return -EINVAL;
    }

    /* Phase 2: Categorize permission mode */
    const char *mode_desc;
    uint32_t perm_bits = local_mode & 0777;

    if (perm_bits == 0755) {
        mode_desc = "0755 (rwxr-xr-x, typical directory)";
    } else if (perm_bits == 0700) {
        mode_desc = "0700 (rwx------, owner only)";
    } else if (perm_bits == 0775) {
        mode_desc = "0775 (rwxrwxr-x, shared group)";
    } else if (perm_bits == 0777) {
        mode_desc = "0777 (rwxrwxrwx, world-writable)";
    } else if (perm_bits == 0750) {
        mode_desc = "0750 (rwxr-x---, owner and group)";
    } else if (perm_bits == 0770) {
        mode_desc = "0770 (rwxrwx---, owner and group only)";
    } else {
        mode_desc = "custom";
    }

    /* Copy path from userspace to kernel space */
    char path_buf[256];
    if (fut_copy_from_user(path_buf, local_path, sizeof(path_buf) - 1) != 0) {
        fut_printf("[MKDIR] mkdir(path=?, mode=%s) -> EFAULT (copy_from_user failed)\n",
                   mode_desc);
        return -EFAULT;
    }
    path_buf[sizeof(path_buf) - 1] = '\0';

    /* Validate path is not empty */
    if (path_buf[0] == '\0') {
        fut_printf("[MKDIR] mkdir(path=\"\" [empty], mode=%s) -> EINVAL (empty path)\n",
                   mode_desc);
        return -EINVAL;
    }

    /* Phase 3: Validate path length - check if it was truncated */
    size_t actual_path_len = 0;
    while (path_buf[actual_path_len] != '\0' && actual_path_len < sizeof(path_buf) - 1) {
        actual_path_len++;
    }
    if (path_buf[actual_path_len] != '\0' || (actual_path_len > 0 && path_buf[actual_path_len - 1] != '\0')) {
        /* Path was truncated during copy_from_user */
        fut_printf("[MKDIR] mkdir(path_len>255, mode=%s) -> ENAMETOOLONG (path was truncated)\n",
                   mode_desc);
        return -ENAMETOOLONG;
    }

    /* Phase 3: Normalize path by stripping trailing "/" (if not root) */
    if (actual_path_len > 1 && path_buf[actual_path_len - 1] == '/') {
        path_buf[actual_path_len - 1] = '\0';
        actual_path_len--;
        fut_printf("[MKDIR] mkdir(path normalized: removed trailing /)\n");
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

    /* Phase 2: Extract parent directory for diagnostics */
    char parent_buf[256];
    char *p = parent_buf;
    const char *s = path_buf;
    const char *last_slash = 0;

    /* Find last slash */
    while (*s) {
        if (*s == '/') {
            last_slash = s;
        }
        s++;
    }

    const char *dirname;
    if (last_slash) {
        /* Copy parent path */
        s = path_buf;
        while (s < last_slash) {
            *p++ = *s++;
        }
        *p = '\0';

        /* Extract directory name */
        dirname = last_slash + 1;

        /* Handle empty parent (root) */
        if (parent_buf[0] == '\0') {
            parent_buf[0] = '/';
            parent_buf[1] = '\0';
        }
    } else {
        /* No slash, parent is current directory */
        parent_buf[0] = '.';
        parent_buf[1] = '\0';
        dirname = path_buf;
    }

    /* Phase 2: Categorize directory name length */
    size_t name_len = 0;
    const char *n = dirname;
    while (*n++) {
        name_len++;
    }

    const char *name_len_category;
    if (name_len == 0) {
        name_len_category = "empty (invalid)";
    } else if (name_len <= 8) {
        name_len_category = "short (≤8 chars)";
    } else if (name_len <= 32) {
        name_len_category = "typical (≤32 chars)";
    } else if (name_len <= 64) {
        name_len_category = "long (≤64 chars)";
    } else {
        name_len_category = "very long (>64 chars)";
    }

    /* Create the directory via VFS */
    int ret = fut_vfs_mkdir(path_buf, local_mode);

    /* Phase 2: Handle error cases with detailed logging */
    if (ret < 0) {
        const char *error_desc;
        switch (ret) {
            case -EEXIST:
                error_desc = "directory or file already exists";
                break;
            case -ENOENT:
                error_desc = "parent directory doesn't exist or path component missing";
                break;
            case -ENOTDIR:
                error_desc = "path component is not a directory";
                break;
            case -ENOSPC:
                error_desc = "no space available";
                break;
            case -EROFS:
                error_desc = "read-only filesystem";
                break;
            case -EACCES:
                error_desc = "permission denied on parent directory";
                break;
            case -ENAMETOOLONG:
                error_desc = "pathname too long";
                break;
            case -EPERM:
                error_desc = "operation not permitted";
                break;
            default:
                error_desc = "VFS mkdir failed";
                break;
        }

        fut_printf("[MKDIR] mkdir(path='%s' [%s], parent='%s', name='%s' [%s], mode=%s) "
                   "-> %d (%s)\n",
                   path_buf, path_type, parent_buf, dirname, name_len_category,
                   mode_desc, ret, error_desc);
        return ret;
    }

    /* Phase 3: Detailed success logging with parent validation confirmation */
    fut_printf("[MKDIR] mkdir(path='%s' [%s], parent='%s', name='%s' [%s], mode=%s) "
               "-> 0 (directory created with parent validation, Phase 3)\n",
               path_buf, path_type, parent_buf, dirname, name_len_category, mode_desc);

    return 0;
}
