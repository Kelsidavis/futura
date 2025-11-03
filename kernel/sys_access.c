/* kernel/sys_access.c - File accessibility check syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements access() for checking file accessibility and permissions.
 * Essential for permission checking before file operations.
 *
 * Phase 1 (Completed): Basic file existence and permission checking
 * Phase 2 (Current): Enhanced validation, mode identification, and detailed logging
 * Phase 3: Advanced permission models (uid/gid checking, ACLs)
 * Phase 4: Performance optimization (permission caching)
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
 * access() - Check file accessibility and permissions
 *
 * Checks whether the calling process has access to the file at pathname.
 * Unlike open(), this checks permissions using the process's real UID/GID
 * rather than effective UID/GID, making it suitable for setuid programs
 * checking if the invoking user has access.
 *
 * @param pathname Path to the file (relative or absolute)
 * @param mode     Accessibility mode to check (F_OK, R_OK, W_OK, X_OK, or combination)
 *
 * Returns:
 *   - 0 if file is accessible with requested permissions
 *   - -EACCES if permission denied or search permission denied on path component
 *   - -EFAULT if pathname points to inaccessible memory
 *   - -EINVAL if pathname is NULL, empty, or mode contains invalid bits
 *   - -ENOENT if file does not exist or path component missing
 *   - -ENAMETOOLONG if pathname too long
 *   - -ENOTDIR if component of path prefix is not a directory
 *
 * Behavior:
 *   - Checks access using real UID/GID (not effective UID/GID)
 *   - mode is bitmask: can combine R_OK | W_OK | X_OK
 *   - F_OK checks file existence only (mode == 0)
 *   - Does not follow symbolic links if AT_SYMLINK_NOFOLLOW (faccessat)
 *   - Returns success if all requested permissions available
 *   - Returns -EACCES if any requested permission unavailable
 *
 * Mode bits:
 *   - F_OK (0): Check file existence only
 *   - R_OK (4): Check read permission (bit 2)
 *   - W_OK (2): Check write permission (bit 1)
 *   - X_OK (1): Check execute permission (bit 0)
 *   - R_OK | W_OK: Check both read and write
 *   - R_OK | W_OK | X_OK: Check all permissions
 *
 * Permission model (simplified):
 *   - Uses file mode bits (Unix permission model)
 *   - Checks "other" permission bits (bits 0-2)
 *   - Full implementation would check uid/gid ownership
 *   - Future: implement proper user/group/other permission checking
 *
 * Common usage patterns:
 *
 * Check if file exists:
 *   if (access("/path/to/file", F_OK) == 0) {
 *       // File exists
 *   }
 *
 * Check if file is readable:
 *   if (access("/path/to/file", R_OK) == 0) {
 *       // File is readable, safe to open for reading
 *   }
 *
 * Check if file is writable:
 *   if (access("/path/to/file", W_OK) == 0) {
 *       // File is writable
 *   }
 *
 * Check multiple permissions:
 *   if (access("/path/to/script", R_OK | X_OK) == 0) {
 *       // File is readable and executable
 *       exec("/path/to/script");
 *   }
 *
 * Check before open (race condition):
 *   // WARNING: This pattern has TOCTOU race condition
 *   if (access("/tmp/file", W_OK) == 0) {
 *       // Between this check and open(), permissions could change
 *       int fd = open("/tmp/file", O_WRONLY);
 *   }
 *   // Better: Just try open() and handle error
 *
 * Setuid program checking real user permissions:
 *   // In setuid program: check if real user (not effective user) has access
 *   if (access("/etc/shadow", R_OK) != 0) {
 *       printf("Real user cannot read /etc/shadow\n");
 *   }
 *
 * Directory traversal check:
 *   if (access("/var/log/app", X_OK) == 0) {
 *       // Can traverse into directory
 *   }
 *
 * TOCTOU warning:
 *   - access() followed by open() has time-of-check-to-time-of-use race
 *   - File permissions can change between access() and open()
 *   - Prefer: Just call open() and handle -EACCES error
 *   - Use access() for informational purposes, not security decisions
 *
 * Phase 1 (Completed): Basic file existence and permission checking
 * Phase 2 (Current): Enhanced validation, mode identification, detailed logging
 * Phase 3: Advanced permission models (uid/gid checking, ACLs)
 * Phase 4: Performance optimization (permission caching)
 */
long sys_access(const char *pathname, int mode) {
    /* Phase 2: Validate pathname pointer */
    if (!pathname) {
        fut_printf("[ACCESS] access(pathname=NULL, mode=%d) -> EINVAL (NULL pathname)\n", mode);
        return -EINVAL;
    }

    /* Phase 2: Categorize mode bits */
    const char *mode_desc;
    int mode_bits = mode & (R_OK | W_OK | X_OK);

    if (mode == F_OK) {
        mode_desc = "F_OK (existence only)";
    } else if (mode_bits == R_OK) {
        mode_desc = "R_OK (read)";
    } else if (mode_bits == W_OK) {
        mode_desc = "W_OK (write)";
    } else if (mode_bits == X_OK) {
        mode_desc = "X_OK (execute)";
    } else if (mode_bits == (R_OK | W_OK)) {
        mode_desc = "R_OK|W_OK (read+write)";
    } else if (mode_bits == (R_OK | X_OK)) {
        mode_desc = "R_OK|X_OK (read+execute)";
    } else if (mode_bits == (W_OK | X_OK)) {
        mode_desc = "W_OK|X_OK (write+execute)";
    } else if (mode_bits == (R_OK | W_OK | X_OK)) {
        mode_desc = "R_OK|W_OK|X_OK (all permissions)";
    } else {
        mode_desc = "unknown";
    }

    /* Phase 2: Validate mode contains only valid bits */
    if (mode & ~(F_OK | R_OK | W_OK | X_OK)) {
        fut_printf("[ACCESS] access(pathname=?, mode=0x%x [%s]) -> EINVAL "
                   "(invalid mode bits)\n", mode, mode_desc);
        return -EINVAL;
    }

    /* Copy pathname from userspace to kernel space */
    char path_buf[256];
    if (fut_copy_from_user(path_buf, pathname, sizeof(path_buf) - 1) != 0) {
        fut_printf("[ACCESS] access(pathname=?, mode=%s) -> EFAULT "
                   "(copy_from_user failed)\n", mode_desc);
        return -EFAULT;
    }
    path_buf[sizeof(path_buf) - 1] = '\0';

    /* Phase 2: Validate pathname is not empty */
    if (path_buf[0] == '\0') {
        fut_printf("[ACCESS] access(pathname=\"\" [empty], mode=%s) -> EINVAL "
                   "(empty pathname)\n", mode_desc);
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

        fut_printf("[ACCESS] access(path='%s' [%s], mode=%s) -> %d (%s)\n",
                   path_buf, path_type, mode_desc, ret, error_desc);
        return ret;
    }

    if (!vnode) {
        fut_printf("[ACCESS] access(path='%s' [%s], mode=%s) -> ENOENT "
                   "(vnode is NULL)\n", path_buf, path_type, mode_desc);
        return -ENOENT;
    }

    /* Phase 2: F_OK just checks if file exists (already verified) */
    if (mode == F_OK) {
        fut_printf("[ACCESS] access(path='%s' [%s], mode=%s) -> 0 "
                   "(file exists, Phase 2)\n", path_buf, path_type, mode_desc);
        return 0;
    }

    /* Get current task for permission checking */
    fut_task_t *current = fut_task_current();
    if (!current) {
        fut_printf("[ACCESS] access(path='%s' [%s], mode=%s) -> EACCES "
                   "(no current task)\n", path_buf, path_type, mode_desc);
        return -EACCES;
    }

    /* Phase 2: Check permissions based on mode bits
     *
     * For simplicity, we use a basic permission model:
     * - Uses "other" permission bits (bits 0-2) from file mode
     * - Full implementation would check uid/gid against vnode ownership
     * - Future Phase 3: Implement proper user/group/other permission checking
     */

    uint32_t file_mode = vnode->mode;

    /* Extract permission bits from file mode (st_mode follows Unix convention:
     * bits 0-8 are permissions: user(6-8), group(3-5), other(0-2) */
    uint32_t other_perms = (file_mode >> 0) & 0x7;   /* rwx for others */

    /* Simplified permission check: use "other" permissions for all users
     * A full implementation would check uid/gid against vnode ownership
     * and apply user/group/other permissions accordingly */
    uint32_t applicable_perms = other_perms;

    /* Phase 2: Build permission check description */
    char perm_check_buf[64];
    char *p = perm_check_buf;
    int perm_count = 0;

    if (mode & R_OK) {
        if (perm_count++ > 0) {
            *p++ = '+';
        }
        const char *s = "read";
        while (*s) *p++ = *s++;
    }
    if (mode & W_OK) {
        if (perm_count++ > 0) {
            *p++ = '+';
        }
        const char *s = "write";
        while (*s) *p++ = *s++;
    }
    if (mode & X_OK) {
        if (perm_count++ > 0) {
            *p++ = '+';
        }
        const char *s = "execute";
        while (*s) *p++ = *s++;
    }
    *p = '\0';

    /* Phase 2: Check each requested permission with detailed logging */
    if ((mode & R_OK) && !(applicable_perms & 4)) {  /* Read bit */
        fut_printf("[ACCESS] access(path='%s' [%s], mode=%s, file_mode=0%o, "
                   "checking=%s) -> EACCES (read permission denied, Phase 2)\n",
                   path_buf, path_type, mode_desc, file_mode, perm_check_buf);
        return -EACCES;
    }

    if ((mode & W_OK) && !(applicable_perms & 2)) {  /* Write bit */
        fut_printf("[ACCESS] access(path='%s' [%s], mode=%s, file_mode=0%o, "
                   "checking=%s) -> EACCES (write permission denied, Phase 2)\n",
                   path_buf, path_type, mode_desc, file_mode, perm_check_buf);
        return -EACCES;
    }

    if ((mode & X_OK) && !(applicable_perms & 1)) {  /* Execute bit */
        fut_printf("[ACCESS] access(path='%s' [%s], mode=%s, file_mode=0%o, "
                   "checking=%s) -> EACCES (execute permission denied, Phase 2)\n",
                   path_buf, path_type, mode_desc, file_mode, perm_check_buf);
        return -EACCES;
    }

    /* Phase 2: Detailed success logging */
    fut_printf("[ACCESS] access(path='%s' [%s], mode=%s, file_mode=0%o, "
               "checking=%s) -> 0 (all permissions granted, Phase 2)\n",
               path_buf, path_type, mode_desc, file_mode, perm_check_buf);

    return 0;
}
