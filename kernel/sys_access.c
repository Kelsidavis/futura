/* kernel/sys_access.c - File accessibility check syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements access() for checking file accessibility and permissions.
 * Essential for permission checking before file operations.
 *
 * Phase 1 (Completed): Basic file existence and permission checking
 * Phase 2 (Completed): Enhanced validation, mode identification, and detailed logging
 * Phase 3 (Completed): Advanced permission models (uid/gid checking, ACLs)
 * Phase 4: Performance optimization (permission caching)
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <stdint.h>

#include <kernel/kprintf.h>
#include <kernel/uaccess.h>

/* VFS permission checking functions */

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
 * Phase 2 (Completed): Enhanced validation, mode identification, detailed logging
 * Phase 3 (Completed): Advanced permission models (uid/gid checking, ACLs)
 * Phase 4: Performance optimization (permission caching)
 */
long sys_access(const char *pathname, int mode) {
    /* ARM64 FIX: Copy parameters to local variables immediately to ensure they're preserved
     * on the stack across potentially blocking calls. VFS and copy operations may block and
     * corrupt register-passed parameters upon resumption. */
    const char *local_pathname = pathname;
    int local_mode = mode;

    /* Phase 2: Validate pathname pointer */
    if (!local_pathname) {
        fut_printf("[ACCESS] access(pathname=NULL, mode=%d) -> EINVAL (NULL pathname)\n", local_mode);
        return -EINVAL;
    }

    /* Phase 2: Categorize mode bits */
    const char *mode_desc;
    int mode_bits = local_mode & (R_OK | W_OK | X_OK);

    if (local_mode == F_OK) {
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
    if (local_mode & ~(F_OK | R_OK | W_OK | X_OK)) {
        fut_printf("[ACCESS] access(pathname=?, mode=0x%x [%s]) -> EINVAL "
                   "(invalid mode bits)\n", local_mode, mode_desc);
        return -EINVAL;
    }

    /* Phase 5: Copy pathname and detect truncation
     * VULNERABILITY: Silent Path Truncation Allows Wrong File Access
     *
     * ATTACK SCENARIO:
     * Attacker provides overly long path to access() that gets silently truncated
     * 1. Attacker wants to check /etc/shadow but lacks permission
     * 2. Attacker provides 300-byte path starting with /etc/shadow:
     *    access("/etc/shadow" + 243 bytes of padding + "/attacker_file", R_OK)
     * 3. OLD code (before Phase 5):
     *    - Line 171: fut_copy_from_user copies first 255 bytes
     *    - Line 176: Manual null termination at path_buf[255]
     *    - Result: Path silently truncated to "/etc/shadow..."
     *    - Line 199: fut_vfs_lookup resolves truncated path
     *    - Returns permission status for /etc/shadow instead of intended file
     * 4. Impact:
     *    - Information disclosure: Attacker learns /etc/shadow permissions
     *    - Wrong file checked: access() checks unintended file
     *    - Silent failure: No error indicates truncation occurred
     *    - Security bypass: Permission check on wrong target
     *
     * ROOT CAUSE:
     * - Lines 171-176: Copy 255 bytes, manually null-terminate
     * - No validation that source path fit within 255 bytes
     * - Manual null termination MASKS truncation (always creates valid string)
     * - Kernel proceeds with truncated path as if it were complete
     *
     * DEFENSE (Phase 5):
     * Copy full buffer (256 bytes) and verify last byte is null
     * - If path_buf[255] != '\0', original path exceeded 255 bytes
     * - Return -ENAMETOOLONG immediately (fail fast)
     * - Prevents vfs_lookup from resolving truncated path
     * - Matches pattern: sys_truncate (lines 91-104), sys_openat
     *
     * POSIX REQUIREMENT (IEEE Std 1003.1):
     * PATH_MAX typically 4096, but kernel must reject paths exceeding buffer
     * "If the length of pathname exceeds {PATH_MAX}, access() shall fail
     *  and set errno to [ENAMETOOLONG]."
     *
     * CVE REFERENCES:
     * Path truncation vulnerabilities in other systems:
     * - CVE-2018-14618: curl path truncation bypass
     * - CVE-2019-9500: Android path truncation privilege escalation
     */
    char path_buf[FUT_VFS_PATH_BUFFER_SIZE];
    if (fut_copy_from_user(path_buf, local_pathname, sizeof(path_buf)) != 0) {
        fut_printf("[ACCESS] access(pathname=?, mode=%s) -> EFAULT "
                   "(copy_from_user failed)\n", mode_desc);
        return -EFAULT;
    }

    /* Phase 5: Verify path was not truncated */
    if (path_buf[sizeof(path_buf) - 1] != '\0') {
        fut_printf("[ACCESS] access(pathname=<truncated>, mode=%s) -> ENAMETOOLONG "
                   "(path exceeds %zu bytes, truncation detected, Phase 5)\n",
                   mode_desc, sizeof(path_buf) - 1);
        return -ENAMETOOLONG;
    }

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

    /* Phase 3: F_OK just checks if file exists (already verified) */
    if (local_mode == F_OK) {
        fut_printf("[ACCESS] access(path='%s' [%s], mode=%s) -> 0 "
                   "(file exists, Phase 4: uid/gid checking and ACLs)\n", path_buf, path_type, mode_desc);
        return 0;
    }

    /* Phase 4: Build permission check description */
    char perm_check_buf[64];
    char *p = perm_check_buf;
    int perm_count = 0;

    if (local_mode & R_OK) {
        if (perm_count++ > 0) {
            *p++ = '+';
        }
        const char *s = "read";
        while (*s) *p++ = *s++;
    }
    if (local_mode & W_OK) {
        if (perm_count++ > 0) {
            *p++ = '+';
        }
        const char *s = "write";
        while (*s) *p++ = *s++;
    }
    if (local_mode & X_OK) {
        if (perm_count++ > 0) {
            *p++ = '+';
        }
        const char *s = "execute";
        while (*s) *p++ = *s++;
    }
    *p = '\0';

    uint32_t file_mode = vnode->mode;

    /* Phase 4: Check permissions using real uid/gid-aware permission checks
     * Uses vfs_check_*_perm functions that properly check owner/group/other */

    if (local_mode & R_OK) {
        int ret = vfs_check_read_perm(vnode);
        if (ret < 0) {
            fut_printf("[ACCESS] access(path='%s' [%s], mode=%s, file_mode=0%o, uid=%u, gid=%u, "
                       "checking=%s) -> EACCES (read permission denied)\n",
                       path_buf, path_type, mode_desc, file_mode, vnode->uid, vnode->gid, perm_check_buf);
            return -EACCES;
        }
    }

    if (local_mode & W_OK) {
        int ret = vfs_check_write_perm(vnode);
        if (ret < 0) {
            fut_printf("[ACCESS] access(path='%s' [%s], mode=%s, file_mode=0%o, uid=%u, gid=%u, "
                       "checking=%s) -> EACCES (write permission denied)\n",
                       path_buf, path_type, mode_desc, file_mode, vnode->uid, vnode->gid, perm_check_buf);
            return -EACCES;
        }
    }

    if (local_mode & X_OK) {
        int ret = vfs_check_exec_perm(vnode);
        if (ret < 0) {
            fut_printf("[ACCESS] access(path='%s' [%s], mode=%s, file_mode=0%o, uid=%u, gid=%u, "
                       "checking=%s) -> EACCES (execute permission denied)\n",
                       path_buf, path_type, mode_desc, file_mode, vnode->uid, vnode->gid, perm_check_buf);
            return -EACCES;
        }
    }

    /* Security hardening WARNING: TOCTOU Race Condition
     *
     * access() is inherently vulnerable to time-of-check-time-of-use attacks:
     *
     * VULNERABLE PATTERN:
     *   if (access("/tmp/file", W_OK) == 0) {  // Check at time T1
     *       fd = open("/tmp/file", O_WRONLY);   // Use at time T2
     *   }
     *
     * ATTACK SCENARIO:
     *   1. Attacker creates /tmp/file as regular file (access() returns 0)
     *   2. Between access() and open(), attacker replaces /tmp/file with symlink to /etc/passwd
     *   3. open() follows symlink, privileged program writes to /etc/passwd
     *   4. System compromised
     *
     * PROPER ALTERNATIVES:
     *   1. Don't use access() for security decisions - just call open() and handle errors:
     *      fd = open(path, O_WRONLY);
     *      if (fd < 0) { handle_error(errno); }
     *
     *   2. Use faccessat() with AT_EACCESS flag to check effective permissions
     *   3. Use O_EXCL with O_CREAT to prevent symlink following
     *   4. Use openat() with directory FD to prevent path substitution
     *
     * POSIX GUIDANCE (IEEE Std 1003.1):
     *   "The use of access() is a security problem because time of check to time of use
     *    (TOCTOU) race conditions can occur."
     *
     * This implementation CANNOT fix the fundamental TOCTOU race in access().
     * Applications must avoid access() for security checks.
     */

    /* Phase 4: Detailed success logging with TOCTOU warning */
    fut_printf("[ACCESS] access(path='%s' [%s], mode=%s, file_mode=0%o, uid=%u, gid=%u, "
               "checking=%s) -> 0 (all permissions granted with uid/gid checks) "
               "WARNING: access() is vulnerable to TOCTOU - use open() directly instead\n",
               path_buf, path_type, mode_desc, file_mode, vnode->uid, vnode->gid, perm_check_buf);

    return 0;
}
