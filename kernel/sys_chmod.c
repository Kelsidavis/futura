/* kernel/sys_chmod.c - File permission change syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements chmod() for changing file permissions.
 * Essential for file security and access control management.
 *
 * Phase 1 (Completed): Basic permission changing with vnode lookup
 * Phase 2 (Completed): Enhanced validation, mode identification, and detailed logging
 * Phase 3 (Current): Advanced features (symbolic permissions, ACL support)
 * Phase 4: Performance optimization (permission change batching)
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);
extern int fut_copy_from_user(void *to, const void *from, size_t size);

/**
 * chmod() - Change file permissions
 *
 * Changes the permission bits of the file specified by pathname to the
 * permissions specified by mode. This allows setting read, write, and
 * execute permissions for owner, group, and others.
 *
 * @param pathname Path to the file (relative or absolute)
 * @param mode     New permission bits (octal, e.g., 0755, 0644)
 *
 * Returns:
 *   - 0 on success
 *   - -EACCES if search permission denied on path component
 *   - -EFAULT if pathname points to inaccessible memory
 *   - -EINVAL if pathname is NULL or empty
 *   - -ENOENT if file does not exist or path component missing
 *   - -ENAMETOOLONG if pathname too long
 *   - -ENOTDIR if component of path prefix is not a directory
 *   - -ENOSYS if filesystem doesn't support permission changes
 *   - -EPERM if process doesn't have permission to change mode
 *   - -EROFS if file is on read-only filesystem
 *
 * Behavior:
 *   - Changes permission bits of file
 *   - Requires ownership of file or CAP_FOWNER capability
 *   - Does not change file type bits (only permission bits)
 *   - Preserves special bits (setuid, setgid, sticky) unless explicitly cleared
 *   - Updates file's ctime (change time)
 *   - Does not affect open file descriptors
 *
 * Permission bits (9 bits total):
 *   - User (owner) permissions: bits 6-8 (0700)
 *     - 0400: Read
 *     - 0200: Write
 *     - 0100: Execute
 *   - Group permissions: bits 3-5 (0070)
 *     - 0040: Read
 *     - 0020: Write
 *     - 0010: Execute
 *   - Other permissions: bits 0-2 (0007)
 *     - 0004: Read
 *     - 0002: Write
 *     - 0001: Execute
 *
 * Special bits (optional):
 *   - 04000: Set-user-ID (setuid) - run with owner's privileges
 *   - 02000: Set-group-ID (setgid) - run with group's privileges
 *   - 01000: Sticky bit - restrict deletion in directories
 *
 * Common permission modes:
 *   - 0644: rw-r--r-- (owner read/write, others read-only) - typical file
 *   - 0755: rwxr-xr-x (owner all, others read/execute) - typical executable
 *   - 0600: rw------- (owner read/write only) - private file
 *   - 0700: rwx------ (owner all only) - private executable
 *   - 0666: rw-rw-rw- (all read/write) - world-writable file
 *   - 0777: rwxrwxrwx (all permissions) - world-writable executable
 *   - 0444: r--r--r-- (all read-only) - read-only file
 *
 * Common usage patterns:
 *
 * Make file readable/writable by owner only:
 *   chmod("/path/to/file", 0600);
 *
 * Make file executable:
 *   chmod("/path/to/script", 0755);
 *
 * Make file world-readable:
 *   chmod("/path/to/public", 0644);
 *
 * Remove all permissions from others:
 *   chmod("/path/to/private", 0700);
 *
 * Set setuid bit (run as owner):
 *   chmod("/usr/bin/sudo", 04755);
 *
 * Set sticky bit on directory:
 *   chmod("/tmp", 01777);
 *
 * Symbolic permissions (not supported in this implementation):
 *   - chmod("file", "u+x")  // Add execute for user
 *   - chmod("file", "go-w") // Remove write for group/others
 *   - chmod("file", "a+r")  // Add read for all
 *
 * Permission checking before chmod:
 *   struct stat st;
 *   if (stat("/path/to/file", &st) == 0) {
 *       mode_t old_mode = st.st_mode & 0777;
 *       printf("Old permissions: %o\n", old_mode);
 *       chmod("/path/to/file", 0755);
 *   }
 *
 * Preserve special bits while changing permissions:
 *   struct stat st;
 *   stat("/path/to/file", &st);
 *   mode_t new_perms = (st.st_mode & 07000) | 0755; // Keep setuid/setgid/sticky
 *   chmod("/path/to/file", new_perms);
 *
 * Security considerations:
 *   - Only file owner or root can change permissions
 *   - Setuid/setgid on scripts may be ignored for security
 *   - Be careful with world-writable permissions (0666, 0777)
 *   - Sticky bit on non-directories may be ignored
 *   - Some filesystems don't support all permission bits
 *
 * TOCTOU warning:
 *   - stat() followed by chmod() has time-of-check-to-time-of-use race
 *   - File permissions can change between stat() and chmod()
 *   - Ownership can change between stat() and chmod()
 *
 * Phase 1 (Completed): Basic permission changing with vnode lookup
 * Phase 2 (Current): Enhanced validation, mode identification, detailed logging
 * Phase 3: Advanced features (symbolic permissions, ACL support)
 * Phase 4: Performance optimization (permission change batching)
 */
long sys_chmod(const char *pathname, uint32_t mode) {
    /* Phase 2: Validate pathname pointer */
    if (!pathname) {
        fut_printf("[CHMOD] chmod(pathname=NULL, mode=0%o) -> EINVAL (NULL pathname)\n", mode);
        return -EINVAL;
    }

    /* Phase 2: Categorize permission mode */
    const char *mode_desc;
    uint32_t perm_bits = mode & 0777;

    if (perm_bits == 0644) {
        mode_desc = "0644 (rw-r--r--, typical file)";
    } else if (perm_bits == 0755) {
        mode_desc = "0755 (rwxr-xr-x, typical executable)";
    } else if (perm_bits == 0600) {
        mode_desc = "0600 (rw-------, owner only)";
    } else if (perm_bits == 0700) {
        mode_desc = "0700 (rwx------, owner only executable)";
    } else if (perm_bits == 0666) {
        mode_desc = "0666 (rw-rw-rw-, world-writable)";
    } else if (perm_bits == 0777) {
        mode_desc = "0777 (rwxrwxrwx, all permissions)";
    } else if (perm_bits == 0444) {
        mode_desc = "0444 (r--r--r--, read-only)";
    } else if (perm_bits == 0000) {
        mode_desc = "0000 (---------, no permissions)";
    } else {
        mode_desc = "custom";
    }

    /* Phase 2: Identify special bits */
    char special_bits_buf[64];
    char *p = special_bits_buf;
    int special_count = 0;

    if (mode & 04000) {
        if (special_count++ > 0) {
            *p++ = '|';
        }
        const char *s = "setuid";
        while (*s) *p++ = *s++;
    }
    if (mode & 02000) {
        if (special_count++ > 0) {
            *p++ = '|';
        }
        const char *s = "setgid";
        while (*s) *p++ = *s++;
    }
    if (mode & 01000) {
        if (special_count++ > 0) {
            *p++ = '|';
        }
        const char *s = "sticky";
        while (*s) *p++ = *s++;
    }
    *p = '\0';

    const char *special_bits_desc = special_count > 0 ? special_bits_buf : "none";

    /* Copy pathname from userspace to kernel space */
    char path_buf[256];
    if (fut_copy_from_user(path_buf, pathname, sizeof(path_buf) - 1) != 0) {
        fut_printf("[CHMOD] chmod(pathname=?, mode=%s, special=%s) -> EFAULT "
                   "(copy_from_user failed)\n", mode_desc, special_bits_desc);
        return -EFAULT;
    }
    path_buf[sizeof(path_buf) - 1] = '\0';

    /* Phase 2: Validate pathname is not empty */
    if (path_buf[0] == '\0') {
        fut_printf("[CHMOD] chmod(pathname=\"\" [empty], mode=%s, special=%s) -> EINVAL "
                   "(empty pathname)\n", mode_desc, special_bits_desc);
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
            case -EFAULT:
                error_desc = "pathname points to inaccessible memory";
                break;
            default:
                error_desc = "lookup failed";
                break;
        }

        fut_printf("[CHMOD] chmod(path='%s' [%s], mode=%s, special=%s) -> %d (%s)\n",
                   path_buf, path_type, mode_desc, special_bits_desc, ret, error_desc);
        return ret;
    }

    /* Phase 2: Validate vnode is not NULL */
    if (!vnode) {
        fut_printf("[CHMOD] chmod(path='%s' [%s], mode=%s, special=%s) -> ENOENT "
                   "(vnode is NULL)\n", path_buf, path_type, mode_desc, special_bits_desc);
        return -ENOENT;
    }

    /* Phase 2: Store old mode for before/after comparison */
    uint32_t old_mode = vnode->mode & 07777;  // Permissions + special bits
    uint32_t old_perms = old_mode & 0777;      // Permissions only

    /* Phase 2: Build permission change description */
    char perms_change_buf[128];
    p = perms_change_buf;

    const char *prefix = "0";
    while (*prefix) *p++ = *prefix++;

    // Convert old_perms to octal string
    if (old_perms >= 0100) {
        *p++ = '0' + ((old_perms >> 6) & 7);
    }
    *p++ = '0' + ((old_perms >> 3) & 7);
    *p++ = '0' + (old_perms & 7);

    const char *arrow = " -> 0";
    while (*arrow) *p++ = *arrow++;

    // Convert perm_bits to octal string
    if (perm_bits >= 0100) {
        *p++ = '0' + ((perm_bits >> 6) & 7);
    }
    *p++ = '0' + ((perm_bits >> 3) & 7);
    *p++ = '0' + (perm_bits & 7);
    *p = '\0';

    /* Check if filesystem supports permission changes */
    if (!vnode->ops || !vnode->ops->setattr) {
        fut_printf("[CHMOD] chmod(path='%s' [%s], vnode_ino=%lu, perms=%s, mode=%s, "
                   "special=%s) -> ENOSYS (filesystem doesn't support setattr)\n",
                   path_buf, path_type, vnode->ino, perms_change_buf, mode_desc,
                   special_bits_desc);
        return -ENOSYS;
    }

    /* Create a stat structure with the new mode */
    struct fut_stat stat = {0};
    stat.st_mode = mode;

    /* Call the filesystem's setattr operation */
    ret = vnode->ops->setattr(vnode, &stat);

    /* Phase 2: Handle setattr errors with detailed logging */
    if (ret < 0) {
        const char *error_desc;
        switch (ret) {
            case -EPERM:
                error_desc = "operation not permitted (not owner)";
                break;
            case -EROFS:
                error_desc = "read-only filesystem";
                break;
            case -EACCES:
                error_desc = "permission denied";
                break;
            default:
                error_desc = "setattr failed";
                break;
        }

        fut_printf("[CHMOD] chmod(path='%s' [%s], vnode_ino=%lu, perms=%s, mode=%s, "
                   "special=%s) -> %d (%s)\n",
                   path_buf, path_type, vnode->ino, perms_change_buf, mode_desc,
                   special_bits_desc, ret, error_desc);
        return ret;
    }

    /* Phase 2: Detailed success logging */
    fut_printf("[CHMOD] chmod(path='%s' [%s], vnode_ino=%lu, perms=%s, mode=%s, "
               "special=%s) -> 0 (permissions changed, Phase 2)\n",
               path_buf, path_type, vnode->ino, perms_change_buf, mode_desc,
               special_bits_desc);

    return 0;
}
