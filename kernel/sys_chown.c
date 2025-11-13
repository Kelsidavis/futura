/* kernel/sys_chown.c - File ownership change syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements chown() for changing file ownership and group.
 * Essential for file ownership management and access control.
 *
 * Phase 1 (Completed): Basic ownership changing with vnode lookup
 * Phase 2 (Completed): Enhanced validation, ownership identification, and detailed logging
 * Phase 3 (Current): Advanced features (lchown support, recursive chown)
 * Phase 4: Performance optimization (ownership change batching)
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);
extern int fut_copy_from_user(void *to, const void *from, size_t size);

/* Special value indicating "don't change" */
#define CHOWN_UNCHANGED ((uint32_t)-1)

/**
 * chown() - Change file ownership and group
 *
 * Changes the owner (uid) and/or group (gid) of the file specified by
 * pathname. This is essential for file ownership management and access
 * control in multi-user systems.
 *
 * @param pathname Path to the file (relative or absolute)
 * @param uid      New user ID, or -1 to leave unchanged
 * @param gid      New group ID, or -1 to leave unchanged
 *
 * Returns:
 *   - 0 on success
 *   - -EACCES if search permission denied on path component
 *   - -EFAULT if pathname points to inaccessible memory
 *   - -EINVAL if pathname is NULL or empty
 *   - -ENOENT if file does not exist or path component missing
 *   - -ENAMETOOLONG if pathname too long
 *   - -ENOTDIR if component of path prefix is not a directory
 *   - -ENOSYS if filesystem doesn't support ownership changes
 *   - -EPERM if process doesn't have permission to change ownership
 *   - -EROFS if file is on read-only filesystem
 *
 * Behavior:
 *   - Changes file's owner and/or group
 *   - Requires superuser privileges (typically)
 *   - uid = -1 means "don't change owner"
 *   - gid = -1 means "don't change group"
 *   - Can specify both uid and gid in single call
 *   - Updates file's ctime (change time)
 *   - May clear setuid/setgid bits for security
 *   - Does not follow symbolic links (use lchown for symlinks)
 *
 * Special uid/gid values:
 *   - -1 (0xFFFFFFFF): Don't change (preserve current value)
 *   - 0: Root user (superuser) or root group
 *   - 1+: Regular users or groups
 *
 * Common usage patterns:
 *
 * Change owner to root:
 *   chown("/path/to/file", 0, -1);  // Owner to root, keep group
 *
 * Change group to wheel:
 *   chown("/path/to/file", -1, 0);  // Keep owner, group to wheel
 *
 * Change both owner and group:
 *   chown("/path/to/file", 1000, 1000);  // Set both to user 1000
 *
 * Transfer ownership to another user:
 *   chown("/home/user/file", 1001, -1);  // New owner, keep group
 *
 * Reset ownership to current user:
 *   uid_t my_uid = getuid();
 *   gid_t my_gid = getgid();
 *   chown("/tmp/myfile", my_uid, my_gid);
 *
 * Permission requirements:
 *   - Typically requires CAP_CHOWN capability (root)
 *   - Some systems allow owner to change group to groups they belong to
 *   - Simplified OS may allow any process to chown
 *   - Security-critical for preventing privilege escalation
 *
 * Security implications:
 *   - Changing ownership can affect access control
 *   - Setuid/setgid bits may be cleared when ownership changes
 *   - Be careful with setuid files (can create privilege escalation)
 *   - Never allow untrusted users to chown arbitrary files
 *
 * Setuid/setgid bit clearing:
 *   - For security, changing ownership typically clears setuid/setgid
 *   - Prevents user from gaining privileges via owned setuid file
 *   - Example: chown on setuid root binary clears setuid bit
 *   - Explicit chmod required after chown to re-enable setuid
 *
 * Common ownership patterns:
 *   - System files: uid=0 (root), gid=0 (root/wheel)
 *   - User files: uid=user, gid=user or users
 *   - Shared files: uid=user, gid=shared_group
 *   - Web files: uid=www, gid=www
 *
 * Ownership change scenarios:
 *   - Installing software: chown root:root /usr/bin/program
 *   - User file management: chown user:user /home/user/file
 *   - Shared project: chown -R user:project /var/project
 *   - Web server: chown www:www /var/www/html
 *
 * Related syscalls:
 *   - lchown(): Change ownership of symlink itself, not target
 *   - fchown(): Change ownership via file descriptor
 *   - fchownat(): Change ownership with directory FD and flags
 *
 * TOCTOU warning:
 *   - stat() followed by chown() has time-of-check-to-time-of-use race
 *   - File ownership can change between stat() and chown()
 *   - File can be replaced with symlink (symlink attack)
 *   - Use fchown() with O_NOFOLLOW for safer operation
 *
 * Phase 1 (Completed): Basic ownership changing with vnode lookup
 * Phase 2 (Current): Enhanced validation, ownership identification, detailed logging
 * Phase 3: Advanced features (lchown support, recursive chown)
 * Phase 4: Performance optimization (ownership change batching)
 */
long sys_chown(const char *pathname, uint32_t uid, uint32_t gid) {
    /* Phase 2: Validate pathname pointer */
    if (!pathname) {
        fut_printf("[CHOWN] chown(pathname=NULL, uid=%u, gid=%u) -> EINVAL (NULL pathname)\n",
                   uid, gid);
        return -EINVAL;
    }

    /* Phase 2: Categorize uid change type */
    const char *uid_desc;
    if (uid == CHOWN_UNCHANGED) {
        uid_desc = "unchanged (-1)";
    } else if (uid == 0) {
        uid_desc = "root (0)";
    } else if (uid < 1000) {
        uid_desc = "system user (<1000)";
    } else {
        uid_desc = "regular user (≥1000)";
    }

    /* Phase 2: Categorize gid change type */
    const char *gid_desc;
    if (gid == CHOWN_UNCHANGED) {
        gid_desc = "unchanged (-1)";
    } else if (gid == 0) {
        gid_desc = "root/wheel (0)";
    } else if (gid < 1000) {
        gid_desc = "system group (<1000)";
    } else {
        gid_desc = "user group (≥1000)";
    }

    /* Phase 2: Categorize operation type */
    const char *operation_type;
    if (uid == CHOWN_UNCHANGED && gid == CHOWN_UNCHANGED) {
        operation_type = "no-op (both unchanged)";
    } else if (uid != CHOWN_UNCHANGED && gid == CHOWN_UNCHANGED) {
        operation_type = "change owner only";
    } else if (uid == CHOWN_UNCHANGED && gid != CHOWN_UNCHANGED) {
        operation_type = "change group only";
    } else {
        operation_type = "change both owner and group";
    }

    /* Copy pathname from userspace to kernel space */
    char path_buf[256];
    if (fut_copy_from_user(path_buf, pathname, sizeof(path_buf) - 1) != 0) {
        fut_printf("[CHOWN] chown(pathname=?, uid=%s, gid=%s, op=%s) -> EFAULT "
                   "(copy_from_user failed)\n", uid_desc, gid_desc, operation_type);
        return -EFAULT;
    }
    path_buf[sizeof(path_buf) - 1] = '\0';

    /* Phase 2: Validate pathname is not empty */
    if (path_buf[0] == '\0') {
        fut_printf("[CHOWN] chown(pathname=\"\" [empty], uid=%s, gid=%s, op=%s) -> EINVAL "
                   "(empty pathname)\n", uid_desc, gid_desc, operation_type);
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

        fut_printf("[CHOWN] chown(path='%s' [%s], uid=%s, gid=%s, op=%s) -> %d (%s)\n",
                   path_buf, path_type, uid_desc, gid_desc, operation_type, ret, error_desc);
        return ret;
    }

    /* Phase 2: Validate vnode is not NULL */
    if (!vnode) {
        fut_printf("[CHOWN] chown(path='%s' [%s], uid=%s, gid=%s, op=%s) -> ENOENT "
                   "(vnode is NULL)\n", path_buf, path_type, uid_desc, gid_desc, operation_type);
        return -ENOENT;
    }

    /* Phase 2: Store old ownership for before/after comparison
     * Note: VFS layer doesn't currently track uid/gid on vnodes,
     * so we show as 0:0 (root:root) for now. Full implementation
     * would store actual uid/gid in vnode structure.
     */
    uint32_t old_uid = 0;  // TODO: vnode->uid when implemented
    uint32_t old_gid = 0;  // TODO: vnode->gid when implemented

    /* Phase 2: Build ownership change description */
    char ownership_change_buf[128];
    char *p = ownership_change_buf;

    // Old ownership
    if (old_uid < 10) {
        *p++ = '0' + old_uid;
    } else {
        // Simple decimal conversion for multi-digit numbers
        uint32_t temp_uid = old_uid;
        char digits[12];
        int digit_count = 0;
        do {
            digits[digit_count++] = '0' + (temp_uid % 10);
            temp_uid /= 10;
        } while (temp_uid > 0);
        for (int i = digit_count - 1; i >= 0; i--) {
            *p++ = digits[i];
        }
    }

    *p++ = ':';

    if (old_gid < 10) {
        *p++ = '0' + old_gid;
    } else {
        uint32_t temp_gid = old_gid;
        char digits[12];
        int digit_count = 0;
        do {
            digits[digit_count++] = '0' + (temp_gid % 10);
            temp_gid /= 10;
        } while (temp_gid > 0);
        for (int i = digit_count - 1; i >= 0; i--) {
            *p++ = digits[i];
        }
    }

    const char *arrow = " -> ";
    while (*arrow) *p++ = *arrow++;

    // New ownership (using actual uid/gid or -1)
    if (uid == CHOWN_UNCHANGED) {
        *p++ = '-';
        *p++ = '1';
    } else if (uid < 10) {
        *p++ = '0' + uid;
    } else {
        uint32_t temp_uid = uid;
        char digits[12];
        int digit_count = 0;
        do {
            digits[digit_count++] = '0' + (temp_uid % 10);
            temp_uid /= 10;
        } while (temp_uid > 0);
        for (int i = digit_count - 1; i >= 0; i--) {
            *p++ = digits[i];
        }
    }

    *p++ = ':';

    if (gid == CHOWN_UNCHANGED) {
        *p++ = '-';
        *p++ = '1';
    } else if (gid < 10) {
        *p++ = '0' + gid;
    } else {
        uint32_t temp_gid = gid;
        char digits[12];
        int digit_count = 0;
        do {
            digits[digit_count++] = '0' + (temp_gid % 10);
            temp_gid /= 10;
        } while (temp_gid > 0);
        for (int i = digit_count - 1; i >= 0; i--) {
            *p++ = digits[i];
        }
    }
    *p = '\0';

    /* Check if filesystem supports ownership changes */
    if (!vnode->ops || !vnode->ops->setattr) {
        fut_printf("[CHOWN] chown(path='%s' [%s], vnode_ino=%lu, ownership=%s, "
                   "uid=%s, gid=%s, op=%s) -> ENOSYS (filesystem doesn't support setattr)\n",
                   path_buf, path_type, vnode->ino, ownership_change_buf,
                   uid_desc, gid_desc, operation_type);
        return -ENOSYS;
    }

    /* Create a stat structure with the new ownership */
    struct fut_stat stat = {0};
    stat.st_uid = uid;
    stat.st_gid = gid;

    /* Call the filesystem's setattr operation */
    ret = vnode->ops->setattr(vnode, &stat);

    /* Phase 2: Handle setattr errors with detailed logging */
    if (ret < 0) {
        const char *error_desc;
        switch (ret) {
            case -EPERM:
                error_desc = "operation not permitted (not owner/root)";
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

        fut_printf("[CHOWN] chown(path='%s' [%s], vnode_ino=%lu, ownership=%s, "
                   "uid=%s, gid=%s, op=%s) -> %d (%s)\n",
                   path_buf, path_type, vnode->ino, ownership_change_buf,
                   uid_desc, gid_desc, operation_type, ret, error_desc);
        return ret;
    }

    /* Phase 2: Detailed success logging */
    fut_printf("[CHOWN] chown(path='%s' [%s], vnode_ino=%lu, ownership=%s, "
               "uid=%s, gid=%s, op=%s) -> 0 (ownership changed, Phase 2)\n",
               path_buf, path_type, vnode->ino, ownership_change_buf,
               uid_desc, gid_desc, operation_type);

    return 0;
}
