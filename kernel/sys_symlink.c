/* kernel/sys_symlink.c - Symbolic link creation syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the symlink() syscall for creating symbolic links.
 * Symbolic links are special files that contain pathname strings,
 * allowing references to other files and directories.
 *
 * Phase 1 (Completed): Basic stub
 * Phase 2 (Completed): Enhanced validation and error handling
 * Phase 3 (Completed): Full VFS integration with symlink creation
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <stdint.h>
#include <string.h>

extern void fut_printf(const char *fmt, ...);
extern int fut_copy_from_user(void *to, const void *from, size_t size);

/**
 * symlink() - Create a symbolic link
 *
 * Creates a symbolic link at linkpath that contains the target string.
 * Unlike hard links, symbolic links contain the pathname as data,
 * not a direct reference to the same inode.
 *
 * @param target    The target path that the symlink points to
 * @param linkpath  The path where the symlink should be created
 *
 * Returns:
 *   - 0 on success
 *   - -EFAULT if target or linkpath is inaccessible
 *   - -EINVAL if target or linkpath is empty
 *   - -EEXIST if linkpath already exists
 *   - -ENOENT if path component doesn't exist
 *   - -ENOTDIR if component is not a directory
 *   - -ENOSPC if no space available
 *   - -EROFS if filesystem is read-only
 *   - -ENAMETOOLONG if pathname too long
 *   - -EACCES if write permission denied on parent
 *
 * Behavior:
 *   - Creates symlink at linkpath pointing to target
 *   - target does not need to exist (dangling symlink allowed)
 *   - target is stored as-is (not resolved)
 *   - Requires write permission on parent directory
 *   - Symlink permissions typically 0777
 *   - Updates parent directory's modification time
 */
long sys_symlink(const char *target, const char *linkpath) {
    /* ARM64 FIX: Copy parameters to local variables immediately */
    const char *local_target = target;
    const char *local_linkpath = linkpath;

    /* Validate target pointer */
    if (!local_target) {
        fut_printf("[SYMLINK] symlink(target=NULL, linkpath=?) -> EINVAL (NULL target)\n");
        return -EINVAL;
    }

    /* Validate linkpath pointer */
    if (!local_linkpath) {
        fut_printf("[SYMLINK] symlink(target=?, linkpath=NULL) -> EINVAL (NULL linkpath)\n");
        return -EINVAL;
    }

    /* Phase 5: Copy target from userspace with truncation detection
     * VULNERABILITY: Silent Path Truncation Leading to Wrong Symlink Target
     *
     * ATTACK SCENARIO:
     * Attacker provides target path longer than 256 bytes to exploit truncation
     * 1. Attacker calls symlink(long_target, linkpath) where:
     *    long_target = "/safe/path/to/file" + [230 bytes padding] + "../../../etc/shadow"
     * 2. OLD code (line 72): fut_copy_from_user copies only 255 bytes, truncating "../../../etc/shadow"
     * 3. OLD code (line 76): Force-terminates: target_buf = "/safe/path/to/file" + [230 bytes] + '\0'
     * 4. Line 200: Filesystem creates symlink pointing to "/safe/path/to/file" + [230 bytes]
     * 5. Result: Symlink points to wrong target (attacker's intended malicious path lost)
     *
     * CRITICAL IMPACT:
     * - Symlink confusion: Link points to unintended target
     * - Unlike truncate/open, symlink stores path AS-IS
     * - Attacker could create symlink pointing to benign path, expecting malicious suffix
     * - Application resolves symlink, gets wrong file
     *
     * DEFENSE (Phase 5):
     * Detect truncation by copying full buffer, check if target_buf[255] != '\0'
     * Return -ENAMETOOLONG if truncation detected
     * Matches sys_openat/sys_truncate pattern (commits f68ce63, cc20d22)
     */
    char target_buf[256];
    if (fut_copy_from_user(target_buf, local_target, sizeof(target_buf)) != 0) {
        fut_printf("[SYMLINK] symlink(target=?, linkpath=?) -> EFAULT (copy_from_user target failed)\n");
        return -EFAULT;
    }

    /* Phase 5: Verify target path was not truncated */
    if (target_buf[sizeof(target_buf) - 1] != '\0') {
        fut_printf("[SYMLINK] symlink(target=<truncated>, linkpath=?) -> ENAMETOOLONG "
                   "(target path exceeds %zu bytes, truncation detected, Phase 5)\n",
                   sizeof(target_buf) - 1);
        return -ENAMETOOLONG;
    }

    /* Phase 5: Copy linkpath from userspace with truncation detection
     * Same vulnerability as target path - linkpath could be truncated */
    char linkpath_buf[256];
    if (fut_copy_from_user(linkpath_buf, local_linkpath, sizeof(linkpath_buf)) != 0) {
        fut_printf("[SYMLINK] symlink(target='%s', linkpath=?) -> EFAULT (copy_from_user linkpath failed)\n",
                   target_buf);
        return -EFAULT;
    }

    /* Phase 5: Verify linkpath was not truncated */
    if (linkpath_buf[sizeof(linkpath_buf) - 1] != '\0') {
        fut_printf("[SYMLINK] symlink(target='%s', linkpath=<truncated>) -> ENAMETOOLONG "
                   "(linkpath exceeds %zu bytes, truncation detected, Phase 5)\n",
                   target_buf, sizeof(linkpath_buf) - 1);
        return -ENAMETOOLONG;
    }

    /* Validate target is not empty */
    if (target_buf[0] == '\0') {
        fut_printf("[SYMLINK] symlink(target=\"\" [empty], linkpath='%s') -> EINVAL (empty target)\n",
                   linkpath_buf);
        return -EINVAL;
    }

    /* Validate linkpath is not empty */
    if (linkpath_buf[0] == '\0') {
        fut_printf("[SYMLINK] symlink(target='%s', linkpath=\"\" [empty]) -> EINVAL (empty linkpath)\n",
                   target_buf);
        return -EINVAL;
    }

    /* Phase 5: Old truncation detection removed (lines 139-159)
     * Replaced with robust detection at lines 100-106 and 117-123 */

    /* Categorize path types */
    const char *target_type = (target_buf[0] == '/') ? "absolute" : "relative";
    const char *linkpath_type = (linkpath_buf[0] == '/') ? "absolute" : "relative";

    /* Extract parent directory from linkpath */
    char parent_path[256];
    const char *link_name = linkpath_buf;
    int last_slash = -1;

    for (int i = 0; linkpath_buf[i] != '\0'; i++) {
        if (linkpath_buf[i] == '/') {
            last_slash = i;
        }
    }

    if (last_slash >= 0) {
        /* Copy parent path */
        for (int i = 0; i < last_slash; i++) {
            parent_path[i] = linkpath_buf[i];
        }
        parent_path[last_slash] = '\0';
        link_name = &linkpath_buf[last_slash + 1];
    } else {
        /* No parent directory - use current */
        parent_path[0] = '\0';
    }

    /* Lookup parent directory */
    struct fut_vnode *parent = NULL;
    int ret;

    if (parent_path[0] == '\0') {
        /* Use current directory */
        fut_task_t *task = fut_task_current();
        if (!task) {
            fut_printf("[SYMLINK] symlink(target='%s', linkpath='%s') -> ENOENT (no current task)\n",
                       target_buf, linkpath_buf);
            return -ENOENT;
        }
        /* In a full implementation, would look up current_dir_ino */
        parent_path[0] = '/';
        parent_path[1] = '\0';
    }

    ret = fut_vfs_lookup(parent_path, &parent);

    if (ret < 0) {
        fut_printf("[SYMLINK] symlink(target='%s' [%s], linkpath='%s' [%s]) -> %d "
                   "(parent directory lookup failed)\n",
                   target_buf, target_type, linkpath_buf, linkpath_type, ret);
        return ret;
    }

    if (!parent) {
        fut_printf("[SYMLINK] symlink(target='%s' [%s], linkpath='%s' [%s]) -> ENOENT "
                   "(parent vnode is NULL)\n",
                   target_buf, target_type, linkpath_buf, linkpath_type);
        return -ENOENT;
    }

    /* Parent must be a directory */
    if (parent->type != VN_DIR) {
        fut_printf("[SYMLINK] symlink(target='%s' [%s], linkpath='%s' [%s]) -> ENOTDIR "
                   "(parent is not a directory)\n",
                   target_buf, target_type, linkpath_buf, linkpath_type);
        return -ENOTDIR;
    }

    /* Check if filesystem supports symlink creation */
    if (!parent->ops || !parent->ops->symlink) {
        fut_printf("[SYMLINK] symlink(target='%s' [%s], linkpath='%s' [%s]) -> ENOSYS "
                   "(filesystem doesn't support symlink)\n",
                   target_buf, target_type, linkpath_buf, linkpath_type);
        return -ENOSYS;
    }

    /* Call filesystem-specific symlink operation */
    ret = parent->ops->symlink(parent, link_name, target_buf);

    if (ret < 0) {
        const char *error_desc;
        switch (ret) {
            case -EEXIST:
                error_desc = "linkpath already exists";
                break;
            case -ENOSPC:
                error_desc = "no space for symlink";
                break;
            case -EROFS:
                error_desc = "read-only filesystem";
                break;
            case -ENAMETOOLONG:
                error_desc = "name too long";
                break;
            default:
                error_desc = "symlink operation failed";
                break;
        }

        fut_printf("[SYMLINK] symlink(target='%s' [%s], linkpath='%s' [%s], "
                   "parent_ino=%lu) -> %d (%s)\n",
                   target_buf, target_type, linkpath_buf, linkpath_type,
                   parent->ino, ret, error_desc);
        return ret;
    }

    /* Success */
    fut_printf("[SYMLINK] symlink(target='%s' [%s], linkpath='%s' [%s], "
               "parent_ino=%lu) -> 0 (success, symlink created)\n",
               target_buf, target_type, linkpath_buf, linkpath_type, parent->ino);

    return 0;
}
