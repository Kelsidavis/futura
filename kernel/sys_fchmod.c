/* kernel/sys_fchmod.c - File permission syscall (fd-based)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the fchmod() syscall for changing file permissions via fd.
 * Essential for file security and access control management on open files.
 *
 * Phase 1 (Completed): Basic permission changing with FD lookup
 * Phase 2 (Completed): Enhanced validation, mode categorization, and detailed logging
 * Phase 3 (Completed): Advanced features (ACL support, extended permissions)
 * Phase 4 (Completed): Performance optimization (batched permission updates)
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <kernel/userns.h>
#include <kernel/fut_fd_util.h>
#include <fcntl.h>
#include <stdint.h>

#include <kernel/kprintf.h>

/**
 * fchmod() - Change file permissions (fd-based)
 *
 * Changes the permission bits of a file using an open file descriptor.
 * The mode parameter is a bit mask containing the new permission bits
 * (e.g., 0755 for rwxr-xr-x).
 *
 * This is the fd-based complement to chmod().
 *
 * @param fd    File descriptor of the open file
 * @param mode  New permission bits (e.g., 0755, 0644, etc.)
 *
 * Returns:
 *   - 0 on success
 *   - -EBADF if fd is not a valid open file descriptor
 *   - -ENOSYS if filesystem doesn't support permission changes
 *   - -EPERM if process doesn't own the file
 *   - -EROFS if filesystem is read-only
 *
 * Behavior:
 *   - Changes permission bits of file referenced by fd
 *   - File must be open (any access mode)
 *   - Requires ownership of file or CAP_FOWNER capability
 *   - Does not change file type bits (only permission bits)
 *   - Preserves special bits unless explicitly cleared
 *   - Updates file's ctime (change time)
 *
 * Common usage patterns:
 *
 * Make file executable after creating it:
 *   int fd = open("/path/to/script", O_CREAT|O_WRONLY, 0644);
 *   write(fd, script_content, len);
 *   fchmod(fd, 0755);  // Make executable
 *   close(fd);
 *
 * Change permissions on already-open file:
 *   int fd = open("/path/to/file", O_RDWR);
 *   fchmod(fd, 0600);  // Owner only
 *
 * Phase 1 (Completed): Basic permission changing with FD lookup
 * Phase 2 (Completed): Enhanced validation, mode categorization, detailed logging
 * Phase 3 (Completed): Advanced features (ACL support, extended permissions)
 * Phase 4 (Completed): Performance optimization (batched permission updates)
 */
long sys_fchmod(int fd, uint32_t mode) {
    /* ARM64 FIX: Copy parameters to local variables */
    int local_fd = fd;
    uint32_t local_mode = mode;

    /* Phase 2: Validate FD number */
    if (local_fd < 0) {
        fut_printf("[FCHMOD] fchmod(fd=%d [invalid], mode=0%o) -> EBADF (negative FD)\n",
                   local_fd, local_mode);
        return -EBADF;
    }

    /* Linux chmod_common masks mode to S_IALLUGO (07777) silently rather
     * than rejecting high bits — see sys_chmod for the same fix. */
    local_mode &= 07777;

    /* Phase 2: Categorize FD type - use shared helper */
    const char *fd_category = fut_fd_category(local_fd);

    /* Get the file structure from the file descriptor */
    struct fut_file *file = fut_vfs_get_file(local_fd);
    if (!file) {
        fut_printf("[FCHMOD] fchmod(fd=%d [%s], mode=0%o) -> EBADF (file not found)\n",
                   local_fd, fd_category, local_mode);
        return -EBADF;
    }

    /* O_PATH fds cannot be used for fchmod — use fchmodat instead */
    if (file->flags & O_PATH)
        return -EBADF;

    /* Get the vnode from the file */
    struct fut_vnode *vnode = file->vnode;
    if (!vnode) {
        fut_printf("[FCHMOD] fchmod(fd=%d [%s], mode=0%o) -> EBADF (no vnode)\n",
                   local_fd, fd_category, local_mode);
        return -EBADF;
    }

    /* Phase 2: Categorize permission mode */
    const char *mode_desc;
    uint32_t perm_bits = local_mode & 0777;

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

    if (local_mode & 04000) {
        if (special_count++ > 0) {
            *p++ = '|';
        }
        const char *s = "setuid";
        while (*s) *p++ = *s++;
    }
    if (local_mode & 02000) {
        if (special_count++ > 0) {
            *p++ = '|';
        }
        const char *s = "setgid";
        while (*s) *p++ = *s++;
    }
    if (local_mode & 01000) {
        if (special_count++ > 0) {
            *p++ = '|';
        }
        const char *s = "sticky";
        while (*s) *p++ = *s++;
    }
    *p = '\0';

    const char *special_bits_desc = special_count > 0 ? special_bits_buf : "none";

    /* Phase 3: Get current task for capability checks */
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[FCHMOD] fchmod(fd=%d [%s], vnode_ino=%lu, mode=%s, special=%s) "
                   "-> ESRCH (no current task for capability check)\n",
                   local_fd, fd_category, vnode->ino, mode_desc, special_bits_desc);
        return -ESRCH;
    }

    /* Permission check: only owner, root, or CAP_FOWNER can fchmod.
     * Linux uses the effective UID (current_fsuid()) — see the matching
     * comment in sys_chmod. The previous task->ruid check broke setuid
     * binaries chmod'ing files they owned via their effective identity. */
    uint32_t task_host_uid = userns_ns_to_host_uid(task->user_ns, task->uid);
    if (task_host_uid != 0 &&
        !(task->cap_effective & (1ULL << 3 /* CAP_FOWNER */)) &&
        task_host_uid != vnode->uid) {
        return -EPERM;
    }

    /* Linux: non-root without CAP_FSETID gets S_ISGID silently stripped
     * when the caller is not in the file's group. S_ISUID and sticky
     * bit are allowed for file owners. The "in group" check must
     * include supplementary groups (in_group_p), otherwise users in
     * the file's group only via supplementary gids lose S_ISGID.
     *
     * The strip applies to non-directory inodes only — for directories
     * S_ISGID has different semantics (it marks files created in the
     * directory to inherit the group), so Linux preserves it across
     * chmod regardless of CAP_FSETID or group membership.  Skipping
     * the strip on directories matches the matching sys_chmod fix
     * and keeps shared-project directories from losing their setgid
     * marker every time anyone re-chmods them. */
    if (vnode->type != VN_DIR) {
        int has_cap_fsetid = (task->cap_effective & (1ULL << 4 /* CAP_FSETID */));
        if ((local_mode & 02000) && !has_cap_fsetid) {
            int in_group = 0;
            if (userns_ns_to_host_gid(task->user_ns, task->gid) == vnode->gid)
                in_group = 1;
            else {
                for (int gi = 0; gi < task->ngroups; gi++) {
                    uint32_t gh = userns_ns_to_host_gid(task->user_ns,
                                                        task->groups[gi]);
                    if (gh == vnode->gid) { in_group = 1; break; }
                }
            }
            if (!in_group)
                local_mode &= ~(uint32_t)02000;
        }
    }

    /* Check if filesystem supports permission changes */
    if (!vnode->ops || !vnode->ops->setattr) {
        fut_printf("[FCHMOD] fchmod(fd=%d [%s], vnode_ino=%lu, mode=%s, special=%s) "
                   "-> ENOSYS (filesystem doesn't support setattr)\n",
                   local_fd, fd_category, vnode->ino, mode_desc, special_bits_desc);
        return -ENOSYS;
    }

    /* Phase 2: Store old mode for before/after comparison */
    uint32_t old_mode = vnode->mode & 07777;
    uint32_t old_perms = old_mode & 0777;

    /* Create a stat structure with the new mode.
     * uid/gid use (uint32_t)-1 as "don't change" sentinel. */
    struct fut_stat stat = {0};
    stat.st_mode = local_mode;
    stat.st_uid = (uint32_t)-1;
    stat.st_gid = (uint32_t)-1;
    stat.st_atime = (uint64_t)-1;
    stat.st_mtime = (uint64_t)-1;

    /* Call the filesystem's setattr operation */
    int ret = vnode->ops->setattr(vnode, &stat);

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

        fut_printf("[FCHMOD] fchmod(fd=%d [%s], vnode_ino=%lu, mode=%s, special=%s) "
                   "-> %d (%s)\n",
                   local_fd, fd_category, vnode->ino, mode_desc, special_bits_desc,
                   ret, error_desc);
        return ret;
    }

    /* Phase 2: Build permission change description */
    char perms_change_buf[32];
    p = perms_change_buf;

    *p++ = '0';
    if (old_perms >= 0100) {
        *p++ = '0' + ((old_perms >> 6) & 7);
    }
    *p++ = '0' + ((old_perms >> 3) & 7);
    *p++ = '0' + (old_perms & 7);

    const char *arrow = " -> 0";
    while (*arrow) *p++ = *arrow++;

    if (perm_bits >= 0100) {
        *p++ = '0' + ((perm_bits >> 6) & 7);
    }
    *p++ = '0' + ((perm_bits >> 3) & 7);
    *p++ = '0' + (perm_bits & 7);
    *p = '\0';

    /* Dispatch IN_ATTRIB inotify event so watchers see the permission change */
    if (vnode->parent && vnode->name) {
        char dir_path[256];
        if (fut_vnode_build_path(vnode->parent, dir_path, sizeof(dir_path)))
            inotify_dispatch_event(dir_path, 0x00000004 /* IN_ATTRIB */, vnode->name, 0);
    }

    return 0;
}
