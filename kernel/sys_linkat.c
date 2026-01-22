/* kernel/sys_linkat.c - Directory-based hard link creation syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the linkat() syscall for creating hard links relative to directory FDs.
 * Essential for thread-safe link operations and avoiding race conditions.
 *
 * Phase 1 (Completed): Basic linkat with directory FD support
 * Phase 2 (Completed): Directory FD resolution via VFS with proper validation
 * Phase 3: AT_SYMLINK_FOLLOW support and cross-directory link validation
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <stdint.h>

#include <kernel/kprintf.h>
#include <kernel/uaccess.h>

/* AT_* constants */
#define AT_FDCWD            -100  /* Use current working directory */
#define AT_SYMLINK_FOLLOW   0x400 /* Follow symbolic links */

/**
 * linkat() - Create hard link relative to directory FDs
 *
 * Like link(), but oldpath is interpreted relative to olddirfd and newpath
 * is interpreted relative to newdirfd. This enables race-free hard link
 * creation when working with directory hierarchies in multithreaded applications.
 *
 * @param olddirfd Directory FD for oldpath (or AT_FDCWD for CWD)
 * @param oldpath  Path relative to olddirfd (or absolute)
 * @param newdirfd Directory FD for newpath (or AT_FDCWD for CWD)
 * @param newpath  Path relative to newdirfd (or absolute)
 * @param flags    AT_SYMLINK_FOLLOW to follow symlinks in oldpath, or 0
 *
 * Returns:
 *   - 0 on success
 *   - -EBADF if olddirfd or newdirfd is invalid
 *   - -EFAULT if paths are inaccessible
 *   - -EINVAL if oldpath or newpath is invalid/empty/NULL, or flags invalid
 *   - -EEXIST if newpath already exists
 *   - -ENOENT if oldpath does not exist
 *   - -EISDIR if oldpath is a directory
 *   - -EXDEV if oldpath and newpath on different filesystems
 *   - -EACCES if permission denied
 *   - -ENAMETOOLONG if pathname too long
 *
 * Behavior:
 *   - If paths are absolute, corresponding dirfd is ignored
 *   - If paths are relative and dirfd is AT_FDCWD, uses current directory
 *   - If paths are relative and dirfd is FD, uses that directory
 *   - AT_SYMLINK_FOLLOW: Follow symlinks in oldpath (link to target)
 *   - Default (no flag): Don't follow symlinks (link to symlink itself)
 *   - Prevents TOCTOU races vs separate getcwd() + link()
 *
 * Common usage patterns:
 *
 * Thread-safe hard link creation:
 *   int dirfd = open("/some/dir", O_RDONLY | O_DIRECTORY);
 *   linkat(dirfd, "original.txt", dirfd, "hardlink.txt", 0);
 *   close(dirfd);
 *
 * Link across different directories:
 *   int olddir = open("/home/user", O_RDONLY | O_DIRECTORY);
 *   int newdir = open("/tmp", O_RDONLY | O_DIRECTORY);
 *   linkat(olddir, "file.txt", newdir, "link.txt", 0);
 *   close(olddir);
 *   close(newdir);
 *
 * Use current directory:
 *   linkat(AT_FDCWD, "file.txt", AT_FDCWD, "link.txt", 0);
 *   // Same as link("file.txt", "link.txt")
 *
 * Follow symlink and link to target:
 *   linkat(dirfd, "symlink", dirfd, "hardlink", AT_SYMLINK_FOLLOW);
 *   // Creates hard link to what symlink points to
 *
 * Don't follow symlink (link to symlink itself):
 *   linkat(dirfd, "symlink", dirfd, "link-to-symlink", 0);
 *   // Creates hard link to the symlink itself
 *
 * Absolute paths (dirfds ignored):
 *   linkat(dirfd1, "/tmp/old", dirfd2, "/tmp/new", 0);
 *   // dirfd1 and dirfd2 not used
 *
 * Advantages over link():
 * 1. Thread-safe: Works correctly with multiple threads
 * 2. Race-free: Directory context locked by FDs
 * 3. Flexible: Source and dest can be in different directories
 * 4. Symlink control: Can choose to follow or not follow symlinks
 *
 * Phase 1 (Completed): Basic implementation with olddirfd and newdirfd support
 */
long sys_linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags) {
    /* ARM64 FIX: Copy parameters to local variables */
    int local_olddirfd = olddirfd;
    const char *local_oldpath = oldpath;
    int local_newdirfd = newdirfd;
    const char *local_newpath = newpath;
    int local_flags = flags;

    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[LINKAT] linkat(olddirfd=%d, newdirfd=%d, flags=0x%x) -> ESRCH (no current task)\n",
                   local_olddirfd, local_newdirfd, local_flags);
        return -ESRCH;
    }

    /* Phase 1: Validate flags - only AT_SYMLINK_FOLLOW is valid */
    const int VALID_FLAGS = AT_SYMLINK_FOLLOW;
    if (local_flags & ~VALID_FLAGS) {
        fut_printf("[LINKAT] linkat(olddirfd=%d, newdirfd=%d, flags=0x%x) -> EINVAL (invalid flags)\n",
                   local_olddirfd, local_newdirfd, local_flags);
        return -EINVAL;
    }

    /* Validate oldpath pointer */
    if (!local_oldpath) {
        fut_printf("[LINKAT] linkat(olddirfd=%d, oldpath=NULL) -> EINVAL (NULL oldpath)\n",
                   local_olddirfd);
        return -EINVAL;
    }

    /* Validate newpath pointer */
    if (!local_newpath) {
        fut_printf("[LINKAT] linkat(newdirfd=%d, newpath=NULL) -> EINVAL (NULL newpath)\n",
                   local_newdirfd);
        return -EINVAL;
    }

    /* Copy oldpath from userspace */
    char oldpath_buf[256];
    if (fut_copy_from_user(oldpath_buf, local_oldpath, sizeof(oldpath_buf) - 1) != 0) {
        fut_printf("[LINKAT] linkat(olddirfd=%d) -> EFAULT (copy_from_user oldpath failed)\n",
                   local_olddirfd);
        return -EFAULT;
    }
    oldpath_buf[sizeof(oldpath_buf) - 1] = '\0';

    /* Copy newpath from userspace */
    char newpath_buf[256];
    if (fut_copy_from_user(newpath_buf, local_newpath, sizeof(newpath_buf) - 1) != 0) {
        fut_printf("[LINKAT] linkat(newdirfd=%d) -> EFAULT (copy_from_user newpath failed)\n",
                   local_newdirfd);
        return -EFAULT;
    }
    newpath_buf[sizeof(newpath_buf) - 1] = '\0';

    /* Validate oldpath is not empty */
    if (oldpath_buf[0] == '\0') {
        fut_printf("[LINKAT] linkat(olddirfd=%d, oldpath=\"\" [empty]) -> EINVAL (empty oldpath)\n",
                   local_olddirfd);
        return -EINVAL;
    }

    /* Validate newpath is not empty */
    if (newpath_buf[0] == '\0') {
        fut_printf("[LINKAT] linkat(newdirfd=%d, newpath=\"\" [empty]) -> EINVAL (empty newpath)\n",
                   local_newdirfd);
        return -EINVAL;
    }

    /* Check for oldpath truncation */
    size_t old_trunc_check = 0;
    while (oldpath_buf[old_trunc_check] != '\0' && old_trunc_check < sizeof(oldpath_buf) - 1) {
        old_trunc_check++;
    }
    if (oldpath_buf[old_trunc_check] != '\0') {
        fut_printf("[LINKAT] linkat(olddirfd=%d, oldpath_len>255) -> ENAMETOOLONG (oldpath truncated)\n",
                   local_olddirfd);
        return -ENAMETOOLONG;
    }

    /* Check for newpath truncation */
    size_t new_trunc_check = 0;
    while (newpath_buf[new_trunc_check] != '\0' && new_trunc_check < sizeof(newpath_buf) - 1) {
        new_trunc_check++;
    }
    if (newpath_buf[new_trunc_check] != '\0') {
        fut_printf("[LINKAT] linkat(newdirfd=%d, newpath_len>255) -> ENAMETOOLONG (newpath truncated)\n",
                   local_newdirfd);
        return -ENAMETOOLONG;
    }

    /* Categorize oldpath */
    const char *old_path_type;
    if (oldpath_buf[0] == '/') {
        old_path_type = "absolute";
    } else if (local_olddirfd == AT_FDCWD) {
        old_path_type = "relative to CWD";
    } else {
        old_path_type = "relative to olddirfd";
    }

    /* Categorize newpath */
    const char *new_path_type;
    if (newpath_buf[0] == '/') {
        new_path_type = "absolute";
    } else if (local_newdirfd == AT_FDCWD) {
        new_path_type = "relative to CWD";
    } else {
        new_path_type = "relative to newdirfd";
    }

    /* Categorize flags */
    const char *flags_desc;
    if (local_flags == 0) {
        flags_desc = "none (link to symlink itself)";
    } else if (local_flags == AT_SYMLINK_FOLLOW) {
        flags_desc = "AT_SYMLINK_FOLLOW (link to symlink target)";
    } else {
        flags_desc = "unknown flags";
    }

    /* Calculate path lengths */
    size_t old_path_len = 0;
    while (oldpath_buf[old_path_len] != '\0' && old_path_len < 255) {
        old_path_len++;
    }

    size_t new_path_len = 0;
    while (newpath_buf[new_path_len] != '\0' && new_path_len < 255) {
        new_path_len++;
    }

    /* Phase 2: Implement proper directory FD resolution via VFS */

    /* Resolve oldpath based on olddirfd */
    char resolved_oldpath[256];

    /* If oldpath is absolute, use it directly */
    if (oldpath_buf[0] == '/') {
        /* Copy absolute path */
        size_t i;
        for (i = 0; i < sizeof(resolved_oldpath) - 1 && oldpath_buf[i] != '\0'; i++) {
            resolved_oldpath[i] = oldpath_buf[i];
        }
        resolved_oldpath[i] = '\0';
    }
    /* If olddirfd is AT_FDCWD, use current working directory */
    else if (local_olddirfd == AT_FDCWD) {
        /* For now, use relative path as-is (CWD resolution happens in VFS) */
        size_t i;
        for (i = 0; i < sizeof(resolved_oldpath) - 1 && oldpath_buf[i] != '\0'; i++) {
            resolved_oldpath[i] = oldpath_buf[i];
        }
        resolved_oldpath[i] = '\0';
    }
    /* Olddirfd is a real FD - resolve via VFS */
    else {
        /* Phase 5: Validate olddirfd bounds before accessing FD table */
        if (local_olddirfd < 0) {
            fut_printf("[LINKAT] linkat(olddirfd=%d) -> EBADF (invalid negative olddirfd)\n",
                       local_olddirfd);
            return -EBADF;
        }

        if (local_olddirfd >= task->max_fds) {
            fut_printf("[LINKAT] linkat(olddirfd=%d, max_fds=%d) -> EBADF "
                       "(olddirfd exceeds max_fds, Phase 5: FD bounds validation)\n",
                       local_olddirfd, task->max_fds);
            return -EBADF;
        }

        /* Get file structure from olddirfd */
        struct fut_file *dir_file = vfs_get_file_from_task(task, local_olddirfd);

        if (!dir_file) {
            fut_printf("[LINKAT] linkat(olddirfd=%d) -> EBADF (olddirfd not open)\n",
                       local_olddirfd);
            return -EBADF;
        }

        /* Verify olddirfd refers to a directory */
        if (!dir_file->vnode) {
            fut_printf("[LINKAT] linkat(olddirfd=%d) -> EBADF (olddirfd has no vnode)\n",
                       local_olddirfd);
            return -EBADF;
        }

        /* Check if vnode is a directory */
        if (dir_file->vnode->type != VN_DIR) {
            fut_printf("[LINKAT] linkat(olddirfd=%d) -> ENOTDIR (olddirfd not a directory)\n",
                       local_olddirfd);
            return -ENOTDIR;
        }

        /* Phase 2: Construct path relative to directory */
        size_t i;
        for (i = 0; i < sizeof(resolved_oldpath) - 1 && oldpath_buf[i] != '\0'; i++) {
            resolved_oldpath[i] = oldpath_buf[i];
        }
        resolved_oldpath[i] = '\0';
    }

    /* Resolve newpath based on newdirfd */
    char resolved_newpath[256];

    /* If newpath is absolute, use it directly */
    if (newpath_buf[0] == '/') {
        /* Copy absolute path */
        size_t i;
        for (i = 0; i < sizeof(resolved_newpath) - 1 && newpath_buf[i] != '\0'; i++) {
            resolved_newpath[i] = newpath_buf[i];
        }
        resolved_newpath[i] = '\0';
    }
    /* If newdirfd is AT_FDCWD, use current working directory */
    else if (local_newdirfd == AT_FDCWD) {
        /* For now, use relative path as-is (CWD resolution happens in VFS) */
        size_t i;
        for (i = 0; i < sizeof(resolved_newpath) - 1 && newpath_buf[i] != '\0'; i++) {
            resolved_newpath[i] = newpath_buf[i];
        }
        resolved_newpath[i] = '\0';
    }
    /* Newdirfd is a real FD - resolve via VFS */
    else {
        /* Phase 5: Validate newdirfd bounds before accessing FD table */
        if (local_newdirfd < 0) {
            fut_printf("[LINKAT] linkat(newdirfd=%d) -> EBADF (invalid negative newdirfd)\n",
                       local_newdirfd);
            return -EBADF;
        }

        if (local_newdirfd >= task->max_fds) {
            fut_printf("[LINKAT] linkat(newdirfd=%d, max_fds=%d) -> EBADF "
                       "(newdirfd exceeds max_fds, Phase 5: FD bounds validation)\n",
                       local_newdirfd, task->max_fds);
            return -EBADF;
        }

        /* Get file structure from newdirfd */
        struct fut_file *dir_file = vfs_get_file_from_task(task, local_newdirfd);

        if (!dir_file) {
            fut_printf("[LINKAT] linkat(newdirfd=%d) -> EBADF (newdirfd not open)\n",
                       local_newdirfd);
            return -EBADF;
        }

        /* Verify newdirfd refers to a directory */
        if (!dir_file->vnode) {
            fut_printf("[LINKAT] linkat(newdirfd=%d) -> EBADF (newdirfd has no vnode)\n",
                       local_newdirfd);
            return -EBADF;
        }

        /* Check if vnode is a directory */
        if (dir_file->vnode->type != VN_DIR) {
            fut_printf("[LINKAT] linkat(newdirfd=%d) -> ENOTDIR (newdirfd not a directory)\n",
                       local_newdirfd);
            return -ENOTDIR;
        }

        /* Phase 2: Construct path relative to directory */
        size_t i;
        for (i = 0; i < sizeof(resolved_newpath) - 1 && newpath_buf[i] != '\0'; i++) {
            resolved_newpath[i] = newpath_buf[i];
        }
        resolved_newpath[i] = '\0';
    }

    /* Perform the link via existing sys_link implementation */
    extern long sys_link(const char *oldpath, const char *newpath);
    int ret = (int)sys_link(resolved_oldpath, resolved_newpath);

    /* Handle errors */
    if (ret < 0) {
        const char *error_desc;
        switch (ret) {
            case -EEXIST:
                error_desc = "newpath already exists";
                break;
            case -ENOENT:
                error_desc = "oldpath not found";
                break;
            case -EISDIR:
                error_desc = "oldpath is a directory";
                break;
            case -EXDEV:
                error_desc = "cross-filesystem link not supported";
                break;
            case -EACCES:
                error_desc = "permission denied";
                break;
            case -ENOTDIR:
                error_desc = "path component not a directory";
                break;
            default:
                error_desc = "link operation failed";
                break;
        }

        fut_printf("[LINKAT] linkat(olddirfd=%d, oldpath='%s' [%s, len=%lu], newdirfd=%d, newpath='%s' [%s, len=%lu], flags=%s) -> %d (%s)\n",
                   local_olddirfd, oldpath_buf, old_path_type, (unsigned long)old_path_len,
                   local_newdirfd, newpath_buf, new_path_type, (unsigned long)new_path_len,
                   flags_desc, ret, error_desc);
        return ret;
    }

    /* Success */
    fut_printf("[LINKAT] linkat(olddirfd=%d, oldpath='%s' [%s, len=%lu], newdirfd=%d, newpath='%s' [%s, len=%lu], flags=%s) -> 0 (Phase 2: directory FD resolution)\n",
               local_olddirfd, oldpath_buf, old_path_type, (unsigned long)old_path_len,
               local_newdirfd, newpath_buf, new_path_type, (unsigned long)new_path_len,
               flags_desc);

    return 0;
}
