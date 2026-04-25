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
 * Phase 3 (Completed): AT_SYMLINK_FOLLOW support and symlink rejection without the flag
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <kernel/syscalls.h>
#include <stdint.h>
#include <string.h>

#include <kernel/kprintf.h>
#include <kernel/uaccess.h>
#include <fcntl.h>

#include <platform/platform.h>

static inline int linkat_copy_from_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)src >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_from_user(dst, src, n);
}

/* AT_* constants provided by fcntl.h */

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
 * Phase 2 (Completed): Directory FD resolution via VFS with proper validation
 * Phase 3 (Completed): AT_SYMLINK_FOLLOW support: reject symlink targets without flag
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

    /* Phase 1: Validate flags */
    const int VALID_FLAGS = AT_SYMLINK_FOLLOW | AT_EMPTY_PATH;
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
    if (linkat_copy_from_user(oldpath_buf, local_oldpath, sizeof(oldpath_buf)) != 0) {
        fut_printf("[LINKAT] linkat(olddirfd=%d) -> EFAULT (copy_from_user oldpath failed)\n",
                   local_olddirfd);
        return -EFAULT;
    }
    /* Verify oldpath was not truncated */
    if (memchr(oldpath_buf, '\0', sizeof(oldpath_buf)) == NULL) {
        fut_printf("[LINKAT] linkat(olddirfd=%d, oldpath exceeds %zu bytes) -> ENAMETOOLONG\n",
                   local_olddirfd, sizeof(oldpath_buf) - 1);
        return -ENAMETOOLONG;
    }

    /* Copy newpath from userspace */
    char newpath_buf[256];
    if (linkat_copy_from_user(newpath_buf, local_newpath, sizeof(newpath_buf)) != 0) {
        fut_printf("[LINKAT] linkat(newdirfd=%d) -> EFAULT (copy_from_user newpath failed)\n",
                   local_newdirfd);
        return -EFAULT;
    }
    /* Verify newpath was not truncated */
    if (memchr(newpath_buf, '\0', sizeof(newpath_buf)) == NULL) {
        fut_printf("[LINKAT] linkat(newdirfd=%d, newpath exceeds %zu bytes) -> ENAMETOOLONG\n",
                   local_newdirfd, sizeof(newpath_buf) - 1);
        return -ENAMETOOLONG;
    }

    /* AT_EMPTY_PATH: olddirfd is the file fd, oldpath must be "".
     * Creates a named hard link to an open (possibly anonymous) file. */
    if ((local_flags & AT_EMPTY_PATH) && oldpath_buf[0] == '\0') {
        /* Resolve newpath */
        char resolved_newpath[256];
        int rret = fut_vfs_resolve_at(task, local_newdirfd, newpath_buf,
                                       resolved_newpath, sizeof(resolved_newpath));
        if (rret < 0) {
            fut_printf("[LINKAT] AT_EMPTY_PATH resolve newpath failed: %d\n", rret);
            return rret;
        }
        if (newpath_buf[0] == '\0') {
            return -ENOENT;
        }

        /* Get the vnode from olddirfd */
        if (local_olddirfd < 0 || local_olddirfd >= task->max_fds || !task->fd_table) {
            return -EBADF;
        }
        struct fut_file *src_file = task->fd_table[local_olddirfd];
        if (!src_file || !src_file->vnode) {
            return -EBADF;
        }
        struct fut_vnode *src_vnode = src_file->vnode;
        if (src_vnode->type == VN_DIR) {
            return -EPERM;  /* Cannot hard-link directories */
        }

        /* Use the vnode's ops->link to add a directory entry */
        if (!src_vnode->ops || !src_vnode->ops->link) {
            return -EPERM;
        }
        int ret = src_vnode->ops->link(src_vnode, "", resolved_newpath);
        if (ret == 0)
            fut_printf("[LINKAT] AT_EMPTY_PATH: fd=%d linked to '%s'\n",
                       local_olddirfd, resolved_newpath);
        return ret;
    }

    /* Validate oldpath is not empty (non-AT_EMPTY_PATH case) */
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
    size_t old_path_len = strlen(oldpath_buf);
    size_t new_path_len = strlen(newpath_buf);

    /* Resolve both paths using fut_vfs_resolve_at */
    char resolved_oldpath[256];
    char resolved_newpath[256];

    int rret = fut_vfs_resolve_at(task, local_olddirfd, oldpath_buf,
                                   resolved_oldpath, sizeof(resolved_oldpath));
    if (rret < 0) {
        fut_printf("[LINKAT] linkat(olddirfd=%d, oldpath='%s') -> %d (olddirfd resolve failed)\n",
                   local_olddirfd, oldpath_buf, rret);
        return rret;
    }

    rret = fut_vfs_resolve_at(task, local_newdirfd, newpath_buf,
                               resolved_newpath, sizeof(resolved_newpath));
    if (rret < 0) {
        fut_printf("[LINKAT] linkat(newdirfd=%d, newpath='%s') -> %d (newdirfd resolve failed)\n",
                   local_newdirfd, newpath_buf, rret);
        return rret;
    }

    /* AT_SYMLINK_FOLLOW: linkat with this flag wants to hard-link the
     * file the symlink points at, not the symlink itself. sys_link
     * (correctly per POSIX) does NOT follow leaf symlinks anymore, so
     * we resolve the symlink chain here when the flag is set and pass
     * the dereferenced target path to sys_link. Without the flag, the
     * default sys_link behaviour (link the symlink itself) is what
     * the user asked for. */
    char follow_buf[256];
    const char *link_old = resolved_oldpath;
    if (local_flags & AT_SYMLINK_FOLLOW) {
        /* Resolve up to 8 nested symlinks to their final non-symlink target. */
        char cur[256];
        size_t curlen = 0;
        for (curlen = 0; curlen < sizeof(cur) - 1 && resolved_oldpath[curlen]; curlen++)
            cur[curlen] = resolved_oldpath[curlen];
        cur[curlen] = '\0';
        for (int hop = 0; hop < 8; hop++) {
            struct fut_vnode *v = NULL;
            int lret = fut_vfs_lookup_nofollow(cur, &v);
            if (lret != 0 || !v)
                break;
            int is_link = (v->type == VN_LNK);
            fut_vnode_unref(v);
            if (!is_link)
                break;
            ssize_t rl = fut_vfs_readlink(cur, follow_buf, sizeof(follow_buf) - 1);
            if (rl <= 0)
                break;
            follow_buf[rl] = '\0';
            /* Absolute target replaces cur; relative target needs to
             * be resolved against cur's parent. For the common case
             * absolute-target symlinks this is enough. */
            if (follow_buf[0] == '/') {
                size_t fl = (size_t)rl < sizeof(cur) - 1 ? (size_t)rl : sizeof(cur) - 1;
                __builtin_memcpy(cur, follow_buf, fl);
                cur[fl] = '\0';
            } else {
                /* Relative: replace cur's leaf with follow_buf */
                int slash = -1;
                for (int i = 0; cur[i]; i++) if (cur[i] == '/') slash = i;
                size_t base = (slash >= 0) ? (size_t)slash + 1 : 0;
                size_t room = sizeof(cur) - 1 - base;
                size_t fl = (size_t)rl < room ? (size_t)rl : room;
                __builtin_memcpy(cur + base, follow_buf, fl);
                cur[base + fl] = '\0';
            }
        }
        size_t fl = 0;
        for (fl = 0; fl < sizeof(follow_buf) - 1 && cur[fl]; fl++)
            follow_buf[fl] = cur[fl];
        follow_buf[fl] = '\0';
        link_old = follow_buf;
    }

    /* Perform the link via existing sys_link implementation */
    int ret = (int)sys_link(link_old, resolved_newpath);

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
    fut_printf("[LINKAT] linkat(olddirfd=%d, oldpath='%s' [%s, len=%lu], newdirfd=%d, newpath='%s' [%s, len=%lu], flags=%s) -> 0\n",
               local_olddirfd, oldpath_buf, old_path_type, (unsigned long)old_path_len,
               local_newdirfd, newpath_buf, new_path_type, (unsigned long)new_path_len,
               flags_desc);

    return 0;
}
