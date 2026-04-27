/* kernel/sys_symlinkat.c - Directory-based symbolic link creation syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the symlinkat() syscall for creating symbolic links relative to a directory FD.
 * Essential for thread-safe symlink operations and avoiding race conditions.
 *
 * Phase 1 (Completed): Basic symlinkat with directory FD support
 * Phase 2 (Completed): Directory FD resolution via VFS with proper validation
 * Phase 3 (Completed): Enhanced error handling and dangling symlink support
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <stdint.h>
#include <string.h>

#include <kernel/kprintf.h>
#include <kernel/uaccess.h>
#include <kernel/syscalls.h>
#include <fcntl.h>

#include <platform/platform.h>

static inline int symlinkat_copy_from_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)src >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_from_user(dst, src, n);
}

/* AT_* constants provided by fcntl.h */

/**
 * symlinkat() - Create symbolic link relative to directory FD
 *
 * Like symlink(), but linkpath is interpreted relative to newdirfd instead of
 * the current working directory. This enables race-free symlink creation when
 * working with directory hierarchies in multithreaded applications.
 *
 * @param target    The target path that the symlink points to
 * @param newdirfd  Directory file descriptor (or AT_FDCWD for CWD)
 * @param linkpath  Path relative to newdirfd (or absolute path)
 *
 * Returns:
 *   - 0 on success
 *   - -EBADF if newdirfd is invalid
 *   - -EFAULT if target or linkpath is inaccessible
 *   - -EINVAL if target or linkpath is empty or NULL
 *   - -EEXIST if linkpath already exists
 *   - -ENOENT if parent directory doesn't exist
 *   - -ENOTDIR if path component is not a directory
 *   - -ENOSPC if no space available
 *   - -EROFS if filesystem is read-only
 *   - -EACCES if permission denied
 *   - -ENAMETOOLONG if pathname too long
 *
 * Behavior:
 *   - If linkpath is absolute, newdirfd is ignored
 *   - If linkpath is relative and newdirfd is AT_FDCWD, uses current directory
 *   - If linkpath is relative and newdirfd is FD, uses that directory
 *   - target does not need to exist (dangling symlink allowed)
 *   - target is stored as-is in the symlink (not resolved)
 *   - Prevents TOCTOU races vs separate getcwd() + symlink()
 *
 * Common usage patterns:
 *
 * Thread-safe symlink creation:
 *   int dirfd = open("/some/dir", O_RDONLY | O_DIRECTORY);
 *   symlinkat("/target/path", dirfd, "link-name");
 *   close(dirfd);
 *
 * Use current directory:
 *   symlinkat("/target", AT_FDCWD, "link");
 *   // Same as symlink("/target", "link")
 *
 * Absolute linkpath (dirfd ignored):
 *   symlinkat("/target", dirfd, "/tmp/link");
 *   // dirfd not used
 *
 * Create relative symlink:
 *   symlinkat("../file.txt", dirfd, "link");
 *   // Creates symlink pointing to relative path
 *
 * Dangling symlink (target doesn't exist):
 *   symlinkat("/nonexistent", dirfd, "broken-link");
 *   // Creates symlink even if /nonexistent doesn't exist
 *
 * Advantages over symlink():
 * 1. Thread-safe: Works correctly with multiple threads
 * 2. Race-free: Directory context locked by FD
 * 3. Flexible: Can use CWD or specific directory
 *
 * Phase 1 (Completed): Basic implementation with newdirfd support
 */
long sys_symlinkat(const char *target, int newdirfd, const char *linkpath) {
    /* ARM64 FIX: Copy parameters to local variables */
    const char *local_target = target;
    int local_newdirfd = newdirfd;
    const char *local_linkpath = linkpath;

    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[SYMLINKAT] symlinkat(newdirfd=%d) -> ESRCH (no current task)\n",
                   local_newdirfd);
        return -ESRCH;
    }

    /* NULL pointers are EFAULT per Linux symlinkat(2). */
    if (!local_target) {
        fut_printf("[SYMLINKAT] symlinkat(target=NULL, newdirfd=%d) -> EFAULT\n",
                   local_newdirfd);
        return -EFAULT;
    }

    if (!local_linkpath) {
        fut_printf("[SYMLINKAT] symlinkat(newdirfd=%d, linkpath=NULL) -> EFAULT\n",
                   local_newdirfd);
        return -EFAULT;
    }

    /* Copy target from userspace */
    char target_buf[256];
    if (symlinkat_copy_from_user(target_buf, local_target, sizeof(target_buf)) != 0) {
        fut_printf("[SYMLINKAT] symlinkat(newdirfd=%d) -> EFAULT (copy_from_user target failed)\n",
                   local_newdirfd);
        return -EFAULT;
    }
    /* Verify target was not truncated */
    if (memchr(target_buf, '\0', sizeof(target_buf)) == NULL) {
        fut_printf("[SYMLINKAT] symlinkat(target exceeds %zu bytes, newdirfd=%d) -> ENAMETOOLONG\n",
                   sizeof(target_buf) - 1, local_newdirfd);
        return -ENAMETOOLONG;
    }

    /* Copy linkpath from userspace */
    char linkpath_buf[256];
    if (symlinkat_copy_from_user(linkpath_buf, local_linkpath, sizeof(linkpath_buf)) != 0) {
        fut_printf("[SYMLINKAT] symlinkat(newdirfd=%d) -> EFAULT (copy_from_user linkpath failed)\n",
                   local_newdirfd);
        return -EFAULT;
    }
    /* Verify linkpath was not truncated */
    if (memchr(linkpath_buf, '\0', sizeof(linkpath_buf)) == NULL) {
        fut_printf("[SYMLINKAT] symlinkat(newdirfd=%d, linkpath exceeds %zu bytes) -> ENAMETOOLONG\n",
                   local_newdirfd, sizeof(linkpath_buf) - 1);
        return -ENAMETOOLONG;
    }

    /* Empty target/linkpath is ENOENT per Linux symlinkat(2). */
    if (target_buf[0] == '\0') {
        fut_printf("[SYMLINKAT] symlinkat(target=\"\" [empty], newdirfd=%d) -> ENOENT\n",
                   local_newdirfd);
        return -ENOENT;
    }

    if (linkpath_buf[0] == '\0') {
        fut_printf("[SYMLINKAT] symlinkat(newdirfd=%d, linkpath=\"\" [empty]) -> ENOENT\n",
                   local_newdirfd);
        return -ENOENT;
    }

    /* Categorize linkpath */
    const char *path_type;
    if (linkpath_buf[0] == '/') {
        path_type = "absolute";
    } else if (local_newdirfd == AT_FDCWD) {
        path_type = "relative to CWD";
    } else {
        path_type = "relative to newdirfd";
    }

    /* Calculate path lengths */
    size_t target_len = strlen(target_buf);
    size_t link_len = strlen(linkpath_buf);

    /* Resolve the full path using fut_vfs_resolve_at */
    char resolved_linkpath[256];
    int rret = fut_vfs_resolve_at(task, local_newdirfd, linkpath_buf,
                                   resolved_linkpath, sizeof(resolved_linkpath));
    if (rret < 0) {
        fut_printf("[SYMLINKAT] symlinkat(newdirfd=%d, linkpath='%s') -> %d (newdirfd resolve failed)\n",
                   local_newdirfd, linkpath_buf, rret);
        return rret;
    }

    /* Perform the symlink via existing sys_symlink implementation */
    int ret = (int)sys_symlink(target_buf, resolved_linkpath);

    /* Handle errors */
    if (ret < 0) {
        const char *error_desc;
        switch (ret) {
            case -EEXIST:
                error_desc = "linkpath already exists";
                break;
            case -ENOENT:
                error_desc = "parent directory doesn't exist";
                break;
            case -ENOTDIR:
                error_desc = "path component not a directory";
                break;
            case -ENOSPC:
                error_desc = "no space available";
                break;
            case -EROFS:
                error_desc = "read-only filesystem";
                break;
            case -EACCES:
                error_desc = "permission denied";
                break;
            default:
                error_desc = "symlink operation failed";
                break;
        }

        fut_printf("[SYMLINKAT] symlinkat(target='%s' [len=%lu], newdirfd=%d, linkpath='%s' [%s, len=%lu]) -> %d (%s)\n",
                   target_buf, (unsigned long)target_len, local_newdirfd,
                   linkpath_buf, path_type, (unsigned long)link_len, ret, error_desc);
        return ret;
    }

    /* Success */
    fut_printf("[SYMLINKAT] symlinkat(target='%s' [len=%lu], newdirfd=%d, linkpath='%s' [%s, len=%lu]) -> 0 (Phase 2: directory FD resolution)\n",
               target_buf, (unsigned long)target_len, local_newdirfd,
               linkpath_buf, path_type, (unsigned long)link_len);

    return 0;
}
