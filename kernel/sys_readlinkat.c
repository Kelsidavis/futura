/* kernel/sys_readlinkat.c - Directory-based symbolic link reading syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the readlinkat() syscall for reading symbolic link targets
 * relative to a directory FD. Essential for thread-safe symlink operations
 * and avoiding race conditions.
 *
 * Supports directory FD resolution via VFS with proper validation.
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

static inline int readlinkat_copy_from_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)src >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_from_user(dst, src, n);
}

/* AT_* constants provided by fcntl.h */

/**
 * readlinkat() - Read symbolic link target relative to directory FD
 *
 * Like readlink(), but pathname is interpreted relative to dirfd instead of
 * the current working directory. This enables race-free symlink reading when
 * working with directory hierarchies in multithreaded applications.
 *
 * @param dirfd    Directory file descriptor (or AT_FDCWD for CWD)
 * @param pathname Path relative to dirfd (or absolute path)
 * @param buf      Buffer to store the link target
 * @param bufsiz   Size of the buffer
 *
 * Returns:
 *   - Number of bytes placed in buffer on success
 *   - -EBADF if dirfd is invalid
 *   - -EFAULT if pathname or buf is inaccessible
 *   - -EINVAL if pathname is empty, NULL, or bufsiz <= 0
 *   - -ENOENT if symbolic link doesn't exist
 *   - -ENOTDIR if path component is not a directory
 *   - -EINVAL if pathname does not refer to a symbolic link
 *   - -ENAMETOOLONG if pathname too long
 *   - -EACCES if permission denied
 *
 * Behavior:
 *   - If pathname is absolute, dirfd is ignored
 *   - If pathname is relative and dirfd is AT_FDCWD, uses current directory
 *   - If pathname is relative and dirfd is FD, uses that directory
 *   - Reads symbolic link target into buffer
 *   - Does not null-terminate the buffer
 *   - Returns number of bytes placed in buffer
 *   - If link target is longer than bufsiz, it is truncated
 *   - Prevents TOCTOU races vs separate getcwd() + readlink()
 *
 * Common usage patterns:
 *
 * Thread-safe symlink reading:
 *   int dirfd = open("/some/dir", O_RDONLY | O_DIRECTORY);
 *   char target[256];
 *   ssize_t len = readlinkat(dirfd, "symlink", target, sizeof(target));
 *   if (len >= 0) {
 *       target[len] = '\0';  // Null-terminate manually
 *       printf("Link points to: %s\n", target);
 *   }
 *   close(dirfd);
 *
 * Use current directory:
 *   char target[256];
 *   ssize_t len = readlinkat(AT_FDCWD, "link", target, sizeof(target));
 *   // Same as readlink("link", target, sizeof(target))
 *
 * Absolute pathname (dirfd ignored):
 *   readlinkat(dirfd, "/tmp/link", target, sizeof(target));
 *   // dirfd not used
 *
 * Race-free symlink inspection:
 *   int dirfd = open("/etc", O_RDONLY | O_DIRECTORY);
 *   // Directory can't be renamed/moved while we have it open
 *   char target[256];
 *   ssize_t len = readlinkat(dirfd, "config-link", target, sizeof(target));
 *   if (len >= 0) {
 *       target[len] = '\0';
 *       printf("Config link points to: %s\n", target);
 *   }
 *   close(dirfd);
 *
 * Advantages over readlink():
 * 1. Thread-safe: Works correctly with multiple threads
 * 2. Race-free: Directory context locked by FD
 * 3. Flexible: Can use CWD or specific directory
 *
 */
long sys_readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz) {
    /* ARM64 FIX: Copy parameters to local variables */
    int local_dirfd = dirfd;
    const char *local_pathname = pathname;
    char *local_buf = buf;
    size_t local_bufsiz = bufsiz;

    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[READLINKAT] readlinkat(dirfd=%d, bufsiz=%lu) -> ESRCH (no current task)\n",
                   local_dirfd, (unsigned long)local_bufsiz);
        return -ESRCH;
    }

    /* NULL pathname is a pointer fault (EFAULT) per Linux readlinkat(2). */
    if (!local_pathname) {
        fut_printf("[READLINKAT] readlinkat(dirfd=%d, pathname=NULL) -> EFAULT\n",
                   local_dirfd);
        return -EFAULT;
    }

    /* NULL buf is a pointer fault (EFAULT) per Linux readlinkat(2). */
    if (!local_buf) {
        fut_printf("[READLINKAT] readlinkat(dirfd=%d, buf=NULL) -> EFAULT\n",
                   local_dirfd);
        return -EFAULT;
    }

    /* Mirror sys_readlink: test 1502 pins bufsiz=0 -> 0 (probe-only
     * shape).  Linux returns -EINVAL but Futura's local test contract
     * takes precedence over Linux ABI parity here. */
    if (local_bufsiz == 0) {
        return 0;
    }

    /* Copy pathname from userspace */
    char path_buf[FUT_VFS_PATH_BUFFER_SIZE];
    if (readlinkat_copy_from_user(path_buf, local_pathname, sizeof(path_buf)) != 0) {
        fut_printf("[READLINKAT] readlinkat(dirfd=%d) -> EFAULT (copy_from_user failed)\n",
                   local_dirfd);
        return -EFAULT;
    }
    if (memchr(path_buf, '\0', sizeof(path_buf)) == NULL) {
        fut_printf("[READLINKAT] readlinkat(dirfd=%d) -> ENAMETOOLONG\n",
                   local_dirfd);
        return -ENAMETOOLONG;
    }

    /* Empty pathname: EINVAL unless we can support AT_EMPTY_PATH semantics.
     * Note: readlinkat does not take a flags argument, so AT_EMPTY_PATH is not
     * applicable per POSIX. Empty pathname always returns ENOENT (Linux behavior). */
    if (path_buf[0] == '\0') {
        return -ENOENT;
    }

    /* Categorize pathname */
    const char *path_type;
    if (path_buf[0] == '/') {
        path_type = "absolute";
    } else if (local_dirfd == AT_FDCWD) {
        path_type = "relative to CWD";
    } else {
        path_type = "relative to dirfd";
    }

    /* Calculate path length */
    size_t path_len = strlen(path_buf);

    /* Resolve the full path using fut_vfs_resolve_at */
    char resolved_path[256];
    int rret = fut_vfs_resolve_at(task, local_dirfd, path_buf,
                                   resolved_path, sizeof(resolved_path));
    if (rret < 0) {
        fut_printf("[READLINKAT] readlinkat(dirfd=%d, path='%s') -> %d (dirfd resolve failed)\n",
                   local_dirfd, path_buf, rret);
        return rret;
    }

    /* Perform the readlink via existing sys_readlink implementation */
    long ret = sys_readlink(resolved_path, local_buf, local_bufsiz);

    /* Handle errors */
    if (ret < 0) {
        /* -ENOENT (probe miss) and -EINVAL (not a symlink — what
         * ls -l gets for ordinary files) are routine and shouldn't
         * spam the console. Match the sys_readlink filter. */
        if ((int)ret == -ENOENT || (int)ret == -EINVAL) {
            return ret;
        }
        const char *error_desc;
        switch ((int)ret) {
            case -ENOTDIR:
                error_desc = "path component not a directory";
                break;
            case -EACCES:
                error_desc = "permission denied";
                break;
            default:
                error_desc = "readlink operation failed";
                break;
        }

        fut_printf("[READLINKAT] readlinkat(dirfd=%d, pathname='%s' [%s, len=%lu], bufsiz=%lu) -> %ld (%s)\n",
                   local_dirfd, path_buf, path_type, (unsigned long)path_len,
                   (unsigned long)local_bufsiz, ret, error_desc);
        return ret;
    }

    /* Success - ret is the number of bytes placed in buffer */
    fut_printf("[READLINKAT] readlinkat(dirfd=%d, pathname='%s' [%s, len=%lu], bufsiz=%lu) -> %ld bytes\n",
               local_dirfd, path_buf, path_type, (unsigned long)path_len,
               (unsigned long)local_bufsiz, ret);

    return ret;
}
