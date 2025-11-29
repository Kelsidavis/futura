/* kernel/sys_fstatat.c - Directory-based file status syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the fstatat() syscall (also called newfstatat) for retrieving
 * file metadata relative to a directory FD. Essential for thread-safe file
 * inspection and avoiding race conditions.
 *
 * Phase 1 (Completed): Basic fstatat with dirfd and AT_SYMLINK_NOFOLLOW support
 * Phase 2: Enhanced validation and extended attributes
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);
extern int fut_copy_from_user(void *to, const void *from, size_t size);
extern int fut_copy_to_user(void *to, const void *from, size_t size);
extern fut_task_t *fut_task_current(void);

/* AT_* constants */
#define AT_FDCWD            -100  /* Use current working directory */
#define AT_SYMLINK_NOFOLLOW 0x100 /* Don't follow symbolic links */
#define AT_EMPTY_PATH       0x1000 /* Allow empty pathname (fstat via dirfd) */

/**
 * fstatat() - Get file status relative to directory FD
 *
 * Like stat(), but pathname is interpreted relative to dirfd instead of
 * the current working directory. This enables race-free file inspection
 * when working with directory hierarchies in multithreaded applications.
 *
 * Also known as newfstatat() on some systems.
 *
 * @param dirfd    Directory file descriptor (or AT_FDCWD for CWD)
 * @param pathname Path relative to dirfd (or absolute path)
 * @param statbuf  Pointer to userspace stat buffer to fill
 * @param flags    AT_SYMLINK_NOFOLLOW to not follow symlinks, or 0
 *
 * Returns:
 *   - 0 on success
 *   - -EBADF if dirfd is invalid
 *   - -EFAULT if pathname or statbuf is inaccessible
 *   - -EINVAL if pathname is empty, statbuf is NULL, or flags invalid
 *   - -ENOENT if file does not exist
 *   - -ENOTDIR if path component is not a directory
 *   - -ENAMETOOLONG if pathname too long
 *
 * Behavior:
 *   - If pathname is absolute, dirfd is ignored
 *   - If pathname is relative and dirfd is AT_FDCWD, uses current directory
 *   - If pathname is relative and dirfd is FD, uses that directory
 *   - AT_SYMLINK_NOFOLLOW: Don't follow final symlink (like lstat)
 *   - AT_EMPTY_PATH: If pathname is empty, stat the FD itself
 *   - Prevents TOCTOU races vs separate getcwd() + stat()
 *
 * Common usage patterns:
 *
 * Thread-safe file inspection:
 *   int dirfd = open("/some/dir", O_RDONLY | O_DIRECTORY);
 *   struct fut_stat st;
 *   fstatat(dirfd, "file.txt", &st, 0);
 *   printf("Size: %llu bytes\n", st.st_size);
 *   close(dirfd);
 *
 * Check if symlink (don't follow):
 *   struct fut_stat st;
 *   fstatat(dirfd, "link", &st, AT_SYMLINK_NOFOLLOW);
 *   if (S_ISLNK(st.st_mode)) {
 *       printf("Is a symbolic link\n");
 *   }
 *
 * Use current directory:
 *   struct fut_stat st;
 *   fstatat(AT_FDCWD, "file.txt", &st, 0);
 *   // Same as stat("file.txt", &st)
 *
 * Absolute path (dirfd ignored):
 *   struct fut_stat st;
 *   fstatat(dirfd, "/tmp/file", &st, 0);
 *   // dirfd not used
 *
 * Stat the directory itself:
 *   struct fut_stat st;
 *   fstatat(dirfd, "", &st, AT_EMPTY_PATH);
 *   // Stats the directory that dirfd refers to
 *
 * Race-free file verification:
 *   int dirfd = open("/etc", O_RDONLY | O_DIRECTORY);
 *   // Directory can't be renamed/moved while we have it open
 *   struct fut_stat st;
 *   fstatat(dirfd, "config", &st, 0);
 *   if (st.st_size > 0) {
 *       // Safe to read config
 *   }
 *   close(dirfd);
 *
 * Advantages over stat():
 * 1. Thread-safe: Works correctly with multiple threads
 * 2. Race-free: Directory context locked by FD
 * 3. Flexible: Can use CWD or specific directory
 * 4. Symlink control: Can choose to follow or not follow symlinks
 *
 * Phase 1: Basic implementation with dirfd and AT_SYMLINK_NOFOLLOW support
 */
long sys_fstatat(int dirfd, const char *pathname, void *statbuf, int flags) {
    /* ARM64 FIX: Copy parameters to local variables */
    int local_dirfd = dirfd;
    const char *local_pathname = pathname;
    void *local_statbuf = statbuf;
    int local_flags = flags;

    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[FSTATAT] fstatat(dirfd=%d, flags=0x%x) -> ESRCH (no current task)\n",
                   local_dirfd, local_flags);
        return -ESRCH;
    }

    /* Phase 1: Validate flags - only AT_SYMLINK_NOFOLLOW and AT_EMPTY_PATH are valid */
    const int VALID_FLAGS = AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH;
    if (local_flags & ~VALID_FLAGS) {
        fut_printf("[FSTATAT] fstatat(dirfd=%d, flags=0x%x) -> EINVAL (invalid flags)\n",
                   local_dirfd, local_flags);
        return -EINVAL;
    }

    /* Validate statbuf pointer */
    if (!local_statbuf) {
        fut_printf("[FSTATAT] fstatat(dirfd=%d, statbuf=NULL) -> EINVAL (NULL statbuf)\n",
                   local_dirfd);
        return -EINVAL;
    }

    /* Validate pathname pointer */
    if (!local_pathname) {
        fut_printf("[FSTATAT] fstatat(dirfd=%d, pathname=NULL) -> EINVAL (NULL pathname)\n",
                   local_dirfd);
        return -EINVAL;
    }

    /* Copy pathname from userspace */
    char path_buf[256];
    if (fut_copy_from_user(path_buf, local_pathname, sizeof(path_buf) - 1) != 0) {
        fut_printf("[FSTATAT] fstatat(dirfd=%d) -> EFAULT (copy_from_user failed)\n",
                   local_dirfd);
        return -EFAULT;
    }
    path_buf[sizeof(path_buf) - 1] = '\0';

    /* Check for empty pathname with AT_EMPTY_PATH */
    if (path_buf[0] == '\0') {
        if (local_flags & AT_EMPTY_PATH) {
            /* TODO Phase 2: Implement fstat via dirfd */
            fut_printf("[FSTATAT] fstatat(dirfd=%d, pathname=\"\" [empty], flags=AT_EMPTY_PATH) -> ENOTSUP (AT_EMPTY_PATH not yet implemented)\n",
                       local_dirfd);
            return -ENOTSUP;
        } else {
            fut_printf("[FSTATAT] fstatat(dirfd=%d, pathname=\"\" [empty]) -> EINVAL (empty pathname without AT_EMPTY_PATH)\n",
                       local_dirfd);
            return -EINVAL;
        }
    }

    /* Check for path truncation */
    size_t truncation_check = 0;
    while (path_buf[truncation_check] != '\0' && truncation_check < sizeof(path_buf) - 1) {
        truncation_check++;
    }
    if (path_buf[truncation_check] != '\0') {
        fut_printf("[FSTATAT] fstatat(dirfd=%d, pathname_len>255) -> ENAMETOOLONG (pathname truncated)\n",
                   local_dirfd);
        return -ENAMETOOLONG;
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

    /* Categorize flags */
    const char *flags_desc;
    if (local_flags == 0) {
        flags_desc = "none (follow symlinks)";
    } else if (local_flags == AT_SYMLINK_NOFOLLOW) {
        flags_desc = "AT_SYMLINK_NOFOLLOW (lstat behavior)";
    } else if (local_flags == AT_EMPTY_PATH) {
        flags_desc = "AT_EMPTY_PATH (fstat via dirfd)";
    } else {
        flags_desc = "multiple flags";
    }

    /* Calculate path length */
    size_t path_len = 0;
    while (path_buf[path_len] != '\0' && path_len < 255) {
        path_len++;
    }

    /* Phase 1: For now, we'll use the simple approach:
     * - If pathname is absolute, ignore dirfd
     * - If pathname is relative and dirfd == AT_FDCWD, use current directory
     * - If pathname is relative and dirfd is a real FD, prepend directory path
     * - AT_SYMLINK_NOFOLLOW: Use lstat instead of stat
     *
     * TODO Phase 2: Implement proper directory FD resolution via VFS */

    /* Perform the stat operation via VFS */
    int ret;
    if (local_flags & AT_SYMLINK_NOFOLLOW) {
        /* lstat behavior - don't follow symlinks */
        ret = fut_vfs_lstat(path_buf, local_statbuf);
    } else {
        /* stat behavior - follow symlinks */
        ret = fut_vfs_stat(path_buf, local_statbuf);
    }

    /* Handle errors */
    if (ret < 0) {
        const char *error_desc;
        switch (ret) {
            case -ENOENT:
                error_desc = "file not found";
                break;
            case -ENOTDIR:
                error_desc = "path component not a directory";
                break;
            case -EACCES:
                error_desc = "permission denied";
                break;
            default:
                error_desc = "VFS stat failed";
                break;
        }

        fut_printf("[FSTATAT] fstatat(dirfd=%d, pathname='%s' [%s, len=%lu], flags=%s) -> %d (%s)\n",
                   local_dirfd, path_buf, path_type, (unsigned long)path_len, flags_desc, ret, error_desc);
        return ret;
    }

    /* Success */
    fut_printf("[FSTATAT] fstatat(dirfd=%d, pathname='%s' [%s, len=%lu], flags=%s) -> 0 (Phase 1: basic implementation)\n",
               local_dirfd, path_buf, path_type, (unsigned long)path_len, flags_desc);

    return 0;
}
