/* kernel/sys_unlinkat.c - Directory-based file deletion syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the unlinkat() syscall for deleting files relative to a directory FD.
 * Essential for thread-safe file operations and avoiding race conditions.
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
#include <fcntl.h>

#include <platform/platform.h>

static inline int unlinkat_copy_from_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)src >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_from_user(dst, src, n);
}

/* AT_* flags provided by fcntl.h */

/**
 * unlinkat() - Delete file or directory relative to directory FD
 *
 * Like unlink(), but pathname is interpreted relative to dirfd instead of
 * the current working directory. This enables race-free operations when
 * working with directory hierarchies.
 *
 * @param dirfd    Directory file descriptor (or AT_FDCWD for CWD)
 * @param pathname Path relative to dirfd (or absolute path)
 * @param flags    AT_REMOVEDIR to remove directories, 0 for files
 *
 * Returns:
 *   - 0 on success
 *   - -EBADF if dirfd is invalid
 *   - -EFAULT if pathname is inaccessible
 *   - -EINVAL if pathname is empty, NULL, or flags invalid
 *   - -ENOENT if file doesn't exist
 *   - -EISDIR if pathname is directory but AT_REMOVEDIR not set
 *   - -ENOTDIR if AT_REMOVEDIR set but pathname not a directory
 *   - -ENOTEMPTY if directory not empty
 *   - -EACCES if permission denied
 *   - -EBUSY if file is in use
 *   - -EROFS if filesystem is read-only
 *
 * Behavior:
 *   - If pathname is absolute, dirfd is ignored
 *   - If pathname is relative and dirfd is AT_FDCWD, uses current directory
 *   - If pathname is relative and dirfd is FD, uses that directory
 *   - AT_REMOVEDIR flag allows removing empty directories (like rmdir)
 *   - Without AT_REMOVEDIR, removes files and symlinks only (like unlink)
 *   - Prevents TOCTOU races vs separate getcwd() + unlink()
 *
 * Common usage patterns:
 *
 * Thread-safe file deletion in directory:
 *   int dirfd = open("/some/dir", O_RDONLY | O_DIRECTORY);
 *   unlinkat(dirfd, "file.txt", 0);  // Delete file in that dir
 *   close(dirfd);
 *
 * Remove directory:
 *   unlinkat(dirfd, "subdir", AT_REMOVEDIR);  // Like rmdir
 *
 * Use current directory:
 *   unlinkat(AT_FDCWD, "file.txt", 0);  // Same as unlink("file.txt")
 *
 * Absolute path (dirfd ignored):
 *   unlinkat(dirfd, "/tmp/file.txt", 0);  // dirfd not used
 *
 * Race-free cleanup:
 *   int dirfd = open("/tmp", O_RDONLY | O_DIRECTORY);
 *   // Directory can't be renamed/moved while we have it open
 *   unlinkat(dirfd, "tempfile", 0);
 *   unlinkat(dirfd, "tempdir", AT_REMOVEDIR);
 *   close(dirfd);
 *
 * Advantages over unlink/rmdir:
 * 1. Thread-safe: Works correctly with multiple threads
 * 2. Race-free: Directory context locked by FD
 * 3. Unified: One syscall for files and directories (with flag)
 * 4. Flexible: Can use CWD or specific directory
 *
 */
long sys_unlinkat(int dirfd, const char *pathname, int flags) {
    /* ARM64 FIX: Copy parameters to local variables */
    int local_dirfd = dirfd;
    const char *local_pathname = pathname;
    int local_flags = flags;

    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[UNLINKAT] unlinkat(dirfd=%d, flags=0x%x) -> ESRCH (no current task)\n",
                   local_dirfd, local_flags);
        return -ESRCH;
    }

    /* Validate flags - Linux accepts ONLY AT_REMOVEDIR for unlinkat;
     * AT_SYMLINK_NOFOLLOW is not valid here (it's an unlink-time decision
     * for unlinkat, not a path-resolution flag). The previous code
     * accepted AT_SYMLINK_NOFOLLOW silently, diverging from Linux's
     * AT_REMOVEDIR-only contract. */
    const int VALID_FLAGS = AT_REMOVEDIR;
    if (local_flags & ~VALID_FLAGS) {
        fut_printf("[UNLINKAT] unlinkat(dirfd=%d, flags=0x%x) -> EINVAL (invalid flags)\n",
                   local_dirfd, local_flags);
        return -EINVAL;
    }

    /* Validate pathname pointer — NULL is a faulting pointer (EFAULT)
     * per Linux, not a parameter-domain error (EINVAL). */
    if (!local_pathname) {
        fut_printf("[UNLINKAT] unlinkat(dirfd=%d, pathname=NULL) -> EFAULT\n",
                   local_dirfd);
        return -EFAULT;
    }

    /* Copy pathname from userspace */
    char path_buf[FUT_VFS_PATH_BUFFER_SIZE];
    if (unlinkat_copy_from_user(path_buf, local_pathname, sizeof(path_buf)) != 0) {
        fut_printf("[UNLINKAT] unlinkat(dirfd=%d) -> EFAULT (copy_from_user failed)\n",
                   local_dirfd);
        return -EFAULT;
    }
    if (memchr(path_buf, '\0', sizeof(path_buf)) == NULL) {
        fut_printf("[UNLINKAT] unlinkat(dirfd=%d) -> ENAMETOOLONG\n",
                   local_dirfd);
        return -ENAMETOOLONG;
    }

    /* Validate pathname is not empty */
    if (path_buf[0] == '\0') {
        fut_printf("[UNLINKAT] unlinkat(dirfd=%d, pathname=\"\" [empty]) -> EINVAL (empty pathname)\n",
                   local_dirfd);
        return -EINVAL;
    }

    /* Categorize operation */
    const char *operation;
    if (local_flags & AT_REMOVEDIR) {
        operation = "remove directory";
    } else {
        operation = "remove file";
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

    size_t path_len = strlen(path_buf);

    /* Resolve the full path using fut_vfs_resolve_at */
    char resolved_path[256];
    int rret = fut_vfs_resolve_at(task, local_dirfd, path_buf,
                                   resolved_path, sizeof(resolved_path));
    if (rret < 0) {
        fut_printf("[UNLINKAT] unlinkat(dirfd=%d, path='%s') -> %d (dirfd resolve failed)\n",
                   local_dirfd, path_buf, rret);
        return rret;
    }

    int ret;
    if (local_flags & AT_REMOVEDIR) {
        /* Remove directory (like rmdir) */
        ret = fut_vfs_rmdir(resolved_path);
    } else {
        /* Remove file or symlink (like unlink) */
        ret = fut_vfs_unlink(resolved_path);
    }

    /* Handle errors */
    if (ret < 0) {
        const char *error_desc;
        switch (ret) {
            case -ENOENT:
                error_desc = "file not found";
                break;
            case -EISDIR:
                error_desc = "is a directory (use AT_REMOVEDIR flag)";
                break;
            case -ENOTDIR:
                error_desc = "not a directory (AT_REMOVEDIR set for non-directory)";
                break;
            case -ENOTEMPTY:
                error_desc = "directory not empty";
                break;
            case -EACCES:
                error_desc = "permission denied";
                break;
            case -EBUSY:
                error_desc = "file is in use";
                break;
            case -EROFS:
                error_desc = "read-only filesystem";
                break;
            default:
                error_desc = "VFS operation failed";
                break;
        }

        fut_printf("[UNLINKAT] unlinkat(dirfd=%d, pathname='%s' [%s, len=%lu], operation=%s, flags=0x%x) -> %d (%s)\n",
                   local_dirfd, path_buf, path_type, (unsigned long)path_len, operation, local_flags, ret, error_desc);
        return ret;
    }

    /* Success */
    fut_printf("[UNLINKAT] unlinkat(dirfd=%d, pathname='%s' [%s, len=%lu], operation=%s, flags=0x%x) -> 0\n",
               local_dirfd, path_buf, path_type, (unsigned long)path_len, operation, local_flags);

    return 0;
}
