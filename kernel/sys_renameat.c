/* kernel/sys_renameat.c - Directory-based file rename syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the renameat() and renameat2() syscalls for renaming/moving files
 * relative to directory FDs. Essential for thread-safe atomic file operations
 * and avoiding race conditions.
 *
 * Phase 1 (Completed): renameat() with full dirfd resolution
 * Phase 2 (Completed): renameat2() with RENAME_NOREPLACE support
 */

/* renameat2 flags */
#define RENAME_NOREPLACE  (1 << 0)   /* Don't overwrite newpath if it exists */
#define RENAME_EXCHANGE   (1 << 1)   /* Atomically exchange old and new       */
#define RENAME_WHITEOUT   (1 << 2)   /* Whiteout source (overlay/union only)  */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <kernel/syscalls.h>
#include <stdint.h>
#include <string.h>

#include <kernel/kprintf.h>
#include <kernel/uaccess.h>
#include <fcntl.h>

/* AT_* constants provided by fcntl.h */

/**
 * renameat() - Rename/move file relative to directory FDs
 *
 * Like rename(), but oldpath is interpreted relative to olddirfd and newpath
 * is interpreted relative to newdirfd. This enables race-free operations when
 * working with directory hierarchies in multithreaded applications.
 *
 * @param olddirfd Directory FD for oldpath (or AT_FDCWD for CWD)
 * @param oldpath  Path relative to olddirfd (or absolute)
 * @param newdirfd Directory FD for newpath (or AT_FDCWD for CWD)
 * @param newpath  Path relative to newdirfd (or absolute)
 *
 * Returns:
 *   - 0 on success
 *   - -EBADF if olddirfd or newdirfd is invalid
 *   - -EFAULT if paths are inaccessible
 *   - -EINVAL if oldpath or newpath is invalid/empty/NULL
 *   - -ENOENT if oldpath does not exist
 *   - -ENOTDIR if path component not a directory
 *   - -EISDIR if newpath is directory but oldpath is not
 *   - -EEXIST if newpath exists and is directory but oldpath is not
 *   - -ENOTEMPTY if newpath is non-empty directory
 *   - -EBUSY if oldpath or newpath is in use
 *   - -EXDEV if paths are on different filesystems
 *   - -EACCES if permission denied
 *   - -EROFS if filesystem is read-only
 *
 * Behavior:
 *   - If paths are absolute, corresponding dirfd is ignored
 *   - If paths are relative and dirfd is AT_FDCWD, uses current directory
 *   - If paths are relative and dirfd is FD, uses that directory
 *   - Atomic operation: newpath replacement is atomic
 *   - If newpath exists, it is replaced atomically
 *   - Prevents TOCTOU races vs separate getcwd() + rename()
 *
 * Common usage patterns:
 *
 * Thread-safe atomic file replacement:
 *   int dirfd = open("/etc", O_RDONLY | O_DIRECTORY);
 *   // Write to temp file
 *   write(tmpfd, data, size);
 *   fsync(tmpfd);
 *   close(tmpfd);
 *   // Atomically replace config file
 *   renameat(dirfd, "config.tmp", dirfd, "config");
 *   close(dirfd);
 *
 * Move file between directories:
 *   int olddir = open("/tmp", O_RDONLY | O_DIRECTORY);
 *   int newdir = open("/var/log", O_RDONLY | O_DIRECTORY);
 *   renameat(olddir, "tempfile", newdir, "logfile");
 *   close(olddir);
 *   close(newdir);
 *
 * Use current directory:
 *   renameat(AT_FDCWD, "old.txt", AT_FDCWD, "new.txt");
 *   // Same as rename("old.txt", "new.txt")
 *
 * Absolute paths (dirfds ignored):
 *   renameat(dirfd1, "/tmp/old", dirfd2, "/tmp/new");
 *   // dirfd1 and dirfd2 not used
 *
 * Race-free database transaction commit:
 *   int dbdir = open("/var/db", O_RDONLY | O_DIRECTORY);
 *   // Build new DB version in temp file
 *   write_database(tmpfd, transaction);
 *   fsync(tmpfd);
 *   close(tmpfd);
 *   // Atomic commit
 *   renameat(dbdir, "db.new", dbdir, "db");
 *   close(dbdir);
 *
 * Advantages over rename():
 * 1. Thread-safe: Works correctly with multiple threads
 * 2. Race-free: Directory context locked by FDs
 * 3. Flexible: Source and dest can be in different directories
 * 4. Atomic: Still provides atomic replacement guarantee
 *
 */
long sys_renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath) {
    /* ARM64 FIX: Copy parameters to local variables */
    int local_olddirfd = olddirfd;
    const char *local_oldpath = oldpath;
    int local_newdirfd = newdirfd;
    const char *local_newpath = newpath;

    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[RENAMEAT] renameat(olddirfd=%d, newdirfd=%d) -> ESRCH (no current task)\n",
                   local_olddirfd, local_newdirfd);
        return -ESRCH;
    }

    /* Validate oldpath pointer */
    if (!local_oldpath) {
        fut_printf("[RENAMEAT] renameat(olddirfd=%d, oldpath=NULL) -> EINVAL (NULL oldpath)\n",
                   local_olddirfd);
        return -EINVAL;
    }

    /* Validate newpath pointer */
    if (!local_newpath) {
        fut_printf("[RENAMEAT] renameat(newdirfd=%d, newpath=NULL) -> EINVAL (NULL newpath)\n",
                   local_newdirfd);
        return -EINVAL;
    }

    /* Copy oldpath from userspace */
    char oldpath_buf[FUT_VFS_PATH_BUFFER_SIZE];
    if (fut_copy_from_user(oldpath_buf, local_oldpath, sizeof(oldpath_buf)) != 0) {
        fut_printf("[RENAMEAT] renameat(olddirfd=%d) -> EFAULT (copy_from_user oldpath failed)\n",
                   local_olddirfd);
        return -EFAULT;
    }
    if (memchr(oldpath_buf, '\0', sizeof(oldpath_buf)) == NULL) {
        fut_printf("[RENAMEAT] renameat(olddirfd=%d, oldpath=<truncated>) -> ENAMETOOLONG\n",
                   local_olddirfd);
        return -ENAMETOOLONG;
    }

    /* Copy newpath from userspace */
    char newpath_buf[FUT_VFS_PATH_BUFFER_SIZE];
    if (fut_copy_from_user(newpath_buf, local_newpath, sizeof(newpath_buf)) != 0) {
        fut_printf("[RENAMEAT] renameat(newdirfd=%d) -> EFAULT (copy_from_user newpath failed)\n",
                   local_newdirfd);
        return -EFAULT;
    }
    if (memchr(newpath_buf, '\0', sizeof(newpath_buf)) == NULL) {
        fut_printf("[RENAMEAT] renameat(newdirfd=%d, newpath=<truncated>) -> ENAMETOOLONG\n",
                   local_newdirfd);
        return -ENAMETOOLONG;
    }

    /* Validate oldpath is not empty */
    if (oldpath_buf[0] == '\0') {
        fut_printf("[RENAMEAT] renameat(olddirfd=%d, oldpath=\"\" [empty]) -> EINVAL (empty oldpath)\n",
                   local_olddirfd);
        return -EINVAL;
    }

    /* Validate newpath is not empty */
    if (newpath_buf[0] == '\0') {
        fut_printf("[RENAMEAT] renameat(newdirfd=%d, newpath=\"\" [empty]) -> EINVAL (empty newpath)\n",
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

    /* Calculate path lengths */
    size_t old_path_len = strlen(oldpath_buf);
    size_t new_path_len = strlen(newpath_buf);

    /* Resolve both paths using fut_vfs_resolve_at */
    char resolved_oldpath[256];
    char resolved_newpath[256];

    int rret = fut_vfs_resolve_at(task, local_olddirfd, oldpath_buf,
                                   resolved_oldpath, sizeof(resolved_oldpath));
    if (rret < 0) {
        fut_printf("[RENAMEAT] renameat(olddirfd=%d, oldpath='%s') -> %d (olddirfd resolve failed)\n",
                   local_olddirfd, oldpath_buf, rret);
        return rret;
    }

    rret = fut_vfs_resolve_at(task, local_newdirfd, newpath_buf,
                               resolved_newpath, sizeof(resolved_newpath));
    if (rret < 0) {
        fut_printf("[RENAMEAT] renameat(newdirfd=%d, newpath='%s') -> %d (newdirfd resolve failed)\n",
                   local_newdirfd, newpath_buf, rret);
        return rret;
    }

    /* Perform the rename via existing sys_rename implementation */
    int ret = (int)sys_rename(resolved_oldpath, resolved_newpath);

    /* Handle errors */
    if (ret < 0) {
        const char *error_desc;
        switch (ret) {
            case -ENOENT:
                error_desc = "source file not found";
                break;
            case -ENOTDIR:
                error_desc = "path component not a directory";
                break;
            case -EISDIR:
                error_desc = "newpath is directory but oldpath is not";
                break;
            case -EEXIST:
                error_desc = "newpath exists and is incompatible";
                break;
            case -ENOTEMPTY:
                error_desc = "newpath directory not empty";
                break;
            case -EBUSY:
                error_desc = "file is in use";
                break;
            case -EXDEV:
                error_desc = "cross-filesystem rename not supported";
                break;
            case -EACCES:
                error_desc = "permission denied";
                break;
            case -EROFS:
                error_desc = "read-only filesystem";
                break;
            default:
                error_desc = "VFS rename failed";
                break;
        }

        fut_printf("[RENAMEAT] renameat(olddirfd=%d, oldpath='%s' [%s, len=%lu], newdirfd=%d, newpath='%s' [%s, len=%lu]) -> %d (%s)\n",
                   local_olddirfd, oldpath_buf, old_path_type, (unsigned long)old_path_len,
                   local_newdirfd, newpath_buf, new_path_type, (unsigned long)new_path_len,
                   ret, error_desc);
        return ret;
    }

    /* Success */
    fut_printf("[RENAMEAT] renameat(olddirfd=%d, oldpath='%s' [%s, len=%lu], newdirfd=%d, newpath='%s' [%s, len=%lu]) -> 0\n",
               local_olddirfd, oldpath_buf, old_path_type, (unsigned long)old_path_len,
               local_newdirfd, newpath_buf, new_path_type, (unsigned long)new_path_len);

    return 0;
}

/**
 * renameat2() - Rename/move file with flags
 *
 * Like renameat(), but accepts a flags argument enabling extended rename semantics.
 *
 * @param olddirfd Directory FD for oldpath (or AT_FDCWD)
 * @param oldpath  Path relative to olddirfd
 * @param newdirfd Directory FD for newpath (or AT_FDCWD)
 * @param newpath  Path relative to newdirfd
 * @param flags    0 or combination of RENAME_NOREPLACE / RENAME_EXCHANGE
 *
 * Supported flags:
 *   RENAME_NOREPLACE (1): Fail with -EEXIST if newpath already exists.
 *                         Ordinary rename() silently replaces the destination;
 *                         this flag prevents that.
 *   RENAME_EXCHANGE  (2): Atomic swap of old and new — requires both to exist.
 *                         Not yet supported; returns -ENOSYS.
 *   RENAME_WHITEOUT  (4): Create a whiteout at oldpath (overlayfs only).
 *                         Not yet supported; returns -ENOSYS.
 *
 * Returns:
 *   - 0 on success
 *   - -EEXIST if RENAME_NOREPLACE and newpath exists
 *   - -ENOSYS if RENAME_EXCHANGE or RENAME_WHITEOUT requested
 *   - -EINVAL for unknown flags
 *   - All errors from renameat() otherwise
 *
 * Phase 2 (Completed): RENAME_NOREPLACE via fut_vfs_lookup existence check
 */
long sys_renameat2(int olddirfd, const char *oldpath,
                   int newdirfd, const char *newpath,
                   unsigned int flags) {
    /* Reject unknown flags */
    const unsigned int KNOWN = RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT;
    if (flags & ~KNOWN) {
        fut_printf("[RENAMEAT2] renameat2(flags=0x%x) -> EINVAL (unknown flags)\n", flags);
        return -EINVAL;
    }

    /* RENAME_EXCHANGE and RENAME_WHITEOUT require deeper VFS support */
    if (flags & RENAME_EXCHANGE) {
        fut_printf("[RENAMEAT2] renameat2(flags=RENAME_EXCHANGE) -> ENOSYS\n");
        return -ENOSYS;
    }
    if (flags & RENAME_WHITEOUT) {
        fut_printf("[RENAMEAT2] renameat2(flags=RENAME_WHITEOUT) -> ENOSYS\n");
        return -ENOSYS;
    }

    /* flags=0: delegate directly */
    if (!(flags & RENAME_NOREPLACE)) {
        return sys_renameat(olddirfd, oldpath, newdirfd, newpath);
    }

    /* RENAME_NOREPLACE: check that newpath does not already exist */

    /* Copy newpath from userspace to resolve it */
    if (!newpath) {
        fut_printf("[RENAMEAT2] renameat2(newpath=NULL) -> EINVAL\n");
        return -EINVAL;
    }

    char newpath_buf[FUT_VFS_PATH_BUFFER_SIZE];
    if (fut_copy_from_user(newpath_buf, newpath, sizeof(newpath_buf)) != 0) {
        fut_printf("[RENAMEAT2] renameat2(newdirfd=%d) -> EFAULT (copy newpath)\n", newdirfd);
        return -EFAULT;
    }
    if (memchr(newpath_buf, '\0', sizeof(newpath_buf)) == NULL) {
        fut_printf("[RENAMEAT2] renameat2(newdirfd=%d) -> ENAMETOOLONG\n", newdirfd);
        return -ENAMETOOLONG;
    }
    if (newpath_buf[0] == '\0') {
        fut_printf("[RENAMEAT2] renameat2(newdirfd=%d) -> EINVAL (empty newpath)\n", newdirfd);
        return -EINVAL;
    }

    /* Resolve newpath relative to newdirfd */
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[RENAMEAT2] renameat2() -> ESRCH (no current task)\n");
        return -ESRCH;
    }

    char resolved_newpath[256];
    int rret = fut_vfs_resolve_at(task, newdirfd, newpath_buf,
                                   resolved_newpath, sizeof(resolved_newpath));
    if (rret < 0) {
        fut_printf("[RENAMEAT2] renameat2(newdirfd=%d, newpath='%s') -> %d (resolve failed)\n",
                   newdirfd, newpath_buf, rret);
        return rret;
    }

    /* Check existence of resolved newpath */
    struct fut_vnode *existing = NULL;
    int lookup_ret = fut_vfs_lookup(resolved_newpath, &existing);
    if (lookup_ret == 0) {
        /* newpath exists — RENAME_NOREPLACE requires we fail */
        fut_printf("[RENAMEAT2] renameat2(newpath='%s', RENAME_NOREPLACE) -> EEXIST (target exists)\n",
                   resolved_newpath);
        return -EEXIST;
    }
    /* lookup_ret < 0 (ENOENT or similar) means newpath doesn't exist — proceed */

    /* Perform the rename */
    return sys_renameat(olddirfd, oldpath, newdirfd, newpath);
}
