/* kernel/sys_openat.c - Open file relative to directory descriptor
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements openat() to open files relative to directory file descriptors.
 * More secure than open() for avoiding race conditions.
 */

#include <kernel/fut_task.h>
#include <kernel/fut_vfs.h>
#include <kernel/uaccess.h>
#include <kernel/errno.h>
#include <subsystems/posix_syscall.h>
#include <stddef.h>
#include <string.h>

#include <kernel/kprintf.h>
#include <fcntl.h>

/* copy_user_string provided by subsystems/posix_syscall.h */
/* AT_* and O_* constants provided by fcntl.h */

/**
 * openat() - Open file relative to directory file descriptor
 *
 * Opens file relative to directory fd. If pathname is absolute, dirfd is
 * ignored. If pathname is relative and dirfd is AT_FDCWD, pathname is
 * relative to current working directory.
 *
 * @param dirfd    Directory file descriptor or AT_FDCWD
 * @param pathname Path to file (absolute or relative to dirfd)
 * @param flags    Open flags
 * @param mode     Permission mode if creating
 *
 * Returns:
 *   - Non-negative file descriptor on success
 *   - Same errors as open()
 *   - -EBADF if dirfd is invalid and pathname is relative
 *   - -ENOTDIR if dirfd is not a directory
 *
 * Phase 1 (Completed): Basic openat with AT_FDCWD support
 * Phase 2 (Completed): Enhanced validation, flag analysis, and detailed logging
 * Phase 3 (Completed): Support real dirfd (relative opens)
 * Phase 4: Advanced flags (O_TMPFILE, O_DIRECT, etc.)
 */
long sys_openat(int dirfd, const char *pathname, int flags, int mode) {
    /* ARM64 FIX: Copy parameters to local variables to survive blocking calls */
    int local_dirfd = dirfd;
    const char *local_pathname = pathname;
    int local_flags = flags;
    int local_mode = mode;

    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Phase 2: Validate pathname pointer */
    if (!local_pathname) {
        fut_printf("[OPENAT] openat(dirfd=%d, pathname=NULL, flags=0x%x, mode=0%o) -> EFAULT\n",
                   local_dirfd, local_flags, local_mode);
        return -EFAULT;
    }

    /* Security hardening - Path truncation detection
     * VULNERABILITY: Silent Path Truncation Leading to Unauthorized File Access
     *
     * ATTACK SCENARIO:
     * Attacker provides path longer than 256 bytes to exploit truncation
     *
     * Example attack:
     * 1. Attacker calls openat(AT_FDCWD, long_path, O_RDONLY, 0)
     * 2. long_path = "/etc/passwd" + [240 bytes of padding] + "_fake"
     * 3. copy_user_string truncates at 256 bytes
     * 4. Kernel path becomes "/etc/passwd" + [246 bytes] (NULL terminated)
     * 5. VFS opens /etc/passwd instead of intended _fake suffixed path
     * 6. Attacker gains access to sensitive file
     *
     * Real-world exploitation:
     * - Access /etc/shadow by providing /etc/shadow + padding
     * - Bypass path-based ACLs via truncation to allowed prefix
     * - Create files in protected directories (truncate suffix)
     * - Symlink confusion via truncated target paths
     *
     * DEFENSE:
     * Verify path was not truncated during copy
     * - copy_user_string returns 0 on success with NULL termination
     * - Validate that kpath is properly NULL-terminated
     * - Check if source path length exceeds buffer capacity
     * - Return -ENAMETOOLONG if truncation detected
     */
    char kpath[256];
    int rc = copy_user_string(local_pathname, kpath, sizeof(kpath));
    if (rc != 0) {
        fut_printf("[OPENAT] openat(dirfd=%d, pathname=?, flags=0x%x, mode=0%o) -> %d (copy failed)\n",
                   local_dirfd, local_flags, local_mode, rc);
        return rc;
    }

    /* Verify path was not truncated (NULL terminator must exist somewhere in buffer)
     * If no '\0' found in buffer, the path was truncated and full path exceeds buffer size */
    if (memchr(kpath, '\0', sizeof(kpath)) == NULL) {
        fut_printf("[OPENAT] openat(dirfd=%d, pathname=<truncated>, flags=0x%x, mode=0%o) -> ENAMETOOLONG "
                   "(path exceeds %zu bytes, truncation detected)\n",
                   local_dirfd, local_flags, local_mode, sizeof(kpath) - 1);
        return -ENAMETOOLONG;
    }

    /* Phase 2: Categorize dirfd type */
    const char *dirfd_desc;
    const char *path_type;

    if (local_dirfd == AT_FDCWD) {
        dirfd_desc = "AT_FDCWD (current directory)";
    } else if (local_dirfd >= 0) {
        dirfd_desc = "real fd";
    } else {
        dirfd_desc = "invalid fd";
    }

    if (kpath[0] == '/') {
        path_type = "absolute";
    } else {
        path_type = "relative";
    }

    /* Phase 2: Analyze access mode */
    int access_mode = local_flags & O_ACCMODE;
    const char *access_desc;

    switch (access_mode) {
        case O_RDONLY:
            access_desc = "read-only";
            break;
        case O_WRONLY:
            access_desc = "write-only";
            break;
        case O_RDWR:
            access_desc = "read-write";
            break;
        default:
            access_desc = "invalid access mode";
            break;
    }

    /* Phase 2: Categorize creation flags */
    const char *creation_desc;

    if (local_flags & O_CREAT) {
        if (local_flags & O_EXCL) {
            creation_desc = "create exclusive (fail if exists)";
        } else {
            creation_desc = "create if missing";
        }
    } else {
        creation_desc = "open existing only";
    }

    /* Phase 2: Analyze behavior flags */
    const char *behavior_desc;

    /* Identify primary behavior flags for diagnostic purposes */
    if ((local_flags & (O_TRUNC | O_APPEND | O_NONBLOCK | O_SYNC | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_PATH)) == 0) {
        behavior_desc = "none";
    } else if (local_flags & O_TRUNC) {
        behavior_desc = "truncate";
    } else if (local_flags & O_APPEND) {
        behavior_desc = "append";
    } else if (local_flags & O_DIRECTORY) {
        behavior_desc = "directory";
    } else if (local_flags & O_CLOEXEC) {
        behavior_desc = "cloexec";
    } else if (local_flags & O_NONBLOCK) {
        behavior_desc = "nonblock";
    } else if (local_flags & O_SYNC) {
        behavior_desc = "sync";
    } else if (local_flags & O_NOFOLLOW) {
        behavior_desc = "nofollow";
    } else if (local_flags & O_PATH) {
        behavior_desc = "path";
    } else {
        behavior_desc = "multiple";
    }

    /* Open via VFS, using fut_vfs_open_at to handle dirfd-relative paths */
    fut_task_t *open_task = fut_task_current();
    int result = fut_vfs_open_at(open_task, local_dirfd, kpath, local_flags, local_mode);

    if (result >= 0) {
        fut_printf("[OPENAT] openat(dirfd=%d [%s], path='%s' [%s], flags=0x%x [%s, %s, behavior: %s], mode=0%o) "
                   "-> %d\n",
                   local_dirfd, dirfd_desc, kpath, path_type, local_flags, access_desc, creation_desc,
                   behavior_desc, local_mode, result);
    } else {
        fut_printf("[OPENAT] openat(dirfd=%d [%s], path='%s' [%s], flags=0x%x [%s, %s, behavior: %s], mode=0%o) "
                   "-> %d (%s)\n",
                   local_dirfd, dirfd_desc, kpath, path_type, local_flags, access_desc, creation_desc,
                   behavior_desc, local_mode, result,
                   (result == -ENOENT) ? "not found" :
                   (result == -EACCES) ? "access denied" :
                   (result == -EEXIST) ? "already exists" :
                   (result == -EISDIR) ? "is directory" :
                   (result == -ENOTDIR) ? "not directory" :
                   (result == -EBADF) ? "bad dirfd" :
                   (result == -ENOTSUP) ? "not supported" : "error");
    }

    return (long)result;
}
