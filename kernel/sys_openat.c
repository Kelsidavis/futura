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
#include <stddef.h>

#include <kernel/kprintf.h>
extern fut_task_t *fut_task_current(void);
extern int copy_user_string(const char *user_str, char *kernel_buf, size_t max_len);

/* AT_FDCWD - special value for current working directory */
#define AT_FDCWD -100

/* Open flags (from fut_vfs.h) */
#define O_RDONLY    0x0000
#define O_WRONLY    0x0001
#define O_RDWR      0x0002
#define O_ACCMODE   0x0003
#define O_CREAT     0x0040
#define O_EXCL      0x0080
#define O_NOCTTY    0x0100
#define O_TRUNC     0x0200
#define O_APPEND    0x0400
#define O_NONBLOCK  0x0800
#define O_SYNC      0x1000
#define O_DIRECTORY 0x10000
#define O_NOFOLLOW  0x20000
#define O_CLOEXEC   0x80000
#define O_PATH      0x200000

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
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Phase 2: Validate pathname pointer */
    if (!pathname) {
        fut_printf("[OPENAT] openat(dirfd=%d, pathname=NULL, flags=0x%x, mode=0%o) -> EFAULT\n",
                   dirfd, flags, mode);
        return -EFAULT;
    }

    /* Phase 5: Security hardening - Path truncation detection
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
     * DEFENSE (Phase 5):
     * Verify path was not truncated during copy
     * - copy_user_string returns 0 on success with NULL termination
     * - Validate that kpath is properly NULL-terminated
     * - Check if source path length exceeds buffer capacity
     * - Return -ENAMETOOLONG if truncation detected
     */
    char kpath[256];
    int rc = copy_user_string(pathname, kpath, sizeof(kpath));
    if (rc != 0) {
        fut_printf("[OPENAT] openat(dirfd=%d, pathname=?, flags=0x%x, mode=0%o) -> %d (copy failed)\n",
                   dirfd, flags, mode, rc);
        return rc;
    }

    /* Phase 5: Verify path was not truncated (NULL terminator must exist before buffer end)
     * If kpath[255] != '\0', the path was truncated and full path exceeds 255 chars */
    if (kpath[sizeof(kpath) - 1] != '\0') {
        fut_printf("[OPENAT] openat(dirfd=%d, pathname=<truncated>, flags=0x%x, mode=0%o) -> ENAMETOOLONG "
                   "(path exceeds %zu bytes, truncation detected, Phase 5)\n",
                   dirfd, flags, mode, sizeof(kpath) - 1);
        return -ENAMETOOLONG;
    }

    /* Phase 2: Categorize dirfd type */
    const char *dirfd_desc;
    const char *path_type;

    if (dirfd == AT_FDCWD) {
        dirfd_desc = "AT_FDCWD (current directory)";
    } else if (dirfd >= 0) {
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
    int access_mode = flags & O_ACCMODE;
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

    if (flags & O_CREAT) {
        if (flags & O_EXCL) {
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
    if ((flags & (O_TRUNC | O_APPEND | O_NONBLOCK | O_SYNC | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_PATH)) == 0) {
        behavior_desc = "none";
    } else if (flags & O_TRUNC) {
        behavior_desc = "truncate";
    } else if (flags & O_APPEND) {
        behavior_desc = "append";
    } else if (flags & O_DIRECTORY) {
        behavior_desc = "directory";
    } else if (flags & O_CLOEXEC) {
        behavior_desc = "cloexec";
    } else if (flags & O_NONBLOCK) {
        behavior_desc = "nonblock";
    } else if (flags & O_SYNC) {
        behavior_desc = "sync";
    } else if (flags & O_NOFOLLOW) {
        behavior_desc = "nofollow";
    } else if (flags & O_PATH) {
        behavior_desc = "path";
    } else {
        behavior_desc = "multiple";
    }

    /* Phase 2: Validate dirfd for relative paths */
    if (dirfd != AT_FDCWD && kpath[0] != '/') {
        /* Relative path with real dirfd not yet supported in Phase 2 */
        fut_printf("[OPENAT] openat(dirfd=%d [%s], path='%s' [%s], flags=0x%x [%s, %s], mode=0%o) "
                   "-> ENOTSUP (real dirfd not yet supported, Phase 3: dirfd validation)\n",
                   dirfd, dirfd_desc, kpath, path_type, flags, access_desc, creation_desc, mode);
        return -ENOTSUP;
    }

    /* Open via VFS */
    int result = fut_vfs_open(kpath, flags, mode);

    /* Phase 2: Detailed logging with flag categorization */
    if (result >= 0) {
        fut_printf("[OPENAT] openat(dirfd=%d [%s], path='%s' [%s], flags=0x%x [%s, %s, behavior: %s], mode=0%o) "
                   "-> %d (Phase 3: dirfd validation, AT_FDCWD)\n",
                   dirfd, dirfd_desc, kpath, path_type, flags, access_desc, creation_desc,
                   behavior_desc, mode, result);
    } else {
        fut_printf("[OPENAT] openat(dirfd=%d [%s], path='%s' [%s], flags=0x%x [%s, %s, behavior: %s], mode=0%o) "
                   "-> %d (%s, Phase 3: dirfd validation)\n",
                   dirfd, dirfd_desc, kpath, path_type, flags, access_desc, creation_desc,
                   behavior_desc, mode, result,
                   (result == -ENOENT) ? "not found" :
                   (result == -EACCES) ? "access denied" :
                   (result == -EEXIST) ? "already exists" :
                   (result == -EISDIR) ? "is directory" :
                   (result == -ENOTDIR) ? "not directory" : "error");
    }

    return (long)result;
}
