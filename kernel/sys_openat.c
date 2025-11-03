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

extern void fut_printf(const char *fmt, ...);
extern fut_task_t *fut_task_current(void);
extern int copy_user_string(const char *user_str, char *kernel_buf, size_t max_len);

/* AT_FDCWD - special value for current working directory */
#define AT_FDCWD -100

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
 */
long sys_openat(int dirfd, const char *pathname, int flags, int mode) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    fut_printf("[SYS-OPENAT] INVOKED: dirfd=%d pathname=0x%p flags=0x%x mode=0%o\n",
               dirfd, pathname, flags, mode);

    /* Copy pathname from userspace */
    char kpath[256];
    int rc = copy_user_string(pathname, kpath, sizeof(kpath));
    fut_printf("[SYS-OPENAT] copy_user_string returned %d, kpath='%s'\n", rc, kpath);
    if (rc != 0) {
        fut_printf("[SYS-OPENAT] returning error %d\n", rc);
        return rc;
    }

    /* Phase 1: Only support AT_FDCWD (current directory) */
    if (dirfd != AT_FDCWD && kpath[0] != '/') {
        /* Relative path with real dirfd not yet supported */
        fut_printf("[SYS-OPENAT] ERROR: dirfd %d not supported (only AT_FDCWD)\n", dirfd);
        return -ENOTSUP;
    }

    /* Open via VFS (same as open for now) */
    int result = fut_vfs_open(kpath, flags, mode);
    fut_printf("[SYS-OPENAT] fut_vfs_open returned %d for path '%s'\n", result, kpath);

    return (long)result;
}
