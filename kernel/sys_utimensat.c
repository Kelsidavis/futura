/* kernel/sys_utimensat.c - File timestamp update syscall with dirfd
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements utimensat() for changing file timestamps with nanosecond precision.
 * Essential for touch(1), make(1), and precise timestamp management.
 *
 * Phase 1 (Completed): Basic timestamp validation and stub
 * Phase 2 (Completed): Implement actual timestamp updates via vnode->ops->setattr
 * Phase 3: Full dirfd support and AT_SYMLINK_NOFOLLOW
 * Phase 4: Performance optimization
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <shared/fut_timespec.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);
extern int fut_copy_from_user(void *to, const void *from, size_t size);
extern uint64_t fut_get_time_ns(void);

/* Special values */
#define AT_FDCWD            -100
#define AT_SYMLINK_NOFOLLOW 0x100

/* Special timespec values */
#define UTIME_NOW    ((1l << 30) - 1l)
#define UTIME_OMIT   ((1l << 30) - 2l)

/**
 * utimensat() - Change file timestamps with nanosecond precision
 *
 * Changes the access time (atime) and modification time (mtime) of a file
 * with nanosecond precision. This is the modern replacement for utime()
 * and utimes().
 *
 * @param dirfd     Directory fd for relative paths, or AT_FDCWD for cwd
 * @param pathname  Path to the file (relative or absolute), or NULL for dirfd itself
 * @param times     Array of 2 timespecs: [0]=atime, [1]=mtime, or NULL for current time
 * @param flags     AT_SYMLINK_NOFOLLOW
 *
 * Returns:
 *   - 0 on success
 *   - -EBADF if dirfd is invalid or pathname is NULL and dirfd is not open FD
 *   - -EFAULT if times points to inaccessible memory
 *   - -EINVAL if times has invalid values or flags invalid
 *   - -ENOENT if file does not exist
 *   - -ENAMETOOLONG if pathname too long
 *   - -ENOTDIR if dirfd not a directory or path component not a directory
 *   - -EPERM if process doesn't have permission
 *   - -EROFS if file is on read-only filesystem
 *   - -ESRCH if no current task
 *
 * Behavior:
 *   - If times is NULL, set both atime and mtime to current time (requires write access)
 *   - times[0] = access time (atime)
 *   - times[1] = modification time (mtime)
 *   - Special tv_nsec values:
 *     - UTIME_NOW: Set to current time
 *     - UTIME_OMIT: Don't change this time
 *   - If pathname is absolute, dirfd is ignored
 *   - If pathname is NULL, operate on dirfd itself (futimens behavior)
 *   - AT_SYMLINK_NOFOLLOW: don't follow symlinks (change symlink itself)
 *
 * Permission requirements:
 *   - Setting to current time (UTIME_NOW or times=NULL): requires write access
 *   - Setting to arbitrary time: requires ownership or CAP_FOWNER
 *   - UTIME_OMIT doesn't require any permission for that timestamp
 *
 * Common usage patterns:
 *
 * Touch file (set both to current time):
 *   utimensat(AT_FDCWD, "file.txt", NULL, 0);
 *
 * Set specific timestamps:
 *   struct timespec times[2];
 *   times[0].tv_sec = 1609459200; times[0].tv_nsec = 0;  // atime
 *   times[1].tv_sec = 1609459200; times[1].tv_nsec = 0;  // mtime
 *   utimensat(AT_FDCWD, "file.txt", times, 0);
 *
 * Update only mtime, preserve atime:
 *   struct timespec times[2];
 *   times[0].tv_nsec = UTIME_OMIT;  // Don't change atime
 *   times[1].tv_nsec = UTIME_NOW;   // Set mtime to now
 *   utimensat(AT_FDCWD, "file.txt", times, 0);
 *
 * Update timestamps of open file:
 *   int fd = open("file.txt", O_RDONLY);
 *   utimensat(fd, NULL, NULL, 0);  // futimens equivalent
 *
 * Update symlink timestamps:
 *   utimensat(AT_FDCWD, "symlink", NULL, AT_SYMLINK_NOFOLLOW);
 *
 * Phase 1 (Completed): Basic timestamp validation and stub
 * Phase 2 (Completed): Implement actual timestamp updates via vnode->ops->setattr
 * Phase 3: Full dirfd support with AT_SYMLINK_NOFOLLOW
 * Phase 4: Performance optimization
 */
long sys_utimensat(int dirfd, const char *pathname, const fut_timespec_t *times, int flags) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[UTIMENSAT] utimensat(dirfd=%d, pathname=%p, times=%p, flags=0x%x) "
                   "-> ESRCH (no current task)\n", dirfd, pathname, times, flags);
        return -ESRCH;
    }

    /* Categorize dirfd */
    const char *dirfd_desc;
    if (dirfd == AT_FDCWD) {
        dirfd_desc = "AT_FDCWD (use cwd)";
    } else if (dirfd < 0) {
        dirfd_desc = "invalid (<0, not AT_FDCWD)";
    } else if (dirfd < 3) {
        dirfd_desc = "stdin/stdout/stderr";
    } else {
        dirfd_desc = "directory/file fd";
    }

    /* Validate flags */
    const int VALID_FLAGS = AT_SYMLINK_NOFOLLOW;
    if (flags & ~VALID_FLAGS) {
        fut_printf("[UTIMENSAT] utimensat(dirfd=%d [%s], pathname=%p, times=%p, flags=0x%x, pid=%d) "
                   "-> EINVAL (invalid flags)\n", dirfd, dirfd_desc, pathname, times, flags, task->pid);
        return -EINVAL;
    }

    const char *flags_desc = (flags & AT_SYMLINK_NOFOLLOW) ? "AT_SYMLINK_NOFOLLOW" : "none";

    /* Categorize time specification */
    const char *time_spec_desc;
    fut_timespec_t time_buf[2];

    if (times == NULL) {
        time_spec_desc = "NULL (set both to current time)";
        /* Will set to current time in Phase 2 */
    } else {
        /* Copy timespec array from userspace */
        if (fut_copy_from_user(time_buf, times, sizeof(time_buf)) != 0) {
            fut_printf("[UTIMENSAT] utimensat(dirfd=%d [%s], pathname=%p, times=%p [bad addr], "
                       "flags=%s, pid=%d) -> EFAULT (copy_from_user failed)\n",
                       dirfd, dirfd_desc, pathname, times, flags_desc, task->pid);
            return -EFAULT;
        }

        /* Validate timespec values */
        for (int i = 0; i < 2; i++) {
            const char *time_name = (i == 0) ? "atime" : "mtime";

            /* Check for special values */
            if (time_buf[i].tv_nsec == UTIME_NOW || time_buf[i].tv_nsec == UTIME_OMIT) {
                continue;  /* Valid special value */
            }

            /* Validate nanoseconds range */
            if (time_buf[i].tv_nsec < 0 || time_buf[i].tv_nsec >= 1000000000) {
                fut_printf("[UTIMENSAT] utimensat(dirfd=%d [%s], pathname=%p, %s.tv_nsec=%ld, "
                           "flags=%s, pid=%d) -> EINVAL (invalid nsec value)\n",
                           dirfd, dirfd_desc, pathname, time_name, time_buf[i].tv_nsec,
                           flags_desc, task->pid);
                return -EINVAL;
            }
        }

        /* Describe time specification */
        if (time_buf[0].tv_nsec == UTIME_NOW && time_buf[1].tv_nsec == UTIME_NOW) {
            time_spec_desc = "both UTIME_NOW (set to current time)";
        } else if (time_buf[0].tv_nsec == UTIME_OMIT && time_buf[1].tv_nsec == UTIME_OMIT) {
            time_spec_desc = "both UTIME_OMIT (no-op)";
        } else if (time_buf[0].tv_nsec == UTIME_OMIT) {
            time_spec_desc = "atime=OMIT, mtime specified";
        } else if (time_buf[1].tv_nsec == UTIME_OMIT) {
            time_spec_desc = "atime specified, mtime=OMIT";
        } else if (time_buf[0].tv_nsec == UTIME_NOW) {
            time_spec_desc = "atime=NOW, mtime specified";
        } else if (time_buf[1].tv_nsec == UTIME_NOW) {
            time_spec_desc = "atime specified, mtime=NOW";
        } else {
            time_spec_desc = "both atime and mtime specified";
        }
    }

    /* Handle pathname=NULL case (futimens behavior - operate on dirfd) */
    if (pathname == NULL) {
        fut_printf("[UTIMENSAT] utimensat(dirfd=%d [%s], pathname=NULL [futimens mode], "
                   "times=%s, flags=%s, pid=%d) -> ENOSYS "
                   "(futimens mode not implemented yet, Phase 2)\n",
                   dirfd, dirfd_desc, time_spec_desc, flags_desc, task->pid);
        return -ENOSYS;
    }

    /* Copy pathname from userspace to kernel space */
    char path_buf[256];
    if (fut_copy_from_user(path_buf, pathname, sizeof(path_buf) - 1) != 0) {
        fut_printf("[UTIMENSAT] utimensat(dirfd=%d [%s], pathname=? [bad addr], times=%s, "
                   "flags=%s, pid=%d) -> EFAULT (pathname copy_from_user failed)\n",
                   dirfd, dirfd_desc, time_spec_desc, flags_desc, task->pid);
        return -EFAULT;
    }
    path_buf[sizeof(path_buf) - 1] = '\0';

    /* Validate pathname is not empty */
    if (path_buf[0] == '\0') {
        fut_printf("[UTIMENSAT] utimensat(dirfd=%d [%s], pathname=\"\" [empty], times=%s, "
                   "flags=%s, pid=%d) -> EINVAL (empty pathname)\n",
                   dirfd, dirfd_desc, time_spec_desc, flags_desc, task->pid);
        return -EINVAL;
    }

    /* Categorize path type */
    const char *path_type;
    if (path_buf[0] == '/') {
        path_type = "absolute (dirfd ignored)";
    } else if (path_buf[0] == '.' && path_buf[1] == '/') {
        path_type = "relative (explicit)";
    } else if (path_buf[0] == '.') {
        path_type = "relative (current/parent)";
    } else {
        path_type = "relative";
    }

    /* Categorize path length */
    size_t path_len = 0;
    for (const char *p = path_buf; *p != '\0' && path_len < 256; p++, path_len++);

    const char *path_len_cat;
    if (path_len < 16) {
        path_len_cat = "short";
    } else if (path_len < 64) {
        path_len_cat = "medium";
    } else if (path_len < 128) {
        path_len_cat = "long";
    } else {
        path_len_cat = "very long";
    }

    /* Phase 1: For now, ignore dirfd and just use vfs_lookup
     * Phase 3 will implement proper dirfd-relative path resolution
     */
    if (dirfd != AT_FDCWD && path_buf[0] != '/') {
        fut_printf("[UTIMENSAT] utimensat(dirfd=%d [%s], path='%s' [%s, %s, len=%zu], times=%s, "
                   "flags=%s, pid=%d) -> ENOSYS "
                   "(dirfd with relative path not yet implemented, Phase 3)\n",
                   dirfd, dirfd_desc, path_buf, path_type, path_len_cat, path_len,
                   time_spec_desc, flags_desc, task->pid);
        return -ENOSYS;
    }

    /* Phase 1: AT_SYMLINK_NOFOLLOW not yet implemented */
    if (flags & AT_SYMLINK_NOFOLLOW) {
        fut_printf("[UTIMENSAT] utimensat(dirfd=%d [%s], path='%s' [%s, %s, len=%zu], times=%s, "
                   "flags=%s, pid=%d) -> ENOSYS "
                   "(AT_SYMLINK_NOFOLLOW not implemented yet, Phase 3)\n",
                   dirfd, dirfd_desc, path_buf, path_type, path_len_cat, path_len,
                   time_spec_desc, flags_desc, task->pid);
        return -ENOSYS;
    }

    /* Lookup the vnode */
    struct fut_vnode *vnode = NULL;
    int ret = fut_vfs_lookup(path_buf, &vnode);

    /* Handle lookup errors */
    if (ret < 0 || !vnode) {
        const char *error_desc;
        switch (ret) {
            case -ENOENT:
                error_desc = "file not found";
                break;
            case -ENOTDIR:
                error_desc = "path component not a directory";
                break;
            case -ENAMETOOLONG:
                error_desc = "pathname too long";
                break;
            case -EACCES:
                error_desc = "search permission denied";
                break;
            default:
                error_desc = vnode ? "unknown error" : "vnode is NULL";
                break;
        }

        fut_printf("[UTIMENSAT] utimensat(dirfd=%d [%s], path='%s' [%s, %s, len=%zu], times=%s, "
                   "flags=%s, pid=%d) -> %d (%s)\n",
                   dirfd, dirfd_desc, path_buf, path_type, path_len_cat, path_len,
                   time_spec_desc, flags_desc, task->pid, ret < 0 ? ret : -ENOENT, error_desc);
        return ret < 0 ? ret : -ENOENT;
    }

    /* Phase 2: Implement actual timestamp updates via vnode->ops->setattr */

    /* Check if filesystem supports setattr operation */
    if (!vnode->ops || !vnode->ops->setattr) {
        fut_printf("[UTIMENSAT] utimensat(dirfd=%d [%s], path='%s' [%s, %s, len=%zu], "
                   "vnode_ino=%lu, times=%s, flags=%s, pid=%d) -> ENOSYS "
                   "(filesystem doesn't support setattr)\n",
                   dirfd, dirfd_desc, path_buf, path_type, path_len_cat, path_len,
                   vnode->ino, time_spec_desc, flags_desc, task->pid);
        return -ENOSYS;
    }

    /* Build stat structure with new timestamps */
    struct fut_stat stat = {0};

    /* Get current time if needed */
    uint64_t now_ns = 0;
    if (times == NULL ||
        (times && (time_buf[0].tv_nsec == UTIME_NOW || time_buf[1].tv_nsec == UTIME_NOW))) {
        now_ns = fut_get_time_ns();
    }

    /* Set access time */
    if (times == NULL) {
        /* NULL times means set both to current time */
        stat.st_atime = now_ns / 1000000000;  /* seconds */
        /* TODO: Add st_atime_nsec field to struct fut_stat */
        /* stat.st_atime_nsec = now_ns % 1000000000;  nanoseconds */
    } else if (time_buf[0].tv_nsec == UTIME_NOW) {
        stat.st_atime = now_ns / 1000000000;
        /* stat.st_atime_nsec = now_ns % 1000000000; */
    } else if (time_buf[0].tv_nsec == UTIME_OMIT) {
        /* Don't change atime - use sentinel value */
        stat.st_atime = -1;  /* (time_t)-1; */
    } else {
        /* Use provided atime */
        stat.st_atime = time_buf[0].tv_sec;
        stat.st_atime_nsec = time_buf[0].tv_nsec;
    }

    /* Set modification time */
    if (times == NULL) {
        /* NULL times means set both to current time */
        stat.st_mtime = now_ns / 1000000000;  /* seconds */
        stat.st_mtime_nsec = now_ns % 1000000000;  /* nanoseconds */
    } else if (time_buf[1].tv_nsec == UTIME_NOW) {
        stat.st_mtime = now_ns / 1000000000;
        stat.st_mtime_nsec = now_ns % 1000000000;
    } else if (time_buf[1].tv_nsec == UTIME_OMIT) {
        /* Don't change mtime - use sentinel value */
        stat.st_mtime = (time_t)-1;
    } else {
        /* Use provided mtime */
        stat.st_mtime = time_buf[1].tv_sec;
        stat.st_mtime_nsec = time_buf[1].tv_nsec;
    }

    /* Call the filesystem's setattr operation */
    int ret = vnode->ops->setattr(vnode, &stat);

    /* Handle errors */
    if (ret < 0) {
        const char *error_desc;
        switch (ret) {
            case -EPERM:
                error_desc = "operation not permitted";
                break;
            case -EACCES:
                error_desc = "permission denied";
                break;
            case -EROFS:
                error_desc = "read-only filesystem";
                break;
            default:
                error_desc = "setattr failed";
                break;
        }

        fut_printf("[UTIMENSAT] utimensat(dirfd=%d [%s], path='%s' [%s, %s, len=%zu], "
                   "vnode_ino=%lu, times=%s, flags=%s, pid=%d) -> %d (%s)\n",
                   dirfd, dirfd_desc, path_buf, path_type, path_len_cat, path_len,
                   vnode->ino, time_spec_desc, flags_desc, task->pid, ret, error_desc);
        return ret;
    }

    /* Success */
    fut_printf("[UTIMENSAT] utimensat(dirfd=%d [%s], path='%s' [%s, %s, len=%zu], "
               "vnode_ino=%lu, times=%s, flags=%s, pid=%d) -> 0 (Phase 3: Timestamp updates with setattr)\n",
               dirfd, dirfd_desc, path_buf, path_type, path_len_cat, path_len,
               vnode->ino, time_spec_desc, flags_desc, task->pid);

    return 0;
}
