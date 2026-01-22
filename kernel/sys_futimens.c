/* kernel/sys_futimens.c - File timestamp update syscall using file descriptor
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements futimens() for updating file timestamps by file descriptor.
 * Similar to utimensat() but operates on open file descriptor instead of path.
 *
 * Phase 1 (Completed): Basic stub returning -ENOSYS
 * Phase 2 (Completed): Enhanced validation, parameter categorization, detailed logging
 * Phase 3 (Completed): FD lookup and vnode->ops->setattr() integration
 * Phase 4: Performance optimization (fd caching, batch updates)
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <stdint.h>
#include <shared/fut_timespec.h>

#include <kernel/kprintf.h>
#include <kernel/uaccess.h>
#include <kernel/fut_timer.h>

/* Special timespec values */
#define UTIME_NOW   ((long)1073741823)
#define UTIME_OMIT  ((long)1073741822)

/**
 * futimens() - Update file timestamps via file descriptor
 *
 * Updates the access time (atime) and/or modification time (mtime) of a file
 * specified by an open file descriptor. Similar to utimensat() but operates
 * on file descriptors instead of paths, providing better atomicity.
 *
 * @param fd       Open file descriptor
 * @param times    Pointer to array of two timespec structures (atime, mtime)
 *                 or NULL to set both to current time
 *
 * Returns:
 *   - 0 on success (timestamps updated)
 *   - -ENOSYS if filesystem doesn't support setattr operation
 *
 * Error codes:
 *   - -EBADF if fd is not a valid file descriptor
 *   - -EFAULT if times points to inaccessible memory
 *   - -EINVAL if times is present but times[0].tv_nsec or times[1].tv_nsec
 *     is not one of UTIME_NOW, UTIME_OMIT, or a valid nanosecond value
 *   - -EPERM if process doesn't have permission to modify file
 *   - -EROFS if file is on read-only filesystem
 *   - -EIO if I/O error occurred
 *
 * Behavior:
 *   - If times is NULL, both atime and mtime set to current time via setattr
 *   - If times[i].tv_nsec == UTIME_NOW, set that time to current time
 *   - If times[i].tv_nsec == UTIME_OMIT, don't change that time
 *   - Otherwise use times[i].tv_sec + times[i].tv_nsec as timestamp
 *   - Requires write access to the file or appropriate privileges
 *   - Does not follow symlinks (operates on fd's underlying file)
 *   - Updates file's ctime (change time) automatically
 *
 * Advantages over utimensat():
 *   - Works on open file descriptor (already have access)
 *   - Avoids race condition: file can't be replaced between lookup and update
 *   - Doesn't need path name (TOCTOU-safe)
 *   - Can update times on files with restricted path access
 *
 * Common usage patterns:
 *
 * Set both times to current time:
 *   futimens(fd, NULL);
 *
 * Set only access time, leave mtime unchanged:
 *   struct timespec times[2] = {
 *       {0, UTIME_NOW},      // atime = now
 *       {0, UTIME_OMIT}      // mtime = unchanged
 *   };
 *   futimens(fd, times);
 *
 * Set specific times:
 *   struct timespec times[2] = {
 *       {1609459200, 500000000},  // atime = 2021-01-01 00:00:00 + 500ms
 *       {1609459200, 500000000}   // mtime = same
 *   };
 *   futimens(fd, times);
 *
 * Difference from utimensat():
 *   - futimens(): Works on open fd, no path involved
 *   - utimensat(): Works on paths, can specify dirfd for relative paths
 *   - futimens(): No flags parameter (no AT_SYMLINK_NOFOLLOW needed)
 *   - utimensat(): Supports AT_SYMLINK_NOFOLLOW and AT_EMPTY_PATH flags
 *
 * File descriptor requirements:
 *   - fd must be valid and open
 *   - Typically obtained from open(), openat(), dup(), or socket() syscalls
 *   - fd can refer to any regular file
 *   - Cannot use stdin/stdout/stderr (fd 0/1/2) for special files like pipes
 *
 * Timespec structure:
 *   - tv_sec: Seconds since epoch (time_t, usually 64-bit)
 *   - tv_nsec: Nanoseconds (0-999999999)
 *   - Special values:
 *     - UTIME_NOW: Use current system time
 *     - UTIME_OMIT: Don't change this timestamp
 *
 * Related syscalls:
 *   - utimensat(): Update timestamps by path (with dirfd support)
 *   - utimes(): Similar but with microsecond precision (legacy)
 *   - utime(): Very old interface with second precision (obsolete)
 *   - stat(): Query file timestamps
 *   - fstat(): Query file timestamps via fd
 *
 * Security considerations:
 *   - Process must have write access to the file
 *   - Or be the file owner (for atime/mtime changes)
 *   - Or have CAP_DAC_OVERRIDE capability
 *   - Relative symlinks are not followed (operates on actual file)
 *   - No path traversal possible (uses fd directly)
 *
 * Phase 1: Stub returning ENOSYS
 * Phase 2: Enhanced validation and parameter categorization
 * Phase 3: FD lookup and setattr() integration
 * Phase 4: Performance optimization
 */
long sys_futimens(int fd, const fut_timespec_t *times) {
    /* Phase 2: Validate fd */
    if (fd < 0) {
        fut_printf("[FUTIMENS] futimens(fd=%d, times=%p) -> EBADF (fd < 0)\n",
                   fd, times);
        return -EBADF;
    }

    /* Categorize fd type */
    const char *fd_desc;
    if (fd < 3) {
        fd_desc = "std stream (0-2)";
    } else if (fd < 256) {
        fd_desc = "normal fd";
    } else {
        fd_desc = "fd >= 256";
    }

    /* Phase 2: Validate times parameter if provided */
    fut_timespec_t time_buf[2] = {0};
    if (times) {
        if (fut_copy_from_user(time_buf, times, sizeof(time_buf)) != 0) {
            fut_printf("[FUTIMENS] futimens(fd=%d [%s], times=%p) -> EFAULT "
                       "(times copy_from_user failed)\n",
                       fd, fd_desc, times);
            return -EFAULT;
        }
    }

    /* Phase 2: Categorize operation type */
    const char *operation_type;
    if (!times) {
        operation_type = "set both times to now (NULL)";
    } else if (time_buf[0].tv_nsec == UTIME_NOW && time_buf[1].tv_nsec == UTIME_NOW) {
        operation_type = "set both times to now (explicit UTIME_NOW)";
    } else if (time_buf[0].tv_nsec == UTIME_NOW && time_buf[1].tv_nsec == UTIME_OMIT) {
        operation_type = "set atime to now, keep mtime";
    } else if (time_buf[0].tv_nsec == UTIME_OMIT && time_buf[1].tv_nsec == UTIME_NOW) {
        operation_type = "keep atime, set mtime to now";
    } else if (time_buf[0].tv_nsec == UTIME_OMIT && time_buf[1].tv_nsec == UTIME_OMIT) {
        operation_type = "no change (both UTIME_OMIT)";
    } else {
        operation_type = "set specific times";
    }

    /*
     * Phase 3: FD lookup and VFS integration
     *
     * Get the file object from the fd table and dispatch to vnode->ops->setattr()
     */

    /* Get current task to access fd table */

    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Phase 5: Validate fd bounds before accessing FD table */
    if (fd < 0) {
        fut_printf("[FUTIMENS] futimens(fd=%d [%s], times=%p, op=%s) -> EBADF "
                   "(invalid negative fd)\n",
                   fd, fd_desc, times, operation_type);
        return -EBADF;
    }

    if (fd >= task->max_fds) {
        fut_printf("[FUTIMENS] futimens(fd=%d, max_fds=%d, times=%p, op=%s) -> EBADF "
                   "(fd exceeds max_fds, Phase 5: FD bounds validation)\n",
                   fd, task->max_fds, times, operation_type);
        return -EBADF;
    }

    /* Look up file object from fd table */
    struct fut_file *file = vfs_get_file_from_task(task, fd);
    if (!file) {
        fut_printf("[FUTIMENS] futimens(fd=%d [%s], times=%p, op=%s) -> EBADF "
                   "(fd not open)\n",
                   fd, fd_desc, times, operation_type);
        return -EBADF;
    }

    /* File must have a vnode */
    if (!file->vnode) {
        fut_printf("[FUTIMENS] futimens(fd=%d [%s], times=%p, op=%s) -> EINVAL "
                   "(file vnode is NULL)\n",
                   fd, fd_desc, times, operation_type);
        return -EINVAL;
    }

    /* Build stat structure with only the timestamp fields set */
    struct fut_stat stat_buf = {0};

    /* Get current time if needed */
    uint64_t now_ns = 0;
    if (!times || time_buf[0].tv_nsec == UTIME_NOW || time_buf[1].tv_nsec == UTIME_NOW) {
        now_ns = fut_get_time_ns();
    }

    /* Set atime */
    if (!times || time_buf[0].tv_nsec == UTIME_NOW) {
        stat_buf.st_atime = now_ns / 1000000000;
        stat_buf.st_atime_nsec = now_ns % 1000000000;
    } else if (time_buf[0].tv_nsec == UTIME_OMIT) {
        /* Sentinel value indicates "don't change" */
        stat_buf.st_atime = (uint64_t)-1;
        stat_buf.st_atime_nsec = 0;
    } else {
        stat_buf.st_atime = time_buf[0].tv_sec;
        stat_buf.st_atime_nsec = time_buf[0].tv_nsec;
    }

    /* Set mtime */
    if (!times || time_buf[1].tv_nsec == UTIME_NOW) {
        stat_buf.st_mtime = now_ns / 1000000000;
        stat_buf.st_mtime_nsec = now_ns % 1000000000;
    } else if (time_buf[1].tv_nsec == UTIME_OMIT) {
        /* Sentinel value indicates "don't change" */
        stat_buf.st_mtime = (uint64_t)-1;
        stat_buf.st_mtime_nsec = 0;
    } else {
        stat_buf.st_mtime = time_buf[1].tv_sec;
        stat_buf.st_mtime_nsec = time_buf[1].tv_nsec;
    }

    /* Check if filesystem supports setattr operation */
    if (!file->vnode->ops || !file->vnode->ops->setattr) {
        fut_printf("[FUTIMENS] futimens(fd=%d [%s], times=%p, op=%s, ino=%lu) -> ENOSYS "
                   "(filesystem doesn't support setattr)\n",
                   fd, fd_desc, times, operation_type, file->vnode->ino);
        return -ENOSYS;
    }

    /* Call VFS setattr operation */
    int ret = file->vnode->ops->setattr(file->vnode, &stat_buf);
    if (ret < 0) {
        const char *error_desc;
        switch (ret) {
            case -EPERM:
                error_desc = "permission denied (not owner or root)";
                break;
            case -EROFS:
                error_desc = "read-only filesystem";
                break;
            case -EIO:
                error_desc = "I/O error";
                break;
            default:
                error_desc = "setattr operation failed";
                break;
        }
        fut_printf("[FUTIMENS] futimens(fd=%d [%s], times=%p, op=%s, ino=%lu) -> %d (%s)\n",
                   fd, fd_desc, times, operation_type, file->vnode->ino, ret, error_desc);
        return ret;
    }

    /* Success */
    fut_printf("[FUTIMENS] futimens(fd=%d [%s], times=%p, op=%s, ino=%lu) -> 0 (success)\n",
               fd, fd_desc, times, operation_type, file->vnode->ino);
    return 0;
}
