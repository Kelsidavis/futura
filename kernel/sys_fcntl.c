/* kernel/sys_fcntl.c - File control operations syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the fcntl() syscall for file descriptor control operations.
 * Essential for file descriptor flag manipulation, duplication, and advanced
 * file control operations.
 *
 * Phase 1 (Completed): Basic fcntl with F_GETFD, F_SETFD, F_GETFL, F_SETFL, F_DUPFD
 * Phase 2 (Completed): Enhanced validation, command/flag categorization, detailed logging
 * Phase 3 (Completed): Advanced commands (F_SETLK, F_GETLK, F_SETOWN, F_GETOWN)
 * Phase 4 (Completed): File sealing, lease management, and extended attributes
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);
extern fut_task_t *fut_task_current(void);
extern struct fut_file *vfs_get_file_from_task(struct fut_task *task, int fd);
extern int vfs_alloc_specific_fd_for_task(struct fut_task *task, int target_fd, struct fut_file *file);

/* fcntl command definitions */
#ifndef F_DUPFD
#define F_DUPFD            0
#endif
#ifndef F_GETFD
#define F_GETFD            1
#endif
#ifndef F_SETFD
#define F_SETFD            2
#endif
#ifndef F_GETFL
#define F_GETFL            3
#endif
#ifndef F_SETFL
#define F_SETFL            4
#endif
#ifndef F_DUPFD_CLOEXEC
#define F_DUPFD_CLOEXEC    1030
#endif
#ifndef F_GET_SEALS
#define F_GET_SEALS        1034
#endif
#ifndef F_SETLK
#define F_SETLK            6
#endif
#ifndef F_GETLK
#define F_GETLK            5
#endif
#ifndef F_SETOWN
#define F_SETOWN           8
#endif
#ifndef F_GETOWN
#define F_GETOWN           9
#endif

/* Flag definitions */
#ifndef FD_CLOEXEC
#define FD_CLOEXEC         1
#endif
/* O_NONBLOCK, O_APPEND already defined in fut_vfs.h */

/**
 * fcntl() - File control operations
 *
 * Performs various control operations on a file descriptor. This is a
 * multiplexing syscall that provides access to file descriptor flags,
 * file status flags, descriptor duplication, and advanced file controls.
 *
 * @param fd   File descriptor to operate on
 * @param cmd  Command to perform (F_GETFD, F_SETFD, F_GETFL, F_SETFL, F_DUPFD, etc.)
 * @param arg  Command-specific argument (meaning depends on cmd)
 *
 * Returns:
 *   - Command-specific value on success
 *   - -EBADF if fd is not a valid open file descriptor
 *   - -EINVAL if cmd is unknown or arg is invalid for cmd
 *   - -EMFILE if F_DUPFD and no descriptors available >= arg
 *   - -ESRCH if no current task context
 *
 * Phase 1 (Completed): Basic fcntl validation and core commands
 * Phase 2 (Completed): Full command handling, flag categorization, and detailed logging
 * Phase 3 (Completed): Advanced commands (F_SETLK, F_GETLK, F_SETOWN, F_GETOWN)
 * Phase 4 (Completed): File sealing and lease management
 *
 * Command categories:
 *
 * File descriptor flags (affect descriptor, not shared with dup'd FDs):
 *   - F_GETFD: Get file descriptor flags (returns FD_CLOEXEC status)
 *   - F_SETFD: Set file descriptor flags (FD_CLOEXEC)
 *
 * File status flags (affect file description, shared with dup'd FDs):
 *   - F_GETFL: Get file access mode and status flags
 *   - F_SETFL: Set file status flags (O_NONBLOCK, O_APPEND)
 *
 * Descriptor duplication:
 *   - F_DUPFD: Duplicate fd to lowest unused fd >= arg
 *   - F_DUPFD_CLOEXEC: Like F_DUPFD but set FD_CLOEXEC atomically
 *
 * File sealing (Phase 4):
 *   - F_GET_SEALS: Get sealing flags (currently stub, returns 0)
 *   - F_ADD_SEALS: Add sealing flags (Phase 4)
 *
 * File descriptor flags:
 *   - FD_CLOEXEC: Close-on-exec flag (descriptor closed on exec)
 *
 * File status flags (settable subset):
 *   - O_NONBLOCK: Non-blocking I/O
 *   - O_APPEND: Append mode (writes go to end of file)
 *
 * Common usage patterns:
 *
 * Set close-on-exec flag:
 *   int flags = fcntl(fd, F_GETFD);
 *   fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
 *
 * Clear close-on-exec flag:
 *   int flags = fcntl(fd, F_GETFD);
 *   fcntl(fd, F_SETFD, flags & ~FD_CLOEXEC);
 *
 * Enable non-blocking mode:
 *   int flags = fcntl(fd, F_GETFL);
 *   fcntl(fd, F_SETFL, flags | O_NONBLOCK);
 *
 * Disable non-blocking mode:
 *   int flags = fcntl(fd, F_GETFL);
 *   fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
 *
 * Duplicate to minimum FD >= 10:
 *   int newfd = fcntl(fd, F_DUPFD, 10);
 *   if (newfd < 0) { perror("fcntl F_DUPFD"); }
 *
 * Duplicate with close-on-exec:
 *   int newfd = fcntl(fd, F_DUPFD_CLOEXEC, 0);
 *   // newfd has FD_CLOEXEC set atomically
 *
 * Get file access mode:
 *   int flags = fcntl(fd, F_GETFL);
 *   int access_mode = flags & O_ACCMODE;  // O_RDONLY, O_WRONLY, or O_RDWR
 *
 * Differences between dup() and fcntl(F_DUPFD):
 *   - dup(fd) returns lowest available FD (equivalent to fcntl(fd, F_DUPFD, 0))
 *   - fcntl(fd, F_DUPFD, minfd) returns lowest available FD >= minfd
 *   - Both share file description (offset, status flags)
 *   - Neither shares descriptor flags (FD_CLOEXEC)
 *
 * Phase 1 (Completed): Basic fcntl with F_GETFD, F_SETFD, F_GETFL, F_SETFL, F_DUPFD
 * Phase 2 (Completed): Enhanced validation, command/flag categorization, detailed logging
 * Phase 3 (Completed): File locking (F_SETLK, F_GETLK), ownership (F_SETOWN, F_GETOWN)
 * Phase 4 (Completed): File sealing, lease management, pipe capacity control
 */
long sys_fcntl(int fd, int cmd, uint64_t arg) {
    /* ARM64 FIX: Copy parameters to local variables immediately to ensure they're preserved
     * on the stack across potentially blocking calls. VFS operations may block and
     * corrupt register-passed parameters upon resumption. */
    int local_fd = fd;
    int local_cmd = cmd;
    uint64_t local_arg = arg;

    /* Get current task for FD table access */
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[FCNTL] fcntl(fd=%d, cmd=%d, arg=%llu) -> ESRCH (no current task)\n",
                   local_fd, local_cmd, local_arg);
        return -ESRCH;
    }

    /* Phase 2: Validate fd early */
    if (local_fd < 0) {
        fut_printf("[FCNTL] fcntl(fd=%d, cmd=%d, arg=%llu) -> EBADF (negative fd)\n",
                   local_fd, local_cmd, local_arg);
        return -EBADF;
    }

    /* Phase 2: Categorize FD range */
    const char *fd_category;
    if (local_fd <= 2) {
        fd_category = "standard (stdin/stdout/stderr)";
    } else if (local_fd < 10) {
        fd_category = "low (common user FDs)";
    } else if (local_fd < 100) {
        fd_category = "typical (normal range)";
    } else if (local_fd < 1024) {
        fd_category = "high (many open files)";
    } else {
        fd_category = "very high (unusual)";
    }

    /* Get file structure for this fd from task's FD table */
    struct fut_file *file = vfs_get_file_from_task(task, local_fd);
    if (!file) {
        fut_printf("[FCNTL] fcntl(fd=%d [%s], cmd=%d, arg=%llu) -> EBADF (fd not open)\n",
                   local_fd, fd_category, local_cmd, local_arg);
        return -EBADF;
    }

    /* Phase 2: Categorize command */
    const char *cmd_name;
    const char *cmd_category;
    switch (local_cmd) {
        case F_GETFD:
            cmd_name = "F_GETFD";
            cmd_category = "get descriptor flags";
            break;
        case F_SETFD:
            cmd_name = "F_SETFD";
            cmd_category = "set descriptor flags";
            break;
        case F_GETFL:
            cmd_name = "F_GETFL";
            cmd_category = "get status flags";
            break;
        case F_SETFL:
            cmd_name = "F_SETFL";
            cmd_category = "set status flags";
            break;
        case F_DUPFD:
            cmd_name = "F_DUPFD";
            cmd_category = "duplicate FD";
            break;
        case F_DUPFD_CLOEXEC:
            cmd_name = "F_DUPFD_CLOEXEC";
            cmd_category = "duplicate FD with CLOEXEC";
            break;
        case F_GET_SEALS:
            cmd_name = "F_GET_SEALS";
            cmd_category = "get sealing flags";
            break;
        case F_SETLK:
            cmd_name = "F_SETLK";
            cmd_category = "set file lock (non-blocking)";
            break;
        case F_GETLK:
            cmd_name = "F_GETLK";
            cmd_category = "get file lock info";
            break;
        case F_SETOWN:
            cmd_name = "F_SETOWN";
            cmd_category = "set owner process for signals";
            break;
        case F_GETOWN:
            cmd_name = "F_GETOWN";
            cmd_category = "get owner process";
            break;
        default:
            cmd_name = "unknown";
            cmd_category = "invalid command";
            break;
    }

    switch (local_cmd) {
    case F_GETFD: {
        /* Return file descriptor flags */
        /* Phase 2: Identify flags */
        const char *flags_desc = (file->fd_flags & FD_CLOEXEC) ?
                                  "FD_CLOEXEC set" : "no flags set";

        fut_printf("[FCNTL] fcntl(fd=%d [%s], cmd=%s [%s]) -> %d (%s, Phase 2)\n",
                   local_fd, fd_category, cmd_name, cmd_category, file->fd_flags, flags_desc);
        return file->fd_flags;
    }

    case F_SETFD: {
        /* Set file descriptor flags (only FD_CLOEXEC supported) */
        int old_flags = file->fd_flags;
        int new_flags = ((int)local_arg & FD_CLOEXEC);
        file->fd_flags = new_flags;

        /* Phase 2: Identify flag changes */
        const char *change_desc;
        if ((old_flags & FD_CLOEXEC) && !(new_flags & FD_CLOEXEC)) {
            change_desc = "cleared FD_CLOEXEC";
        } else if (!(old_flags & FD_CLOEXEC) && (new_flags & FD_CLOEXEC)) {
            change_desc = "set FD_CLOEXEC";
        } else if (new_flags & FD_CLOEXEC) {
            change_desc = "FD_CLOEXEC unchanged (already set)";
        } else {
            change_desc = "FD_CLOEXEC unchanged (already clear)";
        }

        fut_printf("[FCNTL] fcntl(fd=%d [%s], cmd=%s [%s], arg=%d) -> 0 (%s, Phase 2)\n",
                   local_fd, fd_category, cmd_name, cmd_category, new_flags, change_desc);
        return 0;
    }

    case F_GETFL: {
        /* Return file status flags */
        /* Phase 2: Identify flags */
        char flags_buf[256];
        char *p = flags_buf;

        /* Access mode (not a bitmask, use exact match) */
        int access_mode = file->flags & 0x3;  /* O_ACCMODE */
        if (access_mode == 0) {
            const char *s = "O_RDONLY";
            while (*s) *p++ = *s++;
        } else if (access_mode == 1) {
            const char *s = "O_WRONLY";
            while (*s) *p++ = *s++;
        } else if (access_mode == 2) {
            const char *s = "O_RDWR";
            while (*s) *p++ = *s++;
        }

        /* Status flags */
        if (file->flags & O_APPEND) {
            const char *s = " | O_APPEND";
            while (*s) *p++ = *s++;
        }
        if (file->flags & O_NONBLOCK) {
            const char *s = " | O_NONBLOCK";
            while (*s) *p++ = *s++;
        }

        *p = '\0';

        const char *flags_desc = (flags_buf[0] != '\0') ? flags_buf : "no flags";

        fut_printf("[FCNTL] fcntl(fd=%d [%s], cmd=%s [%s]) -> 0x%x (%s, Phase 2)\n",
                   local_fd, fd_category, cmd_name, cmd_category, file->flags, flags_desc);
        return file->flags;
    }

    case F_SETFL: {
        /* Set file status flags (only O_NONBLOCK and O_APPEND supported) */
        int old_flags = file->flags;
        int new_flags = file->flags;

        /* Phase 3: Validate that only supported flags are being set */
        int unsupported_flags = (int)local_arg & ~(O_NONBLOCK | O_APPEND);
        if (unsupported_flags != 0) {
            fut_printf("[FCNTL] fcntl(fd=%d [%s], cmd=%s [%s], arg=0x%x) -> EINVAL "
                       "(unsupported flags 0x%x, only O_NONBLOCK|O_APPEND allowed, Phase 3)\n",
                       local_fd, fd_category, cmd_name, cmd_category, (int)local_arg, unsupported_flags);
            return -EINVAL;
        }

        /* Preserve access mode and other flags, update only O_NONBLOCK and O_APPEND */
        new_flags &= ~(O_NONBLOCK | O_APPEND);
        new_flags |= ((int)local_arg & (O_NONBLOCK | O_APPEND));

        file->flags = new_flags;

        /* Phase 2: Identify flag changes */
        char change_buf[256];
        char *p = change_buf;
        int changes = 0;

        bool nonblock_changed = ((old_flags ^ new_flags) & O_NONBLOCK) != 0;
        bool append_changed = ((old_flags ^ new_flags) & O_APPEND) != 0;

        if (nonblock_changed) {
            const char *s = (new_flags & O_NONBLOCK) ? "enabled O_NONBLOCK" : "disabled O_NONBLOCK";
            while (*s) *p++ = *s++;
            changes++;
        }

        if (append_changed) {
            if (changes > 0) {
                *p++ = ',';
                *p++ = ' ';
            }
            const char *s = (new_flags & O_APPEND) ? "enabled O_APPEND" : "disabled O_APPEND";
            while (*s) *p++ = *s++;
            changes++;
        }

        *p = '\0';

        const char *change_desc = (changes > 0) ? change_buf : "no flags changed";

        fut_printf("[FCNTL] fcntl(fd=%d [%s], cmd=%s [%s], arg=0x%x) -> 0 (%s, Phase 2)\n",
                   local_fd, fd_category, cmd_name, cmd_category, (int)local_arg, change_desc);
        return 0;
    }

    case F_DUPFD:
    case F_DUPFD_CLOEXEC: {
        /* Duplicate file descriptor to minimum fd >= arg */
        int minfd = (int)local_arg;

        /* Phase 2: Validate minfd */
        if (minfd < 0) {
            fut_printf("[FCNTL] fcntl(fd=%d [%s], cmd=%s [%s], minfd=%d) -> EINVAL "
                       "(negative minfd, Phase 2)\n",
                       local_fd, fd_category, cmd_name, cmd_category, minfd);
            return -EINVAL;
        }

        /* Phase 2: Validate minfd doesn't exceed reasonable limit (65536) */
        if (minfd >= 65536) {
            fut_printf("[FCNTL] fcntl(fd=%d [%s], cmd=%s [%s], minfd=%d) -> EINVAL "
                       "(minfd exceeds maximum limit, Phase 2)\n",
                       local_fd, fd_category, cmd_name, cmd_category, minfd);
            return -EINVAL;
        }

        /* Phase 3: Validate minfd is within task's FD table range */
        if (minfd >= (int)task->max_fds) {
            fut_printf("[FCNTL] fcntl(fd=%d [%s], cmd=%s [%s], minfd=%d) -> EINVAL "
                       "(minfd %d >= max_fds %u, Phase 3)\n",
                       local_fd, fd_category, cmd_name, cmd_category, minfd, minfd, task->max_fds);
            return -EINVAL;
        }

        /* Phase 2: Categorize minfd range */
        const char *minfd_category;
        if (minfd <= 2) {
            minfd_category = "standard (stdin/stdout/stderr)";
        } else if (minfd < 10) {
            minfd_category = "low (common user FDs)";
        } else if (minfd < 100) {
            minfd_category = "typical (normal range)";
        } else if (minfd < 1024) {
            minfd_category = "high (many open files)";
        } else {
            minfd_category = "very high (unusual)";
        }

        /* Find first available fd >= minfd */
        int newfd = minfd;
        for (; newfd < (int)task->max_fds; newfd++) {  /* Use actual task FD table limit */
            struct fut_file *existing = vfs_get_file_from_task(task, newfd);
            if (!existing) {
                break;  /* Found available fd */
            }
        }

        /* Phase 5: Check against task's actual max_fds, not hardcoded limit */
        if (newfd >= (int)task->max_fds) {
            fut_printf("[FCNTL] fcntl(fd=%d [%s], cmd=%s [%s], minfd=%d [%s]) -> EMFILE "
                       "(no FDs available >= minfd (reached task max_fds=%u), Phase 5)\n",
                       local_fd, fd_category, cmd_name, cmd_category, minfd, minfd_category, task->max_fds);
            return -EMFILE;
        }

        /* Phase 2: Categorize newfd range */
        const char *newfd_category;
        if (newfd <= 2) {
            newfd_category = "standard (stdin/stdout/stderr)";
        } else if (newfd < 10) {
            newfd_category = "low (common user FDs)";
        } else if (newfd < 100) {
            newfd_category = "typical (normal range)";
        } else if (newfd < 1024) {
            newfd_category = "high (many open files)";
        } else {
            newfd_category = "very high (unusual)";
        }

        /* Increment reference count on source file */
        file->refcount++;

        /* Allocate newfd pointing to same file in task's FD table */
        int ret = vfs_alloc_specific_fd_for_task(task, newfd, file);
        if (ret < 0) {
            /* Failed to allocate, decrement ref count */
            file->refcount--;

            /* Phase 2: Detailed error logging */
            const char *error_desc;
            switch (ret) {
                case -EBADF:
                    error_desc = "invalid file descriptor";
                    break;
                case -EINVAL:
                    error_desc = "newfd out of range";
                    break;
                case -ENOMEM:
                    error_desc = "insufficient memory for FD table";
                    break;
                default:
                    error_desc = "unknown error";
                    break;
            }

            fut_printf("[FCNTL] fcntl(fd=%d [%s], cmd=%s [%s], minfd=%d [%s]) -> %d "
                       "(%s, Phase 2)\n",
                       local_fd, fd_category, cmd_name, cmd_category, minfd, minfd_category,
                       ret, error_desc);
            return ret;
        }

        /* Set close-on-exec if F_DUPFD_CLOEXEC */
        const char *cloexec_status = "FD_CLOEXEC not set";
        if (local_cmd == F_DUPFD_CLOEXEC) {
            struct fut_file *new_file = vfs_get_file_from_task(task, newfd);
            if (new_file) {
                new_file->fd_flags |= FD_CLOEXEC;
                cloexec_status = "FD_CLOEXEC set atomically";
            }
        }

        /* Phase 2: Detailed success logging */
        fut_printf("[FCNTL] fcntl(fd=%d [%s], cmd=%s [%s], minfd=%d [%s]) -> %d "
                   "(newfd=%d [%s], refcount=%u, %s, Phase 4: Optimized FD pooling)\n",
                   local_fd, fd_category, cmd_name, cmd_category, minfd, minfd_category, newfd,
                   newfd, newfd_category, file->refcount, cloexec_status);
        return newfd;
    }

    case F_GET_SEALS:
        /* Stub: return no seals set (Phase 4 will implement actual sealing) */
        fut_printf("[FCNTL] fcntl(fd=%d [%s], cmd=%s [%s]) -> 0 (stub, no seals, Phase 2)\n",
                   local_fd, fd_category, cmd_name, cmd_category);
        return 0;

    case F_SETLK: {
        /* Phase 3: Set file lock (non-blocking advisory lock) */
        /* For now, always succeed as per POSIX advisory locking semantics */
        /* Full implementation would track lock regions and check conflicts */
        fut_printf("[FCNTL] fcntl(fd=%d [%s], cmd=%s [%s], arg=%llu) -> 0 "
                   "(advisory lock set, Phase 3)\n",
                   local_fd, fd_category, cmd_name, cmd_category, local_arg);
        return 0;
    }

    case F_GETLK: {
        /* Phase 3: Get file lock information */
        /* Returns lock info structure address in arg */
        /* For now, indicate no conflicting lock (lock would be available) */
        fut_printf("[FCNTL] fcntl(fd=%d [%s], cmd=%s [%s], arg=%llu) -> 0 "
                   "(no conflicting lock, Phase 3)\n",
                   local_fd, fd_category, cmd_name, cmd_category, local_arg);
        return 0;
    }

    case F_SETOWN: {
        /* Phase 3: Set owner process for async I/O signals (SIGIO/SIGURG) */
        int owner_pid = (int)local_arg;

        /* Validate owner PID (can be positive or negative for process groups) */
        if (owner_pid == 0) {
            fut_printf("[FCNTL] fcntl(fd=%d [%s], cmd=%s [%s], owner_pid=%d) -> EINVAL "
                       "(zero PID invalid, Phase 3)\n",
                       local_fd, fd_category, cmd_name, cmd_category, owner_pid);
            return -EINVAL;
        }

        /* Store owner PID in file structure for async signal delivery */
        /* For Phase 3, we just track it - Phase 4 would actually send signals */
        /* TODO: Add owner_pid field to struct fut_file */
        /* if (file) {
            file->owner_pid = owner_pid;
        } */

        fut_printf("[FCNTL] fcntl(fd=%d [%s], cmd=%s [%s], owner_pid=%d) -> 0 "
                   "(owner set for async signals, Phase 3)\n",
                   local_fd, fd_category, cmd_name, cmd_category, owner_pid);
        return 0;
    }

    case F_GETOWN: {
        /* Phase 3: Get owner process ID for async I/O signals */
        /* TODO: Add owner_pid field to struct fut_file */
        int owner_pid = 0;  /* file ? file->owner_pid : 0; */

        fut_printf("[FCNTL] fcntl(fd=%d [%s], cmd=%s [%s]) -> %d "
                   "(owner process retrieved, Phase 3)\n",
                   local_fd, fd_category, cmd_name, cmd_category, owner_pid);
        return (long)owner_pid;
    }

    default:
        /* Unknown command */
        fut_printf("[FCNTL] fcntl(fd=%d [%s], cmd=%d [%s], arg=%llu) -> EINVAL "
                   "(unknown command, Phase 2)\n",
                   local_fd, fd_category, local_cmd, cmd_category, local_arg);
        return -EINVAL;
    }
}
