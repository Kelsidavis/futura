/* kernel/sys_fcntl.c - File control operations syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the fcntl() syscall for file descriptor control operations.
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

/* Flag definitions */
#ifndef FD_CLOEXEC
#define FD_CLOEXEC         1
#endif
/* O_NONBLOCK already defined in fut_vfs.h */

/**
 * fcntl() - File control operations
 *
 * Performs various operations on a file descriptor. Supported commands:
 *   - F_GETFD: Get file descriptor flags
 *   - F_SETFD: Set file descriptor flags (FD_CLOEXEC)
 *   - F_GETFL: Get file status flags
 *   - F_SETFL: Set file status flags (O_NONBLOCK)
 *   - F_DUPFD: Duplicate fd to minimum fd >= arg
 *   - F_DUPFD_CLOEXEC: Duplicate fd with close-on-exec set
 *   - F_GET_SEALS: Get seals (stub, returns 0)
 *
 * @param fd   File descriptor
 * @param cmd  Command to perform
 * @param arg  Command argument (meaning depends on cmd)
 *
 * Returns:
 *   - Command-specific value on success
 *   - -EBADF if fd is invalid
 *   - -EINVAL if cmd or arg is invalid
 */
long sys_fcntl(int fd, int cmd, uint64_t arg) {
    /* Get current task */
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Get file structure for this fd */
    struct fut_file *file = vfs_get_file_from_task(task, fd);
    if (!file) {
        fut_printf("[FCNTL] fcntl(%d, %d, %llu) -> EBADF\n", fd, cmd, arg);
        return -EBADF;
    }

    switch (cmd) {
    case F_GETFD:
        /* Return file descriptor flags */
        fut_printf("[FCNTL] fcntl(%d, F_GETFD) -> %d\n", fd, file->fd_flags);
        return file->fd_flags;

    case F_SETFD:
        /* Set file descriptor flags (only FD_CLOEXEC supported) */
        file->fd_flags = ((int)arg & FD_CLOEXEC);
        fut_printf("[FCNTL] fcntl(%d, F_SETFD, %d) -> 0\n", fd, file->fd_flags);
        return 0;

    case F_GETFL:
        /* Return file status flags */
        fut_printf("[FCNTL] fcntl(%d, F_GETFL) -> %d\n", fd, file->flags);
        return file->flags;

    case F_SETFL: {
        /* Set file status flags (only O_NONBLOCK supported) */
        int new_flags = file->flags;
        new_flags &= ~O_NONBLOCK;
        new_flags |= ((int)arg & O_NONBLOCK);
        file->flags = new_flags;
        fut_printf("[FCNTL] fcntl(%d, F_SETFL, %d) -> 0\n", fd, new_flags);
        return 0;
    }

    case F_DUPFD:
    case F_DUPFD_CLOEXEC: {
        /* Duplicate file descriptor to minimum fd >= arg */
        int minfd = (int)arg;
        if (minfd < 0) {
            fut_printf("[FCNTL] fcntl(%d, F_DUPFD, %d) -> EINVAL\n", fd, minfd);
            return -EINVAL;
        }

        /* Find first available fd >= minfd */
        int newfd = minfd;
        for (; newfd < 1024; newfd++) {  /* Max 1024 FDs */
            struct fut_file *existing = vfs_get_file_from_task(task, newfd);
            if (!existing) {
                break;  /* Found available fd */
            }
        }

        if (newfd >= 1024) {
            fut_printf("[FCNTL] fcntl(%d, F_DUPFD, %d) -> EMFILE\n", fd, minfd);
            return -EMFILE;
        }

        /* Increment reference count */
        file->refcount++;

        /* Allocate newfd */
        int ret = vfs_alloc_specific_fd_for_task(task, newfd, file);
        if (ret < 0) {
            file->refcount--;
            return ret;
        }

        /* Set close-on-exec if F_DUPFD_CLOEXEC */
        if (cmd == F_DUPFD_CLOEXEC) {
            struct fut_file *new_file = vfs_get_file_from_task(task, newfd);
            if (new_file) {
                new_file->fd_flags |= FD_CLOEXEC;
            }
        }

        fut_printf("[FCNTL] fcntl(%d, F_DUPFD%s, %d) -> %d\n",
                   fd, (cmd == F_DUPFD_CLOEXEC) ? "_CLOEXEC" : "", minfd, newfd);
        return newfd;
    }

    case F_GET_SEALS:
        /* Stub: return no seals set */
        fut_printf("[FCNTL] fcntl(%d, F_GET_SEALS) -> 0 (stub)\n", fd);
        return 0;

    default:
        /* Unknown command */
        fut_printf("[FCNTL] fcntl(%d, %d, %llu) -> EINVAL (unknown cmd)\n", fd, cmd, arg);
        return -EINVAL;
    }
}
