/* kernel/sys_ioctl.c - I/O control device syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements ioctl() to control device parameters.
 */

#include <kernel/fut_task.h>
#include <kernel/fut_vfs.h>
#include <kernel/chrdev.h>
#include <kernel/errno.h>

extern void fut_printf(const char *fmt, ...);
extern fut_task_t *fut_task_current(void);

/* Common ioctl commands */
#define TCGETS      0x5401
#define TCSETS      0x5402
#define TIOCGWINSZ  0x5413
#define FIONREAD    0x541B

/**
 * ioctl() - I/O control
 *
 * Performs device-specific control operations on special files.
 *
 * @param fd      File descriptor
 * @param request Device-dependent request code
 * @param argp    Optional argument pointer
 *
 * Returns:
 *   - 0 or positive value on success (device-dependent)
 *   - -EBADF if fd is invalid
 *   - -EFAULT if argp is invalid
 *   - -EINVAL if request or arg is invalid
 *   - -ENOTTY if fd is not associated with character special device
 *   - -ENOTSUP if request not supported by device
 *
 * Phase 1 (Completed): Stub implementation
 * Phase 2 (Current): Enhanced validation and request type reporting
 * Phase 3: Implement terminal ioctls (TCGETS, TCSETS, TIOCGWINSZ)
 * Phase 4: Implement file ioctls (FIONREAD)
 * Phase 5: Device-specific ioctls
 */
long sys_ioctl(int fd, unsigned long request, void *argp) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[IOCTL] ioctl(fd=%d, request=0x%lx, argp=%p) -> ESRCH (no current task)\n",
                   fd, request, argp);
        return -ESRCH;
    }

    /* Phase 2: Validate file descriptor */
    if (fd < 0 || fd >= task->max_fds) {
        fut_printf("[IOCTL] ioctl(fd=%d, request=0x%lx, argp=%p) -> EBADF (fd out of range)\n",
                   fd, request, argp);
        return -EBADF;
    }

    if (!task->fd_table || !task->fd_table[fd]) {
        fut_printf("[IOCTL] ioctl(fd=%d, request=0x%lx, argp=%p) -> EBADF (fd not open)\n",
                   fd, request, argp);
        return -EBADF;
    }

    /* Identify request type for logging */
    const char *request_name = "UNKNOWN";
    const char *request_category = "unknown";

    switch (request) {
        case TCGETS:
            request_name = "TCGETS";
            request_category = "terminal";
            break;
        case TCSETS:
            request_name = "TCSETS";
            request_category = "terminal";
            break;
        case TIOCGWINSZ:
            request_name = "TIOCGWINSZ";
            request_category = "terminal";
            break;
        case FIONREAD:
            request_name = "FIONREAD";
            request_category = "file";
            break;
        default:
            request_name = "UNKNOWN";
            request_category = "unknown";
            break;
    }

    /* Get file from fd table */
    struct fut_file *file = task->fd_table[fd];
    if (!file) {
        fut_printf("[IOCTL] ioctl(fd=%d, request=0x%lx, argp=%p) -> EBADF (invalid file)\n",
                   fd, request, argp);
        return -EBADF;
    }

    /* Try character device operations */
    if (file->chr_ops && file->chr_ops->ioctl) {
        fut_printf("[IOCTL] ioctl(fd=%d, request=0x%lx [%s], argp=%p) -> dispatching to chr device\n",
                   fd, request, request_name, argp);
        return file->chr_ops->ioctl(file->chr_inode, file->chr_private, request, (unsigned long)argp);
    }

    /* Phase 2: Stub for terminal ioctls if no handler found */
    switch (request) {
        case TCGETS:
        case TCSETS:
        case TIOCGWINSZ:
        case FIONREAD:
            fut_printf("[IOCTL] ioctl(fd=%d, request=0x%lx [%s], argp=%p) -> 0 (category: %s, Phase 2: stubbed)\n",
                       fd, request, request_name, argp, request_category);
            return 0;
        default:
            fut_printf("[IOCTL] ioctl(fd=%d, request=0x%lx [%s], argp=%p) -> ENOTTY (no ioctl op)\n",
                       fd, request, request_name, argp);
            return -ENOTTY;
    }
}
