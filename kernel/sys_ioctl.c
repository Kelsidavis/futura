/* kernel/sys_ioctl.c - I/O control device syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements ioctl() to control device parameters.
 */

#include <kernel/fut_task.h>
#include <kernel/fut_vfs.h>
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
 */
long sys_ioctl(int fd, unsigned long request, void *argp) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    fut_printf("[IOCTL] fd=%d request=0x%lx argp=0x%p\n", fd, request, argp);

    /* Phase 1: Stub implementation */
    /* Phase 2: Implement terminal ioctls (TCGETS, TCSETS, TIOCGWINSZ) */
    /* Phase 3: Implement file ioctls (FIONREAD) */
    /* Phase 4: Device-specific ioctls */

    /* For now, return success for common ioctls */
    switch (request) {
        case TCGETS:
        case TCSETS:
        case TIOCGWINSZ:
        case FIONREAD:
            fut_printf("[IOCTL] Stubbed ioctl 0x%lx\n", request);
            return 0;
        default:
            fut_printf("[IOCTL] Unsupported ioctl 0x%lx\n", request);
            return -ENOTSUP;
    }
}
