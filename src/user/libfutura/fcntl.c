// SPDX-License-Identifier: MPL-2.0

#include <stdarg.h>
#include <errno.h>

#include <user/futura_posix.h>
#include <user/sys.h>
#include "timerfd_internal.h"

static long fcntl_syscall(int fd, int cmd, long arg) {
    return sys_fcntl_call(fd, cmd, arg);
}

int fcntl(int fd, int cmd, ...) {
    va_list ap;
    va_start(ap, cmd);

    long arg = 0;
    switch (cmd) {
    case F_GETFD:
    case F_GETFL:
#ifdef F_GET_SEALS
    case F_GET_SEALS:
#endif
        /* No variadic argument required */
        break;
    default:
        arg = va_arg(ap, long);
        break;
    }

    va_end(ap);

    long timerfd_ret = 0;
    if (__fut_timerfd_is_timer(fd)) {
        bool handled = false;
        switch (cmd) {
        case F_GETFD:
        case F_GETFL:
            timerfd_ret = 0;
            handled = true;
            break;
        case F_SETFD:
        case F_SETFL:
            timerfd_ret = 0;
            handled = true;
            break;
        case F_DUPFD:
        case F_DUPFD_CLOEXEC:
            if (arg < 0 || arg > fd) {
                errno = EINVAL;
                return -1;
            }
            timerfd_ret = fd;
            handled = true;
            break;
        default:
            handled = false;
            break;
        }
        if (handled) {
            errno = 0;
            return (int)timerfd_ret;
        }
    }

    long ret = fcntl_syscall(fd, cmd, arg);
    if (ret < 0) {
        errno = (int)-ret;
        return -1;
    }
    errno = 0;
    return (int)ret;
}

int fcntl64(int fd, int cmd, ...) {
    va_list ap;
    va_start(ap, cmd);
    long arg = va_arg(ap, long);
    va_end(ap);
    return fcntl(fd, cmd, arg);
}
