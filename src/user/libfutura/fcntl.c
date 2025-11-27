// SPDX-License-Identifier: MPL-2.0

#include <stdarg.h>
#include <errno.h>

#include <user/futura_posix.h>
#include <user/sys.h>

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
