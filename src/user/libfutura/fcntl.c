// SPDX-License-Identifier: MPL-2.0

#include <stdarg.h>
#include <errno.h>

#include <user/futura_posix.h>

#include "fd.h"

static int handle_getfd(int fd) {
    int clo = fd_get_cloexec(fd);
    if (clo < 0) {
        errno = EBADF;
        return -1;
    }
    return clo;
}

static int handle_setfd(int fd, int arg) {
    if (fd_set_cloexec(fd, (arg & FD_CLOEXEC) != 0) < 0) {
        errno = EBADF;
        return -1;
    }
    return 0;
}

static int handle_getfl(int fd) {
    int flags = 0;
    if (fd_get_flags(fd, &flags) < 0) {
        errno = EBADF;
        return -1;
    }
    return flags;
}

static int handle_setfl(int fd, int arg) {
    int flags = 0;
    if (fd_get_flags(fd, &flags) < 0) {
        errno = EBADF;
        return -1;
    }
    int new_flags = flags;
    new_flags &= ~O_NONBLOCK;
    new_flags |= (arg & O_NONBLOCK);
    if (fd_set_flags(fd, new_flags) < 0) {
        errno = EBADF;
        return -1;
    }
    return 0;
}

int fcntl(int fd, int cmd, ...) {
    va_list ap;
    va_start(ap, cmd);

    int result = -1;

    switch (cmd) {
    case F_GETFD:
        result = handle_getfd(fd);
        break;
    case F_SETFD:
        result = handle_setfd(fd, va_arg(ap, int));
        break;
    case F_GETFL:
        result = handle_getfl(fd);
        break;
    case F_SETFL:
        result = handle_setfl(fd, va_arg(ap, int));
        break;
    case F_DUPFD:
    case F_DUPFD_CLOEXEC: {
        int minfd = va_arg(ap, int);
        if (minfd < 0) {
            errno = EINVAL;
            result = -1;
            break;
        }
        int clo = (cmd == F_DUPFD_CLOEXEC) ? 1 : 0;
        result = fd_dup(fd, minfd, clo);
        break;
    }
    case F_GET_SEALS:
        result = 0;
        break;
    default:
        errno = EINVAL;
        result = -1;
        break;
    }

    va_end(ap);
    return result;
}

/* fcntl64 wrapper - aliases not supported on some toolchains */
int fcntl64(int fd, int cmd, ...) {
    va_list ap;
    va_start(ap, cmd);
    long arg = va_arg(ap, long);
    va_end(ap);
    return fcntl(fd, cmd, arg);
}
