// SPDX-License-Identifier: MPL-2.0

#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>

#include <user/futura_posix.h>
#include <user/sys/syscall.h>

/* AT_FDCWD: Use current working directory for path */
#ifndef AT_FDCWD
#define AT_FDCWD -100
#endif

static long ret_enosys(void) {
    errno = ENOSYS;
    return -1;
}

long syscall(long number, ...) {
    va_list ap;
    va_start(ap, number);
    long result = -1;

    switch (number) {
    case SYS_getpid:
    case SYS_getppid:
        result = 1; /* single-process stub */
        break;
    case SYS_getuid:
    case SYS_geteuid:
    case SYS_getgid:
    case SYS_getegid:
        result = 0;
        break;
    case SYS_gettid:
        result = 1;
        break;
    case SYS_getrandom:
        result = ret_enosys();
        break;
    case SYS_pipe2:
        result = ret_enosys();
        break;
    case SYS_dup3: {
        int oldfd = va_arg(ap, int);
        int newfd = va_arg(ap, int);
        int flags = va_arg(ap, int);
        (void)newfd;
        (void)flags;
        (void)oldfd;
        result = ret_enosys();
        break;
    }
    case SYS_close_range:
        result = ret_enosys();
        break;
    case SYS_openat: {
        int dirfd = va_arg(ap, int);
        const char *pathname = va_arg(ap, const char *);
        int flags = va_arg(ap, int);
        int mode = va_arg(ap, int);
        /* For now, only support AT_FDCWD (current directory) */
        if (dirfd != AT_FDCWD) {
            errno = EBADF;
            result = -1;
        } else {
            /* Forward to the POSIX wrapper */
            result = open(pathname, flags, mode);
        }
        break;
    }
    default:
        result = ret_enosys();
        break;
    }

    va_end(ap);
    return result;
}

#if defined(__GNUC__) && !defined(__APPLE__)
__asm__(".symver syscall,syscall@GLIBC_2.2.5");
#endif
