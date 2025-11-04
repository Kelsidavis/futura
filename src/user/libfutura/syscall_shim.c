// SPDX-License-Identifier: MPL-2.0

#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>

#include <user/futura_posix.h>
#include <user/sys/syscall.h>

/* Architecture-specific syscall ABI */
#if defined(__x86_64__)
#include <platform/x86_64/syscall_abi.h>
#elif defined(__aarch64__) || defined(__arm64__)
#include <platform/arm64/syscall_abi.h>
#else
#error "Unsupported architecture"
#endif

/* AT_FDCWD: Use current working directory for path */
#ifndef AT_FDCWD
#define AT_FDCWD -100
#endif

/* x86-64 syscall numbers */
#define SYS_open 2

/* File flags */
#ifndef O_DIRECTORY
#define O_DIRECTORY 0200000
#endif

/* O_TMPFILE: Create unnamed temporary file */
#ifndef O_TMPFILE
#define O_TMPFILE (020000000 | O_DIRECTORY)
#endif

static long ret_enosys(void) {
    errno = ENOSYS;
    return -1;
}

__attribute__((weak))
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
    case SYS_open: {
        const char *pathname = va_arg(ap, const char *);
        int flags = va_arg(ap, int);
        int mode = va_arg(ap, int);
        /* Architecture-agnostic syscall invocation */
        result = __SYSCALL_3(SYS_open, pathname, flags, mode);
        break;
    }
    case SYS_openat: {
        int dirfd = va_arg(ap, int);
        const char *pathname = va_arg(ap, const char *);
        int flags = va_arg(ap, int);
        int mode = va_arg(ap, int);

        /* When dirfd is AT_FDCWD (current directory), convert to open() */
        if (dirfd != AT_FDCWD) {
            errno = EBADF;
            result = -1;
        } else {
            /* Architecture-agnostic syscall: open(pathname, flags, mode) */
            result = __SYSCALL_3(SYS_open, pathname, flags, mode);
        }
        break;
    }
    case 73: { /* SYS_flock - file locking stub */
        int fd = va_arg(ap, int);
        int operation = va_arg(ap, int);
        (void)fd;
        (void)operation;
        /* Single-process OS: file locking always succeeds */
        result = 0;
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
