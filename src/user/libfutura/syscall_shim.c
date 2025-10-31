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
        /* Make the actual int 0x80 syscall to reach the kernel handler */
        __asm__ volatile("int $0x80" : "=a"(result) : "a"(SYS_open), "b"(pathname), "c"(flags), "d"(mode) : "cc", "memory");
        break;
    }
    case SYS_openat: {
        int dirfd = va_arg(ap, int);
        const char *pathname = va_arg(ap, const char *);
        int flags = va_arg(ap, int);
        int mode = va_arg(ap, int);

        /* Workaround for SYSCALL instruction not being invoked on x86_64
         * When dirfd is AT_FDCWD (current directory), we can convert to open()
         * which uses int 0x80 and works properly.
         *
         * For now, we only support AT_FDCWD. Other file descriptors would
         * require full openat() kernel support.
         */
        if (dirfd != AT_FDCWD) {
            errno = EBADF;
            result = -1;
        } else {
            /* Make the actual int 0x80 syscall with SYS_open
             * open(pathname, flags, mode) is equivalent to
             * openat(AT_FDCWD, pathname, flags, mode)
             */
            __asm__ volatile("int $0x80" : "=a"(result) : "a"(SYS_open), "b"(pathname), "c"(flags), "d"(mode) : "cc", "memory");
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

/* Wrapper for open() to handle unsupported flags */
int open(const char *pathname, int flags, ...) {
    va_list ap;
    mode_t mode = 0;

    if (flags & (O_CREAT | O_TMPFILE)) {
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }

    extern void fut_printf(const char *, ...);
    fut_printf("[OPEN-WRAPPER] pathname=%s flags=0x%x mode=0%o\n", pathname, flags, mode);

    long result = syscall(SYS_open, pathname, flags, mode);

    fut_printf("[OPEN-WRAPPER] syscall returned %ld\n", result);

    return (int)result;
}

/* Wrapper for open64() - same as open() for our purposes */
int open64(const char *pathname, int flags, ...) {
    va_list ap;
    mode_t mode = 0;

    if (flags & (O_CREAT | O_TMPFILE)) {
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }

    extern void fut_printf(const char *, ...);
    fut_printf("[OPEN64-WRAPPER] pathname=%s flags=0x%x mode=0%o\n", pathname, flags, mode);

    long result = syscall(SYS_open, pathname, flags, mode);

    fut_printf("[OPEN64-WRAPPER] syscall returned %ld\n", result);

    return (int)result;
}

#if defined(__GNUC__) && !defined(__APPLE__)
__asm__(".symver syscall,syscall@GLIBC_2.2.5");
#endif
