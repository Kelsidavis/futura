/* SPDX-License-Identifier: MPL-2.0
 *
 * Direct syscall wrappers for Wayland compositor
 *
 * Uses portable syscall interface from ../libfutura/syscall_portable.h
 * for x86-64 (int $0x80) and ARM64 (svc #0) syscall dispatch.
 *
 * x86-64: Workaround for QEMU's SYSCALL instruction emulation limitations
 *         by using int 0x80 syscalls instead.
 * ARM64:  Uses standard SVC syscalls with proper ARM64 ABI
 *         (X8=syscall number, X0-X7=arguments, X0=return value).
 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <stdarg.h>
#include <errno.h>
#include "timerfd_internal.h"

/* Portable syscall interface - provides architecture-agnostic wrapper functions */
#include "../libfutura/syscall_portable.h"

/* Forward declarations for debug helpers */
static void debug_write(const char *msg);
static void debug_write_int(long num);
static const char *strerror_simple(int err);

/* Syscall number constants - use portable definitions where available */
#define SYS_OPEN      (__NR_open)
#define SYS_SOCKET    (__NR_socket)
#define SYS_BIND      (__NR_bind)
#define SYS_LISTEN    (__NR_listen)
#define SYS_CONNECT   (__NR_connect)
#define SYS_EPOLL_CTL (__NR_epoll_ctl)
#define SYS_FCNTL     (__NR_fcntl)
#define SYS_UNLINK    (__NR_unlink)
#define SYS_CHMOD     (__NR_chmod)
#define SYS_FCHMOD    (__NR_fchmod)

/* Architecture-agnostic syscall dispatch using portable wrappers */
#define SYSCALL_OPEN(p, f, m)          syscall3(__NR_open, (long)(p), (long)(f), (long)(m))
#define SYSCALL_SOCKET(d, t, p)        syscall3(__NR_socket, (long)(d), (long)(t), (long)(p))
#define SYSCALL_BIND(s, a, l)          syscall3(__NR_bind, (long)(s), (long)(a), (long)(l))
#define SYSCALL_LISTEN(s, b)           syscall2(__NR_listen, (long)(s), (long)(b))
#define SYSCALL_CONNECT(s, a, l)       syscall3(__NR_connect, (long)(s), (long)(a), (long)(l))
#define SYSCALL_EPOLL_CTL(e, o, f, ev) syscall4(__NR_epoll_ctl, (long)(e), (long)(o), (long)(f), (long)(ev))
#define SYSCALL_FCNTL(f, c, a)         syscall3(__NR_fcntl, (long)(f), (long)(c), (long)(a))
#define SYSCALL_UNLINK(p)              syscall1(__NR_unlink, (long)(p))
#define SYSCALL_CHMOD(p, m)            syscall2(__NR_chmod, (long)(p), (long)(m))
#define SYSCALL_FCHMOD(f, m)           syscall2(__NR_fchmod, (long)(f), (long)(m))

/* Linker-wrapped flock() - always succeeds (single-process OS) */
int __wrap_flock(int fd, int operation) {
    (void)fd;
    (void)operation;
    /* Single-process OS: file locking always succeeds */
    errno = 0;  /* Clear errno on success */
    return 0;
}

/* Linker-wrapped close() - ensure errno is not corrupted */
int __wrap_close(int fd) {
    extern long syscall(long, ...);

    /* Call kernel close */
    long result = syscall(3, fd);  /* SYS_close = 3 */

    if (result < 0) {
        errno = -result;
        return -1;
    }

    /* Ensure errno is cleared on successful close */
    errno = 0;
    return 0;
}

/* Linker-wrapped open64() */
int __wrap_open64(const char *pathname, int flags, ...) {
    va_list ap;
    mode_t mode = 0;

    if (flags & (O_CREAT | O_TMPFILE)) {
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }

    long result = SYSCALL_OPEN(pathname, flags, mode);
    if (result < 0) {
        errno = -result;
        return -1;
    }
    errno = 0;  /* Clear errno on success */
    return (int)result;
}

/* Linker-wrapped open() */
int __wrap_open(const char *pathname, int flags, ...) {
    va_list ap;
    mode_t mode = 0;

    if (flags & (O_CREAT | O_TMPFILE)) {
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }

    long result = SYSCALL_OPEN(pathname, flags, mode);
    if (result < 0) {
        errno = -result;
        return -1;
    }
    errno = 0;  /* Clear errno on success */
    return (int)result;
}

/* Linker-wrapped openat() - THIS IS THE KEY ONE! */
int __wrap_openat(int dirfd, const char *pathname, int flags, ...) {
    va_list ap;
    mode_t mode = 0;

    if (flags & (O_CREAT | O_TMPFILE)) {
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }

    /* Only support AT_FDCWD - convert to regular open() */
    if (dirfd != -100) { /* AT_FDCWD */
        errno = EBADF;
        return -1;
    }

    long result = SYSCALL_OPEN(pathname, flags, mode);
    if (result < 0) {
        errno = -result;
        return -1;
    }
    errno = 0;  /* Clear errno on success */
    return (int)result;
}

/* Linker-wrapped socket() */
int __wrap_socket(int domain, int type, int protocol) {
    debug_write("[WRAP_SOCKET] socket(");
    debug_write_int(domain);
    debug_write(", ");
    debug_write_int(type & 0xF);
    debug_write(", ");
    debug_write_int(protocol);
    debug_write(")\n");

    /* Strip SOCK_CLOEXEC and SOCK_NONBLOCK flags - kernel doesn't support them */
    int type_masked = type & 0xF;  /* Keep only the socket type bits */
    long result = SYSCALL_SOCKET(domain, type_masked, protocol);
    if (result < 0) {
        int err = -(int)result;
        errno = err;
        debug_write("[WRAP_SOCKET] FAILED: ");
        debug_write(strerror_simple(err));
        debug_write(" (errno=");
        debug_write_int(err);
        debug_write(")\n");
        return -1;
    }
    errno = 0;  /* Clear errno on success */
    debug_write("[WRAP_SOCKET] SUCCESS: fd=");
    debug_write_int(result);
    debug_write("\n");
    return (int)result;
}

/* Linker-wrapped bind() */
int __wrap_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    /* Note: debug helpers are defined later in file */
    debug_write("[WRAP_BIND] bind(fd=");
    debug_write_int(sockfd);
    debug_write(", addr=");
    debug_write_int((long)addr);
    debug_write(", addrlen=");
    debug_write_int(addrlen);
    debug_write(")\n");

    long result = SYSCALL_BIND(sockfd, addr, addrlen);
    if (result < 0) {
        int err = -(int)result;
        errno = err;
        debug_write("[WRAP_BIND] FAILED: ");
        debug_write(strerror_simple(err));
        debug_write(" (errno=");
        debug_write_int(err);
        debug_write(")\n");
        return -1;
    }
    errno = 0;  /* Clear errno on success */
    debug_write("[WRAP_BIND] SUCCESS\n");
    return 0;
}

/* Helper: convert number to string for debug output
 * NOTE: Using static buffers to avoid stack allocation - debugging a stack crash */
static void debug_write_int(long num) {
    static char buf[32];
    static char temp[32];
    int len = 0;

    if (num < 0) {
        buf[len++] = '-';
        num = -num;
    }

    /* Convert to string */
    int tlen = 0;
    long val = num;
    do {
        temp[tlen++] = '0' + (val % 10);
        val /= 10;
    } while (val > 0);

    /* Reverse */
    while (tlen > 0) {
        buf[len++] = temp[--tlen];
    }
    buf[len] = 0;

    debug_write(buf);
}

/* Helper: convert errno to string name */
static const char *strerror_simple(int err) {
    switch (err) {
        case 1: return "EPERM";
        case 2: return "ENOENT";
        case 3: return "ESRCH";
        case 4: return "EINTR";
        case 5: return "EIO";
        case 6: return "ENXIO";
        case 12: return "ENOMEM";
        case 13: return "EACCES";
        case 14: return "EFAULT";
        case 16: return "EBUSY";
        case 17: return "EEXIST";
        case 19: return "ENODEV";
        case 20: return "ENOTDIR";
        case 21: return "EISDIR";
        case 22: return "EINVAL";
        case 28: return "ENOSPC";
        case 39: return "ENOTSOCK";
        case 48: return "EADDRINUSE";
        case 49: return "EADDRNOTAVAIL";
        case 98: return "EADDRINUSE";
        case 111: return "ECONNREFUSED";
        case 113: return "EHOSTUNREACH";
        case 115: return "EINPROGRESS";
        default: return "UNKNOWN";
    }
}

/* Direct write for debugging without errno corruption */
static void debug_write(const char *msg) {
    /* Try to write to console via stdout */
    extern long syscall(long, ...);
    size_t len = 0;
    while (msg[len]) len++;

    /* Write to fd 1 (stdout) instead of stderr */
    long result = syscall(1, 1, msg, len);  /* SYS_write = 1, stdout = 1 */
    (void)result;  /* Suppress unused warning */
}

/* Linker-wrapped listen() */
int __wrap_listen(int sockfd, int backlog) {
    debug_write("[WRAP_LISTEN] listen(fd=");
    debug_write_int(sockfd);
    debug_write(", backlog=");
    debug_write_int(backlog);
    debug_write(")\n");

    long result = SYSCALL_LISTEN(sockfd, backlog);

    if (result < 0) {
        int err = -(int)result;
        errno = err;
        debug_write("[WRAP_LISTEN] FAILED: ");
        debug_write(strerror_simple(err));
        debug_write(" (errno=");
        debug_write_int(err);
        debug_write(")\n");
        return -1;
    }
    /* Clear errno on success - workaround for stale errno issues */
    errno = 0;
    debug_write("[WRAP_LISTEN] SUCCESS\n");
    return 0;
}

/* Linker-wrapped epoll_ctl() - used by Wayland event loop */
int __wrap_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {
    debug_write("[WRAP_EPOLL_CTL] epoll_ctl(epfd=");
    debug_write_int(epfd);
    debug_write(", op=");
    debug_write_int(op);
    debug_write(", fd=");
    debug_write_int(fd);
    debug_write(")\n");

    if (__fut_timerfd_is_timer(fd)) {
        debug_write("[WRAP_EPOLL_CTL] timerfd bypassed\n");
        errno = 0;
        return 0;
    }

    long result = SYSCALL_EPOLL_CTL(epfd, op, fd, (void *)event);

    if (result < 0) {
        int err = -(int)result;
        errno = err;
        debug_write("[WRAP_EPOLL_CTL] FAILED: errno=");
        debug_write_int(err);
        debug_write("\n");
        return -1;
    }
    errno = 0;  /* Clear errno on success */
    debug_write("[WRAP_EPOLL_CTL] SUCCESS\n");
    return 0;
}

/* Linker-wrapped connect() */
int __wrap_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    long result = SYSCALL_CONNECT(sockfd, addr, addrlen);
    if (result < 0) {
        errno = -result;
        return -1;
    }
    errno = 0;  /* Clear errno on success */
    return 0;
}

/* Linker-wrapped fcntl() */
int __wrap_fcntl(int fd, int cmd, ...) {
    va_list ap;
    va_start(ap, cmd);
    long arg = va_arg(ap, long);
    va_end(ap);

    debug_write("[WRAP_FCNTL] Called\n");
    long result = SYSCALL_FCNTL(fd, cmd, arg);
    if (result < 0) {
        errno = -result;
        debug_write("[WRAP_FCNTL] Failed\n");
        return -1;
    }
    errno = 0;  /* Clear errno on success */
    debug_write("[WRAP_FCNTL] Success\n");
    return (int)result;
}

/* Linker-wrapped unlink() */
int __wrap_unlink(const char *pathname) {
    debug_write("[WRAP_UNLINK] Called\n");
    long result = SYSCALL_UNLINK(pathname);
    if (result < 0) {
        errno = -result;
        debug_write("[WRAP_UNLINK] Failed\n");
        return -1;
    }
    errno = 0;  /* Clear errno on success */
    debug_write("[WRAP_UNLINK] Success\n");
    return 0;
}

/* Linker-wrapped chmod() */
int __wrap_chmod(const char *pathname, mode_t mode) {
    debug_write("[WRAP_CHMOD] Called\n");
    long result = SYSCALL_CHMOD(pathname, mode);
    if (result < 0) {
        errno = -result;
        debug_write("[WRAP_CHMOD] Failed\n");
        return -1;
    }
    errno = 0;  /* Clear errno on success */
    debug_write("[WRAP_CHMOD] Success\n");
    return 0;
}

/* Linker-wrapped fchmod() */
int __wrap_fchmod(int fd, mode_t mode) {
    debug_write("[WRAP_FCHMOD] Called\n");
    long result = SYSCALL_FCHMOD(fd, mode);
    if (result < 0) {
        errno = -result;
        debug_write("[WRAP_FCHMOD] Failed\n");
        return -1;
    }
    errno = 0;  /* Clear errno on success */
    debug_write("[WRAP_FCHMOD] Success\n");
    return 0;
}

/* Linker-wrapped syscall() - intercept all glibc syscall() calls */
long __wrap_syscall(long number, ...) {
    va_list ap;
    va_start(ap, number);
    long result = -1;

    /* Handle syscalls that need translation */
    switch (number) {
    case 2: { /* SYS_open */
        const char *pathname = va_arg(ap, const char *);
        int flags = va_arg(ap, int);
        mode_t mode = va_arg(ap, mode_t);
        result = SYSCALL_OPEN(pathname, flags, mode);
        break;
    }
    case 257: { /* SYS_openat */
        int dirfd = va_arg(ap, int);
        const char *pathname = va_arg(ap, const char *);
        int flags = va_arg(ap, int);
        mode_t mode = va_arg(ap, mode_t);
        /* Convert openat(AT_FDCWD, ...) to open(...) */
        if (dirfd == -100) { /* AT_FDCWD */
            result = SYSCALL_OPEN(pathname, flags, mode);
        } else {
            result = -EBADF;
        }
        break;
    }
    case 41: { /* SYS_socket */
        int domain = va_arg(ap, int);
        int type = va_arg(ap, int);
        int protocol = va_arg(ap, int);
        /* Strip SOCK_CLOEXEC and SOCK_NONBLOCK flags */
        int type_masked = type & 0xF;
        result = SYSCALL_SOCKET(domain, type_masked, protocol);
        break;
    }
    case 49: { /* SYS_bind */
        int sockfd = va_arg(ap, int);
        const struct sockaddr *addr = va_arg(ap, const struct sockaddr *);
        socklen_t addrlen = va_arg(ap, socklen_t);
        result = SYSCALL_BIND(sockfd, addr, addrlen);
        break;
    }
    case 50: { /* SYS_listen */
        debug_write("[WRAP_SYSCALL listen] Called\n");
        int sockfd = va_arg(ap, int);
        int backlog = va_arg(ap, int);
        result = SYSCALL_LISTEN(sockfd, backlog);
        if (result >= 0) {
            errno = 0;  /* Clear errno on success */
            debug_write("[WRAP_SYSCALL listen] Success, errno cleared\n");
        } else {
            debug_write("[WRAP_SYSCALL listen] Failed\n");
        }
        break;
    }
    case 42: { /* SYS_connect */
        int sockfd = va_arg(ap, int);
        const struct sockaddr *addr = va_arg(ap, const struct sockaddr *);
        socklen_t addrlen = va_arg(ap, socklen_t);
        result = SYSCALL_CONNECT(sockfd, addr, addrlen);
        break;
    }
    case 72: { /* SYS_fcntl */
        debug_write("[WRAP_SYSCALL fcntl] Called\n");
        int fd = va_arg(ap, int);
        int cmd = va_arg(ap, int);
        long arg = va_arg(ap, long);
        result = SYSCALL_FCNTL(fd, cmd, arg);
        if (result >= 0) {
            errno = 0;
            debug_write("[WRAP_SYSCALL fcntl] Success\n");
        } else {
            debug_write("[WRAP_SYSCALL fcntl] Failed\n");
        }
        break;
    }
    case 87: { /* SYS_unlink */
        debug_write("[WRAP_SYSCALL unlink] Called\n");
        const char *pathname = va_arg(ap, const char *);
        result = SYSCALL_UNLINK(pathname);
        if (result >= 0) {
            errno = 0;
            debug_write("[WRAP_SYSCALL unlink] Success\n");
        } else {
            debug_write("[WRAP_SYSCALL unlink] Failed\n");
        }
        break;
    }
    case 90: { /* SYS_chmod */
        debug_write("[WRAP_SYSCALL chmod] Called\n");
        const char *pathname = va_arg(ap, const char *);
        mode_t mode = va_arg(ap, mode_t);
        result = SYSCALL_CHMOD(pathname, mode);
        if (result >= 0) {
            errno = 0;
            debug_write("[WRAP_SYSCALL chmod] Success\n");
        } else {
            debug_write("[WRAP_SYSCALL chmod] Failed\n");
        }
        break;
    }
    case 91: { /* SYS_fchmod */
        debug_write("[WRAP_SYSCALL fchmod] Called\n");
        int fd = va_arg(ap, int);
        mode_t mode = va_arg(ap, mode_t);
        result = SYSCALL_FCHMOD(fd, mode);
        if (result >= 0) {
            errno = 0;
            debug_write("[WRAP_SYSCALL fchmod] Success\n");
        } else {
            debug_write("[WRAP_SYSCALL fchmod] Failed\n");
        }
        break;
    }
    default:
        /* Fall back to raw syscall with up to 6 args */
        {
            long a1 = va_arg(ap, long);
            long a2 = va_arg(ap, long);
            long a3 = va_arg(ap, long);
            long a4 = va_arg(ap, long);
            long a5 = va_arg(ap, long);
            long a6 = va_arg(ap, long);
            result = syscall6(number, a1, a2, a3, a4, a5, a6);
        }
        break;
    }

    va_end(ap);
    if (result < 0) {
        errno = -result;
        return -1;
    }
    return result;
}
