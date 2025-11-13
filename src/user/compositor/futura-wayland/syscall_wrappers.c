/* SPDX-License-Identifier: MPL-2.0
 *
 * Direct syscall wrappers for Wayland compositor
 *
 * x86-64: Override weak symbols to use int 0x80 syscalls instead of SYSCALL,
 *         bypassing QEMU's SYSCALL instruction emulation limitations.
 * ARM64:  Override weak symbols to use SVC syscalls with proper ARM64 ABI
 *         (X8=syscall number, X0-X7=arguments, X0=return value).
 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <stdarg.h>
#include <errno.h>

/* Forward declarations for debug helpers */
static void debug_write(const char *msg);
static void debug_write_int(long num);
static const char *strerror_simple(int err);

#define SYS_OPEN 2
#define SYS_SOCKET 41
#define SYS_BIND 49
#define SYS_LISTEN 50
#define SYS_CONNECT 42
#define SYS_EPOLL_CTL 233

#if defined(__x86_64__)

/* x86-64: Direct int 0x80 syscall helpers - QEMU bug workaround
 * QEMU's int 0x80 in 64-bit mode reads from x86_64 ABI registers (RDI/RSI/RDX)
 * instead of i386 ABI registers (EBX/ECX/EDX), so we use RDI/RSI/RDX */
static inline long int80_open(const char *pathname, int flags, mode_t mode) {
    long result;
    __asm__ __volatile__ (
        "int $0x80"
        : "=a" (result)
        : "a" (SYS_OPEN), "D" ((long)pathname), "S" (flags), "d" (mode)
        : "memory", "rcx", "r11"
    );
    return result;
}

static inline long int80_socket(int domain, int type, int protocol) {
    long result;
    __asm__ __volatile__ (
        "int $0x80"
        : "=a" (result)
        : "a" (SYS_SOCKET), "D" (domain), "S" (type), "d" (protocol)
        : "memory", "rcx", "r11"
    );
    return result;
}

static inline long int80_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    long result;
    __asm__ __volatile__ (
        "int $0x80"
        : "=a" (result)
        : "a" (SYS_BIND), "D" (sockfd), "S" ((long)addr), "d" (addrlen)
        : "memory", "rcx", "r11"
    );
    return result;
}

static inline long int80_listen(int sockfd, int backlog) {
    long result;
    __asm__ __volatile__ (
        "int $0x80"
        : "=a" (result)
        : "a" (SYS_LISTEN), "D" (sockfd), "S" (backlog)
        : "memory", "rcx", "r11"
    );
    return result;
}

static inline long int80_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    long result;
    __asm__ __volatile__ (
        "int $0x80"
        : "=a" (result)
        : "a" (SYS_CONNECT), "D" (sockfd), "S" ((long)addr), "d" (addrlen)
        : "memory", "rcx", "r11"
    );
    return result;
}

static inline long int80_epoll_ctl(int epfd, int op, int fd, void *event) {
    long result;
    __asm__ __volatile__ (
        "int $0x80"
        : "=a" (result)
        : "a" (SYS_EPOLL_CTL), "D" (epfd), "S" (op), "d" (fd), "c" ((long)event)
        : "memory", "r11"
    );
    return result;
}

static inline long int80_fcntl(int fd, int cmd, long arg) {
    long result;
    __asm__ __volatile__ (
        "int $0x80"
        : "=a" (result)
        : "a" (72), "D" (fd), "S" (cmd), "d" (arg)
        : "memory", "rcx", "r11"
    );
    return result;
}

static inline long int80_unlink(const char *pathname) {
    long result;
    __asm__ __volatile__ (
        "int $0x80"
        : "=a" (result)
        : "a" (87), "D" ((long)pathname)
        : "memory", "rcx", "r11"
    );
    return result;
}

static inline long int80_chmod(const char *pathname, mode_t mode) {
    long result;
    __asm__ __volatile__ (
        "int $0x80"
        : "=a" (result)
        : "a" (90), "D" ((long)pathname), "S" (mode)
        : "memory", "rcx", "r11"
    );
    return result;
}

static inline long int80_fchmod(int fd, mode_t mode) {
    long result;
    __asm__ __volatile__ (
        "int $0x80"
        : "=a" (result)
        : "a" (91), "D" (fd), "S" (mode)
        : "memory", "rcx", "r11"
    );
    return result;
}

#elif defined(__aarch64__)

/* ARM64: Direct SVC syscall helpers
 * ARM64 EABI: X8=syscall number, X0-X7=arguments, X0=return value */

static inline long svc_open(const char *pathname, int flags, mode_t mode) {
    register long x0 asm("x0") = (long)pathname;
    register long x1 asm("x1") = flags;
    register long x2 asm("x2") = mode;
    register long x8 asm("x8") = SYS_OPEN;

    __asm__ __volatile__ (
        "svc #0"
        : "+r" (x0)
        : "r" (x1), "r" (x2), "r" (x8)
        : "memory"
    );
    return x0;
}

static inline long svc_socket(int domain, int type, int protocol) {
    register long x0 asm("x0") = domain;
    register long x1 asm("x1") = type;
    register long x2 asm("x2") = protocol;
    register long x8 asm("x8") = SYS_SOCKET;

    __asm__ __volatile__ (
        "svc #0"
        : "+r" (x0)
        : "r" (x1), "r" (x2), "r" (x8)
        : "memory"
    );
    return x0;
}

static inline long svc_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    register long x0 asm("x0") = sockfd;
    register long x1 asm("x1") = (long)addr;
    register long x2 asm("x2") = addrlen;
    register long x8 asm("x8") = SYS_BIND;

    __asm__ __volatile__ (
        "svc #0"
        : "+r" (x0)
        : "r" (x1), "r" (x2), "r" (x8)
        : "memory"
    );
    return x0;
}

static inline long svc_listen(int sockfd, int backlog) {
    register long x0 asm("x0") = sockfd;
    register long x1 asm("x1") = backlog;
    register long x8 asm("x8") = SYS_LISTEN;

    __asm__ __volatile__ (
        "svc #0"
        : "+r" (x0)
        : "r" (x1), "r" (x8)
        : "memory"
    );
    return x0;
}

static inline long svc_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    register long x0 asm("x0") = sockfd;
    register long x1 asm("x1") = (long)addr;
    register long x2 asm("x2") = addrlen;
    register long x8 asm("x8") = SYS_CONNECT;

    __asm__ __volatile__ (
        "svc #0"
        : "+r" (x0)
        : "r" (x1), "r" (x2), "r" (x8)
        : "memory"
    );
    return x0;
}

static inline long svc_epoll_ctl(int epfd, int op, int fd, void *event) {
    register long x0 asm("x0") = epfd;
    register long x1 asm("x1") = op;
    register long x2 asm("x2") = fd;
    register long x3 asm("x3") = (long)event;
    register long x8 asm("x8") = SYS_EPOLL_CTL;

    __asm__ __volatile__ (
        "svc #0"
        : "+r" (x0)
        : "r" (x1), "r" (x2), "r" (x3), "r" (x8)
        : "memory"
    );
    return x0;
}

static inline long svc_fcntl(int fd, int cmd, long arg) {
    register long x0 asm("x0") = fd;
    register long x1 asm("x1") = cmd;
    register long x2 asm("x2") = arg;
    register long x8 asm("x8") = 72;  /* SYS_fcntl */

    __asm__ __volatile__ (
        "svc #0"
        : "+r" (x0)
        : "r" (x1), "r" (x2), "r" (x8)
        : "memory"
    );
    return x0;
}

static inline long svc_unlink(const char *pathname) {
    register long x0 asm("x0") = (long)pathname;
    register long x8 asm("x8") = 87;  /* SYS_unlink */

    __asm__ __volatile__ (
        "svc #0"
        : "+r" (x0)
        : "r" (x8)
        : "memory"
    );
    return x0;
}

static inline long svc_chmod(const char *pathname, mode_t mode) {
    register long x0 asm("x0") = (long)pathname;
    register long x1 asm("x1") = mode;
    register long x8 asm("x8") = 90;  /* SYS_chmod */

    __asm__ __volatile__ (
        "svc #0"
        : "+r" (x0)
        : "r" (x1), "r" (x8)
        : "memory"
    );
    return x0;
}

static inline long svc_fchmod(int fd, mode_t mode) {
    register long x0 asm("x0") = fd;
    register long x1 asm("x1") = mode;
    register long x8 asm("x8") = 91;  /* SYS_fchmod */

    __asm__ __volatile__ (
        "svc #0"
        : "+r" (x0)
        : "r" (x1), "r" (x8)
        : "memory"
    );
    return x0;
}

#endif  /* __x86_64__ or __aarch64__ */

/* Architecture-agnostic syscall macros */
#if defined(__x86_64__)
#define SYSCALL_OPEN(p, f, m)          int80_open(p, f, m)
#define SYSCALL_SOCKET(d, t, p)        int80_socket(d, t, p)
#define SYSCALL_BIND(s, a, l)          int80_bind(s, a, l)
#define SYSCALL_LISTEN(s, b)           int80_listen(s, b)
#define SYSCALL_CONNECT(s, a, l)       int80_connect(s, a, l)
#define SYSCALL_EPOLL_CTL(e, o, f, ev) int80_epoll_ctl(e, o, f, ev)
#define SYSCALL_FCNTL(f, c, a)         int80_fcntl(f, c, a)
#define SYSCALL_UNLINK(p)              int80_unlink(p)
#define SYSCALL_CHMOD(p, m)            int80_chmod(p, m)
#define SYSCALL_FCHMOD(f, m)           int80_fchmod(f, m)
#elif defined(__aarch64__)
#define SYSCALL_OPEN(p, f, m)          svc_open(p, f, m)
#define SYSCALL_SOCKET(d, t, p)        svc_socket(d, t, p)
#define SYSCALL_BIND(s, a, l)          svc_bind(s, a, l)
#define SYSCALL_LISTEN(s, b)           svc_listen(s, b)
#define SYSCALL_CONNECT(s, a, l)       svc_connect(s, a, l)
#define SYSCALL_EPOLL_CTL(e, o, f, ev) svc_epoll_ctl(e, o, f, ev)
#define SYSCALL_FCNTL(f, c, a)         svc_fcntl(f, c, a)
#define SYSCALL_UNLINK(p)              svc_unlink(p)
#define SYSCALL_CHMOD(p, m)            svc_chmod(p, m)
#define SYSCALL_FCHMOD(f, m)           svc_fchmod(f, m)
#endif

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

/* Helper: convert number to string for debug output */
static void debug_write_int(long num) {
    char buf[32];
    int len = 0;

    if (num < 0) {
        buf[len++] = '-';
        num = -num;
    }

    /* Convert to string */
    char temp[32];
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
            errno = EBADF;
            result = -1;
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
        /* For other syscalls, return ENOSYS */
        errno = ENOSYS;
        result = -1;
        break;
    }

    va_end(ap);
    if (result < 0) {
        errno = -result;
        return -1;
    }
    return result;
}
