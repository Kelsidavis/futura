/* SPDX-License-Identifier: MPL-2.0
 *
 * Direct syscall wrappers for Wayland compositor
 *
 * These override the weak symbols in libwayland-server to use int 0x80
 * syscalls instead of SYSCALL instruction, bypassing QEMU limitations.
 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdarg.h>
#include <errno.h>

/* Forward declaration for debug_write */
static void debug_write(const char *msg);

#define SYS_OPEN 2
#define SYS_SOCKET 41
#define SYS_BIND 49
#define SYS_LISTEN 50
#define SYS_CONNECT 42

/* Direct int 0x80 syscall helpers - QEMU bug workaround
 * QEMU's int 0x80 in 64-bit mode reads from x86_64 ABI registers (RDI/RSI/RDX)
 * instead of i386 ABI registers (EBX/ECX/EDX), so we use RDI/RSI/RDX */
static inline long int80_open(const char *pathname, int flags, mode_t mode) {
    register long _arg1 __asm__("rdi") = (long)pathname;
    register long _arg2 __asm__("rsi") = (long)flags;
    register long _arg3 __asm__("rdx") = (long)mode;
    register long _num __asm__("rax") = SYS_OPEN;
    __asm__ __volatile__ (
        "int $0x80"
        : "+r" (_num)
        : "r" (_arg1), "r" (_arg2), "r" (_arg3)
        : "memory"
    );
    return _num;
}

static inline long int80_socket(int domain, int type, int protocol) {
    register long _arg1 __asm__("rdi") = (long)domain;
    register long _arg2 __asm__("rsi") = (long)type;
    register long _arg3 __asm__("rdx") = (long)protocol;
    register long _num __asm__("rax") = SYS_SOCKET;
    __asm__ __volatile__ (
        "int $0x80"
        : "+r" (_num)
        : "r" (_arg1), "r" (_arg2), "r" (_arg3)
        : "memory"
    );
    return _num;
}

static inline long int80_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    register long _arg1 __asm__("rdi") = (long)sockfd;
    register long _arg2 __asm__("rsi") = (long)addr;
    register long _arg3 __asm__("rdx") = (long)addrlen;
    register long _num __asm__("rax") = SYS_BIND;
    __asm__ __volatile__ (
        "int $0x80"
        : "+r" (_num)
        : "r" (_arg1), "r" (_arg2), "r" (_arg3)
        : "memory"
    );
    return _num;
}

static inline long int80_listen(int sockfd, int backlog) {
    register long _arg1 __asm__("rdi") = (long)sockfd;
    register long _arg2 __asm__("rsi") = (long)backlog;
    register long _num __asm__("rax") = SYS_LISTEN;
    __asm__ __volatile__ (
        "int $0x80"
        : "+r" (_num)
        : "r" (_arg1), "r" (_arg2)
        : "memory"
    );
    return _num;
}

static inline long int80_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    register long _arg1 __asm__("rdi") = (long)sockfd;
    register long _arg2 __asm__("rsi") = (long)addr;
    register long _arg3 __asm__("rdx") = (long)addrlen;
    register long _num __asm__("rax") = SYS_CONNECT;
    __asm__ __volatile__ (
        "int $0x80"
        : "+r" (_num)
        : "r" (_arg1), "r" (_arg2), "r" (_arg3)
        : "memory"
    );
    return _num;
}

static inline long int80_fcntl(int fd, int cmd, long arg) {
    register long _arg1 __asm__("rdi") = (long)fd;
    register long _arg2 __asm__("rsi") = (long)cmd;
    register long _arg3 __asm__("rdx") = arg;
    register long _num __asm__("rax") = 72; /* SYS_fcntl */
    __asm__ __volatile__ (
        "int $0x80"
        : "+r" (_num)
        : "r" (_arg1), "r" (_arg2), "r" (_arg3)
        : "memory"
    );
    return _num;
}

static inline long int80_unlink(const char *pathname) {
    register long _arg1 __asm__("rdi") = (long)pathname;
    register long _num __asm__("rax") = 87; /* SYS_unlink */
    __asm__ __volatile__ (
        "int $0x80"
        : "+r" (_num)
        : "r" (_arg1)
        : "memory"
    );
    return _num;
}

static inline long int80_chmod(const char *pathname, mode_t mode) {
    register long _arg1 __asm__("rdi") = (long)pathname;
    register long _arg2 __asm__("rsi") = (long)mode;
    register long _num __asm__("rax") = 90; /* SYS_chmod */
    __asm__ __volatile__ (
        "int $0x80"
        : "+r" (_num)
        : "r" (_arg1), "r" (_arg2)
        : "memory"
    );
    return _num;
}

static inline long int80_fchmod(int fd, mode_t mode) {
    register long _arg1 __asm__("rdi") = (long)fd;
    register long _arg2 __asm__("rsi") = (long)mode;
    register long _num __asm__("rax") = 91; /* SYS_fchmod */
    __asm__ __volatile__ (
        "int $0x80"
        : "+r" (_num)
        : "r" (_arg1), "r" (_arg2)
        : "memory"
    );
    return _num;
}

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

    long result = int80_open(pathname, flags, mode);
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

    long result = int80_open(pathname, flags, mode);
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

    long result = int80_open(pathname, flags, mode);
    if (result < 0) {
        errno = -result;
        return -1;
    }
    errno = 0;  /* Clear errno on success */
    return (int)result;
}

/* Linker-wrapped socket() */
int __wrap_socket(int domain, int type, int protocol) {
    debug_write("[WRAP_SOCKET] Called with domain=");
    if (domain == 1) debug_write("AF_UNIX");
    else if (domain == 2) debug_write("AF_INET");
    else debug_write("UNKNOWN");
    debug_write(" type=");
    if (type == 1) debug_write("SOCK_STREAM");
    else if (type == 2) debug_write("SOCK_DGRAM");
    else debug_write("MASKED");
    debug_write("\n");

    /* Strip SOCK_CLOEXEC and SOCK_NONBLOCK flags - kernel doesn't support them */
    int type_masked = type & 0xF;  /* Keep only the socket type bits */
    long result = int80_socket(domain, type_masked, protocol);
    if (result < 0) {
        errno = -result;
        debug_write("[WRAP_SOCKET] FAILED with errno=");
        debug_write((const char *)(long)(errno ? errno : -result));
        debug_write("\n");
        return -1;
    }
    errno = 0;  /* Clear errno on success */
    debug_write("[WRAP_SOCKET] SUCCESS, fd=");
    debug_write((const char *)(long)result);
    debug_write("\n");
    return (int)result;
}

/* Linker-wrapped bind() */
int __wrap_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    debug_write("[WRAP_BIND] Called with fd=");
    debug_write((const char *)(long)sockfd);
    debug_write(" addrlen=");
    debug_write((const char *)(long)addrlen);
    debug_write("\n");

    long result = int80_bind(sockfd, addr, addrlen);
    if (result < 0) {
        errno = -result;
        debug_write("[WRAP_BIND] FAILED with errno=");
        debug_write((const char *)(long)errno);
        debug_write("\n");
        return -1;
    }
    errno = 0;  /* Clear errno on success */
    debug_write("[WRAP_BIND] SUCCESS\n");
    return 0;
}

/* Direct write for debugging without errno corruption */
static void debug_write(const char *msg) {
    extern long syscall(long, ...);
    size_t len = 0;
    while (msg[len]) len++;
    syscall(1, 2, msg, len);  /* SYS_write = 1, stderr = 2 */
}

/* Linker-wrapped listen() */
int __wrap_listen(int sockfd, int backlog) {
    debug_write("[WRAP_LISTEN] Called\n");
    long result = int80_listen(sockfd, backlog);

    if (result < 0) {
        errno = -result;
        debug_write("[WRAP_LISTEN] Failed\n");
        return -1;
    }
    /* Clear errno on success - workaround for stale errno issues */
    errno = 0;
    debug_write("[WRAP_LISTEN] Success, errno cleared\n");
    return 0;
}

/* Linker-wrapped connect() */
int __wrap_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    long result = int80_connect(sockfd, addr, addrlen);
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
    long result = int80_fcntl(fd, cmd, arg);
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
    long result = int80_unlink(pathname);
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
    long result = int80_chmod(pathname, mode);
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
    long result = int80_fchmod(fd, mode);
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

    /* Handle syscalls that need int 0x80 translation */
    switch (number) {
    case 2: { /* SYS_open */
        const char *pathname = va_arg(ap, const char *);
        int flags = va_arg(ap, int);
        mode_t mode = va_arg(ap, mode_t);
        result = int80_open(pathname, flags, mode);
        break;
    }
    case 257: { /* SYS_openat */
        int dirfd = va_arg(ap, int);
        const char *pathname = va_arg(ap, const char *);
        int flags = va_arg(ap, int);
        mode_t mode = va_arg(ap, mode_t);
        /* Convert openat(AT_FDCWD, ...) to open(...) */
        if (dirfd == -100) { /* AT_FDCWD */
            result = int80_open(pathname, flags, mode);
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
        result = int80_socket(domain, type_masked, protocol);
        break;
    }
    case 49: { /* SYS_bind */
        int sockfd = va_arg(ap, int);
        const struct sockaddr *addr = va_arg(ap, const struct sockaddr *);
        socklen_t addrlen = va_arg(ap, socklen_t);
        result = int80_bind(sockfd, addr, addrlen);
        break;
    }
    case 50: { /* SYS_listen */
        debug_write("[WRAP_SYSCALL listen] Called\n");
        int sockfd = va_arg(ap, int);
        int backlog = va_arg(ap, int);
        result = int80_listen(sockfd, backlog);
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
        result = int80_connect(sockfd, addr, addrlen);
        break;
    }
    case 72: { /* SYS_fcntl */
        debug_write("[WRAP_SYSCALL fcntl] Called\n");
        int fd = va_arg(ap, int);
        int cmd = va_arg(ap, int);
        long arg = va_arg(ap, long);
        result = int80_fcntl(fd, cmd, arg);
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
        result = int80_unlink(pathname);
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
        result = int80_chmod(pathname, mode);
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
        result = int80_fchmod(fd, mode);
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
