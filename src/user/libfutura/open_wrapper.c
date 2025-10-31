/* SPDX-License-Identifier: MPL-2.0
 *
 * LD_PRELOAD wrapper for syscalls that bypass QEMU SYSCALL emulation
 *
 * Routes critical syscalls through int 0x80 (32-bit syscall gate) instead of
 * SYSCALL instruction to bypass QEMU x86_64 SYSCALL emulation limitations.
 * Covers: open, open64, socket, bind, listen, connect, accept
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdarg.h>
#include <errno.h>

#define SYS_OPEN 2
#define SYS_SOCKET 41
#define SYS_BIND 49
#define SYS_LISTEN 50
#define SYS_ACCEPT 43
#define SYS_CONNECT 42

/* Direct int 0x80 syscall helper - uses i386 ABI calling convention
 * This bypasses QEMU's SYSCALL instruction limitation by using the
 * older 32-bit interrupt gate which is properly emulated. */
static inline long int80_open(const char *pathname, int flags, mode_t mode) {
    long result;

    /* In i386 ABI, arguments to int 0x80 are passed via registers:
     *   EBX = arg1 (pathname pointer)
     *   ECX = arg2 (flags)
     *   EDX = arg3 (mode)
     * We must use explicit mov instructions to ensure values are loaded */

    __asm__ __volatile__ (
        "int $0x80"
        : "=a" (result)                    /* output: EAX = result */
        : "a" (SYS_OPEN),                  /* EAX = syscall number */
          "b" ((long)pathname),             /* EBX = pathname */
          "c" ((long)flags),                /* ECX = flags */
          "d" ((long)mode)                  /* EDX = mode */
        : "memory", "cc"
    );

    return result;
}

/* Wrapper for open64() - override libc version */
int open64(const char *pathname, int flags, ...) __attribute__((visibility("default"))) {
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
    return (int)result;
}

/* Wrapper for open() - override libc version */
int open(const char *pathname, int flags, ...) __attribute__((visibility("default"))) {
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
    return (int)result;
}

/* Socket syscall helpers */
static inline long int80_socket(int domain, int type, int protocol) {
    long result;
    __asm__ __volatile__ (
        "int $0x80"
        : "=a" (result)
        : "a" (SYS_SOCKET),
          "b" ((long)domain),
          "c" ((long)type),
          "d" ((long)protocol)
        : "memory", "cc"
    );
    return result;
}

static inline long int80_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    long result;
    __asm__ __volatile__ (
        "int $0x80"
        : "=a" (result)
        : "a" (SYS_BIND),
          "b" ((long)sockfd),
          "c" ((long)addr),
          "d" ((long)addrlen)
        : "memory", "cc"
    );
    return result;
}

static inline long int80_listen(int sockfd, int backlog) {
    long result;
    __asm__ __volatile__ (
        "int $0x80"
        : "=a" (result)
        : "a" (SYS_LISTEN),
          "b" ((long)sockfd),
          "c" ((long)backlog)
        : "memory", "cc"
    );
    return result;
}

static inline long int80_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    long result;
    __asm__ __volatile__ (
        "int $0x80"
        : "=a" (result)
        : "a" (SYS_CONNECT),
          "b" ((long)sockfd),
          "c" ((long)addr),
          "d" ((long)addrlen)
        : "memory", "cc"
    );
    return result;
}

/* Wrapper for socket() - override libc version */
int socket(int domain, int type, int protocol) __attribute__((visibility("default"))) {
    long result = int80_socket(domain, type, protocol);
    if (result < 0) {
        errno = -result;
        return -1;
    }
    return (int)result;
}

/* Wrapper for bind() - override libc version */
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) __attribute__((visibility("default"))) {
    long result = int80_bind(sockfd, addr, addrlen);
    if (result < 0) {
        errno = -result;
        return -1;
    }
    return 0;
}

/* Wrapper for listen() - override libc version */
int listen(int sockfd, int backlog) __attribute__((visibility("default"))) {
    long result = int80_listen(sockfd, backlog);
    if (result < 0) {
        errno = -result;
        return -1;
    }
    return 0;
}

/* Wrapper for connect() - override libc version */
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) __attribute__((visibility("default"))) {
    long result = int80_connect(sockfd, addr, addrlen);
    if (result < 0) {
        errno = -result;
        return -1;
    }
    return 0;
}
