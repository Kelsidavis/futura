/* SPDX-License-Identifier: MPL-2.0
 *
 * LD_PRELOAD wrapper for syscalls - portable across x86_64 and ARM64
 *
 * Wraps critical syscalls to provide consistent interface across platforms.
 * Uses portable syscall interface from syscall_portable.h.
 * Covers: open, open64, socket, bind, listen, connect
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

/* Portable syscall interface */
#include "syscall_portable.h"

/* Wrapper for open64() - override libc version */
int open64(const char *pathname, int flags, ...) __attribute__((visibility("default"))) {
    va_list ap;
    mode_t mode = 0;

    if (flags & (O_CREAT | O_TMPFILE)) {
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }

    long result = syscall3(__NR_open, (long)pathname, (long)flags, (long)mode);

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

    long result = syscall3(__NR_open, (long)pathname, (long)flags, (long)mode);

    if (result < 0) {
        errno = -result;
        return -1;
    }
    return (int)result;
}


/* Wrapper for socket() - override libc version */
int socket(int domain, int type, int protocol) __attribute__((visibility("default"))) {
    long result = syscall3(__NR_socket, (long)domain, (long)type, (long)protocol);
    if (result < 0) {
        errno = -result;
        return -1;
    }
    return (int)result;
}

/* Wrapper for bind() - override libc version */
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) __attribute__((visibility("default"))) {
    long result = syscall3(__NR_bind, (long)sockfd, (long)addr, (long)addrlen);
    if (result < 0) {
        errno = -result;
        return -1;
    }
    return 0;
}

/* Wrapper for listen() - override libc version */
int listen(int sockfd, int backlog) __attribute__((visibility("default"))) {
    long result = syscall2(__NR_listen, (long)sockfd, (long)backlog);
    if (result < 0) {
        errno = -result;
        return -1;
    }
    return 0;
}

/* Wrapper for connect() - override libc version */
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) __attribute__((visibility("default"))) {
    long result = syscall3(__NR_connect, (long)sockfd, (long)addr, (long)addrlen);
    if (result < 0) {
        errno = -result;
        return -1;
    }
    return 0;
}
