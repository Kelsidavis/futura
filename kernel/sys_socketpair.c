/* kernel/sys_socketpair.c - Create a pair of connected sockets
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements socketpair() for creating bidirectional AF_UNIX socket pairs.
 * Essential for IPC, self-pipe tricks, and process coordination.
 *
 * Linux syscall number: 135 on Futura (53 conflicts with connect)
 */

#include <kernel/fut_task.h>
#include <kernel/fut_socket.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_waitq.h>
#include <kernel/errno.h>
#include <kernel/uaccess.h>
#include <kernel/kprintf.h>
#include <string.h>
#include <stdint.h>

#ifdef __x86_64__
#include <platform/x86_64/memory/paging.h>
#elif defined(__aarch64__)
#include <platform/arm64/memory/paging.h>
#endif

/* Kernel-pointer bypass helper */
static inline int sp_copy_to_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)dst >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_to_user(dst, src, n);
}

extern int allocate_socket_fd(fut_socket_t *socket);
extern int fut_vfs_close(int fd);

/**
 * socketpair() - Create a pair of connected sockets
 *
 * @param domain   Address family (must be AF_UNIX)
 * @param type     Socket type (SOCK_STREAM or SOCK_DGRAM, plus flags)
 * @param protocol Protocol (must be 0 for AF_UNIX)
 * @param sv       Array of two ints to receive the file descriptors
 *
 * Returns 0 on success, negative errno on failure.
 */
long sys_socketpair(int domain, int type, int protocol, int *sv) {
    if (!sv)
        return -EFAULT;

    /* Only AF_UNIX is supported for socketpair */
    if (domain != AF_UNIX)
        return -EAFNOSUPPORT;

    int base_type = type & 0xFF;
    int type_flags = type & ~0xFF;

    if (base_type != SOCK_STREAM && base_type != SOCK_DGRAM && base_type != SOCK_SEQPACKET)
        return -EINVAL;

    if (protocol != 0)
        return -EINVAL;

    /* Create two sockets */
    fut_socket_t *s0 = fut_socket_create(AF_UNIX, base_type);
    if (!s0)
        return -ENOMEM;

    fut_socket_t *s1 = fut_socket_create(AF_UNIX, base_type);
    if (!s1) {
        fut_socket_close(s0);
        return -ENOMEM;
    }

    /* Create bidirectional buffer pairs:
     * pair_forward: s0 sends → s1 receives
     * pair_reverse: s1 sends → s0 receives */
    fut_socket_pair_t *pair_fwd = fut_malloc(sizeof(fut_socket_pair_t));
    fut_socket_pair_t *pair_rev = fut_malloc(sizeof(fut_socket_pair_t));
    if (!pair_fwd || !pair_rev) {
        if (pair_fwd) fut_free(pair_fwd);
        if (pair_rev) fut_free(pair_rev);
        fut_socket_close(s0);
        fut_socket_close(s1);
        return -ENOMEM;
    }

    memset(pair_fwd, 0, sizeof(*pair_fwd));
    memset(pair_rev, 0, sizeof(*pair_rev));

    pair_fwd->send_buf = fut_malloc(FUT_SOCKET_BUFSIZE);
    pair_fwd->recv_buf = fut_malloc(FUT_SOCKET_BUFSIZE);
    pair_fwd->send_waitq = fut_malloc(sizeof(fut_waitq_t));
    pair_fwd->recv_waitq = fut_malloc(sizeof(fut_waitq_t));

    pair_rev->send_buf = fut_malloc(FUT_SOCKET_BUFSIZE);
    pair_rev->recv_buf = fut_malloc(FUT_SOCKET_BUFSIZE);
    pair_rev->send_waitq = fut_malloc(sizeof(fut_waitq_t));
    pair_rev->recv_waitq = fut_malloc(sizeof(fut_waitq_t));

    if (!pair_fwd->send_buf || !pair_fwd->recv_buf ||
        !pair_fwd->send_waitq || !pair_fwd->recv_waitq ||
        !pair_rev->send_buf || !pair_rev->recv_buf ||
        !pair_rev->send_waitq || !pair_rev->recv_waitq) {
        /* Cleanup on allocation failure */
        if (pair_fwd->send_buf) fut_free(pair_fwd->send_buf);
        if (pair_fwd->recv_buf) fut_free(pair_fwd->recv_buf);
        if (pair_fwd->send_waitq) fut_free(pair_fwd->send_waitq);
        if (pair_fwd->recv_waitq) fut_free(pair_fwd->recv_waitq);
        if (pair_rev->send_buf) fut_free(pair_rev->send_buf);
        if (pair_rev->recv_buf) fut_free(pair_rev->recv_buf);
        if (pair_rev->send_waitq) fut_free(pair_rev->send_waitq);
        if (pair_rev->recv_waitq) fut_free(pair_rev->recv_waitq);
        fut_free(pair_fwd);
        fut_free(pair_rev);
        fut_socket_close(s0);
        fut_socket_close(s1);
        return -ENOMEM;
    }

    pair_fwd->send_size = FUT_SOCKET_BUFSIZE;
    pair_fwd->recv_size = FUT_SOCKET_BUFSIZE;
    fut_waitq_init(pair_fwd->send_waitq);
    fut_waitq_init(pair_fwd->recv_waitq);
    pair_fwd->refcount = 2;

    pair_rev->send_size = FUT_SOCKET_BUFSIZE;
    pair_rev->recv_size = FUT_SOCKET_BUFSIZE;
    fut_waitq_init(pair_rev->send_waitq);
    fut_waitq_init(pair_rev->recv_waitq);
    pair_rev->refcount = 2;

    /* Wire up: s0 sends via pair_fwd, receives from pair_rev
     *          s1 sends via pair_rev, receives from pair_fwd
     * pair->peer must point to the receiving socket for send() to work */
    s0->pair = pair_fwd;
    s0->pair_reverse = pair_rev;
    s0->state = FUT_SOCK_CONNECTED;
    pair_fwd->peer = s1;  /* s0's send buffer → s1 receives */
    pair_rev->peer = s0;  /* s1's send buffer → s0 receives */

    s1->pair = pair_rev;
    s1->pair_reverse = pair_fwd;
    s1->state = FUT_SOCK_CONNECTED;

    /* Allocate FDs */
    int fd0 = allocate_socket_fd(s0);
    if (fd0 < 0) {
        fut_socket_close(s0);
        fut_socket_close(s1);
        return fd0;
    }

    int fd1 = allocate_socket_fd(s1);
    if (fd1 < 0) {
        fut_vfs_close(fd0);
        fut_socket_close(s1);
        return fd1;
    }

    /* Apply SOCK_NONBLOCK and SOCK_CLOEXEC flags */
    extern long sys_fcntl(int fd, int cmd, uint64_t arg);
    if (type_flags & SOCK_NONBLOCK) {
        sys_fcntl(fd0, 4 /* F_SETFL */, 0x800 /* O_NONBLOCK */);
        sys_fcntl(fd1, 4 /* F_SETFL */, 0x800 /* O_NONBLOCK */);
    }
    if (type_flags & SOCK_CLOEXEC) {
        sys_fcntl(fd0, 2 /* F_SETFD */, 1 /* FD_CLOEXEC */);
        sys_fcntl(fd1, 2 /* F_SETFD */, 1 /* FD_CLOEXEC */);
    }

    /* Return FDs to caller */
    int fds[2] = { fd0, fd1 };
    if (sp_copy_to_user(sv, fds, sizeof(fds)) != 0) {
        fut_vfs_close(fd0);
        fut_vfs_close(fd1);
        return -EFAULT;
    }

    return 0;
}
