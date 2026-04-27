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
#include <kernel/fut_vfs.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_waitq.h>
#include <kernel/errno.h>
#include <kernel/uaccess.h>
#include <kernel/kprintf.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>

#include <platform/platform.h>

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

    /* Match the matching socket() gate: Linux rejects negative
     * protocol numbers with -EINVAL in __sock_create before any
     * family-specific handler runs. The previous protocol-mismatch
     * check below would surface negative as EPROTONOSUPPORT; that
     * conflicted with the Linux errno class libc probes expect. */
    if (protocol < 0)
        return -EINVAL;

    /* Only AF_UNIX is supported for socketpair */
    if (domain != AF_UNIX)
        return -EAFNOSUPPORT;

    int base_type = type & 0xFF;
    int type_flags = type & ~0xFF;

    /* Linux's net/unix/af_unix.c:unix_create returns -ESOCKTNOSUPPORT
     * for unsupported sock->type within a known family — same as the
     * just-fixed sys_socket path. The distinction matters: glibc's
     * socket()/socketpair() probes branch on ESOCKTNOSUPPORT to retry
     * with another SOCK_* number, but treat EINVAL as a fatal call-
     * shape error and abort. */
    if (base_type != SOCK_STREAM && base_type != SOCK_DGRAM && base_type != SOCK_SEQPACKET)
        return -ESOCKTNOSUPPORT;

    /* Reject unknown type flags (only SOCK_NONBLOCK and SOCK_CLOEXEC are valid) */
    if (type_flags & ~(SOCK_NONBLOCK | SOCK_CLOEXEC))
        return -EINVAL;

    /* Protocol-domain mismatch on AF_UNIX is -EPROTONOSUPPORT per Linux's
     * net/unix/af_unix.c:unix_create (and its shared use under
     * sys_socketpair). EINVAL is reserved for malformed parameters; the
     * dedicated EPROTONOSUPPORT errno lets libc distinguish 'fix the
     * protocol arg' from 'fix the call shape'. Accept PF_UNIX (==1) as
     * an alias for 0 the same way sys_socket does. */
    if (protocol != 0 && protocol != AF_UNIX /* PF_UNIX */)
        return -EPROTONOSUPPORT;

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

    /* Allocate buffers and waitqueues for both directions.
     * Each allocation is checked within 4 lines to satisfy the
     * static-analysis checker; cleanup is shared via goto. */
    pair_fwd->send_buf   = fut_malloc(FUT_SOCKET_BUFSIZE);
    pair_fwd->recv_buf   = fut_malloc(FUT_SOCKET_BUFSIZE);
    pair_fwd->send_waitq = fut_malloc(sizeof(fut_waitq_t));
    if (!pair_fwd->send_buf || !pair_fwd->recv_buf || !pair_fwd->send_waitq)
        goto pair_alloc_fail;
    pair_fwd->recv_waitq = fut_malloc(sizeof(fut_waitq_t));
    if (!pair_fwd->recv_waitq) goto pair_alloc_fail;

    pair_rev->send_buf   = fut_malloc(FUT_SOCKET_BUFSIZE);
    pair_rev->recv_buf   = fut_malloc(FUT_SOCKET_BUFSIZE);
    pair_rev->send_waitq = fut_malloc(sizeof(fut_waitq_t));
    if (!pair_rev->send_buf || !pair_rev->recv_buf || !pair_rev->send_waitq)
        goto pair_alloc_fail;
    pair_rev->recv_waitq = fut_malloc(sizeof(fut_waitq_t));
    if (!pair_rev->recv_waitq) goto pair_alloc_fail;

    if (0) {
pair_alloc_fail:
        if (pair_fwd->send_buf)   fut_free(pair_fwd->send_buf);
        if (pair_fwd->recv_buf)   fut_free(pair_fwd->recv_buf);
        if (pair_fwd->send_waitq) fut_free(pair_fwd->send_waitq);
        if (pair_fwd->recv_waitq) fut_free(pair_fwd->recv_waitq);
        if (pair_rev->send_buf)   fut_free(pair_rev->send_buf);
        if (pair_rev->recv_buf)   fut_free(pair_rev->recv_buf);
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

    /* SO_PEERCRED: for socketpair(), both ends belong to the same creating task */
    {
        fut_task_t *task = fut_task_current();
        uint32_t spid = task ? task->pid : 0;
        uint32_t suid = task ? task->uid : 0;
        uint32_t sgid = task ? task->gid : 0;
        s0->peer_pid = s1->peer_pid = spid;
        s0->peer_uid = s1->peer_uid = suid;
        s0->peer_gid = s1->peer_gid = sgid;
    }

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

    /* Store file back-pointers for O_ASYNC/SIGIO delivery */
    {
        fut_task_t *ftask = fut_task_current();
        if (ftask && ftask->fd_table) {
            if (fd0 < ftask->max_fds)
                s0->socket_file = ftask->fd_table[fd0];
            if (fd1 < ftask->max_fds)
                s1->socket_file = ftask->fd_table[fd1];
        }
    }

    /* Apply SOCK_NONBLOCK and SOCK_CLOEXEC directly on the FD structures
     * to avoid race windows between fd allocation and flag application.
     * (Using sys_fcntl would leave a gap where another thread could
     * observe the fd without the requested flags.) */
    if (type_flags & (SOCK_NONBLOCK | SOCK_CLOEXEC)) {
        fut_task_t *task = fut_task_current();
        if (task) {
            if (type_flags & SOCK_NONBLOCK) {
                if (fd0 < task->max_fds) {
                    struct fut_file *f = task->fd_table[fd0];
                    if (f) f->flags |= O_NONBLOCK;
                }
                if (fd1 < task->max_fds) {
                    struct fut_file *f = task->fd_table[fd1];
                    if (f) f->flags |= O_NONBLOCK;
                }
                /* Also propagate to socket structs so socket_nonblock()
                 * returns true in fut_socket_recv/send. */
                s0->flags |= O_NONBLOCK;
                s1->flags |= O_NONBLOCK;
            }
            if (type_flags & SOCK_CLOEXEC) {
                /* Guard against tasks that haven't allocated fd_flags
                 * (early init / kernel threads). Other syscalls — pipe2,
                 * dup3, pidfd_open — already check; socketpair was
                 * relying on fd_flags being non-NULL for any task that
                 * could call socket(2). Keep the guard for symmetry and
                 * to avoid a NULL deref if that invariant ever slips. */
                if (task->fd_flags) {
                    if (fd0 < task->max_fds)
                        task->fd_flags[fd0] |= FD_CLOEXEC;
                    if (fd1 < task->max_fds)
                        task->fd_flags[fd1] |= FD_CLOEXEC;
                }
            }
        }
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
