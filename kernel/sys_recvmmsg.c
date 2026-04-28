/* kernel/sys_recvmmsg.c - Receive multiple messages from socket
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * recvmmsg(): receive up to vlen messages in one syscall, filling msg_len
 * in each mmsghdr with the number of bytes received.
 * Returns the number of messages received, or a negative error code.
 *
 * timeout: optional struct timespec deadline.  If tv_sec==0 && tv_nsec==0
 * (zero timeout), treat subsequent messages as non-blocking.
 */

#include <time.h>
#include <kernel/fut_task.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_socket.h>
#include <kernel/uaccess.h>
#include <kernel/errno.h>
#include <sys/socket.h>
#include <stddef.h>
#include <stdint.h>

#include <kernel/kprintf.h>

#include <platform/platform.h>

static inline int rcvmm_copy_to_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)dst >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_to_user(dst, src, n);
}

static inline int rcvmm_copy_from_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)src >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_from_user(dst, src, n);
}

#define MMSGHDR_STRIDE \
    (((sizeof(struct msghdr) + sizeof(unsigned int)) + 7u) & ~7u)
#define MMSGHDR_MSGLEN_OFFSET   sizeof(struct msghdr)

long sys_recvmmsg(int sockfd, void *msgvec, unsigned int vlen,
                  unsigned int flags, const struct timespec *timeout) {
    /* Linux's __sys_recvmmsg runs sockfd_lookup_light FIRST, before any
     * vlen / msgvec inspection.  recvmmsg(bad_fd, NULL, 0, ...) therefore
     * returns -EBADF on Linux, not 0 (vlen short-circuit) or -EFAULT
     * (NULL msgvec).  Validate the socket fd up front so the EBADF
     * errno class is preserved for libc probes. */
    {
        extern struct fut_file *vfs_get_file(int fd);
        extern fut_socket_t *get_socket_from_fd(int fd);
        if (sockfd < 0 || !vfs_get_file(sockfd))
            return -EBADF;
        if (!get_socket_from_fd(sockfd))
            return -ENOTSOCK;
    }

    /* Linux's SYSCALL_DEFINE5(recvmmsg) reads and validates the timeout
     * BEFORE entering __sys_recvmmsg, so a bad timeout pointer surfaces
     * as -EFAULT regardless of vlen / msgvec.  Futura's previous order
     * short-circuited vlen=0 to 0 before touching timeout, so
     * recvmmsg(valid_fd, msg, 0, _, bad_timeout_ptr) returned 0 where
     * Linux returns EFAULT — same EFAULT-before-vlen=0 ordering as the
     * sockfd_lookup_light reorder this function already does.
     *
     * If a zero timeout is specified (tv_sec==0, tv_nsec==0), apply
     * MSG_DONTWAIT to every message after the first.
     */
    int nonblock_subsequent = 0;
    if (timeout) {
        long tv_sec = 0, tv_nsec = 0;
        if (rcvmm_copy_from_user(&tv_sec, timeout, sizeof(long)) != 0)
            return -EFAULT;
        if (rcvmm_copy_from_user(&tv_nsec,
                                 (const char *)timeout + sizeof(long),
                                 sizeof(long)) != 0)
            return -EFAULT;
        if (tv_nsec < 0 || tv_nsec >= 1000000000L || tv_sec < 0)
            return -EINVAL;
        if (tv_sec == 0 && tv_nsec == 0)
            nonblock_subsequent = 1;
    }

    /* Linux: vlen == 0 short-circuits — __sys_recvmmsg's loop runs zero
     * times and the syscall returns 0 without dereferencing msgvec.
     * The previous order (NULL check before vlen==0) surfaced EFAULT
     * for the documented no-op recvmmsg(fd, NULL, 0, _, _) probe; libc
     * uses this pattern to detect 'syscall exists, fd is a socket'.
     * Reorder so vlen==0 short-circuits before any pointer deref. */
    if (vlen == 0)
        return 0;
    if (!msgvec)
        return -EFAULT;
    if (vlen > 1024)
        vlen = 1024;

    extern ssize_t sys_recvmsg(int sockfd, struct msghdr *msg, int flags);

    int count = 0;
    for (unsigned int i = 0; i < vlen; i++) {
        uintptr_t entry = (uintptr_t)msgvec + i * MMSGHDR_STRIDE;
        int recv_flags = (int)flags;
        if (count > 0 || nonblock_subsequent)
            recv_flags |= MSG_DONTWAIT;
        ssize_t r = sys_recvmsg(sockfd, (struct msghdr *)entry, recv_flags);
        if (r < 0) {
            if (count > 0) break;   /* partial success */
            return r;
        }
        unsigned int rcvd = (unsigned int)r;
        rcvmm_copy_to_user((void *)(entry + MMSGHDR_MSGLEN_OFFSET), &rcvd, sizeof(rcvd));
        count++;
    }
    return count;
}
