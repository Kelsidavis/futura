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

#ifdef __x86_64__
#include <platform/x86_64/memory/paging.h>
#elif defined(__aarch64__)
#include <platform/arm64/memory/paging.h>
#endif

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
    if (!msgvec || vlen == 0)
        return -EINVAL;
    if (vlen > 1024)
        vlen = 1024;

    extern ssize_t sys_recvmsg(int sockfd, struct msghdr *msg, int flags);

    /*
     * If a zero timeout is specified (tv_sec==0, tv_nsec==0), apply
     * MSG_DONTWAIT to every message after the first.
     * For non-NULL timeouts with actual wait time, we could implement
     * deadline tracking; for now we apply MSG_DONTWAIT after the first
     * message regardless (avoids blocking on a partially filled vlen).
     */
    int nonblock_subsequent = 0;
    if (timeout) {
        /* struct timespec: { time_t tv_sec; long tv_nsec; } */
        long tv_sec = 0, tv_nsec = 0;
        rcvmm_copy_from_user(&tv_sec,  timeout, sizeof(long));
        rcvmm_copy_from_user(&tv_nsec, (const char *)timeout + sizeof(long), sizeof(long));
        if (tv_sec == 0 && tv_nsec == 0)
            nonblock_subsequent = 1;
    }

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
