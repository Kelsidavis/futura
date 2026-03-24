/* kernel/sys_sendmmsg.c - Send multiple messages on socket
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * sendmmsg(): send up to vlen messages in one syscall, filling msg_len
 * in each mmsghdr with the number of bytes transmitted.
 * Returns the number of messages sent, or a negative error code.
 */

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

static inline int sndmm_copy_to_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)dst >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_to_user(dst, src, n);
}

/*
 * struct mmsghdr layout:
 *   struct msghdr msg_hdr;   (sizeof(struct msghdr) bytes)
 *   unsigned int  msg_len;   (4 bytes, padded to 8-byte boundary)
 *
 * The stride between entries is (sizeof(struct msghdr) + sizeof(unsigned int))
 * rounded up to the struct's natural alignment (pointer size = 8).
 */
#define MMSGHDR_STRIDE \
    (((sizeof(struct msghdr) + sizeof(unsigned int)) + 7u) & ~7u)
#define MMSGHDR_MSGLEN_OFFSET   sizeof(struct msghdr)

long sys_sendmmsg(int sockfd, void *msgvec, unsigned int vlen, unsigned int flags) {
    if (!msgvec || vlen == 0)
        return -EINVAL;
    if (vlen > 1024)
        vlen = 1024;

    extern ssize_t sys_sendmsg(int sockfd, const struct msghdr *msg, int flags);

    int count = 0;
    for (unsigned int i = 0; i < vlen; i++) {
        uintptr_t entry = (uintptr_t)msgvec + i * MMSGHDR_STRIDE;
        ssize_t r = sys_sendmsg(sockfd, (const struct msghdr *)entry, (int)flags);
        if (r < 0) {
            if (count > 0) break;   /* partial success */
            return r;
        }
        unsigned int sent = (unsigned int)r;
        sndmm_copy_to_user((void *)(entry + MMSGHDR_MSGLEN_OFFSET), &sent, sizeof(sent));
        count++;
    }
    return count;
}
