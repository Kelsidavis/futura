/* kernel/sys_sendmsg.c - Send message on socket with control data
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements sendmsg() for advanced socket messaging including:
 * - Scatter-gather I/O with multiple buffers
 * - Ancillary data (control messages)
 * - File descriptor passing via SCM_RIGHTS
 */

#include <kernel/fut_task.h>
#include <kernel/fut_vfs.h>
#include <kernel/fut_memory.h>
#include <kernel/uaccess.h>
#include <kernel/errno.h>
#include <stddef.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);
extern fut_task_t *fut_task_current(void);
extern struct fut_file *vfs_get_file(int fd);

typedef uint32_t socklen_t;

/* struct iovec for scatter-gather I/O */
struct iovec {
    void *iov_base;           /* Starting address */
    size_t iov_len;           /* Number of bytes */
};

/* struct msghdr for sendmsg/recvmsg */
struct msghdr {
    void *msg_name;           /* Optional address */
    socklen_t msg_namelen;    /* Size of address */
    struct iovec *msg_iov;    /* Scatter/gather array */
    size_t msg_iovlen;        /* # elements in msg_iov */
    void *msg_control;        /* Ancillary data */
    size_t msg_controllen;    /* Ancillary data buffer len */
    int msg_flags;            /* Flags on received message */
};

/* Control message header */
struct cmsghdr {
    size_t cmsg_len;          /* Data byte count, including header */
    int cmsg_level;           /* Originating protocol */
    int cmsg_type;            /* Protocol-specific type */
    /* followed by unsigned char cmsg_data[] */
};

/* Ancillary data types */
#define SOL_SOCKET  1
#define SCM_RIGHTS  1         /* File descriptor passing */

/**
 * sendmsg() - Send message on socket
 *
 * Transmits a message on a socket with optional ancillary data.
 * More flexible than send() or sendto().
 *
 * @param sockfd  Socket file descriptor
 * @param msg     Message header with scatter-gather and control data
 * @param flags   Send flags (MSG_DONTWAIT, MSG_NOSIGNAL, etc.)
 *
 * Returns:
 *   - Number of bytes sent on success
 *   - -EBADF if sockfd invalid
 *   - -EFAULT if msg points to invalid memory
 *   - -EINVAL if msg_iovlen too large or invalid
 *   - -EMSGSIZE if message too large
 *   - -ENOBUFS if insufficient buffers
 *   - -ENOMEM if out of memory
 *   - -ENOTCONN if socket not connected
 *   - -ENOTSOCK if sockfd not a socket
 *   - -EOPNOTSUPP if operation not supported
 *   - -EPIPE if connection broken (may generate SIGPIPE)
 *
 * Features:
 * - Scatter-gather I/O via msg_iov array
 * - Ancillary data via msg_control (file descriptors, credentials)
 * - Optional destination address via msg_name
 * - Atomic message send
 *
 * Phase 1 (Current): Validates parameters, delegates to writev-style I/O
 * Phase 2: Implement scatter-gather I/O
 * Phase 3: Implement ancillary data support (SCM_RIGHTS for FD passing)
 * Phase 4: Full control message support
 */
ssize_t sys_sendmsg(int sockfd, const struct msghdr *msg, int flags) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    fut_printf("[SENDMSG] sockfd=%d msg=0x%p flags=0x%x\n", sockfd, msg, flags);

    /* Validate socket FD */
    struct fut_file *file = vfs_get_file(sockfd);
    if (!file) {
        fut_printf("[SENDMSG] ERROR: socket fd %d is not valid\n", sockfd);
        return -EBADF;
    }

    /* Validate msg pointer */
    if (!msg) {
        return -EFAULT;
    }

    /* Copy msghdr from userspace */
    struct msghdr kmsg;
    if (fut_copy_from_user(&kmsg, msg, sizeof(struct msghdr)) != 0) {
        return -EFAULT;
    }

    /* Validate iovlen */
    if (kmsg.msg_iovlen == 0) {
        return 0;  /* Nothing to send */
    }
    if (kmsg.msg_iovlen > 1024) {
        return -EINVAL;
    }

    /* Phase 1: Simple implementation - sum up all iovec buffers and write
     * Phase 2: Proper scatter-gather implementation
     * Phase 3: Handle ancillary data (SCM_RIGHTS for FD passing)
     */

    (void)flags;  /* Ignore flags in Phase 1 */

    /* For Phase 1, just iterate through iovecs and write each buffer */
    ssize_t total_sent = 0;
    for (size_t i = 0; i < kmsg.msg_iovlen; i++) {
        struct iovec iov;
        if (fut_copy_from_user(&iov, &kmsg.msg_iov[i], sizeof(struct iovec)) != 0) {
            return total_sent > 0 ? total_sent : -EFAULT;
        }

        if (iov.iov_len == 0) {
            continue;
        }

        /* Allocate kernel buffer */
        void *kbuf = fut_malloc(iov.iov_len);
        if (!kbuf) {
            return total_sent > 0 ? total_sent : -ENOMEM;
        }

        /* Copy from userspace */
        if (fut_copy_from_user(kbuf, iov.iov_base, iov.iov_len) != 0) {
            fut_free(kbuf);
            return total_sent > 0 ? total_sent : -EFAULT;
        }

        /* Write to socket */
        ssize_t ret = fut_vfs_write(sockfd, kbuf, iov.iov_len);
        fut_free(kbuf);

        if (ret < 0) {
            return total_sent > 0 ? total_sent : ret;
        }

        total_sent += ret;

        /* Short write */
        if ((size_t)ret < iov.iov_len) {
            break;
        }
    }

    /* Log ancillary data if present (not yet handled) */
    if (kmsg.msg_controllen > 0) {
        fut_printf("[SENDMSG] Ancillary data present (%zu bytes) - not yet handled\n",
                   kmsg.msg_controllen);
    }

    fut_printf("[SENDMSG] sent %zd bytes total\n", total_sent);
    return total_sent;
}
