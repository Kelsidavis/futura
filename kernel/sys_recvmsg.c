/* kernel/sys_recvmsg.c - Receive message from socket with control data
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements recvmsg() for advanced socket messaging including:
 * - Scatter-gather I/O with multiple buffers
 * - Ancillary data (control messages)
 * - File descriptor receiving via SCM_RIGHTS
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
 * recvmsg() - Receive message from socket
 *
 * Receives a message from a socket with optional ancillary data.
 * More flexible than recv() or recvfrom().
 *
 * @param sockfd  Socket file descriptor
 * @param msg     Message header with scatter-gather and control data
 * @param flags   Receive flags (MSG_PEEK, MSG_WAITALL, etc.)
 *
 * Returns:
 *   - Number of bytes received on success
 *   - 0 at end-of-file
 *   - -EBADF if sockfd invalid
 *   - -EFAULT if msg points to invalid memory
 *   - -EINVAL if msg_iovlen too large or invalid
 *   - -ENOMEM if out of memory
 *   - -ENOTCONN if socket not connected
 *   - -ENOTSOCK if sockfd not a socket
 *   - -EAGAIN if non-blocking and no data available
 *
 * Features:
 * - Scatter-gather I/O via msg_iov array
 * - Ancillary data via msg_control (file descriptors, credentials)
 * - Source address via msg_name (for datagram sockets)
 * - Message flags returned in msg_flags
 *
 * Phase 1 (Current): Validates parameters, delegates to readv-style I/O
 * Phase 2: Implement scatter-gather I/O
 * Phase 3: Implement ancillary data support (SCM_RIGHTS for FD passing)
 * Phase 4: Full control message support and flags
 */
ssize_t sys_recvmsg(int sockfd, struct msghdr *msg, int flags) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    fut_printf("[RECVMSG] sockfd=%d msg=0x%p flags=0x%x\n", sockfd, msg, flags);

    /* Validate socket FD */
    struct fut_file *file = vfs_get_file(sockfd);
    if (!file) {
        fut_printf("[RECVMSG] ERROR: socket fd %d is not valid\n", sockfd);
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
        return 0;  /* Nothing to receive */
    }
    if (kmsg.msg_iovlen > 1024) {
        return -EINVAL;
    }

    /* Phase 1: Simple implementation - iterate through iovecs and read each buffer
     * Phase 2: Proper scatter-gather implementation
     * Phase 3: Handle ancillary data (SCM_RIGHTS for FD receiving)
     */

    (void)flags;  /* Ignore flags in Phase 1 */

    /* For Phase 1, just iterate through iovecs and read each buffer */
    ssize_t total_received = 0;
    for (size_t i = 0; i < kmsg.msg_iovlen; i++) {
        struct iovec iov;
        if (fut_copy_from_user(&iov, &kmsg.msg_iov[i], sizeof(struct iovec)) != 0) {
            return total_received > 0 ? total_received : -EFAULT;
        }

        if (iov.iov_len == 0) {
            continue;
        }

        /* Allocate kernel buffer */
        void *kbuf = fut_malloc(iov.iov_len);
        if (!kbuf) {
            return total_received > 0 ? total_received : -ENOMEM;
        }

        /* Read from socket */
        ssize_t ret = fut_vfs_read(sockfd, kbuf, iov.iov_len);

        if (ret > 0) {
            /* Copy to userspace */
            if (fut_copy_to_user(iov.iov_base, kbuf, (size_t)ret) != 0) {
                fut_free(kbuf);
                return total_received > 0 ? total_received : -EFAULT;
            }
            total_received += ret;
        }

        fut_free(kbuf);

        if (ret < 0) {
            return total_received > 0 ? total_received : ret;
        }

        if (ret == 0) {
            /* EOF */
            break;
        }

        /* Short read */
        if ((size_t)ret < iov.iov_len) {
            break;
        }
    }

    /* Set msg_flags to 0 for now */
    kmsg.msg_flags = 0;

    /* Set msg_controllen to 0 (no ancillary data yet) */
    kmsg.msg_controllen = 0;

    /* Write updated msghdr back to userspace */
    if (fut_copy_to_user(msg, &kmsg, sizeof(struct msghdr)) != 0) {
        return total_received > 0 ? total_received : -EFAULT;
    }

    fut_printf("[RECVMSG] received %zd bytes total\n", total_received);
    return total_received;
}
