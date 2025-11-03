/* kernel/sys_recvfrom.c - Receive message from socket syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements recvfrom() to receive messages from sockets.
 * Essential for network communication and Unix domain sockets.
 *
 * Phase 1 (Completed): Basic recvfrom with VFS read delegation
 * Phase 2 (Current): Enhanced validation, FD/buffer/flags categorization, detailed logging
 * Phase 3: Source address tracking, MSG flags implementation
 * Phase 4: Zero-copy receive, scatter-gather I/O
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

/* Common MSG flags (for reference) */
#define MSG_DONTWAIT  0x40   /* Non-blocking operation */
#define MSG_PEEK      0x02   /* Peek at incoming data */
#define MSG_WAITALL   0x100  /* Wait for full request */
#define MSG_TRUNC     0x20   /* Data was truncated */

/**
 * recvfrom() - Receive message from socket
 *
 * Receives data from a socket. Can be used with both connection-oriented
 * (SOCK_STREAM) and connectionless (SOCK_DGRAM) sockets. Returns the
 * source address for datagram sockets.
 *
 * @param sockfd   Socket file descriptor
 * @param buf      Buffer to receive data
 * @param len      Maximum bytes to receive
 * @param flags    Receive flags (MSG_DONTWAIT, MSG_PEEK, etc.)
 * @param src_addr Source address (output, NULL if not needed)
 * @param addrlen  Address length (input/output, NULL if src_addr NULL)
 *
 * Returns:
 *   - Number of bytes received (≥0) on success
 *   - 0 on graceful connection close (SOCK_STREAM)
 *   - -ESRCH if no task context
 *   - -EBADF if sockfd is invalid
 *   - -EINVAL if buf is NULL
 *   - -ENOMEM if kernel buffer allocation fails
 *   - -EFAULT if copy to user fails
 *   - -EAGAIN if non-blocking and no data available
 *
 * Behavior:
 *   - Blocks until data available (unless MSG_DONTWAIT)
 *   - Returns partial data if some available
 *   - For SOCK_STREAM: Returns available data up to len
 *   - For SOCK_DGRAM: Returns one complete datagram
 *   - MSG_PEEK: Return data without removing from queue
 *   - MSG_WAITALL: Wait for full len bytes (SOCK_STREAM only)
 *   - src_addr filled with sender address (SOCK_DGRAM)
 *
 * Common usage patterns:
 *
 * TCP receive:
 *   char buf[1024];
 *   ssize_t n = recvfrom(sockfd, buf, sizeof(buf), 0, NULL, NULL);
 *   // or just recv(sockfd, buf, sizeof(buf), 0)
 *
 * UDP receive with source address:
 *   char buf[1024];
 *   struct sockaddr_in src;
 *   socklen_t srclen = sizeof(src);
 *   ssize_t n = recvfrom(sockfd, buf, sizeof(buf), 0,
 *                        (struct sockaddr *)&src, &srclen);
 *
 * Non-blocking receive:
 *   ssize_t n = recvfrom(sockfd, buf, sizeof(buf), MSG_DONTWAIT,
 *                        NULL, NULL);
 *   if (n < 0 && errno == EAGAIN) {
 *       // No data available
 *   }
 *
 * Peek at data:
 *   recvfrom(sockfd, buf, sizeof(buf), MSG_PEEK, NULL, NULL);
 *   // Data still in queue
 *
 * Unix domain socket receive:
 *   struct sockaddr_un src;
 *   socklen_t srclen = sizeof(src);
 *   ssize_t n = recvfrom(sockfd, buf, len, 0,
 *                        (struct sockaddr *)&src, &srclen);
 *
 * Related syscalls:
 *   - recv(): Simplified recvfrom (no source address)
 *   - read(): Can be used on connected sockets
 *   - recvmsg(): Advanced receive with scatter-gather
 *   - sendto(): Send message to socket
 *
 * Phase 1 (Completed): Basic recvfrom with VFS read delegation
 * Phase 2 (Current): Enhanced validation, parameter categorization, detailed logging
 * Phase 3: MSG flags implementation, source address tracking
 * Phase 4: Zero-copy receive, scatter-gather I/O
 */
ssize_t sys_recvfrom(int sockfd, void *buf, size_t len, int flags,
                     void *src_addr, socklen_t *addrlen) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[RECVFROM] recvfrom(sockfd=%d) -> ESRCH (no current task)\n", sockfd);
        return -ESRCH;
    }

    /* Phase 2: Validate sockfd */
    if (sockfd < 0) {
        fut_printf("[RECVFROM] recvfrom(sockfd=%d) -> EBADF (negative fd)\n", sockfd);
        return -EBADF;
    }

    /* Phase 2: Categorize socket FD */
    const char *fd_category;
    if (sockfd <= 2) {
        fd_category = "stdio (0-2)";
    } else if (sockfd < 10) {
        fd_category = "low (3-9)";
    } else if (sockfd < 1000) {
        fd_category = "socket range (10-999)";
    } else if (sockfd < 2000) {
        fd_category = "socket range (1000-1999)";
    } else if (sockfd < 3000) {
        fd_category = "socket range (2000-2999)";
    } else {
        fd_category = "high (≥3000)";
    }

    /* Phase 2: Categorize buffer size */
    const char *size_category;
    if (len == 0) {
        size_category = "zero-length";
    } else if (len <= 64) {
        size_category = "tiny (≤64 bytes)";
    } else if (len <= 512) {
        size_category = "small (64-512 bytes)";
    } else if (len <= 4096) {
        size_category = "medium (512B-4KB)";
    } else if (len <= 65536) {
        size_category = "large (4KB-64KB)";
    } else {
        size_category = "very large (>64KB)";
    }

    /* Phase 2: Categorize flags */
    const char *flags_description;
    char flags_str[128];
    int pos = 0;

    if (flags == 0) {
        flags_description = "none (blocking)";
    } else {
        /* Build flags string manually */
        flags_str[0] = '\0';
        if (flags & MSG_DONTWAIT) {
            const char *s = "MSG_DONTWAIT";
            while (*s && pos < 120) flags_str[pos++] = *s++;
        }
        if (flags & MSG_PEEK) {
            if (pos > 0 && pos < 120) flags_str[pos++] = '|';
            const char *s = "MSG_PEEK";
            while (*s && pos < 120) flags_str[pos++] = *s++;
        }
        if (flags & MSG_WAITALL) {
            if (pos > 0 && pos < 120) flags_str[pos++] = '|';
            const char *s = "MSG_WAITALL";
            while (*s && pos < 120) flags_str[pos++] = *s++;
        }
        if (flags & MSG_TRUNC) {
            if (pos > 0 && pos < 120) flags_str[pos++] = '|';
            const char *s = "MSG_TRUNC";
            while (*s && pos < 120) flags_str[pos++] = *s++;
        }
        flags_str[pos] = '\0';

        if (pos == 0) {
            flags_description = "unknown flags";
        } else {
            flags_description = flags_str;
        }
    }

    (void)src_addr;
    (void)addrlen;

    /* Validate socket FD */
    struct fut_file *file = vfs_get_file(sockfd);
    if (!file) {
        fut_printf("[RECVFROM] recvfrom(sockfd=%d [%s]) -> EBADF (fd not open)\n",
                   sockfd, fd_category);
        return -EBADF;
    }

    /* Handle zero-length receive */
    if (len == 0) {
        fut_printf("[RECVFROM] recvfrom(sockfd=%d [%s], len=0, pid=%u) -> 0 "
                   "(zero-length receive)\n",
                   sockfd, fd_category, task->pid);
        return 0;
    }

    /* Validate buf */
    if (!buf) {
        fut_printf("[RECVFROM] recvfrom(sockfd=%d [%s], buf=NULL, len=%zu, pid=%u) -> EINVAL "
                   "(NULL buffer)\n",
                   sockfd, fd_category, len, task->pid);
        return -EINVAL;
    }

    /* Allocate kernel buffer */
    void *kbuf = fut_malloc(len);
    if (!kbuf) {
        fut_printf("[RECVFROM] recvfrom(sockfd=%d [%s], len=%zu [%s], pid=%u) -> ENOMEM "
                   "(kernel buffer allocation failed)\n",
                   sockfd, fd_category, len, size_category, task->pid);
        return -ENOMEM;
    }

    /* Read from socket via VFS */
    ssize_t ret = fut_vfs_read(sockfd, kbuf, len);

    if (ret < 0) {
        const char *error_desc;
        switch (ret) {
            case -EAGAIN:
                error_desc = "would block (non-blocking mode)";
                break;
            default:
                error_desc = "read failed";
                break;
        }

        fut_free(kbuf);
        fut_printf("[RECVFROM] recvfrom(sockfd=%d [%s], len=%zu [%s], "
                   "flags=0x%x [%s], pid=%u) -> %zd (%s)\n",
                   sockfd, fd_category, len, size_category,
                   flags, flags_description, task->pid, ret, error_desc);
        return ret;
    }

    /* Copy to userspace */
    if (ret > 0) {
        if (fut_copy_to_user(buf, kbuf, (size_t)ret) != 0) {
            fut_free(kbuf);
            fut_printf("[RECVFROM] recvfrom(sockfd=%d [%s], len=%zu [%s], pid=%u) -> EFAULT "
                       "(copy_to_user failed)\n",
                       sockfd, fd_category, len, size_category, task->pid);
            return -EFAULT;
        }
    }

    fut_free(kbuf);

    /* Phase 2: Determine address family hint (stub - not yet implemented) */
    const char *addr_family_hint;
    if (src_addr && addrlen) {
        addr_family_hint = "address requested (AF_INET/AF_UNIX)";
    } else {
        addr_family_hint = "no address requested";
    }

    /* Phase 2: Detailed success logging */
    fut_printf("[RECVFROM] recvfrom(sockfd=%d [%s], buf=%p, len=%zu [%s], "
               "flags=0x%x [%s], src_addr=%s, bytes_received=%zd, pid=%u) -> %zd "
               "(received successfully, Phase 2)\n",
               sockfd, fd_category, buf, len, size_category,
               flags, flags_description, addr_family_hint, ret, task->pid, ret);

    return ret;
}
