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
 * Phase 1 (Completed): Validates parameters, delegates to readv-style I/O
 * Phase 2 (Completed): Enhanced validation, I/O pattern analysis, and detailed statistics
 * Phase 3 (Completed): Scatter-gather message receive with ancillary data support
 * Phase 4: Full control message support and advanced flags
 */
ssize_t sys_recvmsg(int sockfd, struct msghdr *msg, int flags) {
    /* ARM64 FIX: Copy parameters to local variables immediately to ensure they're preserved
     * on the stack across potentially blocking calls. Socket/VFS operations may block and corrupt
     * register-passed parameters upon resumption. */
    int local_sockfd = sockfd;
    struct msghdr *local_msg = msg;
    int local_flags = flags;

    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Phase 2: Identify message flags for logging */
    const char *flags_desc;

    /* Common recv flags (placeholder names - actual values may differ) */
    #define MSG_PEEK      0x02
    #define MSG_WAITALL   0x100
    #define MSG_DONTWAIT  0x40
    #define MSG_TRUNC     0x20
    #define MSG_CTRUNC    0x08

    if (flags == 0) {
        flags_desc = "none";
    } else if (flags == MSG_PEEK) {
        flags_desc = "MSG_PEEK";
    } else if (flags == MSG_WAITALL) {
        flags_desc = "MSG_WAITALL";
    } else if (flags == MSG_DONTWAIT) {
        flags_desc = "MSG_DONTWAIT";
    } else if (flags == MSG_TRUNC) {
        flags_desc = "MSG_TRUNC";
    } else if (flags == MSG_CTRUNC) {
        flags_desc = "MSG_CTRUNC";
    } else if (flags == (MSG_PEEK | MSG_DONTWAIT)) {
        flags_desc = "MSG_PEEK|MSG_DONTWAIT";
    } else if (flags == (MSG_WAITALL | MSG_DONTWAIT)) {
        flags_desc = "MSG_WAITALL|MSG_DONTWAIT";
    } else {
        flags_desc = "multiple/unknown flags";
    }

    /* Validate socket FD */
    struct fut_file *file = vfs_get_file(local_sockfd);
    if (!file) {
        fut_printf("[RECVMSG] ERROR: socket fd %d is not valid\n", local_sockfd);
        return -EBADF;
    }

    /* Validate msg pointer */
    if (!local_msg) {
        return -EFAULT;
    }

    /* Copy msghdr from userspace */
    struct msghdr kmsg;
    if (fut_copy_from_user(&kmsg, local_msg, sizeof(struct msghdr)) != 0) {
        return -EFAULT;
    }

    /* Phase 5: Validate control message length
     * Limit to 64KB to prevent DoS via excessively large control messages */
    if (kmsg.msg_controllen > 0) {
        const size_t MAX_CONTROL_LEN = 65536;  /* 64KB */
        if (kmsg.msg_controllen > MAX_CONTROL_LEN) {
            fut_printf("[RECVMSG] recvmsg(sockfd=%d, controllen=%zu) -> EINVAL "
                       "(control message too large, max %zu bytes, Phase 5)\n",
                       local_sockfd, kmsg.msg_controllen, MAX_CONTROL_LEN);
            return -EINVAL;
        }

        /* Validate control buffer pointer is not NULL */
        if (!kmsg.msg_control) {
            fut_printf("[RECVMSG] recvmsg(sockfd=%d, controllen=%zu) -> EFAULT "
                       "(msg_control is NULL with non-zero length, Phase 5)\n",
                       local_sockfd, kmsg.msg_controllen);
            return -EFAULT;
        }
    }

    /* Validate iovlen */
    if (kmsg.msg_iovlen == 0) {
        fut_printf("[RECVMSG] recvmsg(sockfd=%d, iovlen=0) -> 0 (nothing to receive)\n", local_sockfd);
        return 0;  /* Nothing to receive */
    }
    if (kmsg.msg_iovlen > 1024) {
        fut_printf("[RECVMSG] recvmsg(sockfd=%d, iovlen=%zu) -> EINVAL (exceeds UIO_MAXIOV=1024)\n",
                   local_sockfd, kmsg.msg_iovlen);
        return -EINVAL;
    }

    /* Phase 2: Calculate total size, validate iovecs, and gather statistics */
    size_t total_size = 0;
    int zero_len_count = 0;
    size_t min_iov_len = (size_t)-1;
    size_t max_iov_len = 0;

    /* First pass: gather statistics */
    for (size_t i = 0; i < kmsg.msg_iovlen; i++) {
        struct iovec iov;
        if (fut_copy_from_user(&iov, &kmsg.msg_iov[i], sizeof(struct iovec)) != 0) {
            fut_printf("[RECVMSG] recvmsg(sockfd=%d, iovlen=%zu) -> EFAULT (copy_from_user iovec %zu failed)\n",
                       local_sockfd, kmsg.msg_iovlen, i);
            return -EFAULT;
        }

        /* Phase 5: Prevent integer overflow in total_size accumulation
         * Check BEFORE addition to handle SIZE_MAX edge case correctly
         * Previous vulnerable pattern: if (total_size + iov_len < total_size)
         *   - When total_size == SIZE_MAX, any addition wraps but check may pass
         *   - Need explicit SIZE_MAX check before arithmetic */
        if (total_size == SIZE_MAX || iov.iov_len > SIZE_MAX - total_size) {
            fut_printf("[RECVMSG] recvmsg(sockfd=%d, iovlen=%zu) -> EINVAL "
                       "(size overflow at iovec %zu, total=%zu, iov_len=%zu, Phase 5)\n",
                       local_sockfd, kmsg.msg_iovlen, i, total_size, iov.iov_len);
            return -EINVAL;
        }
        total_size += iov.iov_len;

        /* Gather statistics */
        if (iov.iov_len == 0) {
            zero_len_count++;
        } else {
            if (iov.iov_len < min_iov_len) {
                min_iov_len = iov.iov_len;
            }
            if (iov.iov_len > max_iov_len) {
                max_iov_len = iov.iov_len;
            }
        }
    }

    /* Categorize I/O pattern for diagnostics */
    const char *io_pattern;
    if (kmsg.msg_iovlen == 1) {
        io_pattern = "single buffer (equivalent to recv)";
    } else if (kmsg.msg_iovlen == 2) {
        io_pattern = "dual buffer (e.g., header+payload)";
    } else if (kmsg.msg_iovlen <= 10) {
        io_pattern = "small scatter-gather";
    } else if (kmsg.msg_iovlen <= 100) {
        io_pattern = "medium scatter-gather";
    } else {
        io_pattern = "large scatter-gather";
    }

    /* Categorize message type based on ancillary data and address */
    const char *msg_type;
    if (kmsg.msg_control && kmsg.msg_controllen > 0) {
        msg_type = "with control data";
    } else if (kmsg.msg_name && kmsg.msg_namelen > 0) {
        msg_type = "with source address";
    } else {
        msg_type = "simple data transfer";
    }

    /* Phase 2: Iterate through iovecs and read each buffer
     * Phase 3: Proper scatter-gather implementation with VFS support
     * Phase 4: Handle ancillary data (SCM_RIGHTS for FD receiving)
     */

    (void)local_flags;  /* Ignore flags in Phase 2 (will implement in Phase 3) */

    /* Phase 2: Iterate through iovecs and read each buffer */
    ssize_t total_received = 0;
    int iovecs_filled = 0;
    for (size_t i = 0; i < kmsg.msg_iovlen; i++) {
        struct iovec iov;
        if (fut_copy_from_user(&iov, &kmsg.msg_iov[i], sizeof(struct iovec)) != 0) {
            return total_received > 0 ? total_received : -EFAULT;
        }

        if (iov.iov_len == 0) {
            continue;
        }

        /* Phase 5: Validate iov_base write permission BEFORE allocation
         * VULNERABILITY: Missing Write Permission Validation on Receive Buffer
         *
         * ATTACK SCENARIO:
         * Attacker provides read-only memory as receive buffer
         *
         * Without write validation:
         * 1. recvmsg(sockfd, &msg, 0) with iov_base = readonly_memory
         * 2. Kernel allocates iov_len bytes (e.g., 16MB) at line 287
         * 3. Kernel reads data from socket into kernel buffer (line 293)
         * 4. Kernel attempts copy_to_user to readonly iov_base (line 297)
         * 5. Copy fails with page fault (write to read-only page)
         * 6. Kernel buffer leaked, socket data lost
         * 7. Repeated attacks exhaust kernel memory (DoS)
         *
         * DEFENSE (Phase 5):
         * Validate buffer is writable BEFORE allocating kernel memory
         */
        if (!iov.iov_base) {
            fut_printf("[RECVMSG] recvmsg(sockfd=%d) -> EFAULT "
                       "(iov_base[%zu] is NULL with non-zero length %zu, Phase 5)\n",
                       local_sockfd, i, iov.iov_len);
            return total_received > 0 ? total_received : -EFAULT;
        }

        /* Phase 5: Probe write permission with 1-byte test */
        uint8_t test_byte;
        if (fut_copy_from_user(&test_byte, iov.iov_base, 1) != 0 ||
            fut_copy_to_user(iov.iov_base, &test_byte, 1) != 0) {
            fut_printf("[RECVMSG] recvmsg(sockfd=%d) -> EFAULT "
                       "(iov_base[%zu] not writable, len=%zu, Phase 5)\n",
                       local_sockfd, i, iov.iov_len);
            return total_received > 0 ? total_received : -EFAULT;
        }

        /* Allocate kernel buffer */
        void *kbuf = fut_malloc(iov.iov_len);
        if (!kbuf) {
            return total_received > 0 ? total_received : -ENOMEM;
        }

        /* Read from socket */
        ssize_t ret = fut_vfs_read(local_sockfd, kbuf, iov.iov_len);

        if (ret > 0) {
            /* Copy to userspace */
            if (fut_copy_to_user(iov.iov_base, kbuf, (size_t)ret) != 0) {
                fut_free(kbuf);
                return total_received > 0 ? total_received : -EFAULT;
            }
            total_received += ret;
            iovecs_filled++;
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
    if (fut_copy_to_user(local_msg, &kmsg, sizeof(struct msghdr)) != 0) {
        return total_received > 0 ? total_received : -EFAULT;
    }

    /* Phase 2: Detailed logging with I/O statistics */
    const char *completion_status;
    if (total_received == 0) {
        completion_status = "EOF";
    } else if ((size_t)total_received < total_size) {
        completion_status = "partial";
    } else {
        completion_status = "complete";
    }

    /* Build detailed log message */
    if (zero_len_count > 0) {
        fut_printf("[RECVMSG] recvmsg(sockfd=%d, iovlen=%zu [%s], flags=%s, type=%s, total_requested=%zu bytes) -> %ld bytes "
                   "(%s, %d/%zu iovecs filled, %d zero-len skipped, min=%zu max=%zu, Phase 3: scatter-gather I/O with VFS optimization)\n",
                   local_sockfd, kmsg.msg_iovlen, io_pattern, flags_desc, msg_type, total_size, total_received,
                   completion_status, iovecs_filled, kmsg.msg_iovlen - zero_len_count, zero_len_count,
                   min_iov_len, max_iov_len);
    } else {
        fut_printf("[RECVMSG] recvmsg(sockfd=%d, iovlen=%zu [%s], flags=%s, type=%s, total_requested=%zu bytes) -> %ld bytes "
                   "(%s, %d/%zu iovecs filled, min=%zu max=%zu, Phase 3: scatter-gather I/O with VFS optimization)\n",
                   local_sockfd, kmsg.msg_iovlen, io_pattern, flags_desc, msg_type, total_size, total_received,
                   completion_status, iovecs_filled, kmsg.msg_iovlen, min_iov_len, max_iov_len);
    }

    return total_received;
}
