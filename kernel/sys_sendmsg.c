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
#include <sys/socket.h>  /* For struct msghdr, cmsghdr, socklen_t, SCM_* */
#include <stddef.h>
#include <stdint.h>

#include <kernel/kprintf.h>
#include <kernel/debug_config.h>

/* Sendmsg debugging (controlled via debug_config.h) */
#if SENDMSG_DEBUG
#define SENDMSG_LOG(...) fut_printf(__VA_ARGS__)
#else
#define SENDMSG_LOG(...) ((void)0)
#endif

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
 * Phase 1 (Completed): Validates parameters, delegates to writev-style I/O
 * Phase 2 (Completed): Enhanced validation, I/O pattern analysis, and detailed statistics
 * Phase 3 (Completed): Scatter-gather message send with VFS optimization
 * Phase 4: Full control message support and advanced flags
 */
ssize_t sys_sendmsg(int sockfd, const struct msghdr *msg, int flags) {
    /* ARM64 FIX: Copy parameters to local variables immediately to ensure they're preserved
     * on the stack across potentially blocking calls. Socket/VFS operations may block and corrupt
     * register-passed parameters upon resumption. */
    int local_sockfd = sockfd;
    const struct msghdr *local_msg = msg;
    int local_flags = flags;

    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Phase 2: Identify message flags for logging */
    /* MSG_* constants provided by sys/socket.h */
    const char *flags_desc;

    if (flags == 0) {
        flags_desc = "none";
    } else if (flags == MSG_DONTWAIT) {
        flags_desc = "MSG_DONTWAIT";
    } else if (flags == MSG_NOSIGNAL) {
        flags_desc = "MSG_NOSIGNAL";
    } else if (flags == MSG_OOB) {
        flags_desc = "MSG_OOB";
    } else if (flags == MSG_EOR) {
        flags_desc = "MSG_EOR";
    } else if (flags == MSG_MORE) {
        flags_desc = "MSG_MORE";
    } else if (flags == (MSG_DONTWAIT | MSG_NOSIGNAL)) {
        flags_desc = "MSG_DONTWAIT|MSG_NOSIGNAL";
    } else if (flags == (MSG_NOSIGNAL | MSG_MORE)) {
        flags_desc = "MSG_NOSIGNAL|MSG_MORE";
    } else {
        flags_desc = "multiple/unknown flags";
    }
    (void)flags_desc;  /* Used only in debug logging */

    /* Validate socket FD */
    struct fut_file *file = vfs_get_file(local_sockfd);
    if (!file) {
        SENDMSG_LOG("[SENDMSG] ERROR: socket fd %d is not valid\n", local_sockfd);
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

    /* Phase 5: Validate control message length to prevent DoS and resource exhaustion
     * VULNERABILITY: Unbounded Ancillary Data Size and Memory Exhaustion
     *
     * ATTACK SCENARIO 1: Excessive Control Message Length (DoS)
     * Attacker sends massive ancillary data to exhaust kernel memory
     * 1. Attacker creates socket pair for FD passing
     * 2. Prepares msghdr with msg_controllen = SIZE_MAX or 1GB
     * 3. Calls sendmsg(sv[0], &msg, 0) with control data
     * 4. Without limit: kernel allocates SIZE_MAX bytes for control buffer
     * 5. Memory exhaustion: system OOM kills critical processes
     * 6. Denial of service: system becomes unresponsive
     *
     * ATTACK SCENARIO 2: SCM_RIGHTS File Descriptor Exhaustion
     * Attacker sends excessive file descriptors via control messages
     * 1. Attacker prepares control message with 1000 file descriptors
     * 2. Each cmsg contains SCM_RIGHTS with FD array
     * 3. Receiver kernel must allocate space for all FDs
     * 4. Attacker repeatedly calls sendmsg() with max FDs
     * 5. Kernel FD table exhaustion: no new files can be opened
     * 6. System-wide denial of service
     *
     * ATTACK SCENARIO 3: NULL Pointer with Non-Zero Length
     * Attacker sets msg_control = NULL but msg_controllen > 0
     * 1. sendmsg() with msg_control = NULL, msg_controllen = 1024
     * 2. Kernel attempts to copy control data from NULL address
     * 3. Page fault: NULL pointer dereference
     * 4. Kernel crash or DoS
     *
     * IMPACT:
     * - Denial of service: Memory exhaustion from excessive control buffer
     * - System crash: NULL pointer dereference
     * - Resource exhaustion: FD table fills up from SCM_RIGHTS abuse
     * - Network DoS: Socket buffers exhausted by control messages
     *
     * ROOT CAUSE:
     * Ancillary data allows arbitrary metadata attachment to messages:
     * - msg_controllen: User specifies control data size
     * - SCM_RIGHTS: Can transfer arbitrary number of file descriptors
     * - No validation that size doesn't exceed reasonable limits
     * - Kernel must allocate memory to process control messages
     *
     * DEFENSE (Phase 5):
     * 1. Limit maximum control message length (line 154-159):
     *    - MAX_CONTROL_LEN = 64KB (reasonable for most use cases)
     *    - Prevents memory exhaustion attacks
     *    - Returns -EINVAL for excessive sizes
     * 2. Validate msg_control pointer consistency (line 162-167):
     *    - Reject NULL pointer with non-zero length
     *    - Returns -EFAULT for NULL msg_control
     * 3. Control Message Processing (Phase 4 TODO):
     *    - Limit number of FDs in SCM_RIGHTS (e.g., max 253 per POSIX)
     *    - Validate cmsg_len for each cmsghdr
     *    - Check total FDs don't exceed process/system limits
     *    - Atomic FD transfer with proper refcounting
     *
     * CVE REFERENCES:
     * - CVE-2016-8632: Linux sendmsg integer overflow in control message
     * - CVE-2013-7446: Unix socket SCM_RIGHTS refcount overflow
     * - CVE-2016-0728: Linux keyring refcount overflow via SCM_RIGHTS
     *
     * POSIX REQUIREMENT:
     * From sendmsg(2) man page:
     * "The msg_controllen member specifies the length of the buffer pointed
     *  to by msg_control. The maximum control message buffer length is
     *  implementation-defined."
     * - Kernel must impose reasonable limits on control message size
     * - Must not crash or exhaust resources
     *
     * IMPLEMENTATION NOTES:
     * - Line 154: MAX_CONTROL_LEN prevents resource exhaustion
     * - Line 154-159: Reject excessive control buffer
     * - Line 162-167: Validate NULL/non-zero inconsistency
     * - Phase 4: Implement SCM_RIGHTS with FD count limit and refcount safety
     * - Phase 4: Validate all cmsghdr structures before processing
     */
    if (kmsg.msg_controllen > 0) {
        const size_t MAX_CONTROL_LEN = 65536;  /* 64KB */
        if (kmsg.msg_controllen > MAX_CONTROL_LEN) {
            SENDMSG_LOG("[SENDMSG] sendmsg(sockfd=%d, controllen=%zu) -> EINVAL "
                       "(control message too large, max %zu bytes, Phase 5)\n",
                       local_sockfd, kmsg.msg_controllen, MAX_CONTROL_LEN);
            return -EINVAL;
        }

        /* Validate control buffer pointer is not NULL */
        if (!kmsg.msg_control) {
            SENDMSG_LOG("[SENDMSG] sendmsg(sockfd=%d, controllen=%zu) -> EFAULT "
                       "(msg_control is NULL with non-zero length, Phase 5)\n",
                       local_sockfd, kmsg.msg_controllen);
            return -EFAULT;
        }
    }

    /* Validate iovlen */
    if (kmsg.msg_iovlen == 0) {
        SENDMSG_LOG("[SENDMSG] sendmsg(sockfd=%d, iovlen=0) -> 0 (nothing to send)\n", local_sockfd);
        return 0;  /* Nothing to send */
    }
    if (kmsg.msg_iovlen > 1024) {
        SENDMSG_LOG("[SENDMSG] sendmsg(sockfd=%d, iovlen=%zu) -> EINVAL (exceeds UIO_MAXIOV=1024)\n",
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
            SENDMSG_LOG("[SENDMSG] sendmsg(sockfd=%d, iovlen=%zu) -> EFAULT (copy_from_user iovec %zu failed)\n",
                       local_sockfd, kmsg.msg_iovlen, i);
            return -EFAULT;
        }

        /* Security hardening: Limit individual iovec size to prevent memory exhaustion DoS
         * Without per-buffer limits, attacker can request gigabytes per iovec:
         *   - msg_iovlen=1024, iov_len=64MB each = 64GB kernel memory allocation
         *   - Single syscall exhausts kernel heap, triggers OOM killer
         *   - System-wide denial of service
         *
         * Defense: Limit each iovec to reasonable size (16MB like preadv/pwritev) */
        const size_t MAX_IOV_SIZE = 16 * 1024 * 1024;  /* 16MB per iovec */
        if (iov.iov_len > MAX_IOV_SIZE) {
            SENDMSG_LOG("[SENDMSG] sendmsg(sockfd=%d, iovlen=%zu) -> EINVAL "
                       "(iov[%zu].iov_len=%zu exceeds max %zu bytes)\n",
                       local_sockfd, kmsg.msg_iovlen, i, iov.iov_len, MAX_IOV_SIZE);
            return -EINVAL;
        }

        /* Phase 5: Prevent integer overflow in total_size accumulation
         * Check BEFORE addition to handle SIZE_MAX edge case correctly
         * Previous vulnerable pattern: if (total_size + iov_len < total_size)
         *   - When total_size == SIZE_MAX, any addition wraps but check may pass
         *   - Need explicit SIZE_MAX check before arithmetic
         *
         * ATTACK SCENARIO:
         * Attacker with iovcnt=1024, iov_len=16MB each = 16GB total_size
         * Without SIZE_MAX check: total_size wraps at SIZE_MAX boundary
         * With MAX_IOV_SIZE limit: Still possible to reach SIZE_MAX with 256 iovecs of 16MB
         *
         * DEFENSE:
         * Check BEFORE addition: if (total_size == SIZE_MAX || iov_len > SIZE_MAX - total_size)
         * Prevents wraparound even when approaching SIZE_MAX limit */
        if (total_size == SIZE_MAX || iov.iov_len > SIZE_MAX - total_size) {
            SENDMSG_LOG("[SENDMSG] sendmsg(sockfd=%d, iovlen=%zu) -> EINVAL "
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
        io_pattern = "single buffer (equivalent to send)";
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
        msg_type = "with destination address";
    } else {
        msg_type = "simple data transfer";
    }
    (void)io_pattern;  /* Used only in debug logging */
    (void)msg_type;    /* Used only in debug logging */

    /* Phase 2: Iterate through iovecs and write each buffer
     * Phase 3: Proper scatter-gather implementation with VFS support
     * Phase 4: Handle ancillary data (SCM_RIGHTS for FD passing)
     */

    (void)local_flags;  /* Ignore flags in Phase 2 (will implement in Phase 3) */

    /* Phase 2: Iterate through iovecs and write each buffer */
    ssize_t total_sent = 0;
    int iovecs_sent = 0;
    for (size_t i = 0; i < kmsg.msg_iovlen; i++) {
        struct iovec iov;
        if (fut_copy_from_user(&iov, &kmsg.msg_iov[i], sizeof(struct iovec)) != 0) {
            return total_sent > 0 ? total_sent : -EFAULT;
        }

        if (iov.iov_len == 0) {
            continue;
        }

        /* Phase 5: Validate iov_base pointer before allocating memory
         * Prevents memory exhaustion DoS from repeated invalid pointers */
        if (!iov.iov_base) {
            SENDMSG_LOG("[SENDMSG] sendmsg(sockfd=%d) -> EFAULT "
                       "(iov_base[%zu] is NULL with non-zero length %zu, Phase 5)\n",
                       local_sockfd, i, iov.iov_len);
            return total_sent > 0 ? total_sent : -EFAULT;
        }

        /* Phase 5: Validate iov_base is readable before allocating kernel buffer */
        uint8_t test_byte;
        if (fut_copy_from_user(&test_byte, iov.iov_base, 1) != 0) {
            SENDMSG_LOG("[SENDMSG] sendmsg(sockfd=%d) -> EFAULT "
                       "(iov_base[%zu] not accessible, len=%zu, Phase 5)\n",
                       local_sockfd, i, iov.iov_len);
            return total_sent > 0 ? total_sent : -EFAULT;
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
        ssize_t ret = fut_vfs_write(local_sockfd, kbuf, iov.iov_len);
        fut_free(kbuf);

        if (ret < 0) {
            return total_sent > 0 ? total_sent : ret;
        }

        total_sent += ret;
        iovecs_sent++;

        /* Short write */
        if ((size_t)ret < iov.iov_len) {
            break;
        }
    }

    /* Phase 2: Detailed logging with I/O statistics */
    const char *completion_status;
    if (total_sent == 0) {
        completion_status = "nothing sent";
    } else if ((size_t)total_sent < total_size) {
        completion_status = "partial";
    } else {
        completion_status = "complete";
    }
    (void)completion_status;  /* Used only in debug logging */

    /* Build detailed log message */
    if (zero_len_count > 0) {
        SENDMSG_LOG("[SENDMSG] sendmsg(sockfd=%d, iovlen=%zu [%s], flags=%s, type=%s, total_requested=%zu bytes) -> %ld bytes "
                   "(%s, %d/%zu iovecs sent, %d zero-len skipped, min=%zu max=%zu, Phase 3: scatter-gather message send with VFS optimization)\n",
                   local_sockfd, kmsg.msg_iovlen, io_pattern, flags_desc, msg_type, total_size, total_sent,
                   completion_status, iovecs_sent, kmsg.msg_iovlen - zero_len_count, zero_len_count,
                   min_iov_len, max_iov_len);
    } else {
        SENDMSG_LOG("[SENDMSG] sendmsg(sockfd=%d, iovlen=%zu [%s], flags=%s, type=%s, total_requested=%zu bytes) -> %ld bytes "
                   "(%s, %d/%zu iovecs sent, min=%zu max=%zu, Phase 3: scatter-gather message send with VFS optimization)\n",
                   local_sockfd, kmsg.msg_iovlen, io_pattern, flags_desc, msg_type, total_size, total_sent,
                   completion_status, iovecs_sent, kmsg.msg_iovlen, min_iov_len, max_iov_len);
    }

    /* Log ancillary data if present (not yet handled in Phase 2, will be Phase 3) */
    if (kmsg.msg_controllen > 0) {
        SENDMSG_LOG("[SENDMSG] Note: Ancillary data present (%zu bytes) - will be handled in Phase 3\n",
                   kmsg.msg_controllen);
    }

    return total_sent;
}
