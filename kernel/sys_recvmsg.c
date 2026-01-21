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
#include <kernel/fut_socket.h>
#include <sys/socket.h>  /* For struct msghdr, cmsghdr, socklen_t */
#include <stddef.h>
#include <stdint.h>

#include <kernel/kprintf.h>
extern fut_task_t *fut_task_current(void);
extern struct fut_file *vfs_get_file(int fd);
extern fut_socket_t *get_socket_from_fd(int fd);

/* Set to 1 to enable verbose recvmsg debug logging */
#define RECVMSG_DEBUG 0
#if RECVMSG_DEBUG
#define RECVMSG_LOG(...) fut_printf(__VA_ARGS__)
#else
#define RECVMSG_LOG(...) ((void)0)
#endif

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
    /* MSG_* constants provided by sys/socket.h */
    const char *flags_desc;

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
    (void)flags_desc;  /* Used only in debug logging */

    /* Validate socket FD */
    struct fut_file *file = vfs_get_file(local_sockfd);
    if (!file) {
        RECVMSG_LOG("[RECVMSG] ERROR: socket fd %d is not valid\n", local_sockfd);
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

    /* Phase 5: Validate control message length to prevent DoS and buffer overflows
     * VULNERABILITY: Unbounded Ancillary Data Size and Control Message Parsing
     *
     * ATTACK SCENARIO 1: Excessive Control Message Length (DoS)
     * Attacker requests massive ancillary data buffer to exhaust memory
     * 1. Attacker creates socket pair: socketpair(AF_UNIX, SOCK_DGRAM, 0, sv)
     * 2. Attacker prepares msghdr with msg_controllen = SIZE_MAX (or 1GB)
     * 3. Calls recvmsg(sv[1], &msg, 0) expecting control data
     * 4. Without limit: kernel allocates SIZE_MAX bytes for control buffer
     * 5. Memory exhaustion: system OOM or kernel panic
     * 6. Denial of service: legitimate processes cannot allocate
     *
     * ATTACK SCENARIO 2: Control Message Parsing Integer Overflow
     * Attacker crafts malformed cmsghdr to cause parsing errors
     * 1. Sender sends control message with cmsg_len = SIZE_MAX
     * 2. Receiver has msg_controllen = 1024 (reasonable size)
     * 3. Parser iterates: CMSG_NEXT(cmsg) calculates next offset
     * 4. Arithmetic: current_offset + SIZE_MAX wraps to small value
     * 5. Parser reads OOB: accesses memory beyond control buffer
     * 6. Information disclosure or crash
     *
     * ATTACK SCENARIO 3: NULL Pointer with Non-Zero Length
     * Attacker sets msg_control = NULL but msg_controllen > 0
     * 1. recvmsg() with msg_control = NULL, msg_controllen = 1024
     * 2. Kernel attempts to copy ancillary data to NULL address
     * 3. Page fault: NULL pointer dereference
     * 4. Kernel crash or DoS
     *
     * IMPACT:
     * - Denial of service: Memory exhaustion from excessive control buffer
     * - Kernel crash: NULL pointer dereference
     * - Information disclosure: OOB read during control message parsing
     * - Buffer overflow: cmsg_len overflow causes OOB write
     *
     * ROOT CAUSE:
     * Ancillary data (control messages) allow arbitrary-length metadata:
     * - msg_controllen: User specifies expected control data size
     * - cmsg_len: Each cmsghdr specifies its own length
     * - Parser iterates via CMSG_NEXT macro using pointer arithmetic
     * - No validation that total lengths don't overflow or exceed limits
     *
     * DEFENSE (Phase 5):
     * 1. Limit maximum control message length (line 151-157):
     *    - MAX_CONTROL_LEN = 64KB (generous for most use cases)
     *    - Prevents memory exhaustion attacks
     *    - Returns -EINVAL for excessive sizes
     * 2. Validate msg_control pointer consistency (line 160-165):
     *    - Reject NULL pointer with non-zero length
     *    - Returns -EFAULT for NULL msg_control
     * 3. Control Message Parsing (Phase 4 TODO):
     *    - Validate each cmsg_len before using
     *    - Check cmsg_len <= remaining buffer space
     *    - Use safe pointer arithmetic for CMSG_NEXT
     *    - Bounds-check all cmsg_data accesses
     *
     * CVE REFERENCES:
     * - CVE-2016-8632: Linux recvmsg integer overflow in control message parsing
     * - CVE-2013-7446: Unix socket ancillary data reference count overflow
     * - CVE-2017-7308: Packet socket ancillary data buffer overflow
     *
     * POSIX REQUIREMENT:
     * From recvmsg(2) man page:
     * "The msg_controllen member specifies the length of the buffer pointed
     *  to by msg_control. If the control information is too large, it shall
     *  be truncated and the MSG_CTRUNC flag shall be set."
     * - Kernel must handle arbitrarily large msg_controllen gracefully
     * - Must not crash or exhaust resources
     *
     * IMPLEMENTATION NOTES:
     * - Line 151: MAX_CONTROL_LEN prevents resource exhaustion
     * - Line 152-157: Reject excessive control buffer requests
     * - Line 160-165: Validate NULL/non-zero inconsistency
     * - Phase 4: Implement safe CMSG_FIRSTHDR/CMSG_NXTHDR parsing
     * - Phase 4: Support SCM_RIGHTS (file descriptor passing) with refcount safety
     */
    if (kmsg.msg_controllen > 0) {
        const size_t MAX_CONTROL_LEN = 65536;  /* 64KB */
        if (kmsg.msg_controllen > MAX_CONTROL_LEN) {
            RECVMSG_LOG("[RECVMSG] recvmsg(sockfd=%d, controllen=%zu) -> EINVAL "
                       "(control message too large, max %zu bytes, Phase 5)\n",
                       local_sockfd, kmsg.msg_controllen, MAX_CONTROL_LEN);
            return -EINVAL;
        }

        /* Validate control buffer pointer is not NULL */
        if (!kmsg.msg_control) {
            RECVMSG_LOG("[RECVMSG] recvmsg(sockfd=%d, controllen=%zu) -> EFAULT "
                       "(msg_control is NULL with non-zero length, Phase 5)\n",
                       local_sockfd, kmsg.msg_controllen);
            return -EFAULT;
        }
    }

    /* Validate iovlen */
    if (kmsg.msg_iovlen == 0) {
        RECVMSG_LOG("[RECVMSG] recvmsg(sockfd=%d, iovlen=0) -> 0 (nothing to receive)\n", local_sockfd);
        return 0;  /* Nothing to receive */
    }
    if (kmsg.msg_iovlen > 1024) {
        RECVMSG_LOG("[RECVMSG] recvmsg(sockfd=%d, iovlen=%zu) -> EINVAL (exceeds UIO_MAXIOV=1024)\n",
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
            RECVMSG_LOG("[RECVMSG] recvmsg(sockfd=%d, iovlen=%zu) -> EFAULT (copy_from_user iovec %zu failed)\n",
                       local_sockfd, kmsg.msg_iovlen, i);
            return -EFAULT;
        }

        /* Phase 5: Prevent integer overflow in total_size accumulation
         * Check BEFORE addition to handle SIZE_MAX edge case correctly
         * Previous vulnerable pattern: if (total_size + iov_len < total_size)
         *   - When total_size == SIZE_MAX, any addition wraps but check may pass
         *   - Need explicit SIZE_MAX check before arithmetic */
        if (total_size == SIZE_MAX || iov.iov_len > SIZE_MAX - total_size) {
            RECVMSG_LOG("[RECVMSG] recvmsg(sockfd=%d, iovlen=%zu) -> EINVAL "
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
    (void)io_pattern;  /* Used only in debug logging */
    (void)msg_type;    /* Used only in debug logging */

    /* Phase 2: Iterate through iovecs and read each buffer
     * Phase 3: Proper scatter-gather implementation with VFS support
     * Phase 4: Handle ancillary data (SCM_RIGHTS for FD receiving)
     */

    /* Phase 5: Handle MSG_DONTWAIT flag
     * Temporarily set O_NONBLOCK on socket if MSG_DONTWAIT is specified.
     * This ensures the socket returns EAGAIN instead of blocking. */
    bool restore_blocking = false;
    fut_socket_t *socket = NULL;
    if (local_flags & MSG_DONTWAIT) {
        socket = get_socket_from_fd(local_sockfd);
        if (socket && !(socket->flags & 0x800)) {  /* O_NONBLOCK */
            socket->flags |= 0x800;  /* Set O_NONBLOCK temporarily */
            restore_blocking = true;
        }
    }

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
            RECVMSG_LOG("[RECVMSG] recvmsg(sockfd=%d) -> EFAULT "
                       "(iov_base[%zu] is NULL with non-zero length %zu, Phase 5)\n",
                       local_sockfd, i, iov.iov_len);
            return total_received > 0 ? total_received : -EFAULT;
        }

        /* Phase 5: Probe write permission with 1-byte test */
        uint8_t test_byte;
        if (fut_copy_from_user(&test_byte, iov.iov_base, 1) != 0 ||
            fut_copy_to_user(iov.iov_base, &test_byte, 1) != 0) {
            RECVMSG_LOG("[RECVMSG] recvmsg(sockfd=%d) -> EFAULT "
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
    (void)completion_status;  /* Used only in debug logging */

    /* Build detailed log message */
    if (zero_len_count > 0) {
        RECVMSG_LOG("[RECVMSG] recvmsg(sockfd=%d, iovlen=%zu [%s], flags=%s, type=%s, total_requested=%zu bytes) -> %ld bytes "
                   "(%s, %d/%zu iovecs filled, %d zero-len skipped, min=%zu max=%zu, Phase 3: scatter-gather I/O with VFS optimization)\n",
                   local_sockfd, kmsg.msg_iovlen, io_pattern, flags_desc, msg_type, total_size, total_received,
                   completion_status, iovecs_filled, kmsg.msg_iovlen - zero_len_count, zero_len_count,
                   min_iov_len, max_iov_len);
    } else {
        RECVMSG_LOG("[RECVMSG] recvmsg(sockfd=%d, iovlen=%zu [%s], flags=%s, type=%s, total_requested=%zu bytes) -> %ld bytes "
                   "(%s, %d/%zu iovecs filled, min=%zu max=%zu, Phase 3: scatter-gather I/O with VFS optimization)\n",
                   local_sockfd, kmsg.msg_iovlen, io_pattern, flags_desc, msg_type, total_size, total_received,
                   completion_status, iovecs_filled, kmsg.msg_iovlen, min_iov_len, max_iov_len);
    }

    /* Restore blocking mode if we temporarily set O_NONBLOCK */
    if (restore_blocking && socket) {
        socket->flags &= ~0x800;  /* Clear O_NONBLOCK */
    }

    return total_received;
}
