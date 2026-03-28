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
#include <kernel/fut_timer.h>
#include <sys/socket.h>  /* For struct msghdr, cmsghdr, socklen_t, SCM_RIGHTS */
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include <kernel/kprintf.h>
#include <kernel/debug_config.h>

#include <platform/platform.h>

static inline int recvmsg_copy_from_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)src >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_from_user(dst, src, n);
}
static inline int recvmsg_copy_to_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)dst >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_to_user(dst, src, n);
}

/* Recvmsg debugging (controlled via debug_config.h) */
#if RECVMSG_DEBUG
#define RECVMSG_LOG(...) fut_printf(__VA_ARGS__)
#else
#define RECVMSG_LOG(...) ((void)0)
#endif

/* Socket constants (SOL_SOCKET, SCM_RIGHTS) provided by fut_socket.h and sys/socket.h */

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
    if (recvmsg_copy_from_user(&kmsg, local_msg, sizeof(struct msghdr)) != 0) {
        return -EFAULT;
    }

    /* Validate control message length to prevent DoS and buffer overflows
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
     * DEFENSE:
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
                       "(control message too large, max %zu bytes)\n",
                       local_sockfd, kmsg.msg_controllen, MAX_CONTROL_LEN);
            return -EINVAL;
        }

        /* Validate control buffer pointer is not NULL */
        if (!kmsg.msg_control) {
            RECVMSG_LOG("[RECVMSG] recvmsg(sockfd=%d, controllen=%zu) -> EFAULT "
                       "(msg_control is NULL with non-zero length)\n",
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
        if (recvmsg_copy_from_user(&iov, &kmsg.msg_iov[i], sizeof(struct iovec)) != 0) {
            RECVMSG_LOG("[RECVMSG] recvmsg(sockfd=%d, iovlen=%zu) -> EFAULT (copy_from_user iovec %zu failed)\n",
                       local_sockfd, kmsg.msg_iovlen, i);
            return -EFAULT;
        }

        /* Prevent integer overflow in total_size accumulation
         * Check BEFORE addition to handle SIZE_MAX edge case correctly
         * Previous vulnerable pattern: if (total_size + iov_len < total_size)
         *   - When total_size == SIZE_MAX, any addition wraps but check may pass
         *   - Need explicit SIZE_MAX check before arithmetic */
        if (total_size == SIZE_MAX || iov.iov_len > SIZE_MAX - total_size) {
            RECVMSG_LOG("[RECVMSG] recvmsg(sockfd=%d, iovlen=%zu) -> EINVAL "
                       "(size overflow at iovec %zu, total=%zu, iov_len=%zu)\n",
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
     * Phase 3 (Completed): Proper scatter-gather implementation with VFS support
     * Phase 4: Handle ancillary data (SCM_RIGHTS for FD receiving)
     */

    /* AF_NETLINK: drain pre-built response directly into the first iov. */
    {
        extern fut_socket_t *get_socket_from_fd(int fd);
        fut_socket_t *nl_sock = get_socket_from_fd(local_sockfd);
        if (nl_sock && nl_sock->address_family == 16 /* AF_NETLINK */) {
            extern ssize_t netlink_handle_recv(fut_socket_t *sock,
                                               void *out_buf, size_t out_len);
            ssize_t total_nl = 0;
            for (size_t i = 0; i < kmsg.msg_iovlen; i++) {
                struct iovec iov;
                if (recvmsg_copy_from_user(&iov, &kmsg.msg_iov[i], sizeof(iov)) != 0)
                    break;
                if (!iov.iov_base || iov.iov_len == 0) continue;
                /* Allocate a kernel bounce buffer */
                void *kbuf = fut_malloc(iov.iov_len);
                if (!kbuf) break;
                ssize_t got = netlink_handle_recv(nl_sock, kbuf, iov.iov_len);
                if (got > 0) {
                    if (recvmsg_copy_to_user(iov.iov_base, kbuf, (size_t)got) != 0) {
                        fut_free(kbuf);
                        break;
                    }
                    total_nl += got;
                }
                fut_free(kbuf);
                if (got <= 0) break;
            }
            return total_nl;
        }
    }

    /* Apply MSG_DONTWAIT via per-task flag (avoids mutating shared sock->flags) */
    fut_task_t *dw_task = fut_task_current();
    int saved_dontwait = 0;
    if ((local_flags & MSG_DONTWAIT) && dw_task) {
        saved_dontwait = dw_task->msg_dontwait;
        dw_task->msg_dontwait = 1;
    }

    /* Phase 2: Iterate through iovecs and read each buffer */
    ssize_t total_received = 0;
    int iovecs_filled = 0;
    bool msg_trunc_set = false;
    size_t dgram_actual_len = 0;  /* Real datagram length for MSG_TRUNC return value */
    /* Identify DGRAM socket once; used for MSG_TRUNC and direct dgram recv path */
    fut_socket_t *dgsock = get_socket_from_fd(local_sockfd);
    /* Named DGRAM (no stream pair): use direct dgram path for MSG_TRUNC detection.
     * Socketpair DGRAM sockets have pair!=NULL and use the stream recv path. */
    bool is_dgram_sock = (dgsock && dgsock->socket_type == SOCK_DGRAM &&
                          !dgsock->pair && dgsock->dgram_queue != NULL);
    /* Sender address for DGRAM recvmsg (filled by fut_socket_recvfrom_dgram) */
    char dgram_sender_path[108];
    uint16_t dgram_sender_path_len = 0;
    for (size_t i = 0; i < kmsg.msg_iovlen; i++) {
        struct iovec iov;
        if (recvmsg_copy_from_user(&iov, &kmsg.msg_iov[i], sizeof(struct iovec)) != 0) {
            if (total_received == 0) total_received = -EFAULT;
            goto iov_loop_done;
        }

        if (iov.iov_len == 0) {
            continue;
        }

        /* Validate iov_base write permission BEFORE allocation
         * VULNERABILITY: Missing Write Permission Validation on Receive Buffer
         *
         * ATTACK SCENARIO:
         * Attacker provides read-only memory as receive buffer
         *
         * Without write validation:
         * 1. recvmsg(sockfd, &msg, 0) with iov_base = readonly_memory
         * 2. Kernel allocates iov_len bytes (e.g., 16MB)
         * 3. Kernel reads data from socket into kernel buffer
         * 4. Kernel attempts copy_to_user to readonly iov_base
         * 5. Copy fails with page fault (write to read-only page)
         * 6. Kernel buffer leaked, socket data lost
         * 7. Repeated attacks exhaust kernel memory (DoS)
         *
         * DEFENSE:
         * Validate buffer is writable BEFORE allocating kernel memory
         */
        if (!iov.iov_base) {
            RECVMSG_LOG("[RECVMSG] recvmsg(sockfd=%d) -> EFAULT "
                       "(iov_base[%zu] is NULL with non-zero length %zu)\n",
                       local_sockfd, i, iov.iov_len);
            if (total_received == 0) total_received = -EFAULT;
            goto iov_loop_done;
        }

        /* Probe write permission with 1-byte test */
        uint8_t test_byte;
        if (recvmsg_copy_from_user(&test_byte, iov.iov_base, 1) != 0 ||
            recvmsg_copy_to_user(iov.iov_base, &test_byte, 1) != 0) {
            RECVMSG_LOG("[RECVMSG] recvmsg(sockfd=%d) -> EFAULT "
                       "(iov_base[%zu] not writable, len=%zu)\n",
                       local_sockfd, i, iov.iov_len);
            if (total_received == 0) total_received = -EFAULT;
            goto iov_loop_done;
        }

        /* Allocate kernel buffer */
        void *kbuf = fut_malloc(iov.iov_len);
        if (!kbuf) {
            if (total_received == 0) total_received = -ENOMEM;
            goto iov_loop_done;
        }

        /* Read from socket.
         * MSG_PEEK: read without consuming (peek at data).
         * DGRAM: use fut_socket_recvfrom_dgram or fut_socket_peek_dgram.
         * MSG_WAITALL: loop until the full iovec is filled (stream sockets only).
         * SEQPACKET is message-oriented: MSG_WAITALL must be ignored to avoid
         * concatenating messages across boundaries (same fix as sys_recvfrom.c). */
        bool is_msg_socket = dgsock &&
            (dgsock->socket_type == SOCK_DGRAM || dgsock->socket_type == SOCK_SEQPACKET);
        bool do_waitall = (local_flags & MSG_WAITALL) && !(local_flags & MSG_DONTWAIT)
                          && !is_msg_socket;
        bool do_peek = (local_flags & MSG_PEEK) != 0;
        ssize_t ret;
        if (is_dgram_sock) {
            size_t actual_len = 0;
            if (do_peek) {
                /* MSG_PEEK on DGRAM: peek without consuming the datagram */
                extern ssize_t fut_socket_peek_dgram(fut_socket_t *sock, void *buf, size_t len,
                                                      char *sender_path_out, uint16_t *sender_path_len_out,
                                                      size_t *actual_datagram_len_out);
                ret = fut_socket_peek_dgram(dgsock, kbuf, iov.iov_len,
                                            dgram_sender_path, &dgram_sender_path_len,
                                            &actual_len);
            } else {
                ret = fut_socket_recvfrom_dgram(dgsock, kbuf, iov.iov_len,
                                                dgram_sender_path, &dgram_sender_path_len,
                                                &actual_len);
            }
            if (ret >= 0 && actual_len > iov.iov_len) {
                msg_trunc_set = true;
                dgram_actual_len = actual_len;
            }
        } else if (do_peek) {
            extern ssize_t fut_socket_recv_peek(fut_socket_t *sock, void *buf, size_t len);
            extern fut_socket_t *get_socket_from_fd(int fd);
            fut_socket_t *psock = get_socket_from_fd(local_sockfd);
            ret = psock ? fut_socket_recv_peek(psock, kbuf, iov.iov_len) : -EBADF;
        } else if (do_waitall) {
            ssize_t got = 0;
            ret = 0;
            while ((size_t)got < iov.iov_len) {
                ssize_t rc = fut_vfs_read(local_sockfd,
                                          (char *)kbuf + got,
                                          iov.iov_len - (size_t)got);
                if (rc < 0) { ret = (got > 0) ? got : rc; break; }
                if (rc == 0) { ret = got; break; }
                got += rc;
                ret = got;
            }
        } else {
            ret = fut_vfs_read(local_sockfd, kbuf, iov.iov_len);
        }

        if (ret > 0) {
            /* Copy to userspace */
            if (recvmsg_copy_to_user(iov.iov_base, kbuf, (size_t)ret) != 0) {
                fut_free(kbuf);
                if (total_received == 0) total_received = -EFAULT;
                goto iov_loop_done;
            }
            total_received += ret;
            iovecs_filled++;
        }

        fut_free(kbuf);

        if (ret < 0) {
            if (total_received == 0) total_received = ret;
            goto iov_loop_done;
        }

        if (ret == 0) {
            /* EOF */
            break;
        }

        /* DGRAM/SEQPACKET: each recvmsg reads exactly one message; stop after first iovec.
         * Also check the truncation flag for socketpair DGRAM/SEQPACKET sockets. */
        if (is_dgram_sock) {
            break;
        }
        if (dgsock && (dgsock->socket_type == SOCK_DGRAM || dgsock->socket_type == SOCK_SEQPACKET)
            && dgsock->pair != NULL) {
            if (dgsock->last_recv_full_msg_len > 0)
                msg_trunc_set = true;
            break;
        }

        /* Short read (only if MSG_WAITALL not set) */
        if (!do_waitall && (size_t)ret < iov.iov_len) {
            break;
        }
    }
iov_loop_done:

    /* Fill msg_name with sender address for DGRAM recvmsg */
    if (is_dgram_sock && kmsg.msg_name && kmsg.msg_namelen > 0 && dgram_sender_path_len > 0) {
        struct { unsigned short sun_family; char sun_path[108]; } sun = {0};
        sun.sun_family = 1; /* AF_UNIX */
        size_t path_copy = dgram_sender_path_len < 108 ? dgram_sender_path_len : 107;
        __builtin_memcpy(sun.sun_path, dgram_sender_path, path_copy);
        /* sun_len: 2-byte family + path + NUL (for filesystem paths) */
        unsigned int sun_len = (unsigned int)(2 + path_copy +
            (dgram_sender_path_len == 0 || dgram_sender_path[0] != '\0' ? 1 : 0));
        unsigned int to_copy = (sun_len < kmsg.msg_namelen) ? sun_len : kmsg.msg_namelen;
        recvmsg_copy_to_user(kmsg.msg_name, &sun, to_copy);
        kmsg.msg_namelen = sun_len;
    } else if (!is_dgram_sock) {
        kmsg.msg_namelen = 0;  /* STREAM sockets don't fill msg_name */
    }

    kmsg.msg_flags = msg_trunc_set ? MSG_TRUNC : 0;

    /* SOCK_SEQPACKET: set MSG_EOR when a complete message boundary is received.
     * Each SEQPACKET read returns exactly one message, so MSG_EOR is always set. */
    if (total_received > 0) {
        extern fut_socket_t *get_socket_from_fd(int fd);
        fut_socket_t *eor_sock = get_socket_from_fd(local_sockfd);
        if (eor_sock && eor_sock->socket_type == SOCK_SEQPACKET)
            kmsg.msg_flags |= MSG_EOR;
    }

    /* Phase 4: SCM_RIGHTS - dequeue FDs from socket pair and deliver to receiver */
    kmsg.msg_controllen = 0;  /* Default: no ancillary data */

    if (total_received > 0) {
        extern fut_socket_t *get_socket_from_fd(int fd);
        fut_socket_t *sock = get_socket_from_fd(local_sockfd);

        /* Check the receive-direction pair (pair_reverse) for queued FDs */
        fut_socket_pair_t *recv_pair = sock ? sock->pair_reverse : NULL;
        if (recv_pair && recv_pair->fd_queue_count > 0 &&
            kmsg.msg_control != NULL) {
            /* Dequeue FDs and install in receiver's FD table */
            int new_fds[FUT_SOCKET_FD_QUEUE_MAX];
            int nfds = 0;

            fut_spinlock_acquire(&recv_pair->lock);
            while (recv_pair->fd_queue_count > 0 && nfds < FUT_SOCKET_FD_QUEUE_MAX) {
                uint32_t head = recv_pair->fd_queue_head;
                struct fut_file *file = recv_pair->fd_queue[head];
                recv_pair->fd_queue[head] = NULL;
                recv_pair->fd_queue_head = (head + 1) % FUT_SOCKET_FD_QUEUE_MAX;
                recv_pair->fd_queue_count--;

                if (file) {
                    /* Install file in receiver's FD table */
                    int newfd = vfs_alloc_fd_for_task((struct fut_task *)task, file);
                    if (newfd >= 0) {
                        new_fds[nfds++] = newfd;
                        /* MSG_CMSG_CLOEXEC: set FD_CLOEXEC on received fds (per-FD) */
                        if ((local_flags & MSG_CMSG_CLOEXEC) && task->fd_flags) {
                            task->fd_flags[newfd] |= FD_CLOEXEC;
                        }
                        RECVMSG_LOG("[RECVMSG] SCM_RIGHTS: installed file=%p as fd=%d in receiver\n",
                                   file, newfd);
                    } else {
                        /* Failed to allocate FD — drop the in-flight reference
                         * that was added by sendmsg when it queued this file.
                         * Use the same atomic pattern as vfs_file_ref() in reverse. */
                        RECVMSG_LOG("[RECVMSG] SCM_RIGHTS: fd table full, dropping file=%p\n", file);
                        if (file->refcount > 0)
                            __atomic_sub_fetch(&file->refcount, 1, __ATOMIC_ACQ_REL);
                    }
                }
            }
            fut_spinlock_release(&recv_pair->lock);

            /* Build SCM_RIGHTS control message for userspace */
            if (nfds > 0) {
                size_t cmsg_size = CMSG_SPACE(nfds * sizeof(int));
                /* Check if caller's buffer is big enough; read original controllen */
                size_t orig_controllen = 0;
                struct msghdr user_msg;
                if (recvmsg_copy_from_user(&user_msg, local_msg, sizeof(struct msghdr)) == 0) {
                    orig_controllen = user_msg.msg_controllen;
                }

                if (orig_controllen >= cmsg_size) {
                    /* Build the control message in kernel memory */
                    void *kcontrol = fut_malloc(cmsg_size);
                    if (kcontrol) {
                        /* Zero-fill for alignment padding */
                        for (size_t z = 0; z < cmsg_size; z++)
                            ((uint8_t *)kcontrol)[z] = 0;

                        struct cmsghdr *cmsg = (struct cmsghdr *)kcontrol;
                        cmsg->cmsg_len = CMSG_LEN(nfds * sizeof(int));
                        cmsg->cmsg_level = SOL_SOCKET;
                        cmsg->cmsg_type = SCM_RIGHTS;

                        int *fd_data = (int *)CMSG_DATA(cmsg);
                        for (int fi = 0; fi < nfds; fi++) {
                            fd_data[fi] = new_fds[fi];
                        }

                        /* Copy to userspace control buffer */
                        if (recvmsg_copy_to_user(kmsg.msg_control, kcontrol, cmsg_size) == 0) {
                            kmsg.msg_controllen = cmsg_size;
                        }
                        fut_free(kcontrol);
                    }
                } else {
                    /* Buffer too small - set MSG_CTRUNC to indicate
                     * control data was truncated (FDs were installed but
                     * their numbers could not be reported to userspace). */
                    kmsg.msg_flags |= MSG_CTRUNC;
                }
            }
        }
    }

    /* SO_PASSCRED: attach SCM_CREDENTIALS cmsg when credential passing is enabled.
     * Each received message gets a ucred {pid, uid, gid} from the sending process.
     * For AF_UNIX connected sockets, use the peer credentials captured at
     * connect/accept time (stored in sock->peer_pid/uid/gid).  This correctly
     * identifies the *sender*, not the receiver.  Fallback to the current task's
     * credentials only when the peer creds are unset (e.g. socketpair in the
     * same process where peer_pid is 0). */
    if (total_received > 0 && kmsg.msg_control != NULL) {
        extern fut_socket_t *get_socket_from_fd(int fd);
        fut_socket_t *passcred_sock = get_socket_from_fd(local_sockfd);
        if (passcred_sock && passcred_sock->passcred) {
            struct ucred_t { int32_t pid; uint32_t uid; uint32_t gid; } cred;
            if (passcred_sock->peer_pid != 0) {
                /* Use the peer credentials set at connect/accept time */
                cred.pid = (int32_t)passcred_sock->peer_pid;
                cred.uid = passcred_sock->peer_uid;
                cred.gid = passcred_sock->peer_gid;
            } else {
                /* Fallback for socketpair (same-process): use current task */
                cred.pid = task ? (int32_t)task->pid : 0;
                cred.uid = task ? task->uid : 0;
                cred.gid = task ? task->gid : 0;
            }

            size_t cred_cmsg_size = CMSG_SPACE(sizeof(struct ucred_t));
            /* Read original control buffer size to check available space */
            size_t orig_controllen2 = 0;
            {
                struct msghdr user_msg2;
                if (recvmsg_copy_from_user(&user_msg2, local_msg, sizeof(struct msghdr)) == 0)
                    orig_controllen2 = user_msg2.msg_controllen;
            }
            size_t cred_offset = kmsg.msg_controllen;  /* Append after any SCM_RIGHTS */
            if (orig_controllen2 >= cred_offset + cred_cmsg_size) {
                void *kcred_cmsg = fut_malloc(cred_cmsg_size);
                if (kcred_cmsg) {
                    for (size_t z = 0; z < cred_cmsg_size; z++) ((uint8_t *)kcred_cmsg)[z] = 0;
                    struct cmsghdr *cc = (struct cmsghdr *)kcred_cmsg;
                    cc->cmsg_len   = CMSG_LEN(sizeof(struct ucred_t));
                    cc->cmsg_level = SOL_SOCKET;
                    cc->cmsg_type  = SCM_CREDENTIALS;
                    struct ucred_t *cp = (struct ucred_t *)CMSG_DATA(cc);
                    *cp = cred;
                    if (recvmsg_copy_to_user((char *)kmsg.msg_control + cred_offset,
                                             kcred_cmsg, cred_cmsg_size) == 0) {
                        kmsg.msg_controllen = cred_offset + cred_cmsg_size;
                    }
                    fut_free(kcred_cmsg);
                }
            }
        }
    }

    /* SO_TIMESTAMP / SO_TIMESTAMPNS: attach receive timestamp cmsg.
     * When SO_TIMESTAMP is set, deliver SCM_TIMESTAMP with struct timeval (8+8 bytes).
     * When SO_TIMESTAMPNS is set, deliver SCM_TIMESTAMPNS with struct timespec (8+8 bytes). */
    if (total_received > 0 && kmsg.msg_control != NULL) {
        extern fut_socket_t *get_socket_from_fd(int fd);
        fut_socket_t *ts_sock = get_socket_from_fd(local_sockfd);
        if (ts_sock && (ts_sock->so_flags & (FUT_SO_F_TIMESTAMP | FUT_SO_F_TIMESTAMPNS))) {
            extern volatile int64_t g_realtime_offset_sec;
            uint64_t ticks = fut_get_ticks();
            uint64_t total_ns = ticks * 10000000ULL;  /* 100 Hz → 10ms/tick */

            bool use_ns = (ts_sock->so_flags & FUT_SO_F_TIMESTAMPNS) != 0;
            size_t ts_data_size = use_ns ? (2 * sizeof(int64_t)) : (2 * sizeof(int64_t));
            size_t ts_cmsg_size = CMSG_SPACE(ts_data_size);

            size_t ts_orig_controllen = 0;
            {
                struct msghdr user_msg_ts;
                if (recvmsg_copy_from_user(&user_msg_ts, local_msg, sizeof(struct msghdr)) == 0)
                    ts_orig_controllen = user_msg_ts.msg_controllen;
            }
            size_t ts_offset = kmsg.msg_controllen;  /* Append after SCM_RIGHTS / SCM_CREDENTIALS */
            if (ts_orig_controllen >= ts_offset + ts_cmsg_size) {
                void *kts_cmsg = fut_malloc(ts_cmsg_size);
                if (kts_cmsg) {
                    for (size_t z = 0; z < ts_cmsg_size; z++) ((uint8_t *)kts_cmsg)[z] = 0;
                    struct cmsghdr *tc = (struct cmsghdr *)kts_cmsg;
                    tc->cmsg_level = SOL_SOCKET;
                    if (use_ns) {
                        /* struct timespec { tv_sec, tv_nsec } */
                        tc->cmsg_len  = CMSG_LEN(ts_data_size);
                        tc->cmsg_type = SCM_TIMESTAMPNS;
                        int64_t *ts = (int64_t *)CMSG_DATA(tc);
                        ts[0] = (int64_t)(total_ns / 1000000000ULL) + g_realtime_offset_sec;
                        ts[1] = (int64_t)(total_ns % 1000000000ULL);
                    } else {
                        /* struct timeval { tv_sec, tv_usec } */
                        tc->cmsg_len  = CMSG_LEN(ts_data_size);
                        tc->cmsg_type = SCM_TIMESTAMP;
                        int64_t *tv = (int64_t *)CMSG_DATA(tc);
                        tv[0] = (int64_t)(total_ns / 1000000000ULL) + g_realtime_offset_sec;
                        tv[1] = (int64_t)((total_ns % 1000000000ULL) / 1000);
                    }
                    if (recvmsg_copy_to_user((char *)kmsg.msg_control + ts_offset,
                                             kts_cmsg, ts_cmsg_size) == 0) {
                        kmsg.msg_controllen = ts_offset + ts_cmsg_size;
                    }
                    fut_free(kts_cmsg);
                }
            }
        }
    }

    /* Write updated msghdr back to userspace */
    if (recvmsg_copy_to_user(local_msg, &kmsg, sizeof(struct msghdr)) != 0) {
        if (total_received <= 0) total_received = -EFAULT;
        /* Fall through to cleanup */
    }

    /* MSG_TRUNC in input flags: for DGRAM, return the real datagram length
     * even if it was larger than the supplied buffer.  This lets callers
     * discover the original message size without a second recv.
     * Only override when the datagram was actually truncated. */
    if ((local_flags & MSG_TRUNC) && msg_trunc_set && dgram_actual_len > 0
        && total_received > 0) {
        total_received = (ssize_t)dgram_actual_len;
    }

    /* Phase 2: Detailed logging with I/O statistics */
    const char *completion_status;
    if (total_received == 0) {
        completion_status = "EOF";
    } else if (total_received < 0) {
        completion_status = "error";
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

    /* Restore per-task MSG_DONTWAIT flag — must happen on ALL exit paths */
    if ((local_flags & MSG_DONTWAIT) && dw_task) {
        dw_task->msg_dontwait = saved_dontwait;
    }

    return total_received;
}
