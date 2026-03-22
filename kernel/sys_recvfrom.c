/* kernel/sys_recvfrom.c - Receive message from socket syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements recvfrom() to receive messages from sockets.
 * Essential for network communication and Unix domain sockets.
 *
 * Phase 1 (Completed): Basic recvfrom with VFS read delegation
 * Phase 2 (Completed): Enhanced validation, FD/buffer/flags categorization, detailed logging
 * Phase 3 (Completed): MSG flags implementation with source address tracking
 * Phase 4 (Completed): Peer address return for AF_UNIX connected sockets
 * Zero-copy receive, scatter-gather I/O
 */

#include <kernel/fut_task.h>
#include <kernel/fut_vfs.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_io_budget.h>
#include <kernel/uaccess.h>
#include <kernel/errno.h>
#include <kernel/fut_socket.h>
#include <stddef.h>
#include <stdint.h>

#include <kernel/kprintf.h>

#ifdef __x86_64__
#include <platform/x86_64/memory/paging.h>
#elif defined(__aarch64__)
#include <platform/arm64/memory/paging.h>
#endif

/* Internet address structures for peer-address return */
typedef struct {
    uint16_t sin_family;
    uint16_t sin_port;
    uint32_t sin_addr;
    uint8_t  sin_zero[8];
} rfrom_sockaddr_in_t;

typedef struct {
    uint16_t sin6_family;
    uint16_t sin6_port;
    uint32_t sin6_flowinfo;
    uint8_t  sin6_addr[16];
    uint32_t sin6_scope_id;
} rfrom_sockaddr_in6_t;

static inline int recv_copy_from_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)src >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_from_user(dst, src, n);
}
static inline int recv_access_ok_write(const void *ptr, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)ptr >= KERNEL_VIRTUAL_BASE) return 0;
#endif
    return fut_access_ok(ptr, n, 1);
}
static inline int recv_copy_to_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)dst >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_to_user(dst, src, n);
}

/* Message flags (MSG_*) provided by fut_socket.h */

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
 * Phase 2 (Completed): Enhanced validation, parameter categorization, detailed logging
 * Phase 3 (Completed): MSG flags implementation with source address tracking
 * Phase 4 (Completed): Peer address return for AF_UNIX connected sockets
 * Zero-copy receive, scatter-gather I/O
 */
ssize_t sys_recvfrom(int sockfd, void *buf, size_t len, int flags,
                     void *src_addr, socklen_t *addrlen) {
    /* ARM64 FIX: Copy parameters to local variables immediately to ensure they're preserved
     * on the stack across potentially blocking calls. Socket/VFS operations may block and corrupt
     * register-passed parameters upon resumption. */
    int local_sockfd = sockfd;
    void *local_buf = buf;
    size_t local_len = len;
    int local_flags = flags;
    void *local_src_addr = src_addr;
    socklen_t *local_addrlen = addrlen;

    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[RECVFROM] recvfrom(sockfd=%d) -> ESRCH (no current task)\n", local_sockfd);
        return -ESRCH;
    }

    /* I/O Rate Limiting (DoS Prevention)
     * Check per-process I/O operation rate limit before performing network I/O.
     * This prevents CPU exhaustion via tight recvfrom() loops. */
    int rate_limit_result = fut_io_check_and_consume(task, "recvfrom");
    if (rate_limit_result < 0) {
        return rate_limit_result;  /* -EAGAIN if rate limit exceeded */
    }

    /* Phase 2: Validate sockfd */
    if (local_sockfd < 0) {
        fut_printf("[RECVFROM] recvfrom(sockfd=%d) -> EBADF (negative fd)\n", local_sockfd);
        return -EBADF;
    }

    /* Phase 2: Categorize socket FD */
    const char *fd_category;
    if (local_sockfd <= 2) {
        fd_category = "stdio (0-2)";
    } else if (local_sockfd < 10) {
        fd_category = "low (3-9)";
    } else if (local_sockfd < 1000) {
        fd_category = "socket range (10-999)";
    } else if (local_sockfd < 2000) {
        fd_category = "socket range (1000-1999)";
    } else if (local_sockfd < 3000) {
        fd_category = "socket range (2000-2999)";
    } else {
        fd_category = "high (≥3000)";
    }

    /* Phase 2: Categorize buffer size */
    const char *size_category;
    if (local_len == 0) {
        size_category = "zero-length";
    } else if (local_len <= 64) {
        size_category = "tiny (≤64 bytes)";
    } else if (local_len <= 512) {
        size_category = "small (64-512 bytes)";
    } else if (local_len <= 4096) {
        size_category = "medium (512B-4KB)";
    } else if (local_len <= 65536) {
        size_category = "large (4KB-64KB)";
    } else {
        size_category = "very large (>64KB)";
    }

    /* Phase 2: Categorize flags */
    const char *flags_description;
    char flags_str[128];
    int pos = 0;

    if (local_flags == 0) {
        flags_description = "none (blocking)";
    } else {
        /* Build flags string manually */
        flags_str[0] = '\0';
        if (local_flags & MSG_DONTWAIT) {
            const char *s = "MSG_DONTWAIT";
            while (*s && pos < 120) flags_str[pos++] = *s++;
        }
        if (local_flags & MSG_PEEK) {
            if (pos > 0 && pos < 120) flags_str[pos++] = '|';
            const char *s = "MSG_PEEK";
            while (*s && pos < 120) flags_str[pos++] = *s++;
        }
        if (local_flags & MSG_WAITALL) {
            if (pos > 0 && pos < 120) flags_str[pos++] = '|';
            const char *s = "MSG_WAITALL";
            while (*s && pos < 120) flags_str[pos++] = *s++;
        }
        if (local_flags & MSG_TRUNC) {
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

    /* Validate socket FD */
    struct fut_file *file = vfs_get_file(local_sockfd);
    if (!file) {
        fut_printf("[RECVFROM] recvfrom(sockfd=%d [%s]) -> EBADF (fd not open)\n",
                   local_sockfd, fd_category);
        return -EBADF;
    }

    /* Handle zero-length receive */
    if (local_len == 0) {
        fut_printf("[RECVFROM] recvfrom(sockfd=%d [%s], len=0, pid=%u) -> 0 "
                   "(zero-length receive)\n",
                   local_sockfd, fd_category, task->pid);
        return 0;
    }

    /* src_addr/addrlen consistency validation
     * If src_addr is provided, addrlen must also be provided (and non-NULL)
     * to know how much buffer space is available for the address */
    if (local_src_addr != NULL && local_addrlen == NULL) {
        fut_printf("[RECVFROM] recvfrom(sockfd=%d) -> EFAULT "
                   "(src_addr provided but addrlen is NULL)\n", local_sockfd);
        return -EFAULT;
    }

    /* COMPREHENSIVE SECURITY HARDENING
     * VULNERABILITY: Multiple Attack Vectors in Socket Receive Operation
     *
     * The recvfrom() syscall is particularly vulnerable due to:
     * - User-controlled receive buffer size
     * - Output buffer for received data (write permission required)
     * - Optional source address output (value-result addrlen parameter)
     * - Kernel buffer allocation proportional to user request
     * - Blocking operation that may suspend kernel thread
     *
     * ATTACK SCENARIO 1: Excessive Buffer Size Memory Exhaustion
     * Attacker requests enormous receive buffer to exhaust kernel memory
     * 1. Attacker calls recvfrom(sockfd, buf, SIZE_MAX, 0, NULL, NULL)
     *    - SIZE_MAX = 18 exabytes (18,446,744,073,709,551,615 bytes)
     * 2. WITHOUT check (line 230-236):
     *    - Line 247: fut_malloc(SIZE_MAX) attempts allocation
     *    - Kernel heap exhausted instantly
     *    - OOM killer terminates random processes
     *    - System-wide DoS: All processes affected
     * 3. WITH check (line 230-236):
     *    - Line 231: if (local_len > MAX_RECV_SIZE) rejects request
     *    - Syscall fails before allocation
     *    - 16MB limit balances functionality vs DoS prevention
     * 4. Impact:
     *    - DoS via kernel memory exhaustion (single syscall)
     *    - OOM killer: Random process termination
     *    - System instability: Critical services killed
     *    - Cascading failures: Multiple subsystems affected
     *
     * ATTACK SCENARIO 2: Repeated Large Allocations Resource Exhaustion
     * Attacker repeatedly requests maximum allowed buffer to fragment heap
     * 1. Attacker calls recvfrom(sockfd, buf, 16MB, 0, NULL, NULL) in tight loop
     * 2. Each call: Line 247 allocates 16MB kernel buffer
     * 3. Tight loop: 100 calls/second = 1.6GB/sec allocation rate
     * 4. Multiple concurrent attackers: 10 threads = 16GB/sec
     * 5. Memory not freed until syscall returns (line 288)
     * 6. Blocking operation (line 256) holds buffer during wait
     * 7. Kernel heap fragmented with many 16MB allocations
     * 8. System runs out of memory (DoS)
     * 9. Defense: MAX_RECV_SIZE limit (line 230) provides partial protection
     *    - Limits damage per call but doesn't prevent repeated calls
     *    - Phase 4 TODO: Add per-process I/O budget tracking
     *    - Phase 4 TODO: Add rate limiting for large receive operations
     *
     * ATTACK SCENARIO 3: Read-Only Buffer Permission Bypass
     * Attacker provides read-only memory as receive buffer to trigger kernel fault
     * 1. Attacker maps read-only page:
     *    void *readonly = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
     * 2. Attacker calls recvfrom:
     *    recvfrom(sockfd, readonly, 4096, 0, NULL, NULL);
     * 3. Current implementation:
     *    - No early write permission check on buf
     *    - Line 247: fut_malloc(4096) allocates kernel buffer
     *    - Line 256: fut_vfs_read potentially blocks waiting for data
     *    - Line 279: fut_copy_to_user attempts write to readonly → fault
     *    - Result: Crash AFTER doing all the work (fail-slow pattern)
     * 4. Defense (TODO):
     *    - Test write permission on buf BEFORE allocation and blocking
     *    - Fail fast before expensive operations
     *    - Similar to sys_read/sys_getdents64 pattern
     * 5. Impact:
     *    - DoS: Kernel page fault on write to read-only memory
     *    - Resource waste: Allocation and blocking before discovering fault
     *    - Data loss: Received data discarded when copy fails
     *
     * ATTACK SCENARIO 4: Source Address Buffer Overflow via addrlen
     * Attacker exploits src_addr/addrlen to corrupt kernel or application memory
     * 1. Attacker provides small src_addr buffer but large addrlen:
     *    char addr_buf[16];
     *    socklen_t len = 1024;  // Much larger than buffer
     *    recvfrom(sockfd, buf, 1024, 0, &addr_buf, &len);
     * 2. Current implementation (Phase 3):
     *    - Lines 292-296: Logs address request but doesn't populate
     *    - Phase 4 will implement actual address return
     * 3. Potential vulnerability (Phase 4):
     *    - When actual address is copied to src_addr
     *    - If len validation missing: Write beyond addr_buf boundary
     *    - Result: Application buffer overflow, memory corruption
     * 4. Defense (Phase 4 TODO):
     *    - Atomic addrlen copy (prevent TOCTOU)
     *    - Bounds validation: len <= sizeof(sockaddr_storage)
     *    - Truncate address if buffer too small
     *    - Write back actual address size to addrlen
     * 5. Note: Current Phase 3 implementation safe (no address copy yet)
     *
     * ATTACK SCENARIO 5: addrlen TOCTOU Race Condition
     * Concurrent threads exploit addrlen value-result parameter
     * 1. Thread 1 (attacker - recvfrom call):
     *    socklen_t len = 128;
     *    recvfrom(sockfd, buf, 1024, 0, &addr, &len);
     * 2. Thread 2 (attacker - concurrent modifier):
     *    - Waits for Thread 1 to validate addrlen
     *    - Modifies len to 0xFFFFFFFF (4GB) in userspace
     * 3. Current implementation (Phase 3):
     *    - No addrlen copy or validation yet
     *    - Phase 4 will need TOCTOU protection
     * 4. Potential vulnerability (Phase 4):
     *    - If addrlen not copied atomically
     *    - Application reads corrupted addrlen value
     *    - Buffer overflow when parsing address structure
     * 5. Defense (Phase 4 TODO):
     *    - Atomic addrlen copy to kernel memory
     *    - Validate immediately
     *    - Use kernel copy for all operations
     *    - Never re-read from userspace
     *    - Similar to sys_accept pattern
     *
     * IMPACT:
     * - Memory exhaustion DoS: Kernel heap depletion via huge buffer requests
     * - Resource fragmentation: Repeated large allocations fragment heap
     * - Fail-slow waste: Late failure after allocation and blocking
     * - Data loss: Received data discarded on copy failure
     * - Application overflow: (Phase 4) src_addr buffer overflow
     * - TOCTOU race: (Phase 4) addrlen race leads to application corruption
     *
     * ROOT CAUSE:
     * Pre-code lacked comprehensive validation:
     * - No upper bound on buffer size (allows SIZE_MAX requests)
     * - No early write permission check on buf
     * - No addrlen TOCTOU protection (Phase 4 will need this)
     * - No src_addr/addrlen consistency validation
     * - Blocking operations before validation waste resources
     *
     * DEFENSE (Requirements):
     * 1. Buffer Size Limit (line 230-236):
     *    - Check: len <= MAX_RECV_SIZE (16MB)
     *    - BEFORE allocation and blocking operations
     *    - Prevents single-call memory exhaustion
     *    - Balances functionality vs DoS prevention
     * 2. buf Write Permission Check (TODO):
     *    - Test write to buf BEFORE allocation and blocking
     *    - Fail fast before expensive operations
     *    - Similar to sys_read pattern
     * 3. addrlen Atomic Copy (Phase 4 TODO):
     *    - Copy addrlen once to kernel memory
     *    - Validate immediately
     *    - Use kernel copy for all operations
     *    - Prevent TOCTOU race
     * 4. src_addr/addrlen Consistency Check (Phase 4 TODO):
     *    - Reject: src_addr != NULL && addrlen == NULL
     *    - Validate: addrlen <= sizeof(sockaddr_storage)
     *    - Prevent buffer overflow
     *
     * CVE REFERENCES:
     * - CVE-2016-10229: Linux udp.c recvmsg TOCTOU on address length
     * - CVE-2018-5953: Linux swiotlb write to readonly buffer
     * - CVE-2019-14284: Linux floppy driver buffer overflow
     * - CVE-2017-7472: Linux keyctl TOCTOU on value-result
     * - CVE-2020-12826: Linux signal handling memory exhaustion
     *
     * POSIX REQUIREMENT:
     * From POSIX.1-2008 recvfrom(3p):
     * "The recvfrom() function shall receive a message from a
     *  connection-mode or connectionless-mode socket. The address
     *  argument shall be a result parameter that is filled in with
     *  the address of the peer from which the message was received."
     * - Must validate buf and len before use
     * - src_addr and addrlen are optional (may be NULL)
     * - addrlen is value-result parameter
     * - Must handle buffer overflow gracefully
     *
     * LINUX REQUIREMENT:
     * From recvfrom(2) man page:
     * "If src_addr is not NULL, and the underlying protocol provides
     *  the source address, this source address is filled in. When
     *  src_addr is NULL, nothing is filled in; in this case, addrlen
     *  is not used, and should also be NULL."
     * - Must validate pointers before dereferencing
     * - buf must be writable
     * - Maximum buffer size implementation-defined
     * - src_addr and addrlen must be consistent
     *
     * IMPLEMENTATION NOTES:
     * - Added buffer size limit (16MB) at line 230-236 ✓
     * - (Completed): Added buf write permission check at line 417-423
     * - (Completed): Added src_addr/addrlen consistency check at line 214-220
     * - (Completed): Actual src_addr return for AF_UNIX (lines 500-540)
     * - Remaining: Add addrlen TOCTOU protection
     * - Remaining: Add per-process I/O budget tracking
     * - Remaining: Add rate limiting for large receive operations
     */

    /* Security hardening: Limit buffer size to prevent memory exhaustion DoS
     * See ATTACK SCENARIO 1-2 in comprehensive documentation above
     * Defense: Limit to reasonable maximum (16MB, matching sendmsg/preadv/pwritev) */
    const size_t MAX_RECV_SIZE = 16 * 1024 * 1024;  /* 16MB per recv */
    if (local_len > MAX_RECV_SIZE) {
        fut_printf("[RECVFROM] recvfrom(sockfd=%d [%s], len=%zu [%s]) -> EINVAL "
                   "(length exceeds max %zu bytes, memory exhaustion prevention)\n",
                   local_sockfd, fd_category, local_len, size_category, MAX_RECV_SIZE);
        return -EINVAL;
    }

    /* Validate buf write permission early (kernel writes received data) */
    if (local_buf && local_len > 0 && recv_access_ok_write(local_buf, local_len) != 0) {
        fut_printf("[RECVFROM] recvfrom(sockfd=%d, len=%zu) -> EFAULT (buf not writable)\n",
                   local_sockfd, local_len);
        return -EFAULT;
    }

    /* Validate buf */
    if (!local_buf) {
        fut_printf("[RECVFROM] recvfrom(sockfd=%d [%s], buf=NULL, len=%zu, pid=%u) -> EINVAL "
                   "(NULL buffer)\n",
                   local_sockfd, fd_category, local_len, task->pid);
        return -EINVAL;
    }

    /* Allocate kernel buffer */
    void *kbuf = fut_malloc(local_len);
    if (!kbuf) {
        fut_printf("[RECVFROM] recvfrom(sockfd=%d [%s], len=%zu [%s], pid=%u) -> ENOMEM "
                   "(kernel buffer allocation failed)\n",
                   local_sockfd, fd_category, local_len, size_category, task->pid);
        return -ENOMEM;
    }

    /* AF_NETLINK: drain pending response buffer directly */
    {
        extern fut_socket_t *get_socket_from_fd(int fd);
        fut_socket_t *nlsock = get_socket_from_fd(local_sockfd);
        if (nlsock && nlsock->address_family == 16 /* AF_NETLINK */) {
            extern ssize_t netlink_handle_recv(fut_socket_t *sock,
                                               void *out_buf, size_t out_len);
            ssize_t got = netlink_handle_recv(nlsock, kbuf, local_len);
            if (got > 0 && recv_copy_to_user(local_buf, kbuf, (size_t)got) != 0) {
                fut_free(kbuf);
                return -EFAULT;
            }
            fut_free(kbuf);
            return got;
        }
    }

    /* For SOCK_DGRAM sockets with a dgram_queue, use the datagram receive path */
    {
        extern fut_socket_t *get_socket_from_fd(int fd);
        fut_socket_t *dgsock = get_socket_from_fd(local_sockfd);
        if (dgsock && dgsock->socket_type == 2 /* SOCK_DGRAM */ &&
            !dgsock->pair && dgsock->dgram_queue) {
            char sender_path[108];
            uint16_t sender_path_len = 0;
            size_t actual_dgram_len = 0;
            /* Use per-task flag for MSG_DONTWAIT (avoids mutating shared sock->flags) */
            fut_task_t *dg_task = fut_task_current();
            int dg_saved = 0;
            if ((local_flags & MSG_DONTWAIT) && dg_task) {
                dg_saved = dg_task->msg_dontwait;
                dg_task->msg_dontwait = 1;
            }
            ssize_t dg_ret;
            if (local_flags & MSG_PEEK) {
                dg_ret = fut_socket_peek_dgram(dgsock, kbuf, local_len,
                                               sender_path, &sender_path_len,
                                               &actual_dgram_len);
            } else {
                dg_ret = fut_socket_recvfrom_dgram(dgsock, kbuf, local_len,
                                                   sender_path, &sender_path_len,
                                                   &actual_dgram_len);
            }
            if ((local_flags & MSG_DONTWAIT) && dg_task)
                dg_task->msg_dontwait = dg_saved;
            if (dg_ret < 0) {
                fut_free(kbuf);
                return dg_ret;
            }
            if (dg_ret > 0) {
                if (recv_copy_to_user(local_buf, kbuf, (size_t)dg_ret) != 0) {
                    fut_free(kbuf);
                    return -EFAULT;
                }
            }
            fut_free(kbuf);
            /* Fill src_addr with sender address if requested */
            if (local_src_addr && local_addrlen) {
                socklen_t alen = 0;
                if (recv_copy_from_user(&alen, local_addrlen, sizeof(socklen_t)) == 0) {
                    if (sender_path_len == 0xFFFF) {
                        /* AF_INET sender: inet addr:port packed in sender_path[0..5] */
                        struct { uint16_t sin_family; uint16_t sin_port; uint32_t sin_addr; uint8_t sin_zero[8]; } sin;
                        __builtin_memset(&sin, 0, sizeof(sin));
                        sin.sin_family = 2; /* AF_INET */
                        __builtin_memcpy(&sin.sin_addr, &sender_path[0], 4);
                        __builtin_memcpy(&sin.sin_port, &sender_path[4], 2);
                        socklen_t actual_len = 16;
                        socklen_t to_copy = (actual_len < alen) ? actual_len : alen;
                        recv_copy_to_user(local_src_addr, &sin, to_copy);
                        recv_copy_to_user(local_addrlen, &actual_len, sizeof(socklen_t));
                    } else {
                        /* AF_UNIX sender */
                        struct {
                            unsigned short sun_family;
                            char sun_path[108];
                        } src_sun;
                        __builtin_memset(&src_sun, 0, sizeof(src_sun));
                        src_sun.sun_family = 1; /* AF_UNIX */
                        size_t copy_path = sender_path_len < 108 ? sender_path_len : 107;
                        if (copy_path > 0)
                            __builtin_memcpy(src_sun.sun_path, sender_path, copy_path);
                        socklen_t actual_len = (socklen_t)(2 + copy_path + (sender_path_len == 0 || sender_path[0] != '\0' ? 1 : 0));
                        socklen_t to_copy = (actual_len < alen) ? actual_len : alen;
                        recv_copy_to_user(local_src_addr, &src_sun, to_copy);
                        recv_copy_to_user(local_addrlen, &actual_len, sizeof(socklen_t));
                    }
                }
            }
            /* MSG_TRUNC: return actual datagram length even if buffer was too small */
            if ((local_flags & MSG_TRUNC) && actual_dgram_len > (size_t)local_len)
                return (ssize_t)actual_dgram_len;
            return dg_ret;
        }
    }

    /* Apply MSG_DONTWAIT via per-task flag (avoids mutating shared sock->flags) */
    fut_task_t *dw_task = fut_task_current();
    int saved_dontwait = 0;
    if ((local_flags & MSG_DONTWAIT) && dw_task) {
        saved_dontwait = dw_task->msg_dontwait;
        dw_task->msg_dontwait = 1;
    }

    /* Read from socket — use peek path for MSG_PEEK, loop for MSG_WAITALL */
    ssize_t ret;
    if (local_flags & MSG_PEEK) {
        extern fut_socket_t *get_socket_from_fd(int fd);
        fut_socket_t *sock = get_socket_from_fd(local_sockfd);
        if (sock) {
            ret = fut_socket_recv_peek(sock, kbuf, local_len);
        } else {
            ret = fut_vfs_read(local_sockfd, kbuf, local_len);
        }
    } else if ((local_flags & MSG_WAITALL) && !(local_flags & MSG_DONTWAIT)) {
        /* MSG_WAITALL: keep reading until the full buffer is filled, EOF, or error.
         * Only applies to SOCK_STREAM; message-oriented sockets (DGRAM and
         * SEQPACKET) ignore MSG_WAITALL — each recv returns exactly one message.
         * Looping on SEQPACKET would concatenate messages, breaking boundaries. */
        extern fut_socket_t *get_socket_from_fd(int fd);
        fut_socket_t *wtsock = get_socket_from_fd(local_sockfd);
        bool is_msg_oriented = wtsock &&
            (wtsock->socket_type == 2 /* SOCK_DGRAM */ ||
             wtsock->socket_type == 5 /* SOCK_SEQPACKET */);

        if (is_msg_oriented) {
            /* DGRAM/SEQPACKET: single receive, MSG_WAITALL ignored */
            ret = fut_vfs_read(local_sockfd, kbuf, local_len);
        } else {
            /* STREAM: loop until full */
            ssize_t total = 0;
            ret = 0;
            while ((size_t)total < local_len) {
                ssize_t rc = fut_vfs_read(local_sockfd,
                                          (char *)kbuf + total,
                                          local_len - (size_t)total);
                if (rc < 0) {
                    /* Error: return partial data already received, or the error */
                    ret = (total > 0) ? total : rc;
                    goto waitall_done;
                }
                if (rc == 0) {
                    /* EOF */
                    ret = total;
                    goto waitall_done;
                }
                total += rc;
            }
            ret = total;
            waitall_done:;
        }
    } else {
        ret = fut_vfs_read(local_sockfd, kbuf, local_len);
    }

    /* Restore per-task MSG_DONTWAIT flag */
    if ((local_flags & MSG_DONTWAIT) && dw_task) {
        dw_task->msg_dontwait = saved_dontwait;
    }

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
                   local_sockfd, fd_category, local_len, size_category,
                   local_flags, flags_description, task->pid, ret, error_desc);
        return ret;
    }

    /* Copy to userspace */
    if (ret > 0) {
        if (recv_copy_to_user(local_buf, kbuf, (size_t)ret) != 0) {
            fut_free(kbuf);
            fut_printf("[RECVFROM] recvfrom(sockfd=%d [%s], len=%zu [%s], pid=%u) -> EFAULT "
                       "(copy_to_user failed)\n",
                       local_sockfd, fd_category, local_len, size_category, task->pid);
            return -EFAULT;
        }
    }

    fut_free(kbuf);

    /* Phase 4: Return peer address if requested (for connected sockets like SOCK_STREAM)
     * For connection-oriented protocols, recvfrom() returns the same address as getpeername()
     * For datagram sockets, this would return the sender's address for the specific packet */
    /* Return peer address if requested */

    if (local_src_addr && local_addrlen) {
        /* Atomic copy of addrlen to prevent TOCTOU race */
        socklen_t len = 0;
        if (recv_copy_from_user(&len, local_addrlen, sizeof(socklen_t)) != 0) {
            fut_printf("[RECVFROM] recvfrom(sockfd=%d) -> EFAULT (failed to read addrlen)\n",
                       local_sockfd);
            return -EFAULT;
        }

        /* Get socket to retrieve peer address */
        fut_socket_t *socket = get_socket_from_fd(local_sockfd);
        if (socket && socket->address_family == 1 /* AF_UNIX */) {
            /* AF_UNIX: Return peer's bound path if connected */
            if (socket->pair && socket->pair->peer) {
                struct {
                    unsigned short sun_family;
                    char sun_path[108];
                } peer_addr = {0};  /* Zero-init to prevent kernel stack info leak */

                peer_addr.sun_family = 1;  /* AF_UNIX */

                /* Get peer socket's bound path */
                const char *peer_path = "";
                if (socket->pair->peer->bound_path) {
                    peer_path = socket->pair->peer->bound_path;
                }

                /* Copy peer path (truncate if needed) */
                int i;
                for (i = 0; i < 107 && peer_path[i] != '\0'; i++) {
                    peer_addr.sun_path[i] = peer_path[i];
                }
                peer_addr.sun_path[i] = '\0';

                /* Calculate actual address length (sun_family + path + null) */
                socklen_t actual_len = (socklen_t)((char*)&peer_addr.sun_path[0] - (char*)&peer_addr) + (socklen_t)i + 1;

                /* Copy address to userspace (truncate if buffer too small) */
                socklen_t copy_len = (actual_len < len) ? actual_len : len;
                if (recv_copy_to_user(local_src_addr, &peer_addr, copy_len) != 0) {
                    fut_printf("[RECVFROM] recvfrom(sockfd=%d) -> EFAULT (failed to copy peer address)\n",
                               local_sockfd);
                    /* Note: We already received data successfully, so we can't fail now.
                     * Just skip writing the address and continue. */
                    actual_len = 0;
                }

                /* Write back actual address length */
                if (recv_copy_to_user(local_addrlen, &actual_len, sizeof(socklen_t)) != 0) {
                    fut_printf("[RECVFROM] recvfrom(sockfd=%d) -> warning: failed to write back addrlen\n",
                               local_sockfd);
                    /* Non-fatal: data was received successfully */
                } else {
                    fut_printf("[RECVFROM] AF_UNIX peer address: path='%s', actual_len=%u, copied=%u\n",
                               peer_path, actual_len, copy_len);
                }

                /* AF_UNIX peer address returned */
            } else {
                /* AF_UNIX not connected, no peer address */
            }
        } else if (socket && socket->address_family == AF_INET) {
            /* AF_INET: return peer's sockaddr_in */
            fut_socket_t *peer = NULL;
            if (socket->pair && socket->pair->peer)
                peer = socket->pair->peer;
            rfrom_sockaddr_in_t sin = {0};
            sin.sin_family = AF_INET;
            if (peer) {
                sin.sin_port = peer->inet_port;
                sin.sin_addr = peer->inet_addr;
            }
            socklen_t actual_len = (socklen_t)sizeof(rfrom_sockaddr_in_t);
            socklen_t copy_len = (actual_len < len) ? actual_len : len;
            if (recv_copy_to_user(local_src_addr, &sin, copy_len) == 0)
                (void)recv_copy_to_user(local_addrlen, &actual_len, sizeof(socklen_t));
        } else if (socket && socket->address_family == AF_INET6) {
            /* AF_INET6: return peer's sockaddr_in6 */
            fut_socket_t *peer = NULL;
            if (socket->pair && socket->pair->peer)
                peer = socket->pair->peer;
            rfrom_sockaddr_in6_t sin6 = {0};
            sin6.sin6_family = AF_INET6;
            if (peer) {
                sin6.sin6_port = peer->inet_port;
                __builtin_memcpy(&sin6.sin6_addr, peer->inet6_addr, 16);
            }
            socklen_t actual_len = (socklen_t)sizeof(rfrom_sockaddr_in6_t);
            socklen_t copy_len = (actual_len < len) ? actual_len : len;
            if (recv_copy_to_user(local_src_addr, &sin6, copy_len) == 0)
                (void)recv_copy_to_user(local_addrlen, &actual_len, sizeof(socklen_t));
        }
    }

    /* MSG_TRUNC on socketpair DGRAM/SEQPACKET: return actual datagram size.
     * Named DGRAM sockets handle this above (line 581). For socketpairs, the
     * framed recv path in fut_socket_recv stores the full message length when
     * truncation occurs. Return that instead of the truncated byte count. */
    if ((local_flags & MSG_TRUNC) && ret > 0) {
        extern fut_socket_t *get_socket_from_fd(int fd);
        fut_socket_t *tsock = get_socket_from_fd(local_sockfd);
        if (tsock && tsock->pair != NULL && tsock->last_recv_full_msg_len > 0)
            return (ssize_t)tsock->last_recv_full_msg_len;
    }

    return ret;
}
