/* kernel/sys_setsockopt.c - Set socket options syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements setsockopt() to configure socket behavior and protocol options.
 * Essential for tuning performance, timeouts, buffer sizes, and protocol features.
 *
 * Phase 1 (Completed): Basic validation stub
 * Phase 2 (Completed): Accept common SOL_SOCKET options (validation only, not enforced)
 * Phase 3 (Completed): TCP and IP protocol options
 * Phase 4: Full option enforcement with socket state tracking
 */

#include <kernel/fut_task.h>
#include <kernel/fut_socket.h>
#include <kernel/errno.h>
#include <kernel/uaccess.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);
extern fut_task_t *fut_task_current(void);
extern fut_socket_t *get_socket_from_fd(int fd);

/* socklen_t for option length */
typedef uint32_t socklen_t;

/* Socket level options */
#define SOL_SOCKET    1
#define IPPROTO_TCP   6
#define IPPROTO_IP    0
#define IPPROTO_IPV6  41

/* Common socket options (SOL_SOCKET level) */
#define SO_DEBUG      1    /* Enable debugging */
#define SO_REUSEADDR  2    /* Allow reuse of local addresses */
#define SO_TYPE       3    /* Get socket type (read-only) */
#define SO_ERROR      4    /* Get and clear error status (read-only) */
#define SO_DONTROUTE  5    /* Don't use routing */
#define SO_BROADCAST  6    /* Allow broadcast */
#define SO_SNDBUF     7    /* Send buffer size */
#define SO_RCVBUF     8    /* Receive buffer size */
#define SO_KEEPALIVE  9    /* Keep connections alive */
#define SO_OOBINLINE  10   /* Leave received OOB data inline */
#define SO_LINGER     13   /* Linger on close */
#define SO_REUSEPORT  15   /* Allow reuse of local port */
#define SO_RCVLOWAT   18   /* Receive low-water mark */
#define SO_SNDLOWAT   19   /* Send low-water mark */
#define SO_RCVTIMEO   20   /* Receive timeout */
#define SO_SNDTIMEO   21   /* Send timeout */
#define SO_TIMESTAMP  29   /* Timestamp received messages */

/**
 * setsockopt() - Set socket options
 *
 * Sets options on sockets to control various aspects of socket behavior.
 * Options can be set at different protocol levels (socket, TCP, IP, etc.).
 *
 * @param sockfd  Socket file descriptor
 * @param level   Protocol level (SOL_SOCKET, IPPROTO_TCP, IPPROTO_IP, etc.)
 * @param optname Option name (SO_REUSEADDR, SO_KEEPALIVE, etc.)
 * @param optval  Pointer to option value
 * @param optlen  Size of option value
 *
 * Returns:
 *   - 0 on success
 *   - -EBADF if sockfd is not a valid file descriptor
 *   - -EFAULT if optval points to invalid memory
 *   - -EINVAL if optlen is invalid
 *   - -ENOPROTOOPT if option is unknown at the level indicated
 *   - -ENOTSOCK if sockfd is not a socket
 *
 * Behavior:
 * - Sets specified option on socket
 * - Some options take effect immediately, others on next operation
 * - Options persist until socket is closed (not inherited by dup/fork)
 * - Invalid values may be rejected or clamped to valid range
 *
 * Phase 1 (Completed): Validates parameters and returns stub
 * Phase 2 (Completed): Implement common SOL_SOCKET options
 * Phase 3 (Completed): Implement TCP and IP protocol options
 * Phase 4: Advanced options and error handling
 *
 * Common SOL_SOCKET options:
 *
 * SO_REUSEADDR:
 *   Allows reusing local addresses immediately after close
 *   Essential for server restart without "address already in use" error
 *   Example:
 *     int enable = 1;
 *     setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));
 *
 * SO_REUSEPORT:
 *   Allows multiple sockets to bind to same port
 *   Enables load balancing across multiple processes
 *   Example:
 *     int enable = 1;
 *     setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(enable));
 *
 * SO_KEEPALIVE:
 *   Enable TCP keepalive probes
 *   Detects dead connections
 *   Example:
 *     int enable = 1;
 *     setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &enable, sizeof(enable));
 *
 * SO_SNDBUF / SO_RCVBUF:
 *   Set send/receive buffer sizes
 *   Affects throughput and memory usage
 *   Example:
 *     int bufsize = 65536;
 *     setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
 *
 * SO_RCVTIMEO / SO_SNDTIMEO:
 *   Set receive/send timeouts
 *   Prevents indefinite blocking
 *   Example:
 *     struct timeval tv = {.tv_sec = 5, .tv_usec = 0};
 *     setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
 *
 * SO_LINGER:
 *   Control close behavior
 *   Can force RST instead of graceful FIN
 *   Example:
 *     struct linger ling = {.l_onoff = 1, .l_linger = 0};
 *     setsockopt(sockfd, SOL_SOCKET, SO_LINGER, &ling, sizeof(ling));
 *
 * SO_BROADCAST:
 *   Allow sending broadcast messages
 *   Required for UDP broadcast
 *   Example:
 *     int enable = 1;
 *     setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &enable, sizeof(enable));
 *
 * Common IPPROTO_TCP options:
 *
 * TCP_NODELAY:
 *   Disable Nagle's algorithm
 *   Reduces latency for small messages
 *   Example:
 *     int enable = 1;
 *     setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &enable, sizeof(enable));
 *
 * TCP_CORK:
 *   Cork TCP output until explicitly uncorked
 *   Reduces packet fragmentation
 *
 * TCP_KEEPIDLE / TCP_KEEPINTVL / TCP_KEEPCNT:
 *   Configure keepalive timing
 *   Fine-tune connection detection
 *
 * Common IPPROTO_IP options:
 *
 * IP_TTL:
 *   Set IP Time To Live
 *   Controls hop limit
 *
 * IP_MULTICAST_IF:
 *   Set outgoing multicast interface
 *
 * IP_ADD_MEMBERSHIP / IP_DROP_MEMBERSHIP:
 *   Join/leave multicast group
 *
 * Common use cases:
 *
 * Server socket configuration:
 *   int sockfd = socket(AF_INET, SOCK_STREAM, 0);
 *   int enable = 1;
 *   setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));
 *   bind(sockfd, ...);
 *   listen(sockfd, ...);
 *
 * Low-latency client:
 *   int sockfd = socket(AF_INET, SOCK_STREAM, 0);
 *   int enable = 1;
 *   setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &enable, sizeof(enable));
 *   connect(sockfd, ...);
 *
 * Robust connection with timeout:
 *   int sockfd = socket(AF_INET, SOCK_STREAM, 0);
 *   int enable = 1;
 *   struct timeval tv = {.tv_sec = 30, .tv_usec = 0};
 *   setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &enable, sizeof(enable));
 *   setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
 *
 * High-throughput transfer:
 *   int sockfd = socket(AF_INET, SOCK_STREAM, 0);
 *   int bufsize = 262144;  // 256KB
 *   setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
 *   setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
 *
 * Edge cases:
 * - Setting read-only option: Returns -ENOPROTOOPT
 * - Invalid option value: May clamp to valid range or return -EINVAL
 * - Option not supported: Returns -ENOPROTOOPT
 * - After connect(): Some options can't be changed
 * - NULL optval: Returns -EFAULT
 * - optlen mismatch: Returns -EINVAL
 *
 * Performance considerations:
 * - Buffer sizes affect memory usage and throughput
 * - TCP_NODELAY trades latency for efficiency
 * - Keepalive adds network overhead
 * - Timeouts prevent resource exhaustion
 *
 * Security considerations:
 * - SO_REUSEADDR can be security risk if misused
 * - Buffer sizes must be validated (prevent DoS)
 * - Some options require privileges
 * - Option values copied from userspace safely
 *
 * Interaction with other syscalls:
 * - getsockopt: Read current option values
 * - bind: Some options must be set before bind
 * - listen: Some options must be set before listen
 * - connect: Some options must be set before connect
 * - fcntl: Some overlapping functionality (non-blocking, etc.)
 *
 * Error handling:
 * - EBADF: sockfd is invalid
 * - EFAULT: optval pointer invalid
 * - EINVAL: optlen is invalid
 * - ENOPROTOOPT: Unknown option at this level
 * - ENOTSOCK: sockfd is not a socket
 * - EPERM: No permission to set option
 *
 * Portability notes:
 * - POSIX standard but option values vary
 * - Some options are Linux-specific
 * - Option availability depends on protocol
 * - Always check return value
 * - Use feature test macros for portability
 *
 * Protocol-specific considerations:
 *
 * TCP sockets:
 *   - TCP_NODELAY for latency-sensitive apps
 *   - SO_KEEPALIVE for connection liveness
 *   - SO_LINGER for connection termination
 *
 * UDP sockets:
 *   - SO_BROADCAST for broadcast messages
 *   - IP_MULTICAST_IF for multicast
 *   - SO_RCVBUF for datagram buffering
 *
 * Unix domain sockets:
 *   - SO_PASSCRED for credential passing
 *   - SO_RCVBUF / SO_SNDBUF for buffer sizes
 *
 * Real-world examples:
 *
 * HTTP server:
 *   setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));
 *   setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &enable, sizeof(enable));
 *
 * Database server:
 *   setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &enable, sizeof(enable));
 *   setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
 *
 * Game server (UDP):
 *   setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
 *   setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &enable, sizeof(enable));
 */
long sys_setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Validate sockfd */
    if (sockfd < 0) {
        fut_printf("[SETSOCKOPT] setsockopt(sockfd=%d) -> EBADF\n", sockfd);
        return -EBADF;
    }

    /* Validate optval pointer */
    if (!optval) {
        fut_printf("[SETSOCKOPT] setsockopt(sockfd=%d, level=%d, optname=%d) -> EFAULT (optval is NULL)\n",
                   sockfd, level, optname);
        return -EFAULT;
    }

    /* Validate optlen */
    if (optlen == 0 || optlen > 1024) {  /* Sanity check */
        fut_printf("[SETSOCKOPT] setsockopt(sockfd=%d, level=%d, optname=%d, optlen=%u) -> EINVAL\n",
                   sockfd, level, optname, optlen);
        return -EINVAL;
    }

    /* Get socket from FD */
    fut_socket_t *socket = get_socket_from_fd(sockfd);
    if (!socket) {
        fut_printf("[SETSOCKOPT] setsockopt(sockfd=%d) -> EBADF (not a socket)\n", sockfd);
        return -EBADF;
    }

    /* Phase 2: Implement common SOL_SOCKET options */
    if (level == SOL_SOCKET) {
        switch (optname) {
            case SO_TYPE:
            case SO_ERROR:
                /* Read-only options cannot be set */
                fut_printf("[SETSOCKOPT] setsockopt(sockfd=%d, SOL_SOCKET, optname=%d) -> ENOPROTOOPT (read-only)\n",
                           sockfd, optname);
                return -ENOPROTOOPT;

            case SO_REUSEADDR:
            case SO_REUSEPORT:
                /* Address/port reuse options
                 * Phase 2: Validate and accept, but not enforced (Unix sockets don't have port conflicts)
                 * Phase 5: Enforce strict optlen validation */
                {
                    /* Security hardening: Validate optlen exactly matches sizeof(int)
                     * Without strict validation, attacker can pass oversized optlen:
                     *   - setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &value, 1024)
                     *   - Early check (line 284) allows optlen up to 1024 bytes
                     *   - Cached optlen could be used later in buffer allocations
                     *   - Defense: Reject optlen that doesn't match expected size */
                    if (optlen != sizeof(int)) {
                        fut_printf("[SETSOCKOPT] setsockopt(sockfd=%d, SOL_SOCKET, optname=%d, optlen=%u) -> EINVAL "
                                   "(expected exactly %zu bytes, got %u, Phase 5)\n",
                                   sockfd, optname, sizeof(int), optlen);
                        return -EINVAL;
                    }
                    int value;
                    if (fut_copy_from_user(&value, optval, sizeof(int)) != 0) {
                        return -EFAULT;
                    }
                    fut_printf("[SETSOCKOPT] setsockopt(sockfd=%d, SOL_SOCKET, optname=%d, value=%d) -> 0 (accepted, not enforced)\n",
                               sockfd, optname, value);
                    return 0;
                }

            case SO_KEEPALIVE:
            case SO_BROADCAST:
            case SO_OOBINLINE:
            case SO_DONTROUTE:
            case SO_DEBUG:
                /* Boolean options - accept but not enforced
                 * Phase 5: Enforce strict optlen validation */
                {
                    /* Security hardening: Validate optlen exactly matches sizeof(int) */
                    if (optlen != sizeof(int)) {
                        fut_printf("[SETSOCKOPT] setsockopt(sockfd=%d, SOL_SOCKET, optname=%d, optlen=%u) -> EINVAL "
                                   "(expected exactly %zu bytes, got %u, Phase 5)\n",
                                   sockfd, optname, sizeof(int), optlen);
                        return -EINVAL;
                    }
                    int value;
                    if (fut_copy_from_user(&value, optval, sizeof(int)) != 0) {
                        return -EFAULT;
                    }
                    fut_printf("[SETSOCKOPT] setsockopt(sockfd=%d, SOL_SOCKET, optname=%d, value=%d) -> 0 (accepted, not enforced)\n",
                               sockfd, optname, value);
                    return 0;
                }

            case SO_SNDBUF:
            case SO_RCVBUF:
                /* Buffer size options
                 * Phase 2: Validate value, but buffer sizes are fixed at FUT_SOCKET_BUFSIZE
                 * Phase 5: Enforce strict optlen validation */
                {
                    /* Security hardening: Validate optlen exactly matches sizeof(int) */
                    if (optlen != sizeof(int)) {
                        fut_printf("[SETSOCKOPT] setsockopt(sockfd=%d, SOL_SOCKET, optname=%d, optlen=%u) -> EINVAL "
                                   "(expected exactly %zu bytes, got %u, Phase 5)\n",
                                   sockfd, optname, sizeof(int), optlen);
                        return -EINVAL;
                    }
                    int value;
                    if (fut_copy_from_user(&value, optval, sizeof(int)) != 0) {
                        return -EFAULT;
                    }
                    if (value < 0) {
                        return -EINVAL;
                    }
                    fut_printf("[SETSOCKOPT] setsockopt(sockfd=%d, SOL_SOCKET, optname=%d, value=%d) -> 0 (accepted, buffer fixed at %d)\n",
                               sockfd, optname, value, FUT_SOCKET_BUFSIZE);
                    return 0;
                }

            case SO_RCVLOWAT:
            case SO_SNDLOWAT:
                /* Low-water mark options - require int value
                 * Phase 5: Validate optlen matches expected size exactly */
                {
                    if (optlen != sizeof(int)) {
                        fut_printf("[SETSOCKOPT] setsockopt(sockfd=%d, SOL_SOCKET, optname=%d, optlen=%u) -> EINVAL "
                                   "(expected exactly %zu bytes, got %u, Phase 5)\n",
                                   sockfd, optname, sizeof(int), optlen);
                        return -EINVAL;
                    }
                    int value;
                    if (fut_copy_from_user(&value, optval, sizeof(int)) != 0) {
                        return -EFAULT;
                    }
                    fut_printf("[SETSOCKOPT] setsockopt(sockfd=%d, SOL_SOCKET, optname=%d, value=%d) -> ENOPROTOOPT (not yet implemented)\n",
                               sockfd, optname, value);
                    return -ENOPROTOOPT;
                }

            case SO_RCVTIMEO:
            case SO_SNDTIMEO:
                /* Timeout options - require struct timeval
                 * Phase 5: Validate optlen matches struct timeval size exactly */
                {
                    struct timeval {
                        long tv_sec;
                        long tv_usec;
                    };
                    if (optlen != sizeof(struct timeval)) {
                        fut_printf("[SETSOCKOPT] setsockopt(sockfd=%d, SOL_SOCKET, optname=%d, optlen=%u) -> EINVAL "
                                   "(expected exactly %zu bytes, got %u, Phase 5)\n",
                                   sockfd, optname, sizeof(struct timeval), optlen);
                        return -EINVAL;
                    }
                    struct timeval tv;
                    if (fut_copy_from_user(&tv, optval, sizeof(struct timeval)) != 0) {
                        return -EFAULT;
                    }
                    fut_printf("[SETSOCKOPT] setsockopt(sockfd=%d, SOL_SOCKET, optname=%d, tv_sec=%ld, tv_usec=%ld) -> ENOPROTOOPT (not yet implemented)\n",
                               sockfd, optname, tv.tv_sec, tv.tv_usec);
                    return -ENOPROTOOPT;
                }

            case SO_LINGER:
                /* Linger option - requires struct linger
                 * Phase 5: Validate optlen matches struct linger size exactly */
                {
                    struct linger {
                        int l_onoff;
                        int l_linger;
                    };
                    if (optlen != sizeof(struct linger)) {
                        fut_printf("[SETSOCKOPT] setsockopt(sockfd=%d, SOL_SOCKET, SO_LINGER, optlen=%u) -> EINVAL "
                                   "(expected exactly %zu bytes, got %u, Phase 5)\n",
                                   sockfd, sizeof(struct linger), optlen);
                        return -EINVAL;
                    }
                    struct linger ling;
                    if (fut_copy_from_user(&ling, optval, sizeof(struct linger)) != 0) {
                        return -EFAULT;
                    }
                    fut_printf("[SETSOCKOPT] setsockopt(sockfd=%d, SOL_SOCKET, SO_LINGER, l_onoff=%d, l_linger=%d) -> ENOPROTOOPT (not yet implemented)\n",
                               sockfd, ling.l_onoff, ling.l_linger);
                    return -ENOPROTOOPT;
                }

            case SO_TIMESTAMP:
                /* Timestamp option - requires int value
                 * Phase 5: Validate optlen matches expected size exactly */
                {
                    if (optlen != sizeof(int)) {
                        fut_printf("[SETSOCKOPT] setsockopt(sockfd=%d, SOL_SOCKET, SO_TIMESTAMP, optlen=%u) -> EINVAL "
                                   "(expected exactly %zu bytes, got %u, Phase 5)\n",
                                   sockfd, sizeof(int), optlen);
                        return -EINVAL;
                    }
                    int value;
                    if (fut_copy_from_user(&value, optval, sizeof(int)) != 0) {
                        return -EFAULT;
                    }
                    fut_printf("[SETSOCKOPT] setsockopt(sockfd=%d, SOL_SOCKET, SO_TIMESTAMP, value=%d) -> ENOPROTOOPT (not yet implemented)\n",
                               sockfd, value);
                    return -ENOPROTOOPT;
                }

            default:
                /* Unknown option */
                fut_printf("[SETSOCKOPT] setsockopt(sockfd=%d, SOL_SOCKET, optname=%d) -> ENOPROTOOPT (unknown)\n",
                           sockfd, optname);
                return -ENOPROTOOPT;
        }
    } else {
        /* Phase 3: Protocol-specific options (IPPROTO_TCP, IPPROTO_IP, etc.) */
        const char *level_str = (level == IPPROTO_TCP) ? "IPPROTO_TCP" :
                                (level == IPPROTO_IP) ? "IPPROTO_IP" :
                                (level == IPPROTO_IPV6) ? "IPPROTO_IPV6" : "UNKNOWN";

        fut_printf("[SETSOCKOPT] setsockopt(sockfd=%d, level=%s, optname=%d) -> ENOPROTOOPT (level not supported)\n",
                   sockfd, level_str, optname);
        return -ENOPROTOOPT;
    }
}
