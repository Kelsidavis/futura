/* kernel/sys_getsockopt.c - Get socket options syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements getsockopt() to retrieve socket option values.
 * Complement to setsockopt() for querying socket configuration and state.
 *
 * Phase 1 (Completed): Basic validation stub
 * Phase 2 (Completed): Implement common SOL_SOCKET options (SO_TYPE, SO_ERROR, SO_SNDBUF, SO_RCVBUF)
 * Phase 3 (Current): TCP and IP protocol options
 * Phase 4: Advanced options and full POSIX compliance
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
#define SO_DEBUG      1    /* Get debugging state */
#define SO_REUSEADDR  2    /* Get address reuse state */
#define SO_TYPE       3    /* Get socket type */
#define SO_ERROR      4    /* Get and clear error status */
#define SO_DONTROUTE  5    /* Get routing bypass state */
#define SO_BROADCAST  6    /* Get broadcast state */
#define SO_SNDBUF     7    /* Get send buffer size */
#define SO_RCVBUF     8    /* Get receive buffer size */
#define SO_KEEPALIVE  9    /* Get keepalive state */
#define SO_OOBINLINE  10   /* Get OOB inline state */
#define SO_LINGER     13   /* Get linger settings */
#define SO_REUSEPORT  15   /* Get port reuse state */
#define SO_RCVLOWAT   18   /* Get receive low-water mark */
#define SO_SNDLOWAT   19   /* Get send low-water mark */
#define SO_RCVTIMEO   20   /* Get receive timeout */
#define SO_SNDTIMEO   21   /* Get send timeout */

/**
 * getsockopt() - Get socket options
 *
 * Retrieves the value of socket options at various protocol levels.
 * Used to query socket configuration, check socket state, and retrieve
 * error information.
 *
 * @param sockfd  Socket file descriptor
 * @param level   Protocol level (SOL_SOCKET, IPPROTO_TCP, IPPROTO_IP, etc.)
 * @param optname Option name (SO_REUSEADDR, SO_ERROR, etc.)
 * @param optval  Pointer to buffer to receive option value
 * @param optlen  Pointer to size of buffer (in/out parameter)
 *
 * Returns:
 *   - 0 on success
 *   - -EBADF if sockfd is not a valid file descriptor
 *   - -EFAULT if optval or optlen point to invalid memory
 *   - -EINVAL if optlen is invalid
 *   - -ENOPROTOOPT if option is unknown at the level indicated
 *   - -ENOTSOCK if sockfd is not a socket
 *
 * Behavior:
 * - Retrieves current value of specified option
 * - optlen is value-result parameter (input: buffer size, output: actual size)
 * - Some options are read-only (SO_TYPE, SO_ERROR)
 * - SO_ERROR is cleared after reading
 * - Option values reflect current socket state
 *
 * Phase 1 (Completed): Validates parameters and returns stub
 * Phase 2 (Completed): Implement common SOL_SOCKET options
 * Phase 3 (Current): Implement TCP and IP protocol options
 * Phase 4: Advanced options and error handling
 *
 * Common SOL_SOCKET options:
 *
 * SO_TYPE (read-only):
 *   Returns socket type (SOCK_STREAM, SOCK_DGRAM, etc.)
 *   Example:
 *     int type;
 *     socklen_t len = sizeof(type);
 *     getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &type, &len);
 *     if (type == SOCK_STREAM) { printf("TCP socket\n"); }
 *
 * SO_ERROR (read-only, clears on read):
 *   Returns pending error and clears it
 *   Essential for non-blocking connect()
 *   Example:
 *     int error;
 *     socklen_t len = sizeof(error);
 *     getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len);
 *     if (error != 0) { printf("Socket error: %d\n", error); }
 *
 * SO_SNDBUF / SO_RCVBUF:
 *   Returns current send/receive buffer sizes
 *   May differ from values set with setsockopt (kernel adjusts)
 *   Example:
 *     int bufsize;
 *     socklen_t len = sizeof(bufsize);
 *     getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &bufsize, &len);
 *     printf("Receive buffer: %d bytes\n", bufsize);
 *
 * SO_KEEPALIVE:
 *   Returns keepalive state (0 = disabled, 1 = enabled)
 *   Example:
 *     int keepalive;
 *     socklen_t len = sizeof(keepalive);
 *     getsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &keepalive, &len);
 *
 * SO_REUSEADDR / SO_REUSEPORT:
 *   Returns address/port reuse state
 *   Example:
 *     int reuse;
 *     socklen_t len = sizeof(reuse);
 *     getsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, &len);
 *
 * SO_RCVTIMEO / SO_SNDTIMEO:
 *   Returns current timeout values
 *   Example:
 *     struct timeval tv;
 *     socklen_t len = sizeof(tv);
 *     getsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, &len);
 *     printf("Timeout: %ld.%06ld sec\n", tv.tv_sec, tv.tv_usec);
 *
 * SO_LINGER:
 *   Returns linger settings
 *   Example:
 *     struct linger ling;
 *     socklen_t len = sizeof(ling);
 *     getsockopt(sockfd, SOL_SOCKET, SO_LINGER, &ling, &len);
 *     printf("Linger: %s, timeout: %d\n",
 *            ling.l_onoff ? "on" : "off", ling.l_linger);
 *
 * Common use cases:
 *
 * Check socket type:
 *   int type;
 *   socklen_t len = sizeof(type);
 *   getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &type, &len);
 *   if (type == SOCK_STREAM) {
 *       // TCP socket
 *   } else if (type == SOCK_DGRAM) {
 *       // UDP socket
 *   }
 *
 * Non-blocking connect error check:
 *   connect(sockfd, &addr, sizeof(addr));  // Returns -1, errno = EINPROGRESS
 *   // ... wait for writability ...
 *   int error;
 *   socklen_t len = sizeof(error);
 *   getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len);
 *   if (error == 0) {
 *       // Connection succeeded
 *   } else {
 *       // Connection failed with error
 *   }
 *
 * Query buffer sizes:
 *   int sndbuf, rcvbuf;
 *   socklen_t len = sizeof(int);
 *   getsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sndbuf, &len);
 *   getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, &len);
 *   printf("Buffers: send=%d, recv=%d\n", sndbuf, rcvbuf);
 *
 * Verify keepalive enabled:
 *   int keepalive;
 *   socklen_t len = sizeof(keepalive);
 *   getsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &keepalive, &len);
 *   if (!keepalive) {
 *       fprintf(stderr, "Warning: keepalive not enabled\n");
 *   }
 *
 * Edge cases:
 * - Buffer too small: Truncates value, sets optlen to required size
 * - SO_ERROR: Clears error after reading (side effect)
 * - NULL optval or optlen: Returns -EFAULT
 * - Unknown option: Returns -ENOPROTOOPT
 * - optlen mismatch: May truncate or return -EINVAL
 *
 * Value-result parameter pattern:
 *
 *   int value;
 *   socklen_t len = sizeof(value);
 *   getsockopt(sock, SOL_SOCKET, SO_TYPE, &value, &len);
 *   // len now contains actual size written
 *
 * Input: len = buffer size available
 * Output: len = actual data size (may be less than buffer size)
 *
 * Performance considerations:
 * - O(1) operation (lookup in socket structure)
 * - Non-blocking (no network I/O)
 * - Very fast (local data structure access)
 * - SO_ERROR may involve atomic clear operation
 *
 * Security considerations:
 * - Validates all pointers before use
 * - Checks buffer bounds
 * - Cannot query other processes' sockets
 * - Proper error codes prevent information leaks
 * - Buffer size limits prevent overflow
 *
 * Interaction with other syscalls:
 * - setsockopt: Sets values that getsockopt retrieves
 * - connect: SO_ERROR used to check non-blocking connect
 * - bind/listen: Some options affect or reflect these operations
 * - fcntl: Some overlapping functionality (non-blocking, etc.)
 *
 * Error handling:
 * - EBADF: sockfd is invalid
 * - EFAULT: optval or optlen pointer invalid
 * - EINVAL: optlen is invalid
 * - ENOPROTOOPT: Unknown option at this level
 * - ENOTSOCK: sockfd is not a socket
 *
 * Portability notes:
 * - POSIX standard but option values vary
 * - Some options are Linux-specific
 * - Option availability depends on protocol
 * - Always check return value
 * - Buffer sizes may be adjusted by kernel
 *
 * Protocol-specific options:
 *
 * IPPROTO_TCP:
 *   TCP_NODELAY: Get Nagle's algorithm state
 *   TCP_KEEPIDLE: Get keepalive idle time
 *   TCP_KEEPINTVL: Get keepalive interval
 *   TCP_KEEPCNT: Get keepalive probe count
 *
 * IPPROTO_IP:
 *   IP_TTL: Get IP time-to-live
 *   IP_MULTICAST_TTL: Get multicast TTL
 *   IP_MULTICAST_LOOP: Get multicast loopback state
 *
 * IPPROTO_IPV6:
 *   IPV6_V6ONLY: Get IPv6-only state
 *   IPV6_UNICAST_HOPS: Get hop limit
 *
 * Differences from setsockopt:
 * - getsockopt: Retrieves option values (read-only access)
 * - setsockopt: Sets option values (write access)
 * - Both have identical function signature pattern
 * - Both use value-result optlen parameter
 * - Some options are read-only (only getsockopt works)
 *
 * Real-world examples:
 *
 * Library socket type detection:
 *   int get_socket_type(int sockfd) {
 *       int type;
 *       socklen_t len = sizeof(type);
 *       if (getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &type, &len) == 0) {
 *           return type;
 *       }
 *       return -1;
 *   }
 *
 * Connection health check:
 *   bool is_connection_healthy(int sockfd) {
 *       int error = 0;
 *       socklen_t len = sizeof(error);
 *       getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len);
 *       return error == 0;
 *   }
 *
 * Buffer size tuning:
 *   void report_buffer_sizes(int sockfd) {
 *       int sndbuf, rcvbuf;
 *       socklen_t len = sizeof(int);
 *       getsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sndbuf, &len);
 *       getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, &len);
 *       printf("Send buffer: %d bytes\n", sndbuf);
 *       printf("Recv buffer: %d bytes\n", rcvbuf);
 *   }
 *
 * Debugging socket configuration:
 *   void dump_socket_options(int sockfd) {
 *       int value;
 *       socklen_t len = sizeof(value);
 *
 *       getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &value, &len);
 *       printf("Type: %d\n", value);
 *
 *       getsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &value, &len);
 *       printf("Keepalive: %s\n", value ? "on" : "off");
 *
 *       getsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &value, &len);
 *       printf("Reuse addr: %s\n", value ? "on" : "off");
 *   }
 */
long sys_getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Validate sockfd */
    if (sockfd < 0) {
        fut_printf("[GETSOCKOPT] getsockopt(sockfd=%d) -> EBADF\n", sockfd);
        return -EBADF;
    }

    /* Validate optval pointer */
    if (!optval) {
        fut_printf("[GETSOCKOPT] getsockopt(sockfd=%d, level=%d, optname=%d) -> EFAULT (optval is NULL)\n",
                   sockfd, level, optname);
        return -EFAULT;
    }

    /* Validate optlen pointer */
    if (!optlen) {
        fut_printf("[GETSOCKOPT] getsockopt(sockfd=%d, level=%d, optname=%d) -> EFAULT (optlen is NULL)\n",
                   sockfd, level, optname);
        return -EFAULT;
    }

    /* Read optlen from userspace */
    socklen_t len;
    if (fut_copy_from_user(&len, optlen, sizeof(socklen_t)) != 0) {
        fut_printf("[GETSOCKOPT] getsockopt(sockfd=%d, level=%d, optname=%d) -> EFAULT (copy_from_user optlen failed)\n",
                   sockfd, level, optname);
        return -EFAULT;
    }

    /* Validate optlen value */
    if (len == 0 || len > 1024) {  /* Sanity check */
        fut_printf("[GETSOCKOPT] getsockopt(sockfd=%d, level=%d, optname=%d, optlen=%u) -> EINVAL\n",
                   sockfd, level, optname, len);
        return -EINVAL;
    }

    /* Get socket from FD */
    fut_socket_t *socket = get_socket_from_fd(sockfd);
    if (!socket) {
        fut_printf("[GETSOCKOPT] getsockopt(sockfd=%d) -> EBADF (not a socket)\n", sockfd);
        return -EBADF;
    }

    /* Phase 2: Implement common SOL_SOCKET options */
    if (level == SOL_SOCKET) {
        int int_value;
        socklen_t value_len;

        switch (optname) {
            case SO_TYPE:
                /* Return socket type (SOCK_STREAM, etc.) */
                int_value = socket->socket_type;
                value_len = sizeof(int);

                /* Copy as much as fits in user buffer */
                socklen_t copy_len = (len < value_len) ? len : value_len;
                if (fut_copy_to_user(optval, &int_value, copy_len) != 0) {
                    return -EFAULT;
                }

                /* Update optlen with actual size */
                if (fut_copy_to_user(optlen, &value_len, sizeof(socklen_t)) != 0) {
                    return -EFAULT;
                }

                fut_printf("[GETSOCKOPT] getsockopt(sockfd=%d, SOL_SOCKET, SO_TYPE) -> %d\n",
                           sockfd, int_value);
                return 0;

            case SO_ERROR:
                /* Return pending error and clear it
                 * Phase 2: No error tracking yet, always return 0 */
                int_value = 0;
                value_len = sizeof(int);

                copy_len = (len < value_len) ? len : value_len;
                if (fut_copy_to_user(optval, &int_value, copy_len) != 0) {
                    return -EFAULT;
                }

                if (fut_copy_to_user(optlen, &value_len, sizeof(socklen_t)) != 0) {
                    return -EFAULT;
                }

                fut_printf("[GETSOCKOPT] getsockopt(sockfd=%d, SOL_SOCKET, SO_ERROR) -> %d\n",
                           sockfd, int_value);
                return 0;

            case SO_SNDBUF:
                /* Return send buffer size */
                int_value = FUT_SOCKET_BUFSIZE;
                value_len = sizeof(int);

                copy_len = (len < value_len) ? len : value_len;
                if (fut_copy_to_user(optval, &int_value, copy_len) != 0) {
                    return -EFAULT;
                }

                if (fut_copy_to_user(optlen, &value_len, sizeof(socklen_t)) != 0) {
                    return -EFAULT;
                }

                fut_printf("[GETSOCKOPT] getsockopt(sockfd=%d, SOL_SOCKET, SO_SNDBUF) -> %d\n",
                           sockfd, int_value);
                return 0;

            case SO_RCVBUF:
                /* Return receive buffer size */
                int_value = FUT_SOCKET_BUFSIZE;
                value_len = sizeof(int);

                copy_len = (len < value_len) ? len : value_len;
                if (fut_copy_to_user(optval, &int_value, copy_len) != 0) {
                    return -EFAULT;
                }

                if (fut_copy_to_user(optlen, &value_len, sizeof(socklen_t)) != 0) {
                    return -EFAULT;
                }

                fut_printf("[GETSOCKOPT] getsockopt(sockfd=%d, SOL_SOCKET, SO_RCVBUF) -> %d\n",
                           sockfd, int_value);
                return 0;

            case SO_REUSEADDR:
            case SO_REUSEPORT:
            case SO_KEEPALIVE:
            case SO_BROADCAST:
            case SO_OOBINLINE:
            case SO_DONTROUTE:
            case SO_LINGER:
            case SO_RCVLOWAT:
            case SO_SNDLOWAT:
            case SO_RCVTIMEO:
            case SO_SNDTIMEO:
                /* Phase 2: Not yet implemented */
                fut_printf("[GETSOCKOPT] getsockopt(sockfd=%d, SOL_SOCKET, optname=%d) -> ENOPROTOOPT (not yet implemented)\n",
                           sockfd, optname);
                return -ENOPROTOOPT;

            default:
                /* Unknown option */
                fut_printf("[GETSOCKOPT] getsockopt(sockfd=%d, SOL_SOCKET, optname=%d) -> ENOPROTOOPT (unknown)\n",
                           sockfd, optname);
                return -ENOPROTOOPT;
        }
    } else {
        /* Phase 3: Protocol-specific options (IPPROTO_TCP, IPPROTO_IP, etc.) */
        const char *level_str = (level == IPPROTO_TCP) ? "IPPROTO_TCP" :
                                (level == IPPROTO_IP) ? "IPPROTO_IP" :
                                (level == IPPROTO_IPV6) ? "IPPROTO_IPV6" : "UNKNOWN";

        fut_printf("[GETSOCKOPT] getsockopt(sockfd=%d, level=%s, optname=%d) -> ENOPROTOOPT (level not supported)\n",
                   sockfd, level_str, optname);
        return -ENOPROTOOPT;
    }
}
