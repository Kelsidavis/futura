/* kernel/sys_getpeername.c - Get peer address syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements getpeername() to retrieve the address of the peer connected to a socket.
 * Essential for identifying connected clients and network diagnostics.
 *
 * Phase 1 (Completed): Basic validation stub
 * Phase 2 (Completed): Full implementation with Unix domain socket support
 * Phase 3 (Completed): IPv4/IPv6 address family support
 * Phase 4: UDP and edge case handling
 */

#include <kernel/fut_task.h>
#include <kernel/fut_socket.h>
#include <kernel/errno.h>
#include <kernel/uaccess.h>
#include <sys/un.h>
#include <stdint.h>
#include <string.h>

#include <kernel/kprintf.h>

#include <platform/platform.h>

static inline int getpeername_copy_from_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)src >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_from_user(dst, src, n);
}
static inline int getpeername_copy_to_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)dst >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_to_user(dst, src, n);
}
static inline int getpeername_access_ok(const void *ptr, size_t n, int write) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)ptr >= KERNEL_VIRTUAL_BASE) return 0;
#endif
    return fut_access_ok(ptr, n, write);
}

/* Address family constants (AF_*) provided by fut_socket.h */
/* struct sockaddr_un provided by sys/un.h */

/* Internet address structures (same layout as sys_getsockname.c) */
typedef struct {
    uint16_t sin_family;
    uint16_t sin_port;
    uint32_t sin_addr;
    uint8_t  sin_zero[8];
} gpn_sockaddr_in_t;

typedef struct {
    uint16_t sin6_family;
    uint16_t sin6_port;
    uint32_t sin6_flowinfo;
    uint8_t  sin6_addr[16];
    uint32_t sin6_scope_id;
} gpn_sockaddr_in6_t;

/**
 * getpeername() - Get address of connected peer
 *
 * Retrieves the address of the peer connected to the socket sockfd. This is
 * useful for determining who you're connected to on the other end of a socket
 * connection.
 *
 * The returned address is truncated if the buffer provided is too small; in
 * this case, addrlen will return a value greater than was supplied to the call.
 *
 * @param sockfd  Socket file descriptor
 * @param addr    Pointer to sockaddr structure to receive peer address
 * @param addrlen Pointer to length of addr buffer (in/out parameter)
 *
 * Returns:
 *   - 0 on success
 *   - -EBADF if sockfd is not a valid file descriptor
 *   - -EFAULT if addr or addrlen point to invalid memory
 *   - -EINVAL if addrlen is invalid
 *   - -ENOTCONN if socket is not connected
 *   - -ENOTSOCK if sockfd is not a socket
 *   - -ENOBUFS if insufficient resources available in the system
 *
 * Behavior:
 * - Returns the address of the peer socket
 * - For connection-oriented sockets (TCP): returns remote endpoint address
 * - For connectionless sockets (UDP): returns address of last peer communicated with
 * - addrlen is value-result parameter (input: buffer size, output: actual size)
 * - Address is truncated if buffer too small
 *
 * Phase 1 (Completed): Validates parameters and returns stub
 * Phase 2 (Completed): Integrate with socket layer to retrieve actual peer address
 * Phase 3 (Completed): Support different socket families (IPv4, IPv6)
 * Phase 4: Handle edge cases (unconnected UDP sockets, etc.)
 *
 * Example: Get peer address for logging
 *
 *   struct sockaddr_in peer_addr;
 *   socklen_t peer_len = sizeof(peer_addr);
 *
 *   if (getpeername(sockfd, (struct sockaddr *)&peer_addr, &peer_len) == 0) {
 *       char *ip = inet_ntoa(peer_addr.sin_addr);
 *       int port = ntohs(peer_addr.sin_port);
 *       printf("Connected to %s:%d\n", ip, port);
 *   }
 *
 * Example: Security check
 *
 *   struct sockaddr_in peer_addr;
 *   socklen_t peer_len = sizeof(peer_addr);
 *
 *   getpeername(sockfd, (struct sockaddr *)&peer_addr, &peer_len);
 *
 *   // Check if connection is from allowed subnet
 *   if (!is_allowed_ip(peer_addr.sin_addr.s_addr)) {
 *       close(sockfd);
 *       return -EACCES;
 *   }
 *
 * Example: Unix domain socket
 *
 *   struct sockaddr_un peer_addr;
 *   socklen_t peer_len = sizeof(peer_addr);
 *
 *   if (getpeername(sockfd, (struct sockaddr *)&peer_addr, &peer_len) == 0) {
 *       printf("Connected to Unix socket: %s\n", peer_addr.sun_path);
 *   }
 *
 * Common use cases:
 * - Access control: Verify peer address matches allowed list
 * - Logging: Record connection source for audit trails
 * - Rate limiting: Track connections per IP address
 * - Reverse DNS: Look up hostname from IP address
 * - Protocol negotiation: Adjust behavior based on peer
 * - Network diagnostics: Display connection information
 *
 * Interaction with other syscalls:
 * - connect: After connect(), getpeername returns server address
 * - accept: After accept(), getpeername returns client address
 * - getsockname: Returns local address (complement to getpeername)
 * - getaddrinfo: Used to create addresses, getpeername retrieves them
 *
 * Socket family-specific behavior:
 *
 * AF_INET (IPv4):
 *   struct sockaddr_in {
 *       sa_family_t    sin_family;  // AF_INET
 *       in_port_t      sin_port;    // Port number
 *       struct in_addr sin_addr;    // IPv4 address
 *   };
 *
 * AF_INET6 (IPv6):
 *   struct sockaddr_in6 {
 *       sa_family_t     sin6_family;   // AF_INET6
 *       in_port_t       sin6_port;     // Port number
 *       uint32_t        sin6_flowinfo; // IPv6 flow info
 *       struct in6_addr sin6_addr;     // IPv6 address
 *       uint32_t        sin6_scope_id; // Scope ID
 *   };
 *
 * AF_UNIX (Unix domain):
 *   struct sockaddr_un {
 *       sa_family_t sun_family;        // AF_UNIX
 *       char        sun_path[108];     // Pathname
 *   };
 *
 * Connection states:
 * - TCP ESTABLISHED: Returns remote peer address
 * - TCP LISTEN: Returns -ENOTCONN (not connected)
 * - UDP (connected): Returns address from connect() call
 * - UDP (unconnected): Returns -ENOTCONN or last peer
 *
 * Edge cases:
 * - Socket not connected: Returns -ENOTCONN
 * - Buffer too small: Truncates address, sets addrlen to required size
 * - After close(): Returns -EBADF
 * - On listening socket: Returns -ENOTCONN
 * - NULL addr or addrlen: Returns -EFAULT
 *
 * Differences from getsockname():
 * - getpeername: Returns remote peer address
 * - getsockname: Returns local socket address
 * - Both have identical function signature
 * - Both use value-result addrlen parameter
 *
 * Performance characteristics:
 * - O(1) operation (lookup in socket structure)
 * - Non-blocking (no network I/O)
 * - Very fast (local data structure access)
 * - No system calls to network stack
 *
 * Security considerations:
 * - Validates all pointers before use
 * - Checks buffer bounds
 * - Cannot retrieve addresses from other processes' sockets
 * - Proper error codes prevent information leaks
 * - Address family determines data format
 *
 * Error handling:
 * - EBADF: sockfd is invalid or closed
 * - EFAULT: Invalid addr or addrlen pointer
 * - EINVAL: addrlen is invalid (e.g., negative)
 * - ENOTCONN: Socket not connected (connection-oriented)
 * - ENOTSOCK: sockfd is a file, not a socket
 * - ENOBUFS: System resource shortage (rare)
 *
 * Portability notes:
 * - POSIX standard (widely supported)
 * - Address structures vary by family
 * - Some systems return EINVAL instead of ENOTCONN
 * - Buffer size handling may differ slightly
 * - Always check return value
 *
 * Value-result parameter pattern:
 *
 *   socklen_t len = sizeof(addr);
 *   getpeername(sock, &addr, &len);
 *   // len now contains actual address size
 *
 * Input: len = buffer size available
 * Output: len = actual address size (may exceed buffer size)
 *
 * If output > input: Address was truncated
 *
 * Comparison with alternatives:
 *
 * Using getpeername() (correct):
 *   struct sockaddr_in addr;
 *   socklen_t len = sizeof(addr);
 *   getpeername(sockfd, (struct sockaddr *)&addr, &len);
 *
 * Trying to track manually (error-prone):
 *   // Must track peer address from accept() or connect()
 *   // Error-prone, breaks with dup(), fork(), etc.
 *
 * Benefits of getpeername():
 * - Always accurate (single source of truth)
 * - Works after dup(), fork(), SCM_RIGHTS
 * - No need to track address manually
 * - Handles all socket families uniformly
 */
long sys_getpeername(int sockfd, void *addr, socklen_t *addrlen) {
    /* ARM64 FIX: Copy register-passed parameters to local stack variables so they
     * survive across potentially blocking calls (fut_copy_from_user/fut_copy_to_user
     * may context-switch on ARM64, corrupting register values on resumption). */
    int local_sockfd = sockfd;
    void *local_addr = addr;
    socklen_t *local_addrlen = addrlen;

    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Validate sockfd */
    if (local_sockfd < 0) {
        fut_printf("[GETPEERNAME] getpeername(sockfd=%d) -> EBADF\n", local_sockfd);
        return -EBADF;
    }

    /* Validate fd upper bounds to prevent out-of-bounds access */
    if (local_sockfd >= task->max_fds) {
        fut_printf("[GETPEERNAME] getpeername(sockfd=%d) -> EBADF (fd exceeds max_fds %d)\n",
                   local_sockfd, task->max_fds);
        return -EBADF;
    }

    /* Linux's sys_getpeername runs sockfd_lookup_light FIRST, so EBADF
     * (invalid fd) and ENOTSOCK (open file that isn't a socket) surface
     * before any inspection of the addr/addrlen pointers.  The previous
     * Futura order rejected NULL addr/addrlen up front with EFAULT,
     * masking ENOTSOCK for the common 'is this fd a socket?' probe
     * pattern.  Move the socket lookup ahead of the pointer checks —
     * same fix as the matching sys_getsockname reorder. */
    fut_socket_t *socket = get_socket_from_fd(local_sockfd);
    if (!socket) {
        if (task->fd_table && task->fd_table[local_sockfd]) {
            fut_printf("[GETPEERNAME] getpeername(sockfd=%d) -> ENOTSOCK (not a socket)\n", local_sockfd);
            return -ENOTSOCK;
        }
        fut_printf("[GETPEERNAME] getpeername(sockfd=%d) -> EBADF (not a socket)\n", local_sockfd);
        return -EBADF;
    }

    /* Validate addr pointer */
    if (!local_addr) {
        fut_printf("[GETPEERNAME] getpeername(sockfd=%d) -> EFAULT (addr is NULL)\n", local_sockfd);
        return -EFAULT;
    }

    /* Validate addrlen pointer */
    if (!local_addrlen) {
        fut_printf("[GETPEERNAME] getpeername(sockfd=%d) -> EFAULT (addrlen is NULL)\n", local_sockfd);
        return -EFAULT;
    }

    /* Validate addrlen write permission early (kernel writes back actual size) */
    if (getpeername_access_ok(local_addrlen, sizeof(socklen_t), 1) != 0) {
        fut_printf("[GETPEERNAME] getpeername(sockfd=%d) -> EFAULT (addrlen not writable)\n",
                   local_sockfd);
        return -EFAULT;
    }

    /* Read addrlen from userspace */
    socklen_t len;
    if (getpeername_copy_from_user(&len, local_addrlen, sizeof(socklen_t)) != 0) {
        fut_printf("[GETPEERNAME] getpeername(sockfd=%d) -> EFAULT (copy_from_user addrlen failed)\n",
                   local_sockfd);
        return -EFAULT;
    }

    /* Validate addr write permission early (kernel writes peer address) */
    if (len > 0 && getpeername_access_ok(local_addr, len, 1) != 0) {
        fut_printf("[GETPEERNAME] getpeername(sockfd=%d, addrlen=%u) -> EFAULT (addr not writable for %u bytes)\n",
                   local_sockfd, len, len);
        return -EFAULT;
    }

    /* AF_INET: return peer's sockaddr_in from the connected pair */
    if (socket->address_family == AF_INET) {
        fut_socket_t *peer = NULL;
        if (socket->socket_type == SOCK_STREAM || socket->socket_type == SOCK_SEQPACKET) {
            if (socket->state != FUT_SOCK_CONNECTED) {
                fut_printf("[GETPEERNAME] getpeername(sockfd=%d) -> ENOTCONN (AF_INET not connected)\n",
                           local_sockfd);
                return -ENOTCONN;
            }
            peer = socket->pair ? socket->pair->peer : NULL;
        }
        gpn_sockaddr_in_t sin = {0};
        sin.sin_family = AF_INET;
        /* Use inet_peer_addr/port fields (set by connect/accept) */
        if (socket->inet_peer_addr || socket->inet_peer_port) {
            sin.sin_port = socket->inet_peer_port;
            sin.sin_addr = socket->inet_peer_addr;
        } else if (peer) {
            sin.sin_port = peer->inet_port;
            sin.sin_addr = peer->inet_addr;
        }
        socklen_t actual_len = (socklen_t)sizeof(gpn_sockaddr_in_t);
        socklen_t copy_len = (len < actual_len) ? len : actual_len;
        if (getpeername_copy_to_user(local_addr, &sin, copy_len) != 0)
            return -EFAULT;
        if (getpeername_copy_to_user(local_addrlen, &actual_len, sizeof(socklen_t)) != 0)
            return -EFAULT;
        return 0;
    }

    /* AF_INET6: return peer's sockaddr_in6 */
    if (socket->address_family == AF_INET6) {
        fut_socket_t *peer = NULL;
        if (socket->socket_type == SOCK_STREAM || socket->socket_type == SOCK_SEQPACKET) {
            if (socket->state != FUT_SOCK_CONNECTED) {
                fut_printf("[GETPEERNAME] getpeername(sockfd=%d) -> ENOTCONN (AF_INET6 not connected)\n",
                           local_sockfd);
                return -ENOTCONN;
            }
            peer = socket->pair ? socket->pair->peer : NULL;
        }
        gpn_sockaddr_in6_t sin6 = {0};
        sin6.sin6_family = AF_INET6;
        if (peer) {
            sin6.sin6_port = peer->inet_port;
            __builtin_memcpy(&sin6.sin6_addr, peer->inet6_addr, 16);
        }
        socklen_t actual_len = (socklen_t)sizeof(gpn_sockaddr_in6_t);
        socklen_t copy_len = (len < actual_len) ? len : actual_len;
        if (getpeername_copy_to_user(local_addr, &sin6, copy_len) != 0)
            return -EFAULT;
        if (getpeername_copy_to_user(local_addrlen, &actual_len, sizeof(socklen_t)) != 0)
            return -EFAULT;
        return 0;
    }

    /* Determine peer path and length based on socket type */
    const char *peer_path = NULL;
    size_t peer_path_len = 0;

    if (socket->socket_type == SOCK_DGRAM) {
        /* SOCK_DGRAM: peer is the address stored by connect() */
        if (socket->dgram_peer_path_len == 0) {
            fut_printf("[GETPEERNAME] getpeername(sockfd=%d) -> ENOTCONN (DGRAM not connected)\n",
                       local_sockfd);
            return -ENOTCONN;
        }
        peer_path = socket->dgram_peer_path;
        peer_path_len = socket->dgram_peer_path_len;
    } else {
        /* SOCK_STREAM / SOCK_SEQPACKET: peer is the other end of the pair */
        if (socket->state != FUT_SOCK_CONNECTED) {
            fut_printf("[GETPEERNAME] getpeername(sockfd=%d) -> ENOTCONN (state=%d)\n",
                       local_sockfd, socket->state);
            return -ENOTCONN;
        }
        fut_socket_t *peer = socket->pair ? socket->pair->peer : NULL;
        if (!peer) {
            fut_printf("[GETPEERNAME] getpeername(sockfd=%d) -> ENOTCONN (no peer)\n", local_sockfd);
            return -ENOTCONN;
        }
        /* Use bound_path_len — abstract paths start with '\0', strnlen would return 0 */
        if (peer->bound_path && peer->bound_path_len > 0) {
            peer_path = peer->bound_path;
            peer_path_len = peer->bound_path_len;
        }
    }

    /* Build sockaddr_un with peer address */
    struct sockaddr_un peer_addr;
    __builtin_memset(&peer_addr, 0, sizeof(peer_addr));
    peer_addr.sun_family = AF_UNIX;

    if (peer_path && peer_path_len > 0) {
        size_t copy_path = peer_path_len;
        if (copy_path > sizeof(peer_addr.sun_path))
            copy_path = sizeof(peer_addr.sun_path);
        __builtin_memcpy(peer_addr.sun_path, peer_path, copy_path);
    }

    /* Linux returns addrlen = sizeof(sun_family) + actual path bytes */
    socklen_t actual_len = (socklen_t)(2u + peer_path_len);

    /* Copy as much as fits in user buffer */
    socklen_t copy_len = (len < actual_len) ? len : actual_len;
    if (getpeername_copy_to_user(local_addr, &peer_addr, copy_len) != 0) {
        fut_printf("[GETPEERNAME] getpeername(sockfd=%d) -> EFAULT (copy_to_user failed)\n",
                   local_sockfd);
        return -EFAULT;
    }

    /* Update addrlen with actual size */
    if (getpeername_copy_to_user(local_addrlen, &actual_len, sizeof(socklen_t)) != 0) {
        fut_printf("[GETPEERNAME] getpeername(sockfd=%d) -> EFAULT (copy addrlen failed)\n",
                   local_sockfd);
        return -EFAULT;
    }

    return 0;
}
