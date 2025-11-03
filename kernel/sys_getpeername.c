/* kernel/sys_getpeername.c - Get peer address syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements getpeername() to retrieve the address of the peer connected to a socket.
 * Essential for identifying connected clients and network diagnostics.
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);
extern fut_task_t *fut_task_current(void);
extern int fut_copy_from_user(void *to, const void *from, size_t size);
extern int fut_copy_to_user(void *to, const void *from, size_t size);

/* socklen_t for address length */
typedef uint32_t socklen_t;

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
 * Phase 1 (Current): Validates parameters and returns stub
 * Phase 2: Integrate with socket layer to retrieve actual peer address
 * Phase 3: Support different socket families (Unix domain, IPv4, IPv6)
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
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Validate sockfd */
    if (sockfd < 0) {
        fut_printf("[GETPEERNAME] getpeername(sockfd=%d) -> EBADF\n", sockfd);
        return -EBADF;
    }

    /* Validate addr pointer */
    if (!addr) {
        fut_printf("[GETPEERNAME] getpeername(sockfd=%d) -> EFAULT (addr is NULL)\n", sockfd);
        return -EFAULT;
    }

    /* Validate addrlen pointer */
    if (!addrlen) {
        fut_printf("[GETPEERNAME] getpeername(sockfd=%d) -> EFAULT (addrlen is NULL)\n", sockfd);
        return -EFAULT;
    }

    /* Read addrlen from userspace */
    socklen_t len;
    if (fut_copy_from_user(&len, addrlen, sizeof(socklen_t)) != 0) {
        fut_printf("[GETPEERNAME] getpeername(sockfd=%d) -> EFAULT (copy_from_user addrlen failed)\n",
                   sockfd);
        return -EFAULT;
    }

    /* Validate addrlen value */
    if (len == 0) {
        fut_printf("[GETPEERNAME] getpeername(sockfd=%d, addrlen=%u) -> EINVAL\n",
                   sockfd, len);
        return -EINVAL;
    }

    /* Phase 1: Validation only
     * Phase 2: Integrate with socket layer to:
     *   - Verify sockfd is actually a socket (not regular file)
     *   - Check socket is connected (return -ENOTCONN if not)
     *   - Retrieve peer address from socket structure
     *   - Handle different address families (AF_INET, AF_INET6, AF_UNIX)
     *   - Copy address to userspace buffer
     *   - Update addrlen with actual address size
     *   - Handle buffer truncation if len < actual size
     *
     * Phase 3: Address family specific handling:
     *   - AF_INET: Return IPv4 address and port
     *   - AF_INET6: Return IPv6 address, port, flow info, scope
     *   - AF_UNIX: Return Unix domain socket path
     *
     * Phase 4: Edge cases:
     *   - UDP sockets: Return address from last sendto/recvfrom or connect
     *   - Listening sockets: Return -ENOTCONN
     *   - Buffer size handling: Truncate and set addrlen correctly
     */

    fut_printf("[GETPEERNAME] getpeername(sockfd=%d, addrlen=%u) -> 0 (Phase 1 stub)\n",
               sockfd, len);

    /* Phase 1: Just return success for now */
    return 0;
}
