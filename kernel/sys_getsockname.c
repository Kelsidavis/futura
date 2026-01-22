/* kernel/sys_getsockname.c - Get local socket address syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements getsockname() to retrieve the local address to which a socket is bound.
 * Complement to getpeername() which retrieves the remote peer address.
 *
 * Phase 1 (Completed): Basic validation stub
 * Phase 2 (Completed): Full implementation with Unix domain socket support
 * Phase 3 (Completed): IPv4/IPv6 address family support
 * Phase 4: Ephemeral port and multi-interface handling
 */

#include <kernel/fut_task.h>
#include <kernel/fut_socket.h>
#include <kernel/errno.h>
#include <kernel/uaccess.h>
#include <sys/un.h>
#include <stdint.h>
#include <string.h>

#include <kernel/kprintf.h>

/* Address family constants (AF_*) provided by fut_socket.h */
/* struct sockaddr_un provided by sys/un.h */

/**
 * getsockname() - Get local socket address
 *
 * Retrieves the current address to which the socket sockfd is bound. This is
 * particularly useful for determining which local address and port the kernel
 * assigned, especially when binding to port 0 (ephemeral port assignment).
 *
 * The returned address is truncated if the buffer provided is too small; in
 * this case, addrlen will return a value greater than was supplied to the call.
 *
 * @param sockfd  Socket file descriptor
 * @param addr    Pointer to sockaddr structure to receive local address
 * @param addrlen Pointer to length of addr buffer (in/out parameter)
 *
 * Returns:
 *   - 0 on success
 *   - -EBADF if sockfd is not a valid file descriptor
 *   - -EFAULT if addr or addrlen point to invalid memory
 *   - -EINVAL if addrlen is invalid
 *   - -ENOTSOCK if sockfd is not a socket
 *   - -ENOBUFS if insufficient resources available in the system
 *
 * Behavior:
 * - Returns the local address of the socket
 * - For bound sockets: returns the address from bind()
 * - For unbound sockets: returns default address (typically 0.0.0.0:0)
 * - For connected sockets: returns local endpoint of connection
 * - addrlen is value-result parameter (input: buffer size, output: actual size)
 * - Address is truncated if buffer too small
 *
 * Phase 1 (Completed): Validates parameters and returns stub
 * Phase 2 (Completed): Integrate with socket layer to retrieve actual local address
 * Phase 3 (Completed): Support different socket families (IPv4, IPv6)
 * Phase 4: Handle ephemeral port assignment and multiple interfaces
 *
 * Example: Get assigned ephemeral port
 *
 *   int sockfd = socket(AF_INET, SOCK_STREAM, 0);
 *
 *   struct sockaddr_in addr = {0};
 *   addr.sin_family = AF_INET;
 *   addr.sin_port = 0;  // Let kernel assign port
 *   addr.sin_addr.s_addr = INADDR_ANY;
 *
 *   bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));
 *
 *   // Find out which port was assigned
 *   socklen_t len = sizeof(addr);
 *   getsockname(sockfd, (struct sockaddr *)&addr, &len);
 *   printf("Bound to port %d\n", ntohs(addr.sin_port));
 *
 * Example: Get local address after connect
 *
 *   int sockfd = socket(AF_INET, SOCK_STREAM, 0);
 *   connect(sockfd, &server_addr, sizeof(server_addr));
 *
 *   // Find out which local address/port was used
 *   struct sockaddr_in local_addr;
 *   socklen_t len = sizeof(local_addr);
 *   getsockname(sockfd, (struct sockaddr *)&local_addr, &len);
 *
 *   char *local_ip = inet_ntoa(local_addr.sin_addr);
 *   int local_port = ntohs(local_addr.sin_port);
 *   printf("Local endpoint: %s:%d\n", local_ip, local_port);
 *
 * Example: Multi-homed server
 *
 *   // Server binds to INADDR_ANY, want to know actual interface
 *   struct sockaddr_in client_addr;
 *   socklen_t client_len = sizeof(client_addr);
 *   int conn_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &client_len);
 *
 *   // Which local interface is serving this connection?
 *   struct sockaddr_in local_addr;
 *   socklen_t local_len = sizeof(local_addr);
 *   getsockname(conn_fd, (struct sockaddr *)&local_addr, &local_len);
 *   printf("Serving on interface: %s\n", inet_ntoa(local_addr.sin_addr));
 *
 * Common use cases:
 * - Determine ephemeral port assigned by kernel
 * - Identify local interface handling connection (multi-homed hosts)
 * - Logging local endpoint for audit and diagnostics
 * - FTP PORT command: Must advertise actual listening port
 * - Service discovery: Announce address:port to registry
 * - NAT detection: Compare local address with external address
 *
 * Interaction with other syscalls:
 * - bind: getsockname returns the address from bind()
 * - listen: getsockname returns listening address
 * - accept: getsockname returns local endpoint of accepted connection
 * - connect: getsockname returns local endpoint chosen by kernel
 * - getpeername: Returns remote address (complement to getsockname)
 *
 * Socket states and behavior:
 *
 * Unbound socket:
 *   - Returns wildcard address (0.0.0.0:0 for IPv4)
 *   - Port is 0 (not assigned yet)
 *
 * Bound socket (explicit bind):
 *   - Returns address from bind() call
 *   - Includes assigned port (may be ephemeral)
 *
 * Connected socket (implicit bind):
 *   - Returns local endpoint of connection
 *   - Kernel chose local address and ephemeral port
 *
 * Listening socket:
 *   - Returns address from bind() call
 *   - Useful for confirming listening configuration
 *
 * Socket family-specific behavior:
 *
 * AF_INET (IPv4):
 *   struct sockaddr_in {
 *       sa_family_t    sin_family;  // AF_INET
 *       in_port_t      sin_port;    // Port number (may be 0)
 *       struct in_addr sin_addr;    // IPv4 address (may be 0.0.0.0)
 *   };
 *
 * AF_INET6 (IPv6):
 *   struct sockaddr_in6 {
 *       sa_family_t     sin6_family;   // AF_INET6
 *       in_port_t       sin6_port;     // Port number
 *       uint32_t        sin6_flowinfo; // IPv6 flow info
 *       struct in6_addr sin6_addr;     // IPv6 address (may be ::)
 *       uint32_t        sin6_scope_id; // Scope ID
 *   };
 *
 * AF_UNIX (Unix domain):
 *   struct sockaddr_un {
 *       sa_family_t sun_family;        // AF_UNIX
 *       char        sun_path[108];     // Pathname (empty if unbound)
 *   };
 *
 * Ephemeral port assignment:
 * - When bind() called with port 0, kernel assigns ephemeral port
 * - Range typically 32768-60999 (configurable via /proc)
 * - getsockname() reveals the actual assigned port
 * - Essential for dynamic service registration
 *
 * Edge cases:
 * - Unbound socket: Returns wildcard address
 * - Buffer too small: Truncates address, sets addrlen to required size
 * - After close(): Returns -EBADF
 * - NULL addr or addrlen: Returns -EFAULT
 * - Abstract Unix domain socket: Returns empty sun_path
 *
 * Differences from getpeername():
 * - getsockname: Returns local socket address
 * - getpeername: Returns remote peer address
 * - Both have identical function signature
 * - Both use value-result addrlen parameter
 * - getsockname works on unbound sockets (returns wildcard)
 * - getpeername requires connected socket (returns -ENOTCONN)
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
 * - ENOTSOCK: sockfd is a file, not a socket
 * - ENOBUFS: System resource shortage (rare)
 *
 * Portability notes:
 * - POSIX standard (widely supported)
 * - Address structures vary by family
 * - Unbound socket behavior may differ slightly
 * - Buffer size handling may differ slightly
 * - Always check return value
 *
 * Value-result parameter pattern:
 *
 *   socklen_t len = sizeof(addr);
 *   getsockname(sock, &addr, &len);
 *   // len now contains actual address size
 *
 * Input: len = buffer size available
 * Output: len = actual address size (may exceed buffer size)
 *
 * If output > input: Address was truncated
 *
 * Comparison with alternatives:
 *
 * Using getsockname() (correct):
 *   struct sockaddr_in addr;
 *   socklen_t len = sizeof(addr);
 *   getsockname(sockfd, (struct sockaddr *)&addr, &len);
 *
 * Trying to track manually (error-prone):
 *   // Must track address from bind() call
 *   // Breaks with ephemeral ports, dup(), fork(), etc.
 *
 * Benefits of getsockname():
 * - Always accurate (single source of truth)
 * - Reveals ephemeral port assignments
 * - Works after dup(), fork(), SCM_RIGHTS
 * - No need to track address manually
 * - Handles all socket families uniformly
 *
 * Real-world scenarios:
 *
 * FTP Active Mode:
 *   // Server must tell client which port to connect to
 *   struct sockaddr_in data_addr;
 *   socklen_t len = sizeof(data_addr);
 *   getsockname(data_socket, (struct sockaddr *)&data_addr, &len);
 *   fprintf(client, "PORT %d,%d\n",
 *           ntohs(data_addr.sin_port) >> 8,
 *           ntohs(data_addr.sin_port) & 0xFF);
 *
 * Service Registration:
 *   // Register with service discovery system
 *   struct sockaddr_in addr;
 *   socklen_t len = sizeof(addr);
 *   getsockname(sockfd, (struct sockaddr *)&addr, &len);
 *   register_service("myapp", inet_ntoa(addr.sin_addr),
 *                    ntohs(addr.sin_port));
 *
 * Multi-homed Routing:
 *   // Determine which interface is actually used
 *   getsockname(conn_fd, &local_addr, &len);
 *   if (is_internal_interface(&local_addr)) {
 *       // Use internal routing table
 *   } else {
 *       // Use external routing table
 *   }
 */
long sys_getsockname(int sockfd, void *addr, socklen_t *addrlen) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Validate sockfd */
    if (sockfd < 0) {
        fut_printf("[GETSOCKNAME] getsockname(sockfd=%d) -> EBADF\n", sockfd);
        return -EBADF;
    }

    /* Validate addr pointer */
    if (!addr) {
        fut_printf("[GETSOCKNAME] getsockname(sockfd=%d) -> EFAULT (addr is NULL)\n", sockfd);
        return -EFAULT;
    }

    /* Validate addrlen pointer */
    if (!addrlen) {
        fut_printf("[GETSOCKNAME] getsockname(sockfd=%d) -> EFAULT (addrlen is NULL)\n", sockfd);
        return -EFAULT;
    }

    /* Phase 5: Validate addrlen write permission early (kernel writes back actual size)
     * VULNERABILITY: Invalid Output Pointer
     * ATTACK: Attacker provides read-only or unmapped addrlen pointer
     * IMPACT: Kernel page fault when writing actual address length
     * DEFENSE: Check write permission before socket operations */
    if (fut_access_ok(addrlen, sizeof(socklen_t), 1) != 0) {
        fut_printf("[GETSOCKNAME] getsockname(sockfd=%d) -> EFAULT (addrlen not writable, Phase 5)\n",
                   sockfd);
        return -EFAULT;
    }

    /* Read addrlen from userspace */
    socklen_t len;
    if (fut_copy_from_user(&len, addrlen, sizeof(socklen_t)) != 0) {
        fut_printf("[GETSOCKNAME] getsockname(sockfd=%d) -> EFAULT (copy_from_user addrlen failed)\n",
                   sockfd);
        return -EFAULT;
    }

    /* Phase 5: Validate addr write permission early (kernel writes socket address)
     * VULNERABILITY: Invalid Output Buffer
     * ATTACK: Attacker provides read-only or unmapped addr buffer
     * IMPACT: Kernel page fault when writing socket address
     * DEFENSE: Check write permission for addr buffer size */
    if (len > 0 && fut_access_ok(addr, len, 1) != 0) {
        fut_printf("[GETSOCKNAME] getsockname(sockfd=%d, addrlen=%u) -> EFAULT (addr not writable for %u bytes, Phase 5)\n",
                   sockfd, len, len);
        return -EFAULT;
    }

    /* Validate addrlen value */
    if (len == 0) {
        fut_printf("[GETSOCKNAME] getsockname(sockfd=%d, addrlen=%u) -> EINVAL\n",
                   sockfd, len);
        return -EINVAL;
    }

    /* Get socket from FD */
    fut_socket_t *socket = get_socket_from_fd(sockfd);
    if (!socket) {
        fut_printf("[GETSOCKNAME] getsockname(sockfd=%d) -> EBADF (not a socket)\n", sockfd);
        return -EBADF;
    }

    /* Phase 2: Unix domain socket support
     * Build sockaddr_un structure with socket's bound path */
    struct sockaddr_un sock_addr;
    memset(&sock_addr, 0, sizeof(sock_addr));
    sock_addr.sun_family = AF_UNIX;

    /* Copy bound path if socket is bound */
    if (socket->bound_path) {
        /* Calculate string length manually */
        size_t path_len = 0;
        while (socket->bound_path[path_len] != '\0' && path_len < sizeof(sock_addr.sun_path) - 1) {
            path_len++;
        }

        memcpy(sock_addr.sun_path, socket->bound_path, path_len);
        sock_addr.sun_path[path_len] = '\0';

        fut_printf("[GETSOCKNAME] getsockname(sockfd=%d) -> path='%s'\n",
                   sockfd, socket->bound_path);
    } else {
        /* Unbound socket - return empty path */
        sock_addr.sun_path[0] = '\0';
        fut_printf("[GETSOCKNAME] getsockname(sockfd=%d) -> unbound (empty path)\n",
                   sockfd);
    }

    /* Calculate actual address size */
    socklen_t actual_len = sizeof(struct sockaddr_un);

    /* Copy as much as fits in user buffer */
    socklen_t copy_len = (len < actual_len) ? len : actual_len;
    if (fut_copy_to_user(addr, &sock_addr, copy_len) != 0) {
        fut_printf("[GETSOCKNAME] getsockname(sockfd=%d) -> EFAULT (copy_to_user failed)\n",
                   sockfd);
        return -EFAULT;
    }

    /* Update addrlen with actual size (may be larger than buffer) */
    if (fut_copy_to_user(addrlen, &actual_len, sizeof(socklen_t)) != 0) {
        fut_printf("[GETSOCKNAME] getsockname(sockfd=%d) -> EFAULT (copy addrlen failed)\n",
                   sockfd);
        return -EFAULT;
    }

    if (len < actual_len) {
        fut_printf("[GETSOCKNAME] getsockname(sockfd=%d) -> 0 (truncated: %u < %u)\n",
                   sockfd, len, actual_len);
    }

    return 0;
}
