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

/* Internet address structures (mirrors sys_bind.c) */
typedef struct {
    uint16_t sin_family;
    uint16_t sin_port;
    uint32_t sin_addr;
    uint8_t  sin_zero[8];
} sockaddr_in_t;

typedef struct {
    uint16_t sin6_family;
    uint16_t sin6_port;
    uint32_t sin6_flowinfo;
    uint8_t  sin6_addr[16];
    uint32_t sin6_scope_id;
} sockaddr_in6_t;

#include <platform/platform.h>

static inline int getsockname_copy_from_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)src >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_from_user(dst, src, n);
}
static inline int getsockname_copy_to_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)dst >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_to_user(dst, src, n);
}
static inline int getsockname_access_ok(const void *ptr, size_t n, int write) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)ptr >= KERNEL_VIRTUAL_BASE) return 0;
#endif
    return fut_access_ok(ptr, n, write);
}

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
        fut_printf("[GETSOCKNAME] getsockname(sockfd=%d) -> EBADF\n", local_sockfd);
        return -EBADF;
    }

    /* Validate fd upper bounds to prevent out-of-bounds access */
    if (local_sockfd >= task->max_fds) {
        fut_printf("[GETSOCKNAME] getsockname(sockfd=%d) -> EBADF (fd exceeds max_fds %d)\n",
                   local_sockfd, task->max_fds);
        return -EBADF;
    }

    /* Validate addr pointer */
    if (!local_addr) {
        fut_printf("[GETSOCKNAME] getsockname(sockfd=%d) -> EFAULT (addr is NULL)\n", local_sockfd);
        return -EFAULT;
    }

    /* Validate addrlen pointer */
    if (!local_addrlen) {
        fut_printf("[GETSOCKNAME] getsockname(sockfd=%d) -> EFAULT (addrlen is NULL)\n", local_sockfd);
        return -EFAULT;
    }

    /* Validate addrlen write permission early (kernel writes back actual size) */
    if (getsockname_access_ok(local_addrlen, sizeof(socklen_t), 1) != 0) {
        fut_printf("[GETSOCKNAME] getsockname(sockfd=%d) -> EFAULT (addrlen not writable)\n",
                   local_sockfd);
        return -EFAULT;
    }

    /* Read addrlen from userspace */
    socklen_t len;
    if (getsockname_copy_from_user(&len, local_addrlen, sizeof(socklen_t)) != 0) {
        fut_printf("[GETSOCKNAME] getsockname(sockfd=%d) -> EFAULT (copy_from_user addrlen failed)\n",
                   local_sockfd);
        return -EFAULT;
    }

    /* Validate addr write permission early (kernel writes socket address) */
    if (len > 0 && getsockname_access_ok(local_addr, len, 1) != 0) {
        fut_printf("[GETSOCKNAME] getsockname(sockfd=%d, addrlen=%u) -> EFAULT (addr not writable for %u bytes)\n",
                   local_sockfd, len, len);
        return -EFAULT;
    }

    /* Get socket from FD */
    fut_socket_t *socket = get_socket_from_fd(local_sockfd);
    if (!socket) {
        /* Distinguish ENOTSOCK (valid fd, not a socket) from EBADF (invalid fd) */
        if (local_sockfd < task->max_fds && task->fd_table && task->fd_table[local_sockfd]) {
            fut_printf("[GETSOCKNAME] getsockname(sockfd=%d) -> ENOTSOCK (not a socket)\n", local_sockfd);
            return -ENOTSOCK;
        }
        fut_printf("[GETSOCKNAME] getsockname(sockfd=%d) -> EBADF (not a socket)\n", local_sockfd);
        return -EBADF;
    }

    int af = socket->address_family;

    /* AF_NETLINK: return sockaddr_nl{family=16, pad=0, pid=0, groups=0} */
    if (af == 16 /* AF_NETLINK */) {
        struct { uint16_t nl_family; uint16_t nl_pad; uint32_t nl_pid; uint32_t nl_groups; } nladdr = {0};
        nladdr.nl_family = 16;
        socklen_t actual_len = (socklen_t)sizeof(nladdr);
        socklen_t copy_len = (len < actual_len) ? len : actual_len;
        if (getsockname_copy_to_user(local_addr, &nladdr, copy_len) != 0) return -EFAULT;
        if (getsockname_copy_to_user(local_addrlen, &actual_len, sizeof(socklen_t)) != 0) return -EFAULT;
        return 0;
    }

    if (af == AF_INET) {
        /* Return sockaddr_in with stored bound address */
        sockaddr_in_t sin = {0};
        sin.sin_family = AF_INET;
        sin.sin_port   = socket->inet_port;
        sin.sin_addr   = socket->inet_addr;
        socklen_t actual_len = (socklen_t)sizeof(sockaddr_in_t);
        socklen_t copy_len = (len < actual_len) ? len : actual_len;
        if (getsockname_copy_to_user(local_addr, &sin, copy_len) != 0)
            return -EFAULT;
        if (getsockname_copy_to_user(local_addrlen, &actual_len, sizeof(socklen_t)) != 0)
            return -EFAULT;
        return 0;
    }

    if (af == AF_INET6) {
        /* Return sockaddr_in6 with stored bound address */
        sockaddr_in6_t sin6 = {0};
        sin6.sin6_family = AF_INET6;
        sin6.sin6_port   = socket->inet_port;
        __builtin_memcpy(&sin6.sin6_addr, socket->inet6_addr, 16);
        socklen_t actual_len = (socklen_t)sizeof(sockaddr_in6_t);
        socklen_t copy_len = (len < actual_len) ? len : actual_len;
        if (getsockname_copy_to_user(local_addr, &sin6, copy_len) != 0)
            return -EFAULT;
        if (getsockname_copy_to_user(local_addrlen, &actual_len, sizeof(socklen_t)) != 0)
            return -EFAULT;
        return 0;
    }

    /* AF_UNIX: build sockaddr_un with socket's bound path.
     * Use bound_path_len (not strnlen) — abstract paths start with '\0'. */
    struct sockaddr_un sock_addr;
    __builtin_memset(&sock_addr, 0, sizeof(sock_addr));
    sock_addr.sun_family = AF_UNIX;

    size_t path_len = 0;
    if (socket->bound_path && socket->bound_path_len > 0) {
        path_len = socket->bound_path_len;
        if (path_len > sizeof(sock_addr.sun_path))
            path_len = sizeof(sock_addr.sun_path);
        __builtin_memcpy(sock_addr.sun_path, socket->bound_path, path_len);
    }

    /* Linux returns addrlen = sizeof(sun_family) + actual path bytes, not sizeof(sockaddr_un). */
    socklen_t actual_len = (socklen_t)(2u + path_len);

    /* Copy as much as fits in user buffer */
    socklen_t copy_len = (len < actual_len) ? len : actual_len;
    if (getsockname_copy_to_user(local_addr, &sock_addr, copy_len) != 0) {
        fut_printf("[GETSOCKNAME] getsockname(sockfd=%d) -> EFAULT (copy_to_user failed)\n",
                   local_sockfd);
        return -EFAULT;
    }

    /* Update addrlen with actual size */
    if (getsockname_copy_to_user(local_addrlen, &actual_len, sizeof(socklen_t)) != 0) {
        fut_printf("[GETSOCKNAME] getsockname(sockfd=%d) -> EFAULT (copy addrlen failed)\n",
                   local_sockfd);
        return -EFAULT;
    }

    return 0;
}
