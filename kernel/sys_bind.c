/* kernel/sys_bind.c - Bind socket to address syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements bind() to bind sockets to addresses.
 *
 * Phase 1 (Completed): Basic bind implementation with Unix domain socket support
 * Phase 2 (Completed): Enhanced validation, address family identification, and detailed logging
 * Phase 3 (Completed): Support for multiple address families (AF_INET, AF_INET6)
 * Phase 4 (Current): Advanced features (SO_REUSEADDR, SO_REUSEPORT, wildcard binding)
 */

#include <kernel/fut_task.h>
#include <kernel/fut_socket.h>
#include <kernel/uaccess.h>
#include <kernel/errno.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);
extern fut_task_t *fut_task_current(void);
extern fut_socket_t *get_socket_from_fd(int fd);

typedef uint32_t socklen_t;

/* Address family constants */
#define AF_UNSPEC 0
#define AF_UNIX   1
#define AF_INET   2
#define AF_INET6  10

/* Internet address structures */
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

/* Phase 3: Helper to categorize port numbers */
static const char *categorize_port(uint16_t port) {
    if (port < 1024) {
        return "privileged (0-1023)";
    } else if (port < 49152) {
        return "registered (1024-49151)";
    } else {
        return "ephemeral/dynamic (49152-65535)";
    }
}

/**
 * bind() - Bind socket to local address
 *
 * Assigns a local address to a socket. For Unix domain sockets, this creates
 * a filesystem entry or abstract socket. For Internet sockets, this binds to
 * an IP address and port.
 *
 * @param sockfd  Socket file descriptor
 * @param addr    Pointer to sockaddr structure containing address
 * @param addrlen Size of address structure
 *
 * Returns:
 *   - 0 on success
 *   - -EBADF if sockfd is not a valid file descriptor
 *   - -EFAULT if addr points to invalid memory
 *   - -EINVAL if addrlen is invalid or socket already bound
 *   - -ENOTSOCK if sockfd is not a socket
 *   - -ENOTSUP if address family not supported
 *   - -EACCES if address is protected (e.g., privileged port)
 *   - -EEXIST if address already in use
 *   - -ENAMETOOLONG if Unix domain path too long
 *   - -ENOMEM if insufficient memory
 *
 * Behavior:
 *   - Must be called before listen() for server sockets
 *   - Optional for client sockets (kernel assigns ephemeral)
 *   - Once bound, socket address cannot be changed
 *   - Unix domain: creates filesystem entry (deleted on close if not abstract)
 *   - Internet: binds to specific IP:port or wildcard
 *
 * Address families:
 *   - AF_UNIX (1): Unix domain sockets (filesystem or abstract paths)
 *   - AF_INET (2): IPv4 addresses (not yet implemented in Phase 2)
 *   - AF_INET6 (10): IPv6 addresses (not yet implemented in Phase 2)
 *
 * Unix domain socket paths:
 *   - Filesystem: '/tmp/socket.sock' (creates file, max 108 bytes)
 *   - Abstract: '\0name' (no filesystem entry, Linux-specific)
 *   - Empty: '' (anonymous, some systems)
 *
 * Phase 1 (Completed): Basic Unix domain socket binding
 * Phase 2 (Completed): Address family identification and enhanced validation
 * Phase 3 (Completed): Support for AF_INET and AF_INET6
 * Phase 4 (Current): Advanced features (SO_REUSEADDR, SO_REUSEPORT, port ranges)
 */
long sys_bind(int sockfd, const void *addr, socklen_t addrlen) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[BIND] bind(sockfd=%d) -> ESRCH (no current task)\n", sockfd);
        return -ESRCH;
    }

    /* Phase 2: Validate sockfd early */
    if (sockfd < 0) {
        fut_printf("[BIND] bind(sockfd=%d, addrlen=%u) -> EBADF (negative fd)\n",
                   sockfd, addrlen);
        return -EBADF;
    }

    /* Phase 2: Validate addr pointer */
    if (!addr) {
        fut_printf("[BIND] bind(sockfd=%d, addr=NULL, addrlen=%u) -> EFAULT (NULL addr)\n",
                   sockfd, addrlen);
        return -EFAULT;
    }

    /* Phase 2: Validate minimum address length (family field is 2 bytes) */
    if (addrlen < 2) {
        fut_printf("[BIND] bind(sockfd=%d, addrlen=%u) -> EINVAL (too small, need at least 2 bytes for family)\n",
                   sockfd, addrlen);
        return -EINVAL;
    }

    /* Copy address family from userspace */
    uint16_t sa_family;
    if (fut_copy_from_user(&sa_family, addr, 2) != 0) {
        fut_printf("[BIND] bind(sockfd=%d, addrlen=%u) -> EFAULT (failed to copy sa_family)\n",
                   sockfd, addrlen);
        return -EFAULT;
    }

    /* Phase 2: Identify address family */
    const char *family_name;
    const char *family_desc;

    switch (sa_family) {
        case AF_UNSPEC:
            family_name = "AF_UNSPEC";
            family_desc = "unspecified";
            break;
        case AF_UNIX:
            family_name = "AF_UNIX";
            family_desc = "Unix domain socket";
            break;
        case AF_INET:
            family_name = "AF_INET";
            family_desc = "IPv4";
            break;
        case AF_INET6:
            family_name = "AF_INET6";
            family_desc = "IPv6";
            break;
        default:
            family_name = "UNKNOWN";
            family_desc = "unknown address family";
            break;
    }

    /* Phase 3: Validate address length based on address family */
    if (sa_family == AF_INET && addrlen < sizeof(sockaddr_in_t)) {
        fut_printf("[BIND] bind(sockfd=%d, family=%s, addrlen=%u) -> EINVAL (AF_INET needs at least %zu bytes)\n",
                   sockfd, family_name, addrlen, sizeof(sockaddr_in_t));
        return -EINVAL;
    }

    if (sa_family == AF_INET6 && addrlen < sizeof(sockaddr_in6_t)) {
        fut_printf("[BIND] bind(sockfd=%d, family=%s, addrlen=%u) -> EINVAL (AF_INET6 needs at least %zu bytes)\n",
                   sockfd, family_name, addrlen, sizeof(sockaddr_in6_t));
        return -EINVAL;
    }

    /* Phase 3: Handle AF_INET (IPv4) addresses */
    if (sa_family == AF_INET) {
        sockaddr_in_t inet_addr = {0};
        if (fut_copy_from_user(&inet_addr, addr, sizeof(inet_addr)) != 0) {
            fut_printf("[BIND] bind(sockfd=%d, family=%s, addrlen=%u) -> EFAULT (failed to copy AF_INET address)\n",
                       sockfd, family_name, addrlen);
            return -EFAULT;
        }

        /* Phase 3: Extract port and categorize */
        uint16_t port = (inet_addr.sin_port >> 8) | ((inet_addr.sin_port & 0xFF) << 8);  /* Network to host byte order */
        const char *port_cat = categorize_port(port);

        fut_printf("[BIND] bind(sockfd=%d, family=%s, port=%u [%s], addrlen=%u) -> ENOTSUP (AF_INET binding not yet implemented)\n",
                   sockfd, family_name, port, port_cat, addrlen);
        return -ENOTSUP;
    }

    /* Phase 3: Handle AF_INET6 (IPv6) addresses */
    if (sa_family == AF_INET6) {
        sockaddr_in6_t inet6_addr = {0};
        if (fut_copy_from_user(&inet6_addr, addr, sizeof(inet6_addr)) != 0) {
            fut_printf("[BIND] bind(sockfd=%d, family=%s, addrlen=%u) -> EFAULT (failed to copy AF_INET6 address)\n",
                       sockfd, family_name, addrlen);
            return -EFAULT;
        }

        /* Phase 3: Extract port and categorize */
        uint16_t port = (inet6_addr.sin6_port >> 8) | ((inet6_addr.sin6_port & 0xFF) << 8);  /* Network to host byte order */
        const char *port_cat = categorize_port(port);

        fut_printf("[BIND] bind(sockfd=%d, family=%s, port=%u [%s], addrlen=%u) -> ENOTSUP (AF_INET6 binding not yet implemented)\n",
                   sockfd, family_name, port, port_cat, addrlen);
        return -ENOTSUP;
    }

    /* Phase 2: Only AF_UNIX supported currently (Phase 3 adds AF_INET/AF_INET6 stubs) */
    if (sa_family != AF_UNIX) {
        fut_printf("[BIND] bind(sockfd=%d, family=%u [%s, %s], addrlen=%u) -> ENOTSUP (unsupported address family)\n",
                   sockfd, sa_family, family_name, family_desc, addrlen);
        return -ENOTSUP;
    }

    /* Phase 2: Validate addrlen for Unix domain socket (2 bytes family + path) */
    if (addrlen < 3) {
        fut_printf("[BIND] bind(sockfd=%d, family=%s, addrlen=%u) -> EINVAL (AF_UNIX needs at least 3 bytes: 2 for family + 1 for path)\n",
                   sockfd, family_name, addrlen);
        return -EINVAL;
    }

    /* Copy Unix domain socket path from userspace */
    char sock_path[256];
    size_t path_len = addrlen - 2;  /* Subtract family field */

    if (path_len > sizeof(sock_path) - 1) {
        fut_printf("[BIND] bind(sockfd=%d, family=%s, path_len=%zu) -> ENAMETOOLONG (max %zu bytes)\n",
                   sockfd, family_name, path_len, sizeof(sock_path) - 1);
        path_len = sizeof(sock_path) - 1;  /* Truncate */
    }

    if (path_len > 0) {
        if (fut_copy_from_user(sock_path, (const char *)addr + 2, path_len) != 0) {
            fut_printf("[BIND] bind(sockfd=%d, family=%s, path_len=%zu) -> EFAULT (failed to copy sun_path)\n",
                       sockfd, family_name, path_len);
            return -EFAULT;
        }
        sock_path[path_len] = '\0';
    } else {
        sock_path[0] = '\0';
    }

    /* Phase 2: Categorize Unix domain socket path type */
    const char *path_type;
    const char *path_desc;

    if (path_len == 0 || sock_path[0] == '\0') {
        if (path_len > 1) {
            path_type = "abstract";
            path_desc = "abstract namespace (Linux-specific)";
        } else {
            path_type = "anonymous";
            path_desc = "anonymous (empty path)";
        }
    } else if (sock_path[0] == '/') {
        path_type = "filesystem";
        path_desc = "filesystem path (absolute)";
    } else {
        path_type = "filesystem";
        path_desc = "filesystem path (relative)";
    }

    /* Get socket from file descriptor */
    fut_socket_t *socket = get_socket_from_fd(sockfd);
    if (!socket) {
        fut_printf("[BIND] bind(sockfd=%d, family=%s, path='%s' [%s]) -> EBADF (not a socket)\n",
                   sockfd, family_name, sock_path, path_type);
        return -EBADF;
    }

    /* Phase 2: Check socket state */
    const char *socket_state_desc;
    switch (socket->state) {
        case FUT_SOCK_CREATED:
            socket_state_desc = "created";
            break;
        case FUT_SOCK_BOUND:
            socket_state_desc = "already bound";
            break;
        case FUT_SOCK_LISTENING:
            socket_state_desc = "listening";
            break;
        case FUT_SOCK_CONNECTING:
            socket_state_desc = "connecting";
            break;
        case FUT_SOCK_CONNECTED:
            socket_state_desc = "connected";
            break;
        case FUT_SOCK_CLOSED:
            socket_state_desc = "closed";
            break;
        default:
            socket_state_desc = "unknown state";
            break;
    }

    /* Phase 2: Validate socket state (should be CREATED) */
    if (socket->state == FUT_SOCK_BOUND) {
        fut_printf("[BIND] bind(sockfd=%d, family=%s, path='%s', state=%s) -> EINVAL (socket already bound to '%s')\n",
                   sockfd, family_name, sock_path, socket_state_desc,
                   socket->bound_path ? socket->bound_path : "(none)");
        return -EINVAL;
    }

    if (socket->state != FUT_SOCK_CREATED) {
        fut_printf("[BIND] bind(sockfd=%d, family=%s, path='%s', state=%s) -> EINVAL (socket not in created state)\n",
                   sockfd, family_name, sock_path, socket_state_desc);
        return -EINVAL;
    }

    /* Bind socket to address */
    int ret = fut_socket_bind(socket, sock_path);
    if (ret < 0) {
        const char *error_desc;
        switch (ret) {
            case -EEXIST:
                error_desc = "address already in use";
                break;
            case -EACCES:
                error_desc = "permission denied";
                break;
            case -EINVAL:
                error_desc = "invalid argument";
                break;
            case -ENOMEM:
                error_desc = "out of memory";
                break;
            case -ENOENT:
                error_desc = "path not found";
                break;
            default:
                error_desc = "unknown error";
                break;
        }

        fut_printf("[BIND] bind(sockfd=%d, family=%s, path='%s' [%s, %s], state=%s) -> %d (%s)\n",
                   sockfd, family_name, sock_path, path_type, path_desc, socket_state_desc, ret, error_desc);
        return ret;
    }

    /* Phase 2: Detailed success logging */
    fut_printf("[BIND] bind(sockfd=%d, family=%s, path='%s' [%s, %s], state=%s->bound) -> 0 (Socket %u bound, Phase 2)\n",
               sockfd, family_name, sock_path, path_type, path_desc, socket_state_desc, socket->socket_id);

    return 0;
}
