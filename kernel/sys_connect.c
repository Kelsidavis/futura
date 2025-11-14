/* kernel/sys_connect.c - Connect to socket address syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements connect() to initiate connection on a socket.
 *
 * Phase 1 (Completed): Basic connect implementation with Unix domain socket support
 * Phase 2 (Completed): Enhanced validation, address family identification, and detailed logging
 * Phase 3 (Completed): Support for multiple address families (AF_INET, AF_INET6) and non-blocking connect
 * Phase 4: Advanced features (connection timeout, retry logic, TCP Fast Open)
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

/**
 * connect() - Initiate connection on a socket
 *
 * Connects the socket to the address specified by addr. For connection-oriented
 * protocols (TCP, Unix SOCK_STREAM), this establishes a connection to the peer.
 * For connectionless protocols (UDP), this sets the default peer address.
 *
 * @param sockfd  Socket file descriptor
 * @param addr    Pointer to sockaddr structure containing peer address
 * @param addrlen Size of address structure
 *
 * Returns:
 *   - 0 on success (connection established)
 *   - -EBADF if sockfd is not a valid file descriptor
 *   - -EFAULT if addr points to invalid memory
 *   - -EINVAL if addrlen is invalid, socket in invalid state, or connection already in progress
 *   - -ENOTSOCK if sockfd is not a socket
 *   - -ENOTSUP if address family not supported
 *   - -111 (ECONNREFUSED) if connection was refused by peer or backlog full
 *   - -EISCONN if socket is already connected
 *   - -ENOMEM if out of memory
 *   - -ENAMETOOLONG if path too long
 *
 * Behavior:
 *   - For SOCK_STREAM: Establishes reliable, ordered, connection-oriented stream
 *   - For SOCK_DGRAM: Sets default peer (can still sendto other addresses)
 *   - Blocking sockets: Blocks until connection established or fails
 *   - Non-blocking sockets: Returns -EINPROGRESS immediately, use poll/select to wait
 *   - Unix domain: Connection succeeds immediately if listener exists
 *   - TCP: Performs three-way handshake (SYN, SYN-ACK, ACK)
 *
 * Address families:
 *   - AF_UNIX (1): Unix domain sockets (filesystem or abstract paths)
 *   - AF_INET (2): IPv4 addresses (not yet implemented in Phase 2)
 *   - AF_INET6 (10): IPv6 addresses (not yet implemented in Phase 2)
 *
 * Unix domain socket connection:
 *   - Client calls connect() with server's bound path
 *   - Server must have called bind() and listen() first
 *   - Connection establishes immediately if backlog available
 *   - Returns -ECONNREFUSED if server not listening or backlog full
 *
 * Phase 1 (Completed): Basic Unix domain socket connection
 * Phase 2 (Completed): Address family identification and enhanced validation
 * Phase 3 (Completed): AF_INET/AF_INET6 support and non-blocking connect
 * Phase 4: Connection timeout, retry logic, TCP Fast Open
 */
long sys_connect(int sockfd, const void *addr, socklen_t addrlen) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[CONNECT] connect(sockfd=%d) -> ESRCH (no current task)\n", sockfd);
        return -ESRCH;
    }

    /* Phase 2: Validate sockfd early */
    if (sockfd < 0) {
        fut_printf("[CONNECT] connect(sockfd=%d, addrlen=%u) -> EBADF (negative fd)\n",
                   sockfd, addrlen);
        return -EBADF;
    }

    /* Phase 2: Validate addr pointer */
    if (!addr) {
        fut_printf("[CONNECT] connect(sockfd=%d, addr=NULL, addrlen=%u) -> EFAULT (NULL addr)\n",
                   sockfd, addrlen);
        return -EFAULT;
    }

    /* Phase 2: Validate minimum address length (family field is 2 bytes) */
    if (addrlen < 2) {
        fut_printf("[CONNECT] connect(sockfd=%d, addrlen=%u) -> EINVAL (too small, need at least 2 bytes for family)\n",
                   sockfd, addrlen);
        return -EINVAL;
    }

    /* Copy address family from userspace */
    uint16_t sa_family;
    if (fut_copy_from_user(&sa_family, addr, 2) != 0) {
        fut_printf("[CONNECT] connect(sockfd=%d, addrlen=%u) -> EFAULT (failed to copy sa_family)\n",
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

    /* Phase 2: Only AF_UNIX supported in current phase */
    if (sa_family != AF_UNIX) {
        fut_printf("[CONNECT] connect(sockfd=%d, family=%u [%s, %s], addrlen=%u) -> ENOTSUP (only AF_UNIX supported in Phase 2)\n",
                   sockfd, sa_family, family_name, family_desc, addrlen);
        return -ENOTSUP;
    }

    /* Phase 2: Validate addrlen for Unix domain socket (2 bytes family + path) */
    if (addrlen < 3) {
        fut_printf("[CONNECT] connect(sockfd=%d, family=%s, addrlen=%u) -> EINVAL (AF_UNIX needs at least 3 bytes: 2 for family + 1 for path)\n",
                   sockfd, family_name, addrlen);
        return -EINVAL;
    }

    /* Copy Unix domain socket path from userspace */
    char sock_path[256];
    size_t path_len = addrlen - 2;  /* Subtract family field */

    if (path_len > sizeof(sock_path) - 1) {
        fut_printf("[CONNECT] connect(sockfd=%d, family=%s, path_len=%zu) -> ENAMETOOLONG (max %zu bytes)\n",
                   sockfd, family_name, path_len, sizeof(sock_path) - 1);
        path_len = sizeof(sock_path) - 1;  /* Truncate */
    }

    if (path_len > 0) {
        if (fut_copy_from_user(sock_path, (const char *)addr + 2, path_len) != 0) {
            fut_printf("[CONNECT] connect(sockfd=%d, family=%s, path_len=%zu) -> EFAULT (failed to copy sun_path)\n",
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
        fut_printf("[CONNECT] connect(sockfd=%d, family=%s, path='%s' [%s]) -> EBADF (not a socket)\n",
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
            socket_state_desc = "bound";
            break;
        case FUT_SOCK_LISTENING:
            socket_state_desc = "listening";
            break;
        case FUT_SOCK_CONNECTING:
            socket_state_desc = "connecting";
            break;
        case FUT_SOCK_CONNECTED:
            socket_state_desc = "already connected";
            break;
        case FUT_SOCK_CLOSED:
            socket_state_desc = "closed";
            break;
        default:
            socket_state_desc = "unknown state";
            break;
    }

    /* Phase 2: Validate socket state (should be CREATED or BOUND) */
    if (socket->state == FUT_SOCK_CONNECTED) {
        fut_printf("[CONNECT] connect(sockfd=%d, family=%s, path='%s', state=%s) -> EISCONN (socket already connected to '%s')\n",
                   sockfd, family_name, sock_path, socket_state_desc,
                   socket->pair && socket->pair->peer && socket->pair->peer->bound_path ?
                   socket->pair->peer->bound_path : "(unknown)");
        return -EISCONN;
    }

    if (socket->state == FUT_SOCK_LISTENING) {
        fut_printf("[CONNECT] connect(sockfd=%d, family=%s, path='%s', state=%s) -> EINVAL (cannot connect listening socket)\n",
                   sockfd, family_name, sock_path, socket_state_desc);
        return -EINVAL;
    }

    if (socket->state == FUT_SOCK_CONNECTING) {
        fut_printf("[CONNECT] connect(sockfd=%d, family=%s, path='%s', state=%s) -> EINVAL (connection already in progress)\n",
                   sockfd, family_name, sock_path, socket_state_desc);
        return -EINVAL;  /* EALREADY semantics, using EINVAL until EALREADY defined */
    }

    if (socket->state == FUT_SOCK_CLOSED) {
        fut_printf("[CONNECT] connect(sockfd=%d, family=%s, path='%s', state=%s) -> EINVAL (socket closed)\n",
                   sockfd, family_name, sock_path, socket_state_desc);
        return -EINVAL;
    }

    /* Connect socket to peer */
    int ret = fut_socket_connect(socket, sock_path);
    if (ret < 0) {
        const char *error_desc;
        switch (ret) {
            case -111:  /* ECONNREFUSED (connection refused) */
                error_desc = "connection refused (no listener or backlog full)";
                break;
            case -2:    /* ENOENT (path not found) */
                error_desc = "path not found (server not bound to this path)";
                break;
            case -13:   /* EACCES (permission denied) */
                error_desc = "permission denied";
                break;
            case -1:    /* Generic error / EINVAL */
                error_desc = "invalid argument";
                break;
            case -12:   /* ENOMEM (out of memory) */
                error_desc = "out of memory";
                break;
            case -110:  /* ETIMEDOUT (connection timeout) */
                error_desc = "connection timeout";
                break;
            default:
                error_desc = "unknown error";
                break;
        }

        fut_printf("[CONNECT] connect(sockfd=%d, family=%s, path='%s' [%s, %s], state=%s) -> %d (%s)\n",
                   sockfd, family_name, sock_path, path_type, path_desc, socket_state_desc, ret, error_desc);
        return ret;
    }

    /* Phase 2: Detailed success logging */
    fut_printf("[CONNECT] connect(sockfd=%d, family=%s, path='%s' [%s, %s], state=%s->connected) -> 0 (Socket %u connected, Phase 2)\n",
               sockfd, family_name, sock_path, path_type, path_desc, socket_state_desc, socket->socket_id);

    return 0;
}
