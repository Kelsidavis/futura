/* kernel/sys_accept.c - Accept incoming socket connection syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements accept() to accept incoming connections on listening sockets.
 * Essential for server applications implementing TCP servers, Unix domain
 * socket servers, and other connection-oriented protocols.
 *
 * Phase 1 (Completed): Basic validation and socket acceptance
 * Phase 2 (Completed): Enhanced validation, socket state identification, and detailed logging
 * Phase 3 (Completed): Non-blocking accept, EAGAIN handling, and connection queue management
 * Phase 4: Address family specific peer address return (AF_INET, AF_INET6, AF_UNIX)
 */

#include <kernel/fut_task.h>
#include <kernel/fut_socket.h>
#include <kernel/errno.h>
#include <kernel/uaccess.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);
extern fut_task_t *fut_task_current(void);
extern fut_socket_t *get_socket_from_fd(int fd);
extern int allocate_socket_fd(fut_socket_t *socket);

/* socklen_t for address length */
typedef uint32_t socklen_t;

/**
 * accept() - Accept incoming connection on listening socket
 *
 * Extracts the first connection request from the queue of pending connections
 * for the listening socket sockfd, creates a new connected socket, and returns
 * a new file descriptor referring to that socket. The newly created socket is
 * not in listening state. The original socket sockfd is unaffected.
 *
 * This is the server-side counterpart to connect(). After a server calls
 * socket(), bind(), and listen(), it calls accept() to receive incoming
 * client connections.
 *
 * @param sockfd Socket file descriptor (must be in listening state)
 * @param addr   Pointer to sockaddr structure to receive peer address (may be NULL)
 * @param addrlen Pointer to size of addr buffer (in/out parameter, may be NULL if addr is NULL)
 *
 * Returns:
 *   - Non-negative file descriptor for accepted connection on success
 *   - -EBADF if sockfd is not a valid file descriptor
 *   - -EFAULT if addr or addrlen point to invalid memory
 *   - -EINVAL if socket is not listening, addrlen is invalid, or addr/addrlen inconsistent
 *   - -ENOTSOCK if sockfd is not a socket
 *   - -ENOTSUP if socket type does not support accepting connections
 *   - -EAGAIN if socket is non-blocking and no connections are pending
 *   - -EMFILE if per-process file descriptor limit reached
 *   - -ENFILE if system-wide file descriptor limit reached
 *   - -ENOMEM if insufficient memory available
 *
 * Behavior:
 *   - Blocks until connection arrives (unless socket is non-blocking)
 *   - Returns new socket file descriptor for the accepted connection
 *   - New socket inherits properties from listening socket
 *   - Original listening socket remains open and listening
 *   - If addr is NULL, peer address is not returned
 *   - If addr is non-NULL, peer address is stored in addr
 *   - addrlen is value-result parameter (input: buffer size, output: actual address size)
 *   - If buffer too small, address is truncated and addrlen reflects actual size
 *   - For SOCK_STREAM (TCP, Unix), new socket is connected to peer
 *   - Does not work with SOCK_DGRAM (connectionless)
 *
 * Socket states:
 *   - Listening socket: Created with socket(), bound with bind(), listening with listen()
 *   - Must be SOCK_STREAM or SOCK_SEQPACKET type
 *   - Must be in listening state (listen() called)
 *   - Accepts connections from connect() calls
 *
 * Connection queue:
 *   - Kernel maintains queue of pending connections (set by listen backlog)
 *   - accept() removes first connection from queue
 *   - If queue empty and socket blocking: blocks until connection arrives
 *   - If queue empty and socket non-blocking: returns -EAGAIN
 *
 * File descriptor inheritance:
 *   - New socket inherits:
 *     - Socket type (SOCK_STREAM, etc.)
 *     - Protocol family (AF_INET, AF_UNIX, etc.)
 *     - Some socket options (depends on option)
 *   - New socket does NOT inherit:
 *     - Listening state (new socket is connected, not listening)
 *     - File descriptor flags (use accept4 to set atomically)
 *
 * Common usage patterns:
 *
 * Basic server accept loop:
 *   int listenfd = socket(AF_UNIX, SOCK_STREAM, 0);
 *   bind(listenfd, &addr, sizeof(addr));
 *   listen(listenfd, 128);
 *
 *   while (1) {
 *       struct sockaddr_un client_addr;
 *       socklen_t client_len = sizeof(client_addr);
 *       int connfd = accept(listenfd, (struct sockaddr *)&client_addr, &client_len);
 *       if (connfd < 0) {
 *           perror("accept");
 *           continue;
 *       }
 *       handle_client(connfd);
 *       close(connfd);
 *   }
 *
 * Accept without retrieving peer address:
 *   int connfd = accept(listenfd, NULL, NULL);
 *   if (connfd < 0) {
 *       perror("accept");
 *   }
 *
 * Non-blocking accept:
 *   fcntl(listenfd, F_SETFL, O_NONBLOCK);
 *   int connfd = accept(listenfd, NULL, NULL);
 *   if (connfd < 0) {
 *       if (errno == EAGAIN) {
 *           // No connection available, try again later
 *       } else {
 *           perror("accept");
 *       }
 *   }
 *
 * Value-result parameter pattern:
 *   struct sockaddr_un client_addr;
 *   socklen_t client_len = sizeof(client_addr);
 *   int connfd = accept(sockfd, (struct sockaddr *)&client_addr, &client_len);
 *   // client_len now contains actual address size
 *
 * Phase 1 (Completed): Basic validation and socket acceptance
 * Phase 2 (Completed): Enhanced validation, state identification, detailed logging
 * Phase 3 (Completed): Non-blocking support and connection queue management
 * Phase 4: Address family specific peer address return
 */
long sys_accept(int sockfd, void *addr, socklen_t *addrlen) {
    /* ARM64 FIX: Copy parameters to local variables immediately to ensure they're preserved
     * on the stack across potentially blocking calls. Socket operations may block and corrupt
     * register-passed parameters upon resumption. */
    int local_sockfd = sockfd;
    void *local_addr = addr;
    socklen_t *local_addrlen = addrlen;

    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[ACCEPT] accept(local_sockfd=%d) -> ESRCH (no current task)\n", local_sockfd);
        return -ESRCH;
    }

    /* Phase 2: Validate local_sockfd early */
    if (local_sockfd < 0) {
        fut_printf("[ACCEPT] accept(local_sockfd=%d) -> EBADF (negative fd)\n", local_sockfd);
        return -EBADF;
    }

    /* Phase 2: Categorize address request */
    const char *addr_request;
    if (local_addr == NULL && local_addrlen == NULL) {
        addr_request = "no address requested";
    } else if (local_addr != NULL && local_addrlen != NULL) {
        addr_request = "address requested";
    } else if (local_addr != NULL && local_addrlen == NULL) {
        fut_printf("[ACCEPT] accept(local_sockfd=%d) -> EFAULT (local_addr non-NULL but local_addrlen is NULL)\n", local_sockfd);
        return -EFAULT;
    } else {
        // local_addr == NULL && local_addrlen != NULL
        addr_request = "local_addrlen without local_addr (unusual)";
    }

    /* Phase 2: If local_addrlen provided, validate it */
    socklen_t len = 0;
    if (local_addrlen != NULL) {
        if (fut_copy_from_user(&len, local_addrlen, sizeof(socklen_t)) != 0) {
            fut_printf("[ACCEPT] accept(local_sockfd=%d, addr_request=%s) -> EFAULT (copy_from_user local_addrlen failed)\n",
                       local_sockfd, addr_request);
            return -EFAULT;
        }

        /* Phase 2: Categorize buffer size */
        const char *buffer_size_category;
        if (len == 0) {
            buffer_size_category = "zero (no space)";
        } else if (len < 16) {
            buffer_size_category = "tiny (< 16 bytes)";
        } else if (len < 128) {
            buffer_size_category = "typical (sockaddr_un)";
        } else if (len < 256) {
            buffer_size_category = "large (generous buffer)";
        } else if (len <= 1024) {
            buffer_size_category = "very large (≤1 KB)";
        } else {
            buffer_size_category = "excessive (>1 KB)";
        }

        /* Phase 2: Sanity check on local_addrlen */
        if (len > 1024) {
            fut_printf("[ACCEPT] accept(local_sockfd=%d, local_addrlen=%u [%s]) -> EINVAL (excessive address length)\n",
                       local_sockfd, len, buffer_size_category);
            return -EINVAL;
        }
    }

    /* Get listening socket from FD */
    fut_socket_t *listen_socket = get_socket_from_fd(local_sockfd);
    if (!listen_socket) {
        fut_printf("[ACCEPT] accept(local_sockfd=%d, addr_request=%s) -> EBADF (not a socket)\n",
                   local_sockfd, addr_request);
        return -EBADF;
    }

    /* Phase 2: Identify listening socket state */
    const char *socket_state_desc;
    switch (listen_socket->state) {
        case FUT_SOCK_CREATED:
            socket_state_desc = "created (not listening)";
            break;
        case FUT_SOCK_BOUND:
            socket_state_desc = "bound (not listening)";
            break;
        case FUT_SOCK_LISTENING:
            socket_state_desc = "listening";
            break;
        case FUT_SOCK_CONNECTING:
            socket_state_desc = "connecting (invalid for accept)";
            break;
        case FUT_SOCK_CONNECTED:
            socket_state_desc = "connected (invalid for accept)";
            break;
        case FUT_SOCK_CLOSED:
            socket_state_desc = "closed";
            break;
        default:
            socket_state_desc = "unknown state";
            break;
    }

    /* Phase 2: Validate socket is in listening state */
    if (listen_socket->state != FUT_SOCK_LISTENING) {
        fut_printf("[ACCEPT] accept(local_sockfd=%d, state=%s, addr_request=%s) -> EINVAL (socket not listening)\n",
                   local_sockfd, socket_state_desc, addr_request);
        return -EINVAL;
    }

    /* Phase 2: Identify socket type */
    const char *socket_type_desc;
    switch (listen_socket->socket_type) {
        case 1:  // SOCK_STREAM
            socket_type_desc = "SOCK_STREAM";
            break;
        case 2:  // SOCK_DGRAM
            socket_type_desc = "SOCK_DGRAM (invalid for accept)";
            break;
        case 5:  // SOCK_SEQPACKET
            socket_type_desc = "SOCK_SEQPACKET";
            break;
        default:
            socket_type_desc = "unknown type";
            break;
    }

    /* Accept connection using kernel socket layer */
    fut_socket_t *accepted_socket = NULL;
    int ret = fut_socket_accept(listen_socket, &accepted_socket);

    /* Phase 2: Handle error cases with detailed logging */
    if (ret < 0) {
        const char *error_desc;
        switch (ret) {
            case -EINVAL:
                error_desc = "invalid socket state or not listening";
                break;
            case -EAGAIN:
                error_desc = "no pending connections (would block)";
                break;
            case -ENOMEM:
                error_desc = "insufficient memory for new socket";
                break;
            case -ENOTSUP:
                error_desc = "socket type does not support accept";
                break;
            default:
                error_desc = "unknown error";
                break;
        }

        fut_printf("[ACCEPT] accept(local_sockfd=%d, type=%s, state=%s, socket_id=%u, addr_request=%s) -> %d (%s)\n",
                   local_sockfd, socket_type_desc, socket_state_desc, listen_socket->socket_id,
                   addr_request, ret, error_desc);
        return ret;
    }

    /* Allocate new file descriptor for accepted socket */
    int newfd = allocate_socket_fd(accepted_socket);
    if (newfd < 0) {
        fut_printf("[ACCEPT] accept(local_sockfd=%d, socket_id=%u) -> EMFILE (failed to allocate FD)\n",
                   local_sockfd, listen_socket->socket_id);
        // TODO: Clean up accepted socket
        fut_socket_unref(accepted_socket);
        return -EMFILE;
    }

    /* Phase 3: Handle peer address return if requested
     * Phase 3: For Unix domain sockets, we don't populate peer address yet
     * Phase 4: Will implement AF_INET/AF_INET6/AF_UNIX peer address return */
    if (local_addr != NULL && local_addrlen != NULL) {
        /* Set local_addrlen to 0 to indicate no address returned (Phase 3 limitation) */
        socklen_t actual_len = 0;
        if (fut_copy_to_user(local_addrlen, &actual_len, sizeof(socklen_t)) != 0) {
            fut_printf("[ACCEPT] accept(local_sockfd=%d, newfd=%d, listen_socket_id=%u, accepted_socket_id=%u) "
                       "-> warning: failed to update local_addrlen (connection established)\n",
                       local_sockfd, newfd, listen_socket->socket_id, accepted_socket->socket_id);
            /* Not fatal - connection is established, just couldn't return address */
        }

        fut_printf("[ACCEPT] accept(local_sockfd=%d, type=%s, state=%s, listen_socket_id=%u, addr_request=%s) "
                   "-> %d (accepted_socket_id=%u, peer address not yet implemented, Phase 4: AF_INET/AF_INET6/AF_UNIX)\n",
                   local_sockfd, socket_type_desc, socket_state_desc, listen_socket->socket_id,
                   addr_request, newfd, accepted_socket->socket_id);
    } else {
        fut_printf("[ACCEPT] accept(local_sockfd=%d, type=%s, state=%s, listen_socket_id=%u, addr_request=%s) "
                   "-> %d (accepted_socket_id=%u, Phase 4: AF_INET/AF_INET6/AF_UNIX peer address)\n",
                   local_sockfd, socket_type_desc, socket_state_desc, listen_socket->socket_id,
                   addr_request, newfd, accepted_socket->socket_id);
    }

    return newfd;
}
