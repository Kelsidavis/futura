/* kernel/sys_listen.c - Listen for connections syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements listen() to mark socket as passive, ready to accept connections.
 *
 * Phase 1 (Completed): Basic listen implementation with socket infrastructure
 * Phase 2 (Completed): Enhanced validation, backlog categorization, and detailed logging
 * Phase 3 (Completed): Connection queue management with backlog enforcement
 * Phase 4: Advanced features (TCP Fast Open, defer_accept, etc.)
 */

#include <kernel/fut_task.h>
#include <kernel/fut_socket.h>
#include <kernel/errno.h>

#include <kernel/kprintf.h>

/* Disable verbose LISTEN debugging for performance */
#define LISTEN_DEBUG 0
#define listen_printf(...) do { if (LISTEN_DEBUG) fut_printf(__VA_ARGS__); } while(0)

/* Common backlog values */
#define SOMAXCONN 4096  /* Maximum listen backlog */

/**
 * listen() - Listen for connections on a socket
 *
 * Marks the socket as passive, willing to accept incoming connection requests.
 * The backlog parameter defines the maximum length of the queue of pending
 * connections.
 *
 * @param sockfd  Socket file descriptor
 * @param backlog Maximum length of pending connection queue
 *
 * Returns:
 *   - 0 on success
 *   - -EBADF if sockfd is not a valid file descriptor
 *   - -ENOTSOCK if sockfd is not a socket
 *   - -ENOTSUP if socket doesn't support listen (e.g., UDP)
 *   - -EINVAL if already listening or invalid state
 *
 * Behavior:
 *   - Marks socket as passive (server socket)
 *   - Creates pending connection queue with size backlog
 *   - Must be called after bind() and before accept()
 *   - Only valid for connection-oriented sockets (TCP, Unix stream)
 *
 * Backlog semantics:
 *   - Defines max number of pending connections in SYN_RCVD state
 *   - Connections in ESTABLISHED state waiting for accept() also counted
 *   - Kernel may round up to next power of 2
 *   - Values > SOMAXCONN are clamped to SOMAXCONN
 *   - Common values: 5 (minimal), 128 (typical), 1024 (high load)
 *
 * Phase 1 (Completed): Basic listen with socket infrastructure
 * Phase 2 (Completed): Backlog categorization and enhanced validation
 * Phase 3 (Completed): Connection queue management with backlog enforcement
 * Phase 4: Advanced features (TCP_FASTOPEN, TCP_DEFER_ACCEPT, etc.)
 */
long sys_listen(int sockfd, int backlog) {
    /* ARM64 FIX: Copy parameters to local variables immediately to ensure they're preserved
     * on the stack across potentially blocking calls. Socket operations may block and corrupt
     * register-passed parameters upon resumption. */
    int local_sockfd = sockfd;
    int local_backlog = backlog;

    fut_task_t *task = fut_task_current();
    if (!task) {
        listen_printf("[LISTEN] listen(sockfd=%d, backlog=%d) -> ESRCH (no current task)\n",
                   local_sockfd, local_backlog);
        return -ESRCH;
    }

    /* Phase 2: Validate sockfd early */
    if (local_sockfd < 0) {
        listen_printf("[LISTEN] listen(sockfd=%d, backlog=%d) -> EBADF (negative fd)\n",
                   local_sockfd, local_backlog);
        return -EBADF;
    }

    /* Phase 5: Validate fd upper bounds to prevent out-of-bounds access */
    if (local_sockfd >= task->max_fds) {
        listen_printf("[LISTEN] listen(sockfd=%d, backlog=%d) -> EBADF (fd exceeds max_fds %d)\n",
                   local_sockfd, local_backlog, task->max_fds);
        return -EBADF;
    }

    /* Phase 2: Categorize backlog for diagnostics */
    const char *backlog_desc;
    int original_backlog = local_backlog;
    int effective_backlog = local_backlog;

    if (local_backlog < 0) {
        /* Negative backlog: treat as 0 or minimal default */
        backlog_desc = "negative (will use default)";
        effective_backlog = 128;  /* Common default */
    } else if (local_backlog == 0) {
        backlog_desc = "zero (minimal queue)";
        effective_backlog = 1;  /* At least 1 */
    } else if (local_backlog <= 5) {
        backlog_desc = "minimal (simple servers)";
    } else if (local_backlog <= 64) {
        backlog_desc = "small (low traffic)";
    } else if (local_backlog <= 256) {
        backlog_desc = "typical (moderate traffic)";
    } else if (local_backlog <= 1024) {
        backlog_desc = "large (high traffic)";
    } else if (local_backlog <= SOMAXCONN) {
        backlog_desc = "very large (heavy load)";
    } else {
        /* Backlog exceeds SOMAXCONN, will be clamped */
        backlog_desc = "excessive (will clamp to SOMAXCONN)";
        effective_backlog = SOMAXCONN;
    }

    /* Phase 2: Get socket and validate */
    fut_socket_t *socket = get_socket_from_fd(local_sockfd);
    if (!socket) {
        listen_printf("[LISTEN] listen(sockfd=%d, backlog=%d [%s]) -> EBADF (socket not found)\n",
                   local_sockfd, local_backlog, backlog_desc);
        return -EBADF;
    }

    /* Phase 2: Check socket state for better diagnostics */
    const char *socket_state_desc;
    switch (socket->state) {
        case FUT_SOCK_CREATED:
            socket_state_desc = "created";
            break;
        case FUT_SOCK_BOUND:
            socket_state_desc = "bound";
            break;
        case FUT_SOCK_LISTENING:
            socket_state_desc = "already listening";
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

    /* Phase 2: Enhanced error messages based on socket state */
    if (socket->state == FUT_SOCK_LISTENING) {
        listen_printf("[LISTEN] listen(sockfd=%d, backlog=%d [%s]) -> EINVAL (socket already listening)\n",
                   local_sockfd, local_backlog, backlog_desc);
        return -EINVAL;
    }

    if (socket->state == FUT_SOCK_CONNECTED) {
        listen_printf("[LISTEN] listen(sockfd=%d, backlog=%d [%s]) -> EINVAL (socket already connected, state=%s)\n",
                   local_sockfd, local_backlog, backlog_desc, socket_state_desc);
        return -EINVAL;
    }

    /* Call socket layer to mark as listening */
    int ret = fut_socket_listen(socket, effective_backlog);
    if (ret < 0) {
        const char *error_desc;
        switch (ret) {
            case -ENOTSUP:
                error_desc = "socket type doesn't support listen";
                break;
            case -EINVAL:
                error_desc = "invalid socket state";
                break;
            default:
                error_desc = "unknown error";
                break;
        }

        listen_printf("[LISTEN] listen(sockfd=%d, backlog=%d [%s], state=%s) -> %d (%s)\n",
                   local_sockfd, local_backlog, backlog_desc, socket_state_desc, ret, error_desc);
        return ret;
    }

    /* Phase 3: Detailed success logging with backlog categorization and queue management */
    if (original_backlog != effective_backlog) {
        listen_printf("[LISTEN] listen(sockfd=%d, backlog=%d->%d [%s], state=%s->listening) -> 0 (Phase 3: backlog clamped, queue enforced)\n",
                   local_sockfd, original_backlog, effective_backlog, backlog_desc, socket_state_desc);
    } else {
        listen_printf("[LISTEN] listen(sockfd=%d, backlog=%d [%s], state=%s->listening) -> 0 (Phase 3: queue management)\n",
                   local_sockfd, local_backlog, backlog_desc, socket_state_desc);
    }

    return 0;
}
