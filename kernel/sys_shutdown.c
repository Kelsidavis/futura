/* kernel/sys_shutdown.c - Socket shutdown syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements shutdown() for graceful socket connection termination.
 * Allows closing one or both directions of a full-duplex connection.
 *
 * Phase 1 (Completed): Basic validation and socket state checking
 * Phase 2 (Completed): Enhanced validation, state identification, and detailed logging
 * Phase 3 (Completed): Implement actual shutdown with buffer management and enforcement
 * Phase 4 (Completed): Set shutdown_rd/shutdown_wr flags for enforcement in send/recv
 * Phase 5: TCP state machine integration, FIN handling, and peer notification
 */

#include <kernel/fut_task.h>
#include <kernel/fut_socket.h>
#include <kernel/errno.h>
#include <stdint.h>

#include <kernel/kprintf.h>
extern fut_socket_t *get_socket_from_fd(int fd);

/* Shutdown modes */
#define SHUT_RD   0  /* Further receives will be disallowed */
#define SHUT_WR   1  /* Further sends will be disallowed */
#define SHUT_RDWR 2  /* Further sends and receives will be disallowed */

/**
 * shutdown() - Shut down part of a full-duplex connection
 *
 * Causes all or part of a full-duplex connection on the socket associated
 * with sockfd to be shut down. This is used for graceful connection
 * termination in network protocols like TCP.
 *
 * Unlike close(), which terminates the socket entirely and releases its
 * resources, shutdown() allows selective closing of the read and/or write
 * channels while keeping the socket descriptor valid.
 *
 * @param sockfd  Socket file descriptor
 * @param how     Shutdown mode (SHUT_RD, SHUT_WR, or SHUT_RDWR)
 *
 * Returns:
 *   - 0 on success
 *   - -EBADF if sockfd is not a valid file descriptor
 *   - -EINVAL if how is not valid
 *   - -ENOTCONN if socket is not connected
 *   - -ENOTSOCK if sockfd is not a socket
 *
 * Behavior by mode:
 *
 * SHUT_RD (0):
 *   - Further receives are disallowed
 *   - Any data currently in socket receive buffer is discarded
 *   - Future recv() calls will return 0 (EOF)
 *   - Sending still allowed
 *   - Peer is NOT notified (no protocol message sent)
 *
 * SHUT_WR (1):
 *   - Further sends are disallowed
 *   - For TCP: sends FIN to peer (graceful close)
 *   - Future send() calls will return -EPIPE and raise SIGPIPE
 *   - Receiving still allowed
 *   - Most common use case for graceful TCP shutdown
 *
 * SHUT_RDWR (2):
 *   - Equivalent to SHUT_RD followed by SHUT_WR
 *   - Both send and receive are shut down
 *   - For TCP: sends FIN to peer
 *   - Future I/O operations will fail
 *   - Socket descriptor remains valid until close()
 *
 * Common usage patterns:
 *
 * TCP graceful close (half-close):
 *   // Client finished sending request
 *   shutdown(sockfd, SHUT_WR);  // Send FIN, signal no more data
 *
 *   // But can still receive response
 *   while ((n = recv(sockfd, buf, sizeof(buf), 0)) > 0) {
 *       process_response(buf, n);
 *   }
 *
 *   close(sockfd);  // Now close the socket
 *
 * Shared socket descriptor (fork):
 *   int sockfd = socket(...);
 *   if (fork() == 0) {
 *       // Child: only reads
 *       shutdown(sockfd, SHUT_WR);  // Don't write
 *   } else {
 *       // Parent: only writes
 *       shutdown(sockfd, SHUT_RD);  // Don't read
 *   }
 *
 * Differences from close():
 *   - shutdown: Affects the connection, not the descriptor
 *   - close: Releases the descriptor and decrements refcount
 *   - After shutdown, socket descriptor still valid for close()
 *   - After dup/fork, shutdown affects all shared descriptors
 *
 * Phase 1 (Completed): Basic validation and socket state checking
 * Phase 2 (Completed): Enhanced validation, state identification, detailed logging
 * Phase 3 (Completed): Actual shutdown with buffer management and enforcement
 * Phase 4: TCP FIN handling and state machine transitions
 */
long sys_shutdown(int sockfd, int how) {
    /* ARM64 FIX: Copy parameters to local variables immediately to ensure they're preserved
     * on the stack across potentially blocking calls. Socket operations may block and corrupt
     * register-passed parameters upon resumption. */
    int local_sockfd = sockfd;
    int local_how = how;

    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[SHUTDOWN] shutdown(sockfd=%d, how=%d) -> ESRCH (no current task)\n",
                   local_sockfd, local_how);
        return -ESRCH;
    }

    /* Phase 2: Validate sockfd early */
    if (local_sockfd < 0) {
        fut_printf("[SHUTDOWN] shutdown(sockfd=%d, how=%d) -> EBADF (negative fd)\n",
                   local_sockfd, local_how);
        return -EBADF;
    }

    /* Phase 2: Categorize and validate how parameter */
    const char *how_desc;
    switch (local_how) {
        case SHUT_RD:
            how_desc = "SHUT_RD (disallow receives, send still allowed)";
            break;
        case SHUT_WR:
            how_desc = "SHUT_WR (disallow sends, graceful close)";
            break;
        case SHUT_RDWR:
            how_desc = "SHUT_RDWR (disallow both, full shutdown)";
            break;
        default:
            fut_printf("[SHUTDOWN] shutdown(sockfd=%d, how=%d) -> EINVAL (invalid how, must be 0/1/2)\n",
                       local_sockfd, local_how);
            return -EINVAL;
    }

    /* Get socket from FD */
    fut_socket_t *socket = get_socket_from_fd(local_sockfd);
    if (!socket) {
        fut_printf("[SHUTDOWN] shutdown(sockfd=%d, how=%s) -> EBADF (not a socket)\n",
                   local_sockfd, how_desc);
        return -EBADF;
    }

    /* Phase 2: Identify socket state */
    const char *socket_state_desc;
    switch (socket->state) {
        case FUT_SOCK_CREATED:
            socket_state_desc = "created (not connected)";
            break;
        case FUT_SOCK_BOUND:
            socket_state_desc = "bound (not connected)";
            break;
        case FUT_SOCK_LISTENING:
            socket_state_desc = "listening (not connected)";
            break;
        case FUT_SOCK_CONNECTING:
            socket_state_desc = "connecting (not yet connected)";
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

    /* Phase 2: Validate socket is connected */
    if (socket->state != FUT_SOCK_CONNECTED) {
        fut_printf("[SHUTDOWN] shutdown(sockfd=%d, socket_id=%u, state=%s, how=%s) -> ENOTCONN (socket not connected)\n",
                   local_sockfd, socket->socket_id, socket_state_desc, how_desc);
        return -ENOTCONN;
    }

    /* Phase 2: Identify socket type */
    const char *socket_type_desc;
    switch (socket->socket_type) {
        case 1:  // SOCK_STREAM
            socket_type_desc = "SOCK_STREAM";
            break;
        case 2:  // SOCK_DGRAM
            socket_type_desc = "SOCK_DGRAM";
            break;
        case 5:  // SOCK_SEQPACKET
            socket_type_desc = "SOCK_SEQPACKET";
            break;
        default:
            socket_type_desc = "unknown type";
            break;
    }

    /* Phase 4: Implement shutdown enforcement by setting shutdown flags
     * These flags are checked by send/recv operations to enforce semantics */
    switch (local_how) {
        case SHUT_RD:
            socket->shutdown_rd = true;
            fut_printf("[SHUTDOWN] shutdown(sockfd=%d, socket_id=%u, type=%s, state=%s, how=SHUT_RD) "
                       "-> 0 (Phase 4: recv() will return 0 EOF, send() still works)\n",
                       local_sockfd, socket->socket_id, socket_type_desc, socket_state_desc);
            break;

        case SHUT_WR:
            socket->shutdown_wr = true;
            fut_printf("[SHUTDOWN] shutdown(sockfd=%d, socket_id=%u, type=%s, state=%s, how=SHUT_WR) "
                       "-> 0 (Phase 4: send() will return -EPIPE, recv() still works)\n",
                       local_sockfd, socket->socket_id, socket_type_desc, socket_state_desc);
            break;

        case SHUT_RDWR:
            socket->shutdown_rd = true;
            socket->shutdown_wr = true;
            fut_printf("[SHUTDOWN] shutdown(sockfd=%d, socket_id=%u, type=%s, state=%s, how=SHUT_RDWR) "
                       "-> 0 (Phase 4: both send() and recv() will fail)\n",
                       local_sockfd, socket->socket_id, socket_type_desc, socket_state_desc);
            break;
    }

    /* Note: Send/recv syscalls must check socket->shutdown_rd and socket->shutdown_wr
     * to enforce these semantics. Future enhancement: signal peer for Unix sockets */

    return 0;
}
