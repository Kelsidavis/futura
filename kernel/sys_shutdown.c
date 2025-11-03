/* kernel/sys_shutdown.c - Socket shutdown syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements shutdown() for graceful socket connection termination.
 * Allows closing one or both directions of a full-duplex connection.
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);
extern fut_task_t *fut_task_current(void);

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
 * channels while keeping the socket descriptor valid. This is particularly
 * important for:
 * - TCP half-close scenarios (sending FIN while still receiving)
 * - Signaling end-of-data to peer
 * - Graceful connection termination
 * - Shared socket descriptors (dup/fork)
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
 * Phase 1 (Current): Validates parameters and returns success
 * Phase 2: Integrate with socket layer to actually shut down channels
 * Phase 3: Implement proper TCP FIN handling for SHUT_WR
 * Phase 4: Handle socket buffer flushing and state transitions
 *
 * Example: TCP graceful close (half-close)
 *
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
 * Example: Server graceful shutdown
 *
 *   // Server finished sending response
 *   shutdown(sockfd, SHUT_WR);
 *
 *   // Drain any remaining client data
 *   char dummy[1024];
 *   while (recv(sockfd, dummy, sizeof(dummy), 0) > 0);
 *
 *   close(sockfd);
 *
 * Example: Shared socket descriptor (fork)
 *
 *   int sockfd = socket(...);
 *   if (fork() == 0) {
 *       // Child: only reads
 *       shutdown(sockfd, SHUT_WR);  // Don't write
 *       // ...
 *   } else {
 *       // Parent: only writes
 *       shutdown(sockfd, SHUT_RD);  // Don't read
 *       // ...
 *   }
 *
 * TCP State Transitions (Phase 3+):
 *
 * SHUT_WR on ESTABLISHED socket:
 *   - Sends TCP FIN packet
 *   - Transitions to FIN_WAIT_1 state
 *   - Waits for peer's ACK
 *   - Eventually reaches TIME_WAIT or CLOSED
 *
 * SHUT_RD on ESTABLISHED socket:
 *   - No TCP packet sent (local operation only)
 *   - Remains in ESTABLISHED state
 *   - Incoming data segments are discarded
 *
 * Interaction with other syscalls:
 * - close: Implicitly does SHUT_RDWR + releases descriptor
 * - send: Returns -EPIPE after SHUT_WR or SHUT_RDWR
 * - recv: Returns 0 (EOF) after SHUT_RD or SHUT_RDWR
 * - dup/fork: Shared descriptors each need their own shutdown
 *
 * Differences from close():
 * - shutdown: Affects the connection, not the descriptor
 * - close: Releases the descriptor and decrements refcount
 * - After shutdown, socket descriptor still valid for close()
 * - After dup/fork, shutdown affects all shared descriptors
 * - close only affects current descriptor (refcount)
 *
 * Common use cases:
 * - HTTP/1.1: Shutdown write after sending request, read response
 * - TCP proxy: Shutdown one direction while keeping other open
 * - Database client: Signal end of query, wait for results
 * - File transfer: Shutdown write after sending, wait for ACK
 * - Protocol state machines: Signal transition to closing state
 *
 * Error handling:
 * - EBADF: sockfd is not valid (not open)
 * - EINVAL: how is not SHUT_RD, SHUT_WR, or SHUT_RDWR
 * - ENOTCONN: Socket not connected (connection-oriented socket)
 * - ENOTSOCK: sockfd is a file, not a socket
 *
 * Edge cases:
 * - Shutdown already shut-down direction: No-op, returns 0
 * - Shutdown on listening socket: -ENOTCONN (not connected)
 * - Shutdown on UDP socket: Allowed but mostly meaningless
 * - Multiple shutdowns: Idempotent (safe to call multiple times)
 * - Shutdown after close: -EBADF (descriptor invalid)
 *
 * Performance characteristics:
 * - SHUT_RD: O(1) - just set flag, discard buffer
 * - SHUT_WR: O(1) - queue FIN packet
 * - SHUT_RDWR: O(1) - combination of above
 * - No blocking (shutdown is non-blocking)
 * - FIN transmission is asynchronous
 *
 * Security considerations:
 * - Cannot shutdown other process's sockets
 * - Proper descriptor validation required
 * - Buffer contents discarded (no data leak)
 * - TCP RST vs FIN affects security (Phase 3)
 *
 * Portability notes:
 * - POSIX standard (widely supported)
 * - Constant values (SHUT_*) are standard across systems
 * - Behavior on UDP sockets varies
 * - Some systems allow shutdown on non-connected sockets
 * - Always check return value
 *
 * Protocol-specific behavior:
 *
 * TCP:
 * - SHUT_WR sends FIN (graceful close)
 * - Proper TCP state machine transitions
 * - TIME_WAIT state handling
 *
 * UDP:
 * - Shutdown allowed but limited effect
 * - No connection state to tear down
 * - Mostly affects local socket state
 *
 * Unix domain sockets:
 * - Similar to TCP for SOCK_STREAM
 * - SHUT_WR causes peer recv() to return 0
 * - No network packets involved
 *
 * Comparison with alternatives:
 *
 * Using close() (not graceful):
 *   close(sockfd);  // Abrupt termination, may lose data
 *
 * Using shutdown() then close() (graceful):
 *   shutdown(sockfd, SHUT_WR);  // Signal end of data
 *   // Wait for peer acknowledgment...
 *   close(sockfd);  // Clean shutdown
 *
 * Benefits of shutdown():
 * - Graceful connection termination
 * - Half-duplex communication (one-way shutdown)
 * - Works with shared descriptors (dup/fork)
 * - Protocol-level shutdown (TCP FIN)
 * - Peer notification of end-of-data
 */
long sys_shutdown(int sockfd, int how) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Validate how parameter */
    if (how != SHUT_RD && how != SHUT_WR && how != SHUT_RDWR) {
        fut_printf("[SHUTDOWN] shutdown(sockfd=%d, how=%d) -> EINVAL (invalid how)\n",
                   sockfd, how);
        return -EINVAL;
    }

    /* Validate sockfd */
    if (sockfd < 0) {
        fut_printf("[SHUTDOWN] shutdown(sockfd=%d, how=%d) -> EBADF\n",
                   sockfd, how);
        return -EBADF;
    }

    /* Phase 1: Validation only
     * Phase 2: Integrate with socket layer to:
     *   - Verify sockfd is actually a socket (not regular file)
     *   - Check socket is connected (for connection-oriented protocols)
     *   - Set appropriate shutdown flags on socket structure
     *   - For SHUT_RD: Discard receive buffer, block future receives
     *   - For SHUT_WR: Queue TCP FIN if applicable, block future sends
     *   - For SHUT_RDWR: Combination of above
     *
     * Phase 3: TCP state machine integration:
     *   - Send TCP FIN for SHUT_WR
     *   - Transition socket state (FIN_WAIT_1, etc.)
     *   - Handle ACK and FIN from peer
     *   - Implement TIME_WAIT state
     *
     * Phase 4: Advanced features:
     *   - Graceful shutdown timeouts
     *   - Handle RST vs FIN scenarios
     *   - SO_LINGER socket option interaction
     *   - Non-blocking socket considerations
     */

    const char *how_str = (how == SHUT_RD) ? "SHUT_RD" :
                          (how == SHUT_WR) ? "SHUT_WR" : "SHUT_RDWR";

    fut_printf("[SHUTDOWN] shutdown(sockfd=%d, how=%s) -> 0 (Phase 1 stub)\n",
               sockfd, how_str);

    return 0;
}
