/* kernel/sys_socket.c - Create socket syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements socket() to create communication endpoints.
 * Foundation for network and IPC programming.
 */

#include <kernel/fut_task.h>
#include <kernel/fut_socket.h>
#include <kernel/errno.h>

extern void fut_printf(const char *fmt, ...);
extern fut_task_t *fut_task_current(void);
extern int allocate_socket_fd(fut_socket_t *socket);

/* Socket domains */
#define AF_UNIX  1
#define AF_INET  2

/* Socket types */
#define SOCK_STREAM 1
#define SOCK_DGRAM  2

/**
 * socket() - Create communication endpoint
 *
 * Creates an endpoint for communication and returns a file descriptor.
 *
 * @param domain   Communication domain (AF_UNIX, AF_INET, etc.)
 * @param type     Socket type (SOCK_STREAM, SOCK_DGRAM, etc.)
 * @param protocol Protocol (usually 0 for default)
 *
 * Returns:
 *   - Non-negative file descriptor on success
 *   - -EAFNOSUPPORT if address family not supported
 *   - -EINVAL if unknown protocol or invalid flags
 *   - -EMFILE if per-process limit on open FDs reached
 *   - -ENFILE if system limit on open files reached
 *   - -ENOBUFS if insufficient buffer space
 *   - -ENOMEM if insufficient memory
 *   - -EPROTONOSUPPORT if protocol not supported
 */
long sys_socket(int domain, int type, int protocol) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    fut_printf("[SOCKET] domain=%d type=%d protocol=%d\n", domain, type, protocol);

    (void)protocol;  /* Unused in phase 1 */

    /* Phase 1: Support AF_UNIX SOCK_STREAM only */
    if (domain != AF_UNIX) {
        fut_printf("[SOCKET] ERROR: Unsupported domain %d\n", domain);
        return -EINVAL;
    }

    if (type != SOCK_STREAM) {
        fut_printf("[SOCKET] ERROR: Unsupported type %d\n", type);
        return -EINVAL;
    }

    /* Create kernel socket object */
    fut_socket_t *socket = fut_socket_create(domain, type);
    if (!socket) {
        fut_printf("[SOCKET] ERROR: fut_socket_create failed\n");
        return -ENOMEM;
    }

    /* Allocate file descriptor for socket */
    int sockfd = allocate_socket_fd(socket);
    if (sockfd < 0) {
        fut_printf("[SOCKET] ERROR: Failed to allocate FD\n");
        fut_socket_unref(socket);
        return -EMFILE;
    }

    fut_printf("[SOCKET] Created socket %u with fd %d\n", socket->socket_id, sockfd);
    return (long)sockfd;
}
