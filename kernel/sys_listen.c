/* kernel/sys_listen.c - Listen for connections syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements listen() to mark socket as passive, ready to accept connections.
 */

#include <kernel/fut_task.h>
#include <kernel/fut_socket.h>
#include <kernel/errno.h>

extern void fut_printf(const char *fmt, ...);
extern fut_task_t *fut_task_current(void);
extern fut_socket_t *get_socket_from_fd(int fd);

long sys_listen(int sockfd, int backlog) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    fut_printf("[LISTEN] sockfd=%d backlog=%d\n", sockfd, backlog);

    fut_socket_t *socket = get_socket_from_fd(sockfd);
    if (!socket) {
        fut_printf("[LISTEN] ERROR: socket fd %d not valid\n", sockfd);
        return -EBADF;
    }

    int ret = fut_socket_listen(socket, backlog);
    if (ret < 0) {
        fut_printf("[LISTEN] ERROR: fut_socket_listen failed with code %d\n", ret);
        return ret;
    }

    fut_printf("[LISTEN] Socket %u marked as listening with backlog %d\n",
               socket->socket_id, backlog);
    return 0;
}
