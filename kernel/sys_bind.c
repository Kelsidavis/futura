/* kernel/sys_bind.c - Bind socket to address syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements bind() to bind sockets to addresses.
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

long sys_bind(int sockfd, const void *addr, socklen_t addrlen) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    fut_printf("[BIND] sockfd=%d addr=0x%p addrlen=%u\n", sockfd, addr, addrlen);

    if (addrlen < 3) {
        fut_printf("[BIND] ERROR: addrlen too small (%u)\n", addrlen);
        return -EINVAL;
    }

    /* Copy socket path from userspace */
    char sock_path[256];
    uint16_t sun_family;
    if (fut_copy_from_user(&sun_family, addr, 2) != 0) {
        fut_printf("[BIND] ERROR: failed to copy sun_family\n");
        return -EFAULT;
    }

    size_t path_len = addrlen - 2;
    if (path_len > sizeof(sock_path) - 1) {
        path_len = sizeof(sock_path) - 1;
    }

    if (path_len > 0) {
        if (fut_copy_from_user(sock_path, (const char *)addr + 2, path_len) != 0) {
            fut_printf("[BIND] ERROR: failed to copy sun_path\n");
            return -EFAULT;
        }
        sock_path[path_len] = '\0';
    } else {
        sock_path[0] = '\0';
    }

    fut_printf("[BIND] Binding to path: '%s'\n", sock_path);

    fut_socket_t *socket = get_socket_from_fd(sockfd);
    if (!socket) {
        fut_printf("[BIND] ERROR: socket fd %d not valid\n", sockfd);
        return -EBADF;
    }

    int ret = fut_socket_bind(socket, sock_path);
    if (ret < 0) {
        fut_printf("[BIND] ERROR: fut_socket_bind failed with code %d\n", ret);
        return ret;
    }

    fut_printf("[BIND] Socket %u bound to '%s'\n", socket->socket_id, sock_path);
    return 0;
}
