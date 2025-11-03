/* kernel/sys_sendto.c - Send message on socket syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements sendto() to transmit messages on sockets.
 */

#include <kernel/fut_task.h>
#include <kernel/fut_vfs.h>
#include <kernel/fut_memory.h>
#include <kernel/uaccess.h>
#include <kernel/errno.h>
#include <stddef.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);
extern fut_task_t *fut_task_current(void);
extern struct fut_file *vfs_get_file(int fd);

typedef uint32_t socklen_t;

ssize_t sys_sendto(int sockfd, const void *buf, size_t len, int flags,
                   const void *dest_addr, socklen_t addrlen) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    (void)flags;
    (void)dest_addr;
    (void)addrlen;

    fut_printf("[SENDTO] sockfd=%d buf=0x%p len=%zu\n", sockfd, buf, len);

    /* Validate socket FD */
    struct fut_file *file = vfs_get_file(sockfd);
    if (!file) {
        fut_printf("[SENDTO] ERROR: socket fd %d is not valid\n", sockfd);
        return -EBADF;
    }

    /* For connected sockets, write via VFS */
    if (len == 0) {
        return 0;
    }

    void *kbuf = fut_malloc(len);
    if (!kbuf) {
        return -ENOMEM;
    }

    if (fut_copy_from_user(kbuf, buf, len) != 0) {
        fut_free(kbuf);
        return -EFAULT;
    }

    ssize_t ret = fut_vfs_write(sockfd, kbuf, len);
    fut_free(kbuf);

    fut_printf("[SENDTO] wrote %zd bytes\n", ret);
    return ret;
}
