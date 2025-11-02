/* kernel/sys_poll.c - poll() syscall implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements I/O multiplexing syscall for monitoring multiple file descriptors.
 */

#include <kernel/errno.h>
#include <kernel/uaccess.h>
#include <kernel/fut_task.h>
#include <kernel/fut_vfs.h>
#include <stdint.h>
#include <string.h>

extern void fut_printf(const char *fmt, ...);
extern int fut_copy_from_user(void *to, const void *from, size_t size);
extern int fut_copy_to_user(void *to, const void *from, size_t size);
extern fut_task_t *fut_task_current(void);
extern void *fut_malloc(size_t size);
extern void fut_free(void *ptr);

/* Poll event flags */
#define POLLIN      0x0001  /* There is data to read */
#define POLLPRI     0x0002  /* There is urgent data to read */
#define POLLOUT     0x0004  /* Writing now will not block */
#define POLLERR     0x0008  /* Error condition */
#define POLLHUP     0x0010  /* Hung up */
#define POLLNVAL    0x0020  /* Invalid request: fd not open */
#define POLLRDNORM  0x0040  /* Normal data may be read */
#define POLLRDBAND  0x0080  /* Priority data may be read */
#define POLLWRNORM  0x0100  /* Writing now will not block */
#define POLLWRBAND  0x0200  /* Priority data may be written */

/* pollfd structure */
struct pollfd {
    int fd;         /* File descriptor */
    short events;   /* Requested events */
    short revents;  /* Returned events */
};

/**
 * poll() syscall - Wait for events on file descriptors
 *
 * @param fds      Array of pollfd structures
 * @param nfds     Number of file descriptors in fds
 * @param timeout  Timeout in milliseconds (-1 = infinite, 0 = return immediately)
 *
 * Returns:
 *   - Number of file descriptors with events (>= 0) on success
 *   - -EFAULT if fds points to invalid memory
 *   - -EINVAL if nfds exceeds limits
 *
 * Behavior:
 *   - Monitors file descriptors specified in fds array
 *   - Returns when at least one FD has an event or timeout occurs
 *   - Sets revents field for each FD based on actual events
 *   - For now, implements basic stub returning immediate readiness
 *
 * Phase 1 (Current): Stub implementation - returns all FDs as ready
 * Phase 2: Check actual FD readiness via VFS layer
 * Phase 3: Add blocking support with wait queues
 * Phase 4: Integrate with epoll for efficient event notification
 */
long sys_poll(struct pollfd *fds, unsigned long nfds, int timeout) {
    if (!fds) {
        return -EFAULT;
    }

    /* Reasonable limit on number of file descriptors */
    if (nfds > 1024) {
        return -EINVAL;
    }

    /* Allocate kernel buffer for pollfd array */
    size_t size = nfds * sizeof(struct pollfd);
    struct pollfd *kfds = fut_malloc(size);
    if (!kfds) {
        return -ENOMEM;
    }

    /* Copy pollfd array from userspace */
    if (fut_copy_from_user(kfds, fds, size) != 0) {
        fut_free(kfds);
        return -EFAULT;
    }

    fut_task_t *task = fut_task_current();
    if (!task || !task->fd_table) {
        fut_free(kfds);
        return -ESRCH;
    }

    int ready_count = 0;

    /* Check each file descriptor */
    for (unsigned long i = 0; i < nfds; i++) {
        kfds[i].revents = 0;  /* Clear returned events */

        /* Check if FD is valid */
        if (kfds[i].fd < 0 || kfds[i].fd >= task->max_fds) {
            kfds[i].revents = POLLNVAL;
            ready_count++;
            continue;
        }

        struct fut_file *file = task->fd_table[kfds[i].fd];
        if (!file) {
            kfds[i].revents = POLLNVAL;
            ready_count++;
            continue;
        }

        /* Stub implementation: assume all valid FDs are ready for requested events
         * Phase 2 would check actual readiness via VFS/driver layer
         */
        if (kfds[i].events & POLLIN) {
            kfds[i].revents |= POLLIN;
        }
        if (kfds[i].events & POLLOUT) {
            kfds[i].revents |= POLLOUT;
        }
        if (kfds[i].events & POLLPRI) {
            kfds[i].revents |= POLLPRI;
        }

        if (kfds[i].revents != 0) {
            ready_count++;
        }
    }

    /* Copy results back to userspace */
    if (fut_copy_to_user(fds, kfds, size) != 0) {
        fut_free(kfds);
        return -EFAULT;
    }

    fut_free(kfds);

    fut_printf("[POLL] poll(nfds=%lu, timeout=%d) -> %d ready (stub)\n",
               nfds, timeout, ready_count);

    return ready_count;
}
