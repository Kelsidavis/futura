/* kernel/sys_epoll.c - epoll() syscall implementations
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements event-driven I/O multiplexing via epoll_create, epoll_ctl, and epoll_wait.
 * Provides efficient polling of many file descriptors with event notification.
 */

#include <kernel/fut_vfs.h>
#include <kernel/errno.h>
#include <kernel/uaccess.h>
#include <shared/fut_timespec.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

extern void fut_printf(const char *fmt, ...);
extern void *fut_malloc(size_t size);
extern void fut_free(void *ptr);
extern long sys_nanosleep(struct fut_timespec *req, struct fut_timespec *rem);

/* epoll event flag definitions */
#define EPOLLIN      0x00000001  /* Data available for reading */
#define EPOLLOUT     0x00000004  /* Ready for writing */
#define EPOLLERR     0x00000008  /* Error condition */
#define EPOLLHUP     0x00000010  /* Hang-up condition */
#define EPOLLRDNORM  0x00000040  /* Data available (same as EPOLLIN) */
#define EPOLLRDBAND  0x00000080  /* OOB data available */
#define EPOLLWRNORM  0x00000100  /* Ready for writing (same as EPOLLOUT) */
#define EPOLLWRBAND  0x00000200  /* OOB write ready */
#define EPOLLMASK_IOCTLS  (EPOLLERR | EPOLLHUP)

/* epoll_ctl operation codes */
#define EPOLL_CTL_ADD 1  /* Register a file descriptor with epoll instance */
#define EPOLL_CTL_MOD 2  /* Modify the interest mask for a file descriptor */
#define EPOLL_CTL_DEL 3  /* Deregister a file descriptor from epoll instance */

/* Maximum file descriptors per epoll instance */
#define MAX_EPOLL_FDS 64

/* Maximum epoll instances */
#define MAX_EPOLL_INSTANCES 256

/* epoll_event structure (user-visible) */
struct epoll_event {
    uint32_t events;   /* Requested events bitmask */
    uint64_t data;     /* User data associated with this FD */
};

/* Internal epoll FD registration */
struct epoll_fd_entry {
    int fd;                    /* File descriptor number */
    uint32_t events;           /* Requested events mask */
    uint64_t data;             /* User data to return on event */
    bool registered;           /* Whether this entry is active */
};

/* Internal epoll set structure */
struct epoll_set {
    int epfd;                                    /* This epoll FD number */
    struct epoll_fd_entry fds[MAX_EPOLL_FDS];  /* Registered FDs */
    int count;                                   /* Number of registered FDs */
    bool active;                                 /* Whether this epoll set is in use */
};

/* Global epoll instance table */
static struct epoll_set epoll_instances[MAX_EPOLL_INSTANCES];
static int next_epoll_fd = 4000;  /* Start epoll FDs at 4000 to avoid collision with regular FDs */

/* Helper to find epoll set by epoll FD */
static struct epoll_set *epoll_get_set(int epfd) {
    for (int i = 0; i < MAX_EPOLL_INSTANCES; i++) {
        if (epoll_instances[i].active && epoll_instances[i].epfd == epfd) {
            return &epoll_instances[i];
        }
    }
    return NULL;
}

/* Helper to allocate a new epoll set */
static struct epoll_set *epoll_allocate_set(void) {
    for (int i = 0; i < MAX_EPOLL_INSTANCES; i++) {
        if (!epoll_instances[i].active) {
            memset(&epoll_instances[i], 0, sizeof(epoll_instances[i]));
            epoll_instances[i].active = true;
            epoll_instances[i].epfd = next_epoll_fd++;
            epoll_instances[i].count = 0;
            return &epoll_instances[i];
        }
    }
    return NULL;
}

/* Helper to deallocate an epoll set */
__attribute__((unused))
static void epoll_deallocate_set(struct epoll_set *set) {
    if (set) {
        set->active = false;
        set->count = 0;
        memset(set->fds, 0, sizeof(set->fds));
    }
}

/**
 * epoll_create(size_t size) - Create an epoll instance
 *
 * Creates an event notification context for monitoring multiple file descriptors.
 * The size parameter is ignored but must be positive (for POSIX compatibility).
 *
 * @param size  Hint for number of FDs (ignored, provided for POSIX compatibility)
 *
 * Returns:
 *   - epoll file descriptor (>= 0) on success
 *   - -EINVAL if size <= 0
 *   - -ENOMEM if no epoll instances available
 */
long sys_epoll_create(int size) {
    if (size <= 0) {
        return -EINVAL;
    }

    struct epoll_set *set = epoll_allocate_set();
    if (!set) {
        return -ENOMEM;  /* No more epoll instances available */
    }

    fut_printf("[EPOLL] Created epoll instance epfd=%d\n", set->epfd);
    return set->epfd;
}

/**
 * epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) - Control an epoll instance
 *
 * Modifies the set of file descriptors monitored by an epoll instance.
 * Supports add, modify, and delete operations.
 *
 * @param epfd   epoll file descriptor from epoll_create()
 * @param op     Operation: EPOLL_CTL_ADD, EPOLL_CTL_MOD, or EPOLL_CTL_DEL
 * @param fd     File descriptor to add/modify/delete
 * @param event  epoll_event structure with events mask and user data
 *
 * Returns:
 *   - 0 on success
 *   - -EBADF if epfd is invalid or fd doesn't exist
 *   - -EINVAL if op is invalid
 *   - -EEXIST if trying to add an already-registered FD
 *   - -ENOENT if trying to modify/delete a non-registered FD
 *   - -ENOMEM if no more FD slots available in epoll set
 */
long sys_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {
    if (!event) {
        return -EINVAL;
    }

    /* Verify user pointer is readable */
    if (fut_access_ok(event, sizeof(struct epoll_event), 0) != 0) {
        return -EFAULT;
    }

    /* Validate FD exists */
    struct fut_file *file = fut_vfs_get_file(fd);
    if (!file) {
        return -EBADF;
    }

    /* Get the epoll set */
    struct epoll_set *set = epoll_get_set(epfd);
    if (!set) {
        return -EBADF;
    }

    /* Copy event structure from user space */
    struct epoll_event ev;
    if (fut_copy_from_user(&ev, event, sizeof(ev)) != 0) {
        return -EFAULT;
    }

    switch (op) {
    case EPOLL_CTL_ADD: {
        /* Check if FD is already registered */
        for (int i = 0; i < MAX_EPOLL_FDS; i++) {
            if (set->fds[i].registered && set->fds[i].fd == fd) {
                return -EEXIST;  /* Already registered */
            }
        }

        /* Find empty slot */
        int slot = -1;
        for (int i = 0; i < MAX_EPOLL_FDS; i++) {
            if (!set->fds[i].registered) {
                slot = i;
                break;
            }
        }

        if (slot == -1) {
            return -ENOMEM;  /* No more slots */
        }

        /* Register the FD */
        set->fds[slot].fd = fd;
        set->fds[slot].events = ev.events;
        set->fds[slot].data = ev.data;
        set->fds[slot].registered = true;
        set->count++;

        fut_printf("[EPOLL] Added fd=%d to epfd=%d events=0x%x\n", fd, epfd, ev.events);
        return 0;
    }

    case EPOLL_CTL_MOD: {
        /* Find and modify the entry */
        for (int i = 0; i < MAX_EPOLL_FDS; i++) {
            if (set->fds[i].registered && set->fds[i].fd == fd) {
                set->fds[i].events = ev.events;
                set->fds[i].data = ev.data;
                fut_printf("[EPOLL] Modified fd=%d on epfd=%d events=0x%x\n", fd, epfd, ev.events);
                return 0;
            }
        }
        return -ENOENT;  /* FD not found */
    }

    case EPOLL_CTL_DEL: {
        /* Find and remove the entry */
        for (int i = 0; i < MAX_EPOLL_FDS; i++) {
            if (set->fds[i].registered && set->fds[i].fd == fd) {
                set->fds[i].registered = false;
                set->count--;
                memset(&set->fds[i], 0, sizeof(set->fds[i]));
                fut_printf("[EPOLL] Deleted fd=%d from epfd=%d\n", fd, epfd);
                return 0;
            }
        }
        return -ENOENT;  /* FD not found */
    }

    default:
        return -EINVAL;  /* Invalid operation */
    }
}

/**
 * epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
 *     - Wait for events on an epoll instance
 *
 * Polls all registered file descriptors and waits for events.
 * Returns when events occur or timeout expires.
 *
 * @param epfd       epoll file descriptor
 * @param events     Array to store returned events (user buffer)
 * @param maxevents  Maximum number of events to return (must be > 0)
 * @param timeout    Timeout in milliseconds (-1 = infinite, 0 = non-blocking)
 *
 * Returns:
 *   - Number of ready file descriptors on success (0 if timeout)
 *   - -EBADF if epfd is invalid
 *   - -EINVAL if maxevents <= 0
 *   - -EFAULT if events pointer is invalid
 */
long sys_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout) {
    if (maxevents <= 0) {
        return -EINVAL;
    }

    if (!events) {
        return -EINVAL;
    }

    /* Verify events array is writable */
    if (fut_access_ok(events, maxevents * sizeof(struct epoll_event), 1) != 0) {
        return -EFAULT;
    }

    /* Get the epoll set */
    struct epoll_set *set = epoll_get_set(epfd);
    if (!set) {
        return -EBADF;
    }

    /* Poll with timeout support */
    int max_iterations = (timeout == 0) ? 1 : ((timeout < 0) ? 10000 : (timeout / 10 + 1));
    int iteration = 0;

    while (iteration < max_iterations) {
        int ready_count = 0;
        struct epoll_event ready_events[MAX_EPOLL_FDS];

        /* Check all registered file descriptors */
        for (int i = 0; i < MAX_EPOLL_FDS && ready_count < maxevents; i++) {
            if (!set->fds[i].registered) {
                continue;
            }

            struct fut_file *file = fut_vfs_get_file(set->fds[i].fd);
            if (!file) {
                /* FD closed - report error event */
                ready_events[ready_count].events = EPOLLERR | EPOLLHUP;
                ready_events[ready_count].data = set->fds[i].data;
                ready_count++;
                continue;
            }

            /* Check if FD is readable/writable */
            uint32_t events_ready = 0;

            /* For regular files: always ready for both read and write */
            if (file->vnode && file->vnode->type == 1) {  /* VNODE_FILE */
                if (set->fds[i].events & (EPOLLIN | EPOLLRDNORM)) {
                    events_ready |= EPOLLIN | EPOLLRDNORM;
                }
                if (set->fds[i].events & (EPOLLOUT | EPOLLWRNORM)) {
                    events_ready |= EPOLLOUT | EPOLLWRNORM;
                }
            }
            /* For character devices/sockets: would need more sophisticated checks */
            /* For now, report as ready if requested */
            else if (file->vnode) {
                if (set->fds[i].events & (EPOLLIN | EPOLLRDNORM)) {
                    events_ready |= EPOLLIN | EPOLLRDNORM;
                }
                if (set->fds[i].events & (EPOLLOUT | EPOLLWRNORM)) {
                    events_ready |= EPOLLOUT | EPOLLWRNORM;
                }
            }

            /* Report events if any match the registered mask */
            if (events_ready) {
                ready_events[ready_count].events = events_ready;
                ready_events[ready_count].data = set->fds[i].data;
                ready_count++;
            }
        }

        /* If we have events, copy to user and return */
        if (ready_count > 0) {
            if (fut_copy_to_user(events, ready_events,
                                ready_count * sizeof(struct epoll_event)) != 0) {
                return -EFAULT;
            }
            fut_printf("[EPOLL] epoll_wait on epfd=%d returned %d events\n", epfd, ready_count);
            return ready_count;
        }

        /* Check timeout */
        if (timeout == 0) {
            /* Non-blocking mode */
            return 0;
        }

        /* Sleep for 10ms before next iteration */
        fut_timespec_t ts;
        ts.tv_sec = 0;
        ts.tv_nsec = 10000000;  /* 10ms */
        sys_nanosleep(&ts, NULL);

        iteration++;
    }

    /* Timeout expired */
    return 0;
}
