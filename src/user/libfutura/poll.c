// SPDX-License-Identifier: MPL-2.0

#include <errno.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>

#include <shared/fut_timespec.h>
#include <user/sys.h>

#include "eventfd_internal.h"
#include "signalfd_internal.h"
#include "socket_unix.h"
#include "timerfd_internal.h"

#ifndef POLLIN
#define POLLIN      0x0001
#endif
#ifndef POLLOUT
#define POLLOUT     0x0004
#endif
#ifndef POLLERR
#define POLLERR     0x0008
#endif
#ifndef POLLHUP
#define POLLHUP     0x0010
#endif
#ifndef POLLNVAL
#define POLLNVAL    0x0020
#endif
#ifndef POLLPRI
#define POLLPRI     0x0002
#endif
#ifndef POLLRDNORM
#define POLLRDNORM  0x0040
#endif
#ifndef POLLWRNORM
#define POLLWRNORM  0x0100
#endif

#ifndef EPOLLIN
#define EPOLLIN 0x001u
#endif
#ifndef EPOLLOUT
#define EPOLLOUT 0x004u
#endif

static void sleep_millis(int millis) {
    if (millis <= 0) {
        return;
    }
    fut_timespec_t ts = {
        .tv_sec = (int64_t)millis / 1000,
        .tv_nsec = (int64_t)(millis % 1000) * 1000000LL,
    };
    sys_nanosleep_call(&ts, NULL);
}

static uint32_t poll_to_epoll_mask(short events) {
    uint32_t mask = 0;
    if (events & (POLLIN | POLLRDNORM | POLLPRI)) {
        mask |= EPOLLIN;
    }
    if (events & (POLLOUT | POLLWRNORM)) {
        mask |= EPOLLOUT;
    }
    return mask;
}

static short epoll_to_poll_mask(uint32_t ready) {
    short mask = 0;
    if (ready & EPOLLIN) {
        mask |= POLLIN | POLLRDNORM;
    }
    if (ready & EPOLLOUT) {
        mask |= POLLOUT | POLLWRNORM;
    }
    return mask;
}

int poll(struct pollfd *fds, nfds_t nfds, int timeout) {
    if (!fds && nfds > 0) {
        errno = EFAULT;
        return -1;
    }

    int remaining = timeout;

    for (;;) {
        int ready = 0;
        for (nfds_t i = 0; i < nfds; ++i) {
            struct pollfd *pfd = &fds[i];
            pfd->revents = 0;

            if (pfd->fd < 0) {
                continue;
            }

            uint32_t requested = poll_to_epoll_mask(pfd->events);
            if (requested == 0 && !(pfd->events & (POLLERR | POLLHUP))) {
                continue;
            }

            if (__fut_timerfd_is_timer(pfd->fd)) {
                uint32_t mask = requested;
                if (__fut_timerfd_poll(pfd->fd, &mask) && mask) {
                    pfd->revents |= epoll_to_poll_mask(mask);
                }
            } else if (__fut_unix_socket_poll(pfd->fd, requested, &requested)) {
                if (requested) {
                    pfd->revents |= epoll_to_poll_mask(requested);
                }
            } else if (__fut_eventfd_is(pfd->fd)) {
                uint32_t mask = 0;
                if (__fut_eventfd_poll(pfd->fd, poll_to_epoll_mask(pfd->events), &mask) && mask) {
                    pfd->revents |= epoll_to_poll_mask(mask);
                }
            } else if (__fut_signalfd_is(pfd->fd)) {
                uint32_t mask = 0;
                if (__fut_signalfd_poll(pfd->fd, &mask) && mask) {
                    pfd->revents |= POLLIN;
                }
            } else {
                pfd->revents |= POLLNVAL;
            }

            if (pfd->revents) {
                ready++;
            }
        }

        if (ready > 0 || timeout == 0) {
            return ready;
        }

        if (timeout < 0) {
            sleep_millis(1);
            continue;
        }

        if (remaining <= 0) {
            return 0;
        }

        int wait = remaining < 10 ? remaining : 10;
        sleep_millis(wait);
        remaining -= wait;
    }
}
