#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <shared/fut_timespec.h>
#include <user/sys.h>
#include "timerfd_internal.h"
#include "signalfd_internal.h"
#include "socket_unix.h"
#include "eventfd_internal.h"

#ifndef EPOLLIN
#define EPOLLIN 0x001u
#endif
#ifndef EPOLLOUT
#define EPOLLOUT 0x004u
#endif

#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2
#define EPOLL_CTL_MOD 3

#define MAX_EPOLL_SETS 8
#define MAX_EPOLL_ENTRIES 64

typedef union {
    void *ptr;
    int fd;
    uint32_t u32;
    uint64_t u64;
} epoll_data_t;

struct epoll_event {
    uint32_t events;
    epoll_data_t data;
};

struct epoll_entry {
    int fd;
    uint32_t events;
};

struct epoll_stub {
    bool in_use;
    int handle;
    int count;
    struct epoll_entry items[MAX_EPOLL_ENTRIES];
};

static struct epoll_stub epoll_sets[MAX_EPOLL_SETS];
static int next_handle = 3; /* avoid clashing with stdin/out/err */

static struct epoll_stub *lookup_epoll(int epfd) {
    for (int i = 0; i < MAX_EPOLL_SETS; ++i) {
        if (epoll_sets[i].in_use && epoll_sets[i].handle == epfd) {
            return &epoll_sets[i];
        }
    }
    return NULL;
}

int epoll_create1(int flags) {
    (void)flags;
    for (int i = 0; i < MAX_EPOLL_SETS; ++i) {
        if (!epoll_sets[i].in_use) {
            epoll_sets[i].in_use = true;
            epoll_sets[i].count = 0;
            epoll_sets[i].handle = next_handle++;
            return epoll_sets[i].handle;
        }
    }
    return -1;
}

static int add_entry(struct epoll_stub *stub, int fd, uint32_t events) {
    if (stub->count >= MAX_EPOLL_ENTRIES) {
        return -1;
    }
    /* replace if already present */
    for (int i = 0; i < stub->count; ++i) {
        if (stub->items[i].fd == fd) {
            stub->items[i].events = events;
            return 0;
        }
    }
    stub->items[stub->count].fd = fd;
    stub->items[stub->count].events = events;
    stub->count++;
    return 0;
}

static int remove_entry(struct epoll_stub *stub, int fd) {
    for (int i = 0; i < stub->count; ++i) {
        if (stub->items[i].fd == fd) {
            stub->items[i] = stub->items[stub->count - 1];
            stub->count--;
            return 0;
        }
    }
    return -1;
}

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {
    struct epoll_stub *stub = lookup_epoll(epfd);
    if (!stub) {
        return -1;
    }

    uint32_t evmask = event ? event->events : 0;

    switch (op) {
    case EPOLL_CTL_ADD:
        return add_entry(stub, fd, evmask);
    case EPOLL_CTL_MOD:
        if (remove_entry(stub, fd) < 0) {
            return -1;
        }
        return add_entry(stub, fd, evmask);
    case EPOLL_CTL_DEL:
        return remove_entry(stub, fd);
    default:
        return -1;
    }
}

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

int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout) {
    struct epoll_stub *stub = lookup_epoll(epfd);
    if (!stub || !events || maxevents <= 0) {
        if (timeout > 0) {
            fut_timespec_t ts = {
                .tv_sec = (int64_t)timeout / 1000,
                .tv_nsec = (int64_t)(timeout % 1000) * 1000000LL,
            };
            sys_nanosleep_call(&ts, NULL);
        }
        return -1;
    }

    int remaining = timeout;

    for (;;) {
        int produced = 0;
        for (int i = 0; i < stub->count && produced < maxevents; ++i) {
            uint32_t evmask = stub->items[i].events ? stub->items[i].events : EPOLLIN;
            int fd = stub->items[i].fd;

            if (__fut_timerfd_is_timer(fd)) {
                uint32_t ready_mask = evmask;
                if (__fut_timerfd_poll(fd, &ready_mask)) {
                    events[produced].events = ready_mask;
                    events[produced].data.fd = fd;
                    produced++;
                }
                continue;
            }

            uint32_t ready_mask = 0;
            if (__fut_unix_socket_poll(fd, evmask, &ready_mask)) {
                if (ready_mask) {
                    events[produced].events = ready_mask;
                    events[produced].data.fd = fd;
                    produced++;
                }
                continue;
            }

            if (__fut_eventfd_is(fd)) {
                uint32_t mask = 0;
                if (__fut_eventfd_poll(fd, evmask, &mask) && mask) {
                    events[produced].events = mask;
                    events[produced].data.fd = fd;
                    produced++;
                }
                continue;
            }

            if (__fut_signalfd_is(fd)) {
                uint32_t mask = 0;
                if (__fut_signalfd_poll(fd, &mask) && mask) {
                    events[produced].events = mask;
                    events[produced].data.fd = fd;
                    produced++;
                }
                continue;
            }

            events[produced].events = evmask;
            events[produced].data.fd = fd;
            produced++;
        }

        if (produced > 0 || timeout == 0) {
            return produced;
        }

        int wait_ms = -1;
        int timer_wait = __fut_timerfd_next_timeout_ms();
        if (timeout > 0) {
            if (timer_wait >= 0) {
                wait_ms = timer_wait < remaining ? timer_wait : remaining;
            } else {
                wait_ms = remaining;
            }
            if (wait_ms <= 0) {
                return 0;
            }
        } else if (timeout < 0) {
            if (timer_wait >= 0) {
                wait_ms = timer_wait > 0 ? timer_wait : 0;
            } else {
                wait_ms = 1;
            }
        } else {
            return 0;
        }

        if (wait_ms <= 0) {
            wait_ms = 1;
        }
        sleep_millis(wait_ms);

        if (timeout > 0) {
            remaining -= wait_ms;
            if (remaining <= 0) {
                return 0;
            }
        }
    }
}

int epoll_create(int size) {
    (void)size;
    return epoll_create1(0);
}

int __fut_epoll_close(int epfd) {
    struct epoll_stub *stub = lookup_epoll(epfd);
    if (!stub) {
        return -1;
    }
    stub->in_use = false;
    stub->count = 0;
    return 0;
}
