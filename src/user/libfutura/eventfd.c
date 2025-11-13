// SPDX-License-Identifier: MPL-2.0

#include <errno.h>
// #include <limits.h>  // Temporarily disabled due to build issue
#define INT_MAX 2147483647
#define ULLONG_MAX 18446744073709551615ULL
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <shared/fut_timespec.h>
#include <user/futura_posix.h>
#include <user/libfutura.h>
#include <user/sys.h>

#include "fd.h"
#include "eventfd_internal.h"

#ifndef EPOLLIN
#define EPOLLIN 0x001u
#endif
#ifndef EPOLLOUT
#define EPOLLOUT 0x004u
#endif

struct fut_eventfd_entry {
    bool in_use;
    int fd;
    uint64_t counter;
    bool nonblock;
    bool semaphore;
    int refcount;
};

#define MAX_EVENTFDS 16

static struct fut_eventfd_entry eventfds[MAX_EVENTFDS];

static struct fut_eventfd_entry *lookup_entry(int fd) {
    struct fut_fd_entry *entry = fut_fd_lookup(fd);
    if (!entry || entry->kind != FUT_FD_EVENTFD) {
        return NULL;
    }
    return (struct fut_eventfd_entry *)entry->payload;
}

static struct fut_eventfd_entry *allocate_entry(void) {
    for (int i = 0; i < MAX_EVENTFDS; ++i) {
        if (!eventfds[i].in_use) {
            return &eventfds[i];
        }
    }
    return NULL;
}

static void sleep_brief(void) {
    fut_timespec_t ts = {
        .tv_sec = 0,
        .tv_nsec = 1000000L,
    };
    sys_nanosleep_call(&ts, NULL);
}

int eventfd(unsigned int initval, int flags) {
    struct fut_eventfd_entry *slot = allocate_entry();
    if (!slot) {
        errno = EMFILE;
        return -1;
    }

    int fd = fut_fd_alloc(FUT_FD_EVENTFD, slot);
    if (fd < 0) {
        errno = EMFILE;
        return -1;
    }

    slot->in_use = true;
    slot->fd = fd;
    slot->counter = (uint64_t)initval;
    slot->semaphore = (flags & EFD_SEMAPHORE) != 0;
    slot->refcount = 1;
    slot->nonblock = (flags & EFD_NONBLOCK) != 0;

    int stored_flags = slot->nonblock ? O_NONBLOCK : 0;
    fd_set_flags(fd, stored_flags);

    if (flags & EFD_CLOEXEC) {
        fd_set_cloexec(fd, 1);
    }

    return fd;
}

int __fut_eventfd_retain(int fd) {
    struct fut_eventfd_entry *entry = lookup_entry(fd);
    if (!entry) {
        return -1;
    }
    entry->refcount += 1;
    return 0;
}

int __fut_eventfd_close(int fd) {
    struct fut_eventfd_entry *entry = lookup_entry(fd);
    if (!entry) {
        return -1;
    }
    if (entry->refcount > 1) {
        entry->refcount -= 1;
        return 0;
    }
    entry->in_use = false;
    entry->fd = -1;
    entry->counter = 0;
    entry->nonblock = false;
    entry->semaphore = false;
    entry->refcount = 0;
    return 0;
}

int __fut_eventfd_set_flags(int fd, int flags) {
    struct fut_eventfd_entry *entry = lookup_entry(fd);
    if (!entry) {
        return -1;
    }
    entry->nonblock = (flags & O_NONBLOCK) != 0;
    return 0;
}

int __fut_eventfd_is(int fd) {
    return lookup_entry(fd) ? 1 : 0;
}

static int wait_for_counter(struct fut_eventfd_entry *entry) {
    if (!entry) {
        errno = EBADF;
        return -1;
    }
    while (entry->counter == 0) {
        if (entry->nonblock) {
            errno = EAGAIN;
            return -1;
        }
        sleep_brief();
    }
    return 0;
}

ssize_t __fut_eventfd_read(int fd, void *buf, size_t count) {
    if (!buf || count < sizeof(uint64_t)) {
        errno = EINVAL;
        return -1;
    }
    struct fut_eventfd_entry *entry = lookup_entry(fd);
    if (!entry) {
        errno = EBADF;
        return -1;
    }

    if (wait_for_counter(entry) < 0) {
        return -1;
    }

    uint64_t value = entry->semaphore ? 1ULL : entry->counter;
    if (entry->semaphore) {
        entry->counter -= 1ULL;
    } else {
        entry->counter = 0ULL;
    }

    memcpy(buf, &value, sizeof(value));
    return (ssize_t)sizeof(value);
}

ssize_t __fut_eventfd_write(int fd, const void *buf, size_t count) {
    if (!buf || count < sizeof(uint64_t)) {
        errno = EINVAL;
        return -1;
    }
    struct fut_eventfd_entry *entry = lookup_entry(fd);
    if (!entry) {
        errno = EBADF;
        return -1;
    }

    uint64_t add = 0;
    memcpy(&add, buf, sizeof(add));

    if (add > ULLONG_MAX - entry->counter) {
        errno = EAGAIN;
        return -1;
    }

    entry->counter += add;
    return (ssize_t)sizeof(add);
}

int __fut_eventfd_poll(int fd, uint32_t requested, uint32_t *ready_out) {
    struct fut_eventfd_entry *entry = lookup_entry(fd);
    if (!entry) {
        return 0;
    }

    uint32_t mask = requested ? requested : (EPOLLIN | EPOLLOUT);
    uint32_t ready = 0;

    if (entry->counter > 0 && (mask & EPOLLIN)) {
        ready |= EPOLLIN;
    }
    if (mask & EPOLLOUT) {
        ready |= EPOLLOUT;
    }

    if (ready_out) {
        *ready_out = ready;
    }
    return 1;
}
