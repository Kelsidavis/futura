// SPDX-License-Identifier: MPL-2.0

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <errno.h>
#include <sys/signalfd.h>
#include "fd.h"
#include "signalfd_internal.h"

#ifndef EPOLLIN
#define EPOLLIN 0x001u
#endif

struct fut_signalfd_entry {
    bool in_use;
    int fd;
    sigset_t mask;
    int flags;
};

#define MAX_SIGNALFDS 8

static struct fut_signalfd_entry signalfds[MAX_SIGNALFDS];

static struct fut_signalfd_entry *lookup_entry(int fd) {
    struct fut_fd_entry *entry = fut_fd_lookup(fd);
    if (!entry || entry->kind != FUT_FD_SIGNALFD) {
        return NULL;
    }
    return (struct fut_signalfd_entry *)entry->payload;
}

static struct fut_signalfd_entry *allocate_entry(void) {
    for (int i = 0; i < MAX_SIGNALFDS; ++i) {
        if (!signalfds[i].in_use) {
            return &signalfds[i];
        }
    }
    return NULL;
}

int signalfd(int fd, const sigset_t *mask, int flags) {
    if (!mask) {
        errno = EINVAL;
        return -1;
    }

    if (fd >= 0) {
        struct fut_signalfd_entry *entry = lookup_entry(fd);
        if (!entry) {
            errno = EBADF;
            return -1;
        }
        entry->mask = *mask;
        entry->flags = flags;
        return fd;
    }

    struct fut_signalfd_entry *slot = allocate_entry();
    if (!slot) {
        errno = EMFILE;
        return -1;
    }

    int handle = fut_fd_alloc(FUT_FD_SIGNALFD, slot);
    if (handle < 0) {
        errno = EMFILE;
        return -1;
    }

    slot->in_use = true;
    slot->fd = handle;
    slot->mask = *mask;
    slot->flags = flags;
    return handle;
}

int __fut_signalfd_close(int fd) {
    struct fut_signalfd_entry *entry = lookup_entry(fd);
    if (!entry) {
        return -1;
    }
    entry->in_use = false;
    entry->fd = -1;
    entry->mask = 0;
    entry->flags = 0;
    return 0;
}

int __fut_signalfd_is(int fd) {
    return lookup_entry(fd) ? 1 : 0;
}

int __fut_signalfd_poll(int fd, uint32_t *events_out) {
    (void)fd;
    if (events_out) {
        *events_out = 0;
    }
    return 0;
}

ssize_t __fut_signalfd_read(int fd, void *buf, size_t count) {
    (void)fd;
    (void)buf;
    (void)count;
    errno = EAGAIN;
    return -1;
}

int __fut_signalfd_update(int fd, const sigset_t *mask, int flags) {
    struct fut_signalfd_entry *entry = lookup_entry(fd);
    if (!entry || !mask) {
        errno = EBADF;
        return -1;
    }
    entry->mask = *mask;
    entry->flags = flags;
    return 0;
}
