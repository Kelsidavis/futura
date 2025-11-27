// SPDX-License-Identifier: MPL-2.0

#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include <user/sys.h>

#include "eventfd_internal.h"

int eventfd(unsigned int initval, int flags) {
    long ret = sys_eventfd2_call(initval, flags);
    if (ret < 0) {
        errno = (int)-ret;
        return -1;
    }
    errno = 0;
    return (int)ret;
}

int __fut_eventfd_is(int fd) {
    (void)fd;
    return 0;
}

int __fut_eventfd_close(int fd) {
    (void)fd;
    return -1;
}

int __fut_eventfd_retain(int fd) {
    (void)fd;
    return -1;
}

int __fut_eventfd_set_flags(int fd, int flags) {
    (void)fd;
    (void)flags;
    return -1;
}

ssize_t __fut_eventfd_read(int fd, void *buf, size_t count) {
    (void)fd;
    (void)buf;
    (void)count;
    errno = EBADF;
    return -1;
}

ssize_t __fut_eventfd_write(int fd, const void *buf, size_t count) {
    (void)fd;
    (void)buf;
    (void)count;
    errno = EBADF;
    return -1;
}

int __fut_eventfd_poll(int fd, uint32_t requested, uint32_t *ready_out) {
    (void)fd;
    (void)requested;
    if (ready_out) {
        *ready_out = 0;
    }
    return 0;
}
