// SPDX-License-Identifier: MPL-2.0

#include <errno.h>
#include <stdint.h>
#include <stddef.h>

#include <user/sys.h>

#ifndef EPOLL_CTL_ADD
#define EPOLL_CTL_ADD 1
#endif
#ifndef EPOLL_CTL_DEL
#define EPOLL_CTL_DEL 2
#endif
#ifndef EPOLL_CTL_MOD
#define EPOLL_CTL_MOD 3
#endif

typedef union {
    void    *ptr;
    int      fd;
    uint32_t u32;
    uint64_t u64;
} epoll_data_t;

struct epoll_event {
    uint32_t events;
    epoll_data_t data;
};

int epoll_create1(int flags) {
    long ret = sys_epoll_create1_call(flags);
    if (ret < 0) {
        errno = (int)-ret;
        return -1;
    }
    errno = 0;
    return (int)ret;
}

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {
    long ret = sys_epoll_ctl_call(epfd, op, fd, event);
    if (ret < 0) {
        errno = (int)-ret;
        return -1;
    }
    errno = 0;
    return 0;
}

int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout) {
    long ret = sys_epoll_wait_call(epfd, events, maxevents, timeout);
    if (ret < 0) {
        errno = (int)-ret;
        return -1;
    }
    errno = 0;
    return (int)ret;
}

int epoll_create(int size) {
    (void)size;
    return epoll_create1(0);
}
