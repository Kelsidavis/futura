// SPDX-License-Identifier: MPL-2.0
/*
 * sys/epoll.h - Event poll interface
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides the epoll interface for scalable I/O event notification.
 * Epoll monitors multiple file descriptors and returns those that are
 * ready for I/O operations.
 */

#pragma once

#include <stdint.h>

/* epoll_ctl() operations */
#ifndef EPOLL_CTL_ADD
#define EPOLL_CTL_ADD   1   /* Register fd with epoll instance */
#endif
#ifndef EPOLL_CTL_DEL
#define EPOLL_CTL_DEL   2   /* Deregister fd from epoll instance */
#endif
#ifndef EPOLL_CTL_MOD
#define EPOLL_CTL_MOD   3   /* Modify interest mask for fd */
#endif

/* epoll event types */
#ifndef EPOLLIN
#define EPOLLIN         0x001   /* Data available for reading */
#endif
#ifndef EPOLLPRI
#define EPOLLPRI        0x002   /* Urgent data available */
#endif
#ifndef EPOLLOUT
#define EPOLLOUT        0x004   /* Ready for writing */
#endif
#ifndef EPOLLERR
#define EPOLLERR        0x008   /* Error condition */
#endif
#ifndef EPOLLHUP
#define EPOLLHUP        0x010   /* Hang up (peer closed connection) */
#endif
#ifndef EPOLLRDNORM
#define EPOLLRDNORM     0x040   /* Normal data available */
#endif
#ifndef EPOLLRDBAND
#define EPOLLRDBAND     0x080   /* Priority band data available */
#endif
#ifndef EPOLLWRNORM
#define EPOLLWRNORM     0x100   /* Writing normal data possible */
#endif
#ifndef EPOLLWRBAND
#define EPOLLWRBAND     0x200   /* Writing priority data possible */
#endif
#ifndef EPOLLMSG
#define EPOLLMSG        0x400   /* Message available */
#endif
#ifndef EPOLLRDHUP
#define EPOLLRDHUP      0x2000  /* Peer shutdown writing half */
#endif
#ifndef EPOLLONESHOT
#define EPOLLONESHOT    (1 << 30)   /* One-shot behavior */
#endif
#ifndef EPOLLET
#define EPOLLET         (1 << 31)   /* Edge-triggered behavior */
#endif

/* epoll_create1() flags */
#ifndef EPOLL_CLOEXEC
#define EPOLL_CLOEXEC   0x80000     /* Close-on-exec flag */
#endif

/* epoll event structure */
#ifndef _EPOLL_DATA_T
#define _EPOLL_DATA_T
typedef union epoll_data {
    void    *ptr;
    int      fd;
    uint32_t u32;
    uint64_t u64;
} epoll_data_t;
#endif

#ifndef _STRUCT_EPOLL_EVENT
#define _STRUCT_EPOLL_EVENT
struct epoll_event {
    uint32_t     events;    /* Epoll events */
    epoll_data_t data;      /* User data variable */
} __attribute__((packed));
#endif

/* Function declarations */
extern int epoll_create(int size);
extern int epoll_create1(int flags);
extern int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
extern int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);
extern int epoll_pwait(int epfd, struct epoll_event *events, int maxevents,
                       int timeout, const void *sigmask);
