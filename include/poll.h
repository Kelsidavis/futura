// SPDX-License-Identifier: MPL-2.0
/*
 * poll.h - I/O multiplexing
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides the poll() interface for waiting on multiple file descriptors.
 */

#pragma once

#include <stdint.h>

/* ============================================================
 *   Data Structures
 * ============================================================ */

#ifndef _STRUCT_POLLFD
#define _STRUCT_POLLFD
struct pollfd {
    int fd;         /* File descriptor to poll */
    short events;   /* Requested events */
    short revents;  /* Returned events */
};
#endif

/* Type for number of file descriptors */
#ifndef nfds_t
typedef unsigned long nfds_t;
#endif

/* ============================================================
 *   Event Flags
 * ============================================================ */

/* Input events (can be set in events field) */
#ifndef POLLIN
#define POLLIN      0x0001  /* Data available to read */
#endif
#ifndef POLLPRI
#define POLLPRI     0x0002  /* Urgent data available */
#endif
#ifndef POLLOUT
#define POLLOUT     0x0004  /* Writing will not block */
#endif
#ifndef POLLRDNORM
#define POLLRDNORM  0x0040  /* Normal data may be read */
#endif
#ifndef POLLRDBAND
#define POLLRDBAND  0x0080  /* Priority data may be read */
#endif
#ifndef POLLWRNORM
#define POLLWRNORM  0x0100  /* Writing normal data will not block */
#endif
#ifndef POLLWRBAND
#define POLLWRBAND  0x0200  /* Writing priority data will not block */
#endif

/* Output events (only returned in revents field) */
#ifndef POLLERR
#define POLLERR     0x0008  /* Error condition */
#endif
#ifndef POLLHUP
#define POLLHUP     0x0010  /* Hung up */
#endif
#ifndef POLLNVAL
#define POLLNVAL    0x0020  /* Invalid request: fd not open */
#endif

/* ============================================================
 *   Function Declarations
 * ============================================================ */

extern int poll(struct pollfd *fds, nfds_t nfds, int timeout);
extern int ppoll(struct pollfd *fds, nfds_t nfds,
                 const void *tmo_p, const void *sigmask);
