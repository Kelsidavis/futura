// SPDX-License-Identifier: MPL-2.0
#pragma once

#include <stdint.h>

/* poll() - I/O multiplexing */

struct pollfd {
    int fd;         /* file descriptor */
    short events;   /* requested events */
    short revents;  /* returned events */
};

/* Event flags */
#define POLLIN      0x0001  /* Data available to read */
#define POLLPRI     0x0002  /* High priority data available */
#define POLLOUT     0x0004  /* Ready for writing */
#define POLLERR     0x0008  /* Error condition */
#define POLLHUP     0x0010  /* Hang up */
#define POLLNVAL    0x0020  /* Invalid request */

typedef unsigned long nfds_t;

/* poll() system call */
extern int poll(struct pollfd *fds, nfds_t nfds, int timeout);
