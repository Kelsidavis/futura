// SPDX-License-Identifier: MPL-2.0
/*
 * sys/select.h - Synchronous I/O multiplexing
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides the select() interface for monitoring multiple file descriptors
 * for I/O readiness.
 */

#pragma once

#include <stdint.h>

/* ============================================================
 *   Constants
 * ============================================================ */

/* Maximum number of file descriptors in fd_set */
#ifndef FD_SETSIZE
#define FD_SETSIZE      1024
#endif

/* Number of bits per unsigned long */
#ifndef NFDBITS
#define NFDBITS         (8 * sizeof(unsigned long))
#endif

/* Number of unsigned longs needed for FD_SETSIZE bits */
#define _FDSET_LONGS    (FD_SETSIZE / NFDBITS)

/* ============================================================
 *   Data Structures
 * ============================================================ */

/* File descriptor set */
#ifndef _FD_SET_T
#define _FD_SET_T
typedef struct {
    unsigned long fds_bits[_FDSET_LONGS];
} fd_set;
#endif

/* ============================================================
 *   fd_set Manipulation Macros
 * ============================================================ */

/* Set a bit in the fd_set */
#ifndef FD_SET
#define FD_SET(fd, fdsetp) \
    ((fdsetp)->fds_bits[(fd) / NFDBITS] |= (1UL << ((fd) % NFDBITS)))
#endif

/* Clear a bit in the fd_set */
#ifndef FD_CLR
#define FD_CLR(fd, fdsetp) \
    ((fdsetp)->fds_bits[(fd) / NFDBITS] &= ~(1UL << ((fd) % NFDBITS)))
#endif

/* Test if a bit is set in the fd_set */
#ifndef FD_ISSET
#define FD_ISSET(fd, fdsetp) \
    (((fdsetp)->fds_bits[(fd) / NFDBITS] & (1UL << ((fd) % NFDBITS))) != 0)
#endif

/* Clear all bits in the fd_set */
#ifndef FD_ZERO
#define FD_ZERO(fdsetp) do { \
    unsigned long *__bits = (fdsetp)->fds_bits; \
    for (int __i = 0; __i < _FDSET_LONGS; __i++) \
        __bits[__i] = 0; \
} while (0)
#endif

/* Copy an fd_set */
#ifndef FD_COPY
#define FD_COPY(src, dest) do { \
    unsigned long *__src = (src)->fds_bits; \
    unsigned long *__dest = (dest)->fds_bits; \
    for (int __i = 0; __i < _FDSET_LONGS; __i++) \
        __dest[__i] = __src[__i]; \
} while (0)
#endif

/* ============================================================
 *   Time Structures
 * ============================================================ */

/* Include sys/time.h for struct timeval if needed */
#ifndef _STRUCT_TIMEVAL
#define _STRUCT_TIMEVAL
struct timeval {
    long tv_sec;        /* Seconds */
    long tv_usec;       /* Microseconds */
};
#endif

/* ============================================================
 *   Function Declarations
 * ============================================================ */

extern int select(int nfds, fd_set *readfds, fd_set *writefds,
                  fd_set *exceptfds, struct timeval *timeout);
extern int pselect(int nfds, fd_set *readfds, fd_set *writefds,
                   fd_set *exceptfds, const void *timeout,
                   const void *sigmask);

