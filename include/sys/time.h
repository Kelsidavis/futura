// SPDX-License-Identifier: MPL-2.0
/*
 * sys/time.h - Time types and operations
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides time-related structures and functions including
 * gettimeofday, setitimer, and time value manipulation macros.
 */

#pragma once

#include <time.h>
#include <stdint.h>

/* ============================================================
 *   Time Structures
 * ============================================================ */

#ifndef _STRUCT_TIMEVAL
#define _STRUCT_TIMEVAL
struct timeval {
    long tv_sec;        /* Seconds */
    long tv_usec;       /* Microseconds */
};
#endif

#ifndef _STRUCT_TIMEZONE
#define _STRUCT_TIMEZONE
struct timezone {
    int tz_minuteswest;  /* Minutes west of Greenwich */
    int tz_dsttime;      /* Type of DST correction */
};
#endif

/* ============================================================
 *   Interval Timer Types
 * ============================================================ */

#ifndef ITIMER_REAL
#define ITIMER_REAL     0   /* Decrements in real time */
#endif
#ifndef ITIMER_VIRTUAL
#define ITIMER_VIRTUAL  1   /* Decrements in process virtual time */
#endif
#ifndef ITIMER_PROF
#define ITIMER_PROF     2   /* Decrements in process virtual time and system time */
#endif

#ifndef _STRUCT_ITIMERVAL
#define _STRUCT_ITIMERVAL
struct itimerval {
    struct timeval it_interval;  /* Timer interval */
    struct timeval it_value;     /* Current value */
};
#endif

/* ============================================================
 *   Time Manipulation Macros
 * ============================================================ */

/* Check if timeval is set (non-zero) */
#define timerisset(tvp)     ((tvp)->tv_sec || (tvp)->tv_usec)

/* Clear a timeval */
#define timerclear(tvp)     ((tvp)->tv_sec = (tvp)->tv_usec = 0)

/* Compare two timevals */
#define timercmp(a, b, CMP) \
    (((a)->tv_sec == (b)->tv_sec) ? \
        ((a)->tv_usec CMP (b)->tv_usec) : \
        ((a)->tv_sec CMP (b)->tv_sec))

/* Add two timevals: result = a + b */
#define timeradd(a, b, result) do { \
    (result)->tv_sec = (a)->tv_sec + (b)->tv_sec; \
    (result)->tv_usec = (a)->tv_usec + (b)->tv_usec; \
    if ((result)->tv_usec >= 1000000) { \
        ++(result)->tv_sec; \
        (result)->tv_usec -= 1000000; \
    } \
} while (0)

/* Subtract two timevals: result = a - b */
#define timersub(a, b, result) do { \
    (result)->tv_sec = (a)->tv_sec - (b)->tv_sec; \
    (result)->tv_usec = (a)->tv_usec - (b)->tv_usec; \
    if ((result)->tv_usec < 0) { \
        --(result)->tv_sec; \
        (result)->tv_usec += 1000000; \
    } \
} while (0)

/* ============================================================
 *   Function Declarations
 * ============================================================ */

extern int gettimeofday(struct timeval *tv, void *tz);
extern int settimeofday(const struct timeval *tv, const struct timezone *tz);
extern int getitimer(int which, struct itimerval *curr_value);
extern int setitimer(int which, const struct itimerval *new_value,
                     struct itimerval *old_value);
extern int utimes(const char *filename, const struct timeval times[2]);
extern int futimes(int fd, const struct timeval times[2]);
