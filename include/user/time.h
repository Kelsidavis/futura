// SPDX-License-Identifier: MPL-2.0
/*
 * time.h - Time types and functions
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides time-related types, clock constants, and functions
 * for time measurement and manipulation.
 */

#pragma once

#include <stdint.h>

/* ============================================================
 *   Type Definitions
 * ============================================================ */

#ifndef __time_t_defined
#define __time_t_defined 1
typedef int64_t time_t;
#endif

#ifndef __clockid_t_defined
#define __clockid_t_defined 1
typedef int clockid_t;
#endif

/* ============================================================
 *   Clock ID Constants
 * ============================================================ */

#ifndef CLOCK_REALTIME
#define CLOCK_REALTIME          0   /* System-wide real-time clock */
#endif
#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC         1   /* Monotonic clock (cannot be set) */
#endif
#ifndef CLOCK_PROCESS_CPUTIME_ID
#define CLOCK_PROCESS_CPUTIME_ID 2  /* Per-process CPU-time clock */
#endif
#ifndef CLOCK_THREAD_CPUTIME_ID
#define CLOCK_THREAD_CPUTIME_ID 3   /* Per-thread CPU-time clock */
#endif
#ifndef CLOCK_MONOTONIC_RAW
#define CLOCK_MONOTONIC_RAW     4   /* Raw hardware monotonic clock */
#endif
#ifndef CLOCK_REALTIME_COARSE
#define CLOCK_REALTIME_COARSE   5   /* Faster but less precise realtime */
#endif
#ifndef CLOCK_MONOTONIC_COARSE
#define CLOCK_MONOTONIC_COARSE  6   /* Faster but less precise monotonic */
#endif
#ifndef CLOCK_BOOTTIME
#define CLOCK_BOOTTIME          7   /* Monotonic + time spent suspended */
#endif
#ifndef CLOCK_REALTIME_ALARM
#define CLOCK_REALTIME_ALARM    8   /* Like REALTIME but wakes from suspend */
#endif
#ifndef CLOCK_BOOTTIME_ALARM
#define CLOCK_BOOTTIME_ALARM    9   /* Like BOOTTIME but wakes from suspend */
#endif
#ifndef CLOCK_TAI
#define CLOCK_TAI               11  /* International Atomic Time */
#endif

/* ============================================================
 *   Time Structures
 * ============================================================ */

#ifndef _STRUCT_TIMESPEC
#define _STRUCT_TIMESPEC
struct timespec {
    long tv_sec;    /* Seconds */
    long tv_nsec;   /* Nanoseconds (0 to 999,999,999) */
};
#endif

/* ============================================================
 *   Timer Constants
 * ============================================================ */

#ifndef TIMER_ABSTIME
#define TIMER_ABSTIME           1   /* Absolute time flag for timer_settime */
#endif

/* ============================================================
 *   Nanoseconds Helpers
 * ============================================================ */

#ifndef NSEC_PER_SEC
#define NSEC_PER_SEC    1000000000L     /* Nanoseconds per second */
#endif
#ifndef NSEC_PER_MSEC
#define NSEC_PER_MSEC   1000000L        /* Nanoseconds per millisecond */
#endif
#ifndef NSEC_PER_USEC
#define NSEC_PER_USEC   1000L           /* Nanoseconds per microsecond */
#endif
#ifndef USEC_PER_SEC
#define USEC_PER_SEC    1000000L        /* Microseconds per second */
#endif
#ifndef MSEC_PER_SEC
#define MSEC_PER_SEC    1000L           /* Milliseconds per second */
#endif

/* ============================================================
 *   Function Declarations
 * ============================================================ */

int clock_gettime(clockid_t clock_id, struct timespec *tp);
int clock_settime(clockid_t clock_id, const struct timespec *tp);
int clock_getres(clockid_t clock_id, struct timespec *res);
int clock_nanosleep(clockid_t clock_id, int flags,
                    const struct timespec *request, struct timespec *remain);
int nanosleep(const struct timespec *req, struct timespec *rem);
time_t time(time_t *tloc);
double difftime(time_t time1, time_t time0);
