// SPDX-License-Identifier: MPL-2.0
#pragma once

/* Include system headers if available */
#if __has_include(<time.h>)
#include <time.h>
#endif

/* Define clock constants for freestanding environments */
#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 1
#endif

#ifndef CLOCK_REALTIME
#define CLOCK_REALTIME 0
#endif

/* Declare clock_gettime if not already available from system headers */
#if !__has_include(<time.h>)
struct timespec {
    long tv_sec;
    long tv_nsec;
};
int clock_gettime(int clock_id, struct timespec *tp);
#endif
