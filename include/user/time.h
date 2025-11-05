// SPDX-License-Identifier: MPL-2.0
#pragma once

#include <stdint.h>

/* time_t definition */
#ifndef time_t
typedef int64_t time_t;
#endif

/* Define clock constants for freestanding environments */
#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 1
#endif

#ifndef CLOCK_REALTIME
#define CLOCK_REALTIME 0
#endif

/* Always define timespec for freestanding */
#ifndef _STRUCT_TIMESPEC
#define _STRUCT_TIMESPEC
struct timespec {
    long tv_sec;
    long tv_nsec;
};
#endif

int clock_gettime(int clock_id, struct timespec *tp);
int nanosleep(const struct timespec *req, struct timespec *rem);
time_t time(time_t *tloc);
