// SPDX-License-Identifier: MPL-2.0
#pragma once

#include <time.h>
#include <stdint.h>

struct timeval {
    long tv_sec;        /* seconds */
    long tv_usec;       /* microseconds */
};

struct timezone {
    int tz_minuteswest;  /* minutes west of Greenwich */
    int tz_dsttime;      /* type of DST correction */
};

extern int gettimeofday(struct timeval *tv, void *tz);
