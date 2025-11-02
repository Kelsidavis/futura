// SPDX-License-Identifier: MPL-2.0
/*
 * fut_timeval.h - Shared time value struct
 */

#pragma once

#include <stdint.h>

typedef struct fut_timeval {
    int64_t tv_sec;   /* Seconds */
    int64_t tv_usec;  /* Microseconds */
} fut_timeval_t;
