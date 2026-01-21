// SPDX-License-Identifier: MPL-2.0
/*
 * fut_timespec.h - Shared time specification struct
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides timespec structure for kernel and userspace code.
 */

#pragma once

#include <stdint.h>

/* Futura-specific timespec typedef */
typedef struct fut_timespec {
    int64_t tv_sec;
    int64_t tv_nsec;
} fut_timespec_t;

/* Standard POSIX struct timespec */
#ifndef _STRUCT_TIMESPEC
#define _STRUCT_TIMESPEC
struct timespec {
    long tv_sec;    /* Seconds */
    long tv_nsec;   /* Nanoseconds (0 to 999,999,999) */
};
#endif
