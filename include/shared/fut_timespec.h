// SPDX-License-Identifier: MPL-2.0
/*
 * fut_timespec.h - Shared time specification struct
 */

#pragma once

#include <stdint.h>

typedef struct fut_timespec {
    int64_t tv_sec;
    int64_t tv_nsec;
} fut_timespec_t;
