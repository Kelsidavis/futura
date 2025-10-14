// SPDX-License-Identifier: MPL-2.0
#pragma once

#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 1
#endif

#ifndef FUTURA_TIMESPEC_DEFINED
#define FUTURA_TIMESPEC_DEFINED
#if !defined(__timespec_defined) && !defined(_STRUCT_TIMESPEC) && !defined(__STRUCT_TIMESPEC__) && !defined(__have_timespec)
struct timespec {
    long tv_sec;
    long tv_nsec;
};
#endif
#endif

int clock_gettime(int clock_id, struct timespec *tp);
