// SPDX-License-Identifier: MPL-2.0
#pragma once

/* In hosted environment, get timespec from system headers */
#if defined(__STDC_HOSTED__) && __STDC_HOSTED__ == 1
#include <time.h>
#else

#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 1
#endif

#ifndef CLOCK_REALTIME
#define CLOCK_REALTIME 0
#endif

#ifndef FUTURA_TIMESPEC_DEFINED
#define FUTURA_TIMESPEC_DEFINED
/* Only define struct timespec if not already defined by system headers */
#if !defined(__timespec_defined) && !defined(_STRUCT_TIMESPEC) && !defined(__STRUCT_TIMESPEC__) && !defined(__have_timespec) && !defined(_BITS_TYPES_STRUCT_TIMESPEC_H)
struct timespec {
    long tv_sec;
    long tv_nsec;
};
#endif
#endif

#endif /* __STDC_HOSTED__ */

int clock_gettime(int clock_id, struct timespec *tp);
