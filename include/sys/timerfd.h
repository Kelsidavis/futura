// SPDX-License-Identifier: MPL-2.0
#pragma once

#include <fcntl.h>
#include <user/time.h>

/* Define flags - use standard O_* flag equivalents if system didn't */
#ifndef TFD_CLOEXEC
#define TFD_CLOEXEC O_CLOEXEC
#endif
#ifndef TFD_NONBLOCK
#define TFD_NONBLOCK O_NONBLOCK
#endif

#define TFD_TIMER_ABSTIME 0x0001

/* Ensure struct itimerspec is defined for function declarations below */
#ifndef __itimerspec_defined
#define __itimerspec_defined 1
struct itimerspec {
    struct timespec it_interval;
    struct timespec it_value;
};
#endif

int timerfd_create(int clockid, int flags);
int timerfd_settime(int fd, int flags,
                    const struct itimerspec *new_value,
                    struct itimerspec *old_value);
int timerfd_gettime(int fd, struct itimerspec *curr_value);

