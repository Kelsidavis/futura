// SPDX-License-Identifier: MPL-2.0
#pragma once

#include <stdint.h>

#include <user/time.h>

#define TFD_CLOEXEC   0x0001
#define TFD_NONBLOCK  0x0002

#define TFD_TIMER_ABSTIME 0x0001

struct itimerspec {
    struct timespec it_interval;
    struct timespec it_value;
};

int timerfd_create(int clockid, int flags);
int timerfd_settime(int fd, int flags,
                    const struct itimerspec *new_value,
                    struct itimerspec *old_value);
int timerfd_gettime(int fd, struct itimerspec *curr_value);

