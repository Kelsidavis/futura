// SPDX-License-Identifier: MPL-2.0
#pragma once

/* Suppress wayland_nofortify.h's stub timerfd: */
#ifndef _SYS_TIMERFD_H
#define _SYS_TIMERFD_H
#endif

#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TFD_NONBLOCK     0x0800
#define TFD_CLOEXEC      0x80000
#define TFD_TIMER_ABSTIME    (1 << 0)
#define TFD_TIMER_CANCEL_ON_SET (1 << 1)

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

#ifdef __cplusplus
}
#endif
