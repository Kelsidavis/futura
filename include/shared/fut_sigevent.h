// SPDX-License-Identifier: MPL-2.0
/*
 * fut_sigevent.h - Shared signal event structures
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides POSIX sigevent structure and related types for kernel and userspace.
 * Used by timer_create() and asynchronous I/O APIs.
 */

#pragma once

#include <stdint.h>

/* ============================================================
 *   timer_t Type (POSIX timer identifier)
 * ============================================================ */

#ifndef __timer_t_defined
#define __timer_t_defined 1
typedef int timer_t;
#endif

/* ============================================================
 *   Signal Value Union
 * ============================================================ */

#ifndef __sigval_defined
#define __sigval_defined 1
union sigval {
    int   sival_int;            /* Integer value */
    void *sival_ptr;            /* Pointer value */
};
#endif

/* ============================================================
 *   sigevent Notification Methods
 * ============================================================ */

#ifndef SIGEV_NONE
#define SIGEV_NONE      0       /* No notification */
#endif
#ifndef SIGEV_SIGNAL
#define SIGEV_SIGNAL    1       /* Notify via signal */
#endif
#ifndef SIGEV_THREAD
#define SIGEV_THREAD    2       /* Notify via thread */
#endif

/* ============================================================
 *   sigevent Structure (for timer notification)
 * ============================================================ */

#ifndef __sigevent_defined
#define __sigevent_defined 1
struct sigevent {
    int sigev_notify;                   /* Notification method */
    int sigev_signo;                    /* Signal number */
    union sigval sigev_value;           /* Value passed to handler */
    void (*sigev_notify_function)(union sigval);  /* Thread function */
    void *sigev_notify_attributes;      /* Thread attributes */
};
#endif
