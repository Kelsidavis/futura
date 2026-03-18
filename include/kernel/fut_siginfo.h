/* kernel/fut_siginfo.h - Standalone siginfo_t definition
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides siginfo_t without pulling in signal.h (which defines a kernel-ABI
 * sigset_t that conflicts with the user-ABI sigset_t in user/signal.h).
 *
 * This header is safe to include from headers that are shared between kernel
 * and user-space code (e.g. fut_thread.h via fut_waitq.h via fut_fipc.h).
 */

#pragma once

#include <stdint.h>
#include <stddef.h>

#ifndef FUT_THREAD_NSIG
#define FUT_THREAD_NSIG 65
#endif

#ifndef __siginfo_t_defined
#define __siginfo_t_defined 1
typedef struct {
    int      si_signum;   /* Signal number */
    int      si_errno;    /* Error number */
    int      si_code;     /* Signal code (SI_USER, SI_QUEUE, SI_TIMER, ...) */
    int64_t  si_pid;      /* Sending process PID */
    uint32_t si_uid;      /* Sending process UID */
    int      si_status;   /* Exit status or signal number (SIGCHLD) */
    void    *si_addr;     /* Faulting address (SIGSEGV, SIGBUS) */
    long     si_value;    /* Signal value for rt_sigqueue / POSIX timer */
    int      si_overrun;  /* POSIX timer overrun count */
    int      si_timerid;  /* POSIX timer ID */
} siginfo_t;
#endif
