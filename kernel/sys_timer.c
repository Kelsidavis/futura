/* kernel/sys_timer.c - POSIX timer syscalls
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements POSIX interval timer syscalls for per-process timers.
 * Timers are stored per-task and checked in fut_timer_tick().
 */

#include <kernel/fut_task.h>
#include <kernel/fut_timer.h>
#include <kernel/errno.h>
#include <kernel/uaccess.h>
#include <shared/fut_timespec.h>
#include <shared/fut_sigevent.h>
#include <kernel/signal.h>
#include <time.h>

#include <kernel/kprintf.h>

/* Convert timespec to milliseconds (clamped to 0 for negative values) */
static uint64_t timespec_to_ms(const struct timespec *ts) {
    if (ts->tv_sec < 0)
        return 0;
    uint64_t ms = (uint64_t)ts->tv_sec * 1000;
    ms += (uint64_t)ts->tv_nsec / 1000000;
    return ms;
}

/* Convert milliseconds to timespec */
static void ms_to_timespec(uint64_t ms, struct timespec *ts) {
    ts->tv_sec = (long)(ms / 1000);
    ts->tv_nsec = (long)((ms % 1000) * 1000000);
}

/* Validate a timespec: tv_nsec must be in [0, 999999999] */
static int timespec_valid(const struct timespec *ts) {
    return ts->tv_nsec >= 0 && ts->tv_nsec < 1000000000L;
}

/* Validate timer ID and return pointer, or NULL */
static fut_posix_timer_t *get_timer(fut_task_t *task, timer_t id) {
    int idx = id - 1;  /* IDs are 1-based */
    if (idx < 0 || idx >= FUT_POSIX_TIMER_MAX)
        return NULL;
    fut_posix_timer_t *pt = &task->posix_timers[idx];
    if (!pt->active)
        return NULL;
    return pt;
}

/**
 * sys_timer_create - Create a POSIX per-process timer
 */
long sys_timer_create(int clockid, struct sigevent *sevp, timer_t *timerid) {
    /* ARM64 FIX: Copy register params to local stack vars before blocking calls */
    int local_clockid = clockid;
    struct sigevent *local_sevp = sevp;
    timer_t *local_timerid = timerid;

    fut_task_t *task = fut_task_current();
    if (!task)
        return -ESRCH;

    if (!local_timerid)
        return -EINVAL;

    /* Validate clock ID */
    if (local_clockid != CLOCK_REALTIME && local_clockid != CLOCK_MONOTONIC)
        return -EINVAL;

    /* Validate userspace pointer */
    if (fut_access_ok(local_timerid, sizeof(timer_t), 1) != 0)
        return -EFAULT;

    /* Parse sigevent if provided */
    int signo = SIGALRM;  /* Default signal */
    int notify = SIGEV_SIGNAL;
    if (local_sevp) {
        struct sigevent sev;
        if (fut_copy_from_user(&sev, local_sevp, sizeof(struct sigevent)) != 0)
            return -EFAULT;

        if (sev.sigev_notify != SIGEV_NONE && sev.sigev_notify != SIGEV_SIGNAL)
            return -EINVAL;

        notify = sev.sigev_notify;
        if (notify == SIGEV_SIGNAL) {
            if (sev.sigev_signo < 1 || sev.sigev_signo >= _NSIG)
                return -EINVAL;
            signo = sev.sigev_signo;
        }
    }

    /* Find a free timer slot */
    int slot = -1;
    for (int i = 0; i < FUT_POSIX_TIMER_MAX; i++) {
        if (!task->posix_timers[i].active) {
            slot = i;
            break;
        }
    }
    if (slot < 0)
        return -EAGAIN;  /* No free timer slots */

    /* Initialize timer */
    fut_posix_timer_t *pt = &task->posix_timers[slot];
    pt->active = 1;
    pt->armed = 0;
    pt->clockid = local_clockid;
    pt->signo = signo;
    pt->notify = notify;
    pt->overrun = 0;
    pt->expiry_ms = 0;
    pt->interval_ms = 0;

    /* Write timer ID back to userspace (1-based) */
    timer_t id = slot + 1;
    if (fut_copy_to_user(local_timerid, &id, sizeof(timer_t)) != 0) {
        pt->active = 0;
        return -EFAULT;
    }

    return 0;
}

/**
 * sys_timer_settime - Arm/disarm a POSIX per-process timer
 */
long sys_timer_settime(timer_t timerid, int flags,
                        const struct itimerspec *new_value,
                        struct itimerspec *old_value) {
    /* ARM64 FIX */
    timer_t local_timerid = timerid;
    int local_flags = flags;
    const struct itimerspec *local_new_value = new_value;
    struct itimerspec *local_old_value = old_value;

    fut_task_t *task = fut_task_current();
    if (!task)
        return -ESRCH;

    if (!local_new_value)
        return -EINVAL;

    fut_posix_timer_t *pt = get_timer(task, local_timerid);
    if (!pt)
        return -EINVAL;

    /* Copy new value from userspace */
    struct itimerspec new_timer;
    if (fut_copy_from_user(&new_timer, local_new_value, sizeof(struct itimerspec)) != 0)
        return -EFAULT;

    /* Validate timespec values */
    if (!timespec_valid(&new_timer.it_value) || !timespec_valid(&new_timer.it_interval))
        return -EINVAL;

    /* Return old timer state if requested */
    if (local_old_value) {
        if (fut_access_ok(local_old_value, sizeof(struct itimerspec), 1) != 0)
            return -EFAULT;

        struct itimerspec old_timer;
        if (pt->armed && pt->expiry_ms > 0) {
            uint64_t now = fut_get_ticks();
            uint64_t remaining = (pt->expiry_ms > now) ? (pt->expiry_ms - now) : 0;
            ms_to_timespec(remaining, &old_timer.it_value);
        } else {
            old_timer.it_value.tv_sec = 0;
            old_timer.it_value.tv_nsec = 0;
        }
        ms_to_timespec(pt->interval_ms, &old_timer.it_interval);

        if (fut_copy_to_user(local_old_value, &old_timer, sizeof(struct itimerspec)) != 0)
            return -EFAULT;
    }

    /* Disarm if it_value is zero */
    uint64_t value_ms = timespec_to_ms(&new_timer.it_value);
    if (value_ms == 0) {
        pt->armed = 0;
        pt->expiry_ms = 0;
        pt->interval_ms = 0;
        return 0;
    }

    /* Set interval */
    pt->interval_ms = timespec_to_ms(&new_timer.it_interval);

    /* Arm timer */
    uint64_t now = fut_get_ticks();
    if (local_flags & 1 /* TIMER_ABSTIME */) {
        pt->expiry_ms = value_ms;
    } else {
        pt->expiry_ms = now + value_ms;
    }
    pt->armed = 1;
    pt->overrun = 0;

    return 0;
}

/**
 * sys_timer_gettime - Get current setting of a timer
 */
long sys_timer_gettime(timer_t timerid, struct itimerspec *curr_value) {
    timer_t local_timerid = timerid;
    struct itimerspec *local_curr_value = curr_value;

    fut_task_t *task = fut_task_current();
    if (!task)
        return -ESRCH;

    if (!local_curr_value)
        return -EINVAL;

    fut_posix_timer_t *pt = get_timer(task, local_timerid);
    if (!pt)
        return -EINVAL;

    if (fut_access_ok(local_curr_value, sizeof(struct itimerspec), 1) != 0)
        return -EFAULT;

    struct itimerspec result;
    ms_to_timespec(pt->interval_ms, &result.it_interval);

    if (pt->armed && pt->expiry_ms > 0) {
        uint64_t now = fut_get_ticks();
        uint64_t remaining = (pt->expiry_ms > now) ? (pt->expiry_ms - now) : 0;
        ms_to_timespec(remaining, &result.it_value);
    } else {
        result.it_value.tv_sec = 0;
        result.it_value.tv_nsec = 0;
    }

    if (fut_copy_to_user(local_curr_value, &result, sizeof(struct itimerspec)) != 0)
        return -EFAULT;

    return 0;
}

/**
 * sys_timer_getoverrun - Get overrun count for a timer
 */
long sys_timer_getoverrun(timer_t timerid) {
    timer_t local_timerid = timerid;

    fut_task_t *task = fut_task_current();
    if (!task)
        return -ESRCH;

    fut_posix_timer_t *pt = get_timer(task, local_timerid);
    if (!pt)
        return -EINVAL;

    return (long)pt->overrun;
}

/**
 * sys_timer_delete - Delete a POSIX per-process timer
 */
long sys_timer_delete(timer_t timerid) {
    timer_t local_timerid = timerid;

    fut_task_t *task = fut_task_current();
    if (!task)
        return -ESRCH;

    fut_posix_timer_t *pt = get_timer(task, local_timerid);
    if (!pt)
        return -EINVAL;

    /* Disarm and free the slot */
    pt->armed = 0;
    pt->expiry_ms = 0;
    pt->interval_ms = 0;
    pt->active = 0;

    return 0;
}
