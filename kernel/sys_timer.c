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
#include <platform/platform.h>

/* POSIX DELAYTIMER_MAX: maximum overrun count returned by timer_getoverrun().
 * Linux uses INT_MAX; we follow suit. */
#ifndef DELAYTIMER_MAX
#define DELAYTIMER_MAX 2147483647
#endif

/* Kernel-pointer bypass helpers for selftest support */
static inline int timer_copy_to_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)dst >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_to_user(dst, src, n);
}
static inline int timer_copy_from_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)src >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_from_user(dst, src, n);
}
static inline int timer_access_ok_write(const void *ptr, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)ptr >= KERNEL_VIRTUAL_BASE) return 0;
#endif
    return fut_access_ok(ptr, n, 1);
}
static inline int timer_access_ok_read(const void *ptr, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)ptr >= KERNEL_VIRTUAL_BASE) return 0;
#endif
    return fut_access_ok(ptr, n, 0);
}

/* Convert timespec to milliseconds (clamped to 0 for negative values).
 * Sub-millisecond values are rounded UP to 1ms to prevent truncation
 * to zero which would silently disarm timers. */
static uint64_t timespec_to_ms(const struct timespec *ts) {
    if (ts->tv_sec < 0)
        return 0;
    uint64_t ms = (uint64_t)ts->tv_sec * 1000;
    ms += ((uint64_t)ts->tv_nsec + 999999) / 1000000;
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

    /* Validate clock ID — accept all Linux timer_create-compatible clocks.
     * Extended set: CLOCK_BOOTTIME(7) == MONOTONIC here; TAI(11) and alarm
     * clocks (8,9) accepted (no suspend/alarm hardware in Futura). */
    switch (local_clockid) {
        case CLOCK_REALTIME:          /* 0 */
        case CLOCK_MONOTONIC:         /* 1 */
        case CLOCK_PROCESS_CPUTIME_ID:/* 2 */
        case CLOCK_THREAD_CPUTIME_ID: /* 3 */
        case CLOCK_BOOTTIME:          /* 7 */
        case CLOCK_REALTIME_ALARM:    /* 8 */
        case CLOCK_BOOTTIME_ALARM:    /* 9 */
        case CLOCK_TAI:               /* 11 */
            break;
        default:
            return -EINVAL;
    }

    /* Validate userspace pointer */
    if (timer_access_ok_write(local_timerid, sizeof(timer_t)) != 0)
        return -EFAULT;

    /* Parse sigevent if provided */
    int signo = SIGALRM;  /* Default signal */
    int notify = SIGEV_SIGNAL;
    long sigev_value = 0;  /* sigev_value.sival_int for SA_SIGINFO handlers */
    uint64_t target_tid = 0;  /* For SIGEV_THREAD_ID: target thread TID */
    if (local_sevp) {
        struct sigevent sev;
        if (timer_copy_from_user(&sev, local_sevp, sizeof(struct sigevent)) != 0)
            return -EFAULT;

        if (sev.sigev_notify != SIGEV_NONE &&
            sev.sigev_notify != SIGEV_SIGNAL &&
            sev.sigev_notify != SIGEV_THREAD_ID)
            return -EINVAL;

        notify = sev.sigev_notify;
        if (notify == SIGEV_SIGNAL || notify == SIGEV_THREAD_ID) {
            if (sev.sigev_signo < 1 || sev.sigev_signo >= _NSIG)
                return -EINVAL;
            signo = sev.sigev_signo;
        }

        /* SIGEV_THREAD_ID: caller specifies which thread receives the signal */
        if (notify == SIGEV_THREAD_ID) {
            if (sev.sigev_notify_thread_id <= 0)
                return -EINVAL;
            target_tid = (uint64_t)sev.sigev_notify_thread_id;
            /* Map to SIGEV_SIGNAL for delivery path — target_tid distinguishes it */
            notify = SIGEV_THREAD_ID;
        }

        /* Store sigev_value for SA_SIGINFO delivery (si_value in siginfo_t) */
        sigev_value = (long)sev.sigev_value.sival_int;
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
    pt->sigev_value = sigev_value;
    pt->target_tid = target_tid;

    /* Write timer ID back to userspace (1-based) */
    timer_t id = slot + 1;
    if (timer_copy_to_user(local_timerid, &id, sizeof(timer_t)) != 0) {
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
    if (timer_copy_from_user(&new_timer, local_new_value, sizeof(struct itimerspec)) != 0)
        return -EFAULT;

    /* Validate timespec values */
    if (!timespec_valid(&new_timer.it_value) || !timespec_valid(&new_timer.it_interval))
        return -EINVAL;

    /* Return old timer state if requested */
    if (local_old_value) {
        if (timer_access_ok_write(local_old_value, sizeof(struct itimerspec)) != 0)
            return -EFAULT;

        struct itimerspec old_timer;
        if (pt->armed && pt->expiry_ms > 0) {
            uint64_t now = fut_get_ticks();
            uint64_t remaining_ticks = (pt->expiry_ms > now) ? (pt->expiry_ms - now) : 0;
            ms_to_timespec(remaining_ticks * 10, &old_timer.it_value);  /* ticks → ms */
        } else {
            old_timer.it_value.tv_sec = 0;
            old_timer.it_value.tv_nsec = 0;
        }
        ms_to_timespec(pt->interval_ms * 10, &old_timer.it_interval);  /* ticks → ms */

        if (timer_copy_to_user(local_old_value, &old_timer, sizeof(struct itimerspec)) != 0)
            return -EFAULT;
    }

    /* Disarm if it_value is zero */
    uint64_t value_ms = timespec_to_ms(&new_timer.it_value);
    if (value_ms == 0) {
        pt->armed = 0;
        pt->expiry_ms = 0;
        pt->interval_ms = 0;
        pt->overrun = 0;  /* POSIX: re-arming/disarming resets overrun */
        return 0;
    }

    /* Set interval: convert ms to ticks (100 Hz = 10ms/tick) */
    uint64_t intv_ms = timespec_to_ms(&new_timer.it_interval);
    pt->interval_ms = intv_ms / 10;
    if (intv_ms % 10 != 0) pt->interval_ms++;

    /* Arm timer: convert value_ms to ticks.
     * For relative timers, round UP to guarantee minimum sleep duration.
     * For absolute timers, truncate so the timer fires at or before the
     * requested time (rounding up would delay expiry past the deadline). */
    uint64_t now = fut_get_ticks();
    uint64_t value_ticks = value_ms / 10;
    if (!(local_flags & 1 /* TIMER_ABSTIME */)) {
        /* Relative: round up */
        if (value_ms % 10 != 0) value_ticks++;
        if (value_ticks == 0 && value_ms > 0) value_ticks = 1;
    }

    if (local_flags & 1 /* TIMER_ABSTIME */) {
        /* For CLOCK_REALTIME, convert wall-clock absolute to monotonic ticks */
        if (pt->clockid == 0 /* CLOCK_REALTIME */) {
            extern volatile int64_t g_realtime_offset_sec;
            int64_t offset_ticks = g_realtime_offset_sec * 100;
            if (offset_ticks >= 0) {
                if (value_ticks >= (uint64_t)offset_ticks)
                    value_ticks -= (uint64_t)offset_ticks;
                else
                    value_ticks = 0; /* Wall-clock time before boot → already expired */
            } else {
                value_ticks += (uint64_t)(-offset_ticks);
            }
        }
        pt->expiry_ms = value_ticks;  /* absolute monotonic ticks */
    } else {
        pt->expiry_ms = now + value_ticks;
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

    if (timer_access_ok_write(local_curr_value, sizeof(struct itimerspec)) != 0)
        return -EFAULT;

    struct itimerspec result;
    ms_to_timespec(pt->interval_ms * 10, &result.it_interval);  /* ticks → ms */

    if (pt->armed && pt->expiry_ms > 0) {
        uint64_t now = fut_get_ticks();
        uint64_t remaining_ticks = (pt->expiry_ms > now) ? (pt->expiry_ms - now) : 0;
        ms_to_timespec(remaining_ticks * 10, &result.it_value);  /* ticks → ms */
    } else {
        result.it_value.tv_sec = 0;
        result.it_value.tv_nsec = 0;
    }

    if (timer_copy_to_user(local_curr_value, &result, sizeof(struct itimerspec)) != 0)
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

    long ov = (long)pt->overrun;
    if (ov > DELAYTIMER_MAX)
        ov = DELAYTIMER_MAX;
    return ov;
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

    /* Disarm and fully reset the slot so no stale state leaks
     * into a future timer_create that reuses this index. */
    pt->armed = 0;
    pt->expiry_ms = 0;
    pt->interval_ms = 0;
    pt->overrun = 0;
    pt->signo = 0;
    pt->notify = 0;
    pt->sigev_value = 0;
    pt->target_tid = 0;
    pt->clockid = 0;
    pt->active = 0;  /* Must be last — tick handler checks active first */

    return 0;
}
