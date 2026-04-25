/* kernel/sys_clock_advanced.c - Advanced clock and timer syscalls for ARM64
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements advanced clock and interval timer syscalls for time management.
 * These provide fine-grained control over clocks, intervals, and time adjustment.
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/syscalls.h>
#include <shared/fut_timespec.h>
#include <shared/fut_timeval.h>
#include <sys/time.h>
#include <sys/capability.h>
#include <stdint.h>
#include <string.h>

#include <kernel/kprintf.h>
#include <kernel/uaccess.h>
#include <kernel/debug_config.h>
#include <platform/platform.h>

/* Clock nanosleep debugging (controlled via debug_config.h) */
#define clock_nanosleep_printf(...) do { if (NANOSLEEP_DEBUG) fut_printf(__VA_ARGS__); } while(0)

/* Copy timespec to user or kernel buffer (bypass fut_copy_to_user for kernel pointers) */
static inline int clock_copy_to_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)dst >= KERNEL_VIRTUAL_BASE) {
        __builtin_memcpy(dst, src, n);
        return 0;
    }
#endif
    return fut_copy_to_user(dst, src, n);
}

/* Copy timespec from user or kernel buffer */
static inline int clock_copy_from_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)src >= KERNEL_VIRTUAL_BASE) {
        __builtin_memcpy(dst, src, n);
        return 0;
    }
#endif
    return fut_copy_from_user(dst, src, n);
}
#include <kernel/fut_timer.h>
#include <time.h>

/* CLOCK_* constants provided by time.h */
/* ITIMER_* constants provided by sys/time.h */

/* Wall clock offset and NTP state maintained by sys_time.c */
extern volatile int64_t g_realtime_offset_sec;
extern volatile int64_t g_ntp_adj_usec;
extern volatile int32_t g_ntp_freq_ppm;
extern volatile int32_t g_ntp_status;

/* Interval timer structure — may already be provided by sys/time.h */
#ifndef _STRUCT_ITIMERVAL
#define _STRUCT_ITIMERVAL
struct itimerval {
    fut_timeval_t it_interval;  /* Timer interval */
    fut_timeval_t it_value;     /* Current value */
};
#endif

/* Time adjustment structure for adjtimex */
#ifndef _STRUCT_TIMEX
#define _STRUCT_TIMEX
struct timex {
    unsigned int modes;      /* Mode selector */
    long offset;             /* Time offset (microseconds) */
    long freq;               /* Frequency offset */
    long maxerror;           /* Maximum error (microseconds) */
    long esterror;           /* Estimated error (microseconds) */
    int status;              /* Clock status */
    long constant;           /* PLL time constant */
    long precision;          /* Clock precision (microseconds) */
    long tolerance;          /* Clock frequency tolerance */
    fut_timeval_t time;      /* Current time */
    long tick;               /* Microseconds per tick */
};
#endif

/**
 * sys_clock_settime - Set clock time
 *
 * @param clock_id: Clock identifier (CLOCK_REALTIME, etc.)
 * @param tp: New time to set
 *
 * Sets the specified clock to the given time. Most clocks are read-only;
 * only CLOCK_REALTIME can be set (and requires CAP_SYS_TIME capability).
 *
 * Phase 1 (Completed): Validate parameters, accept but don't actually set time
 * Phase 2 (Completed): Store real-time clock offset for CLOCK_REALTIME
 * Phase 3 (Completed): CAP_SYS_TIME capability check
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL if clock_id invalid or clock not settable
 *   - -EFAULT if tp invalid
 *   - -EPERM if insufficient privileges (missing CAP_SYS_TIME)
 */
long sys_clock_settime(int clock_id, const fut_timespec_t *tp) {
    /* ARM64 FIX: Copy register params to local stack vars before blocking calls */
    int local_clock_id = clock_id;
    const fut_timespec_t *local_tp = tp;

    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    if (!local_tp) {
        fut_printf("[CLOCK_SETTIME] clock_settime(clock_id=%d, tp=%p) -> EFAULT (tp is NULL)\n",
                   local_clock_id, local_tp);
        return -EFAULT;
    }

    /* Copy time from user */
    fut_timespec_t time;
    if (clock_copy_from_user(&time, local_tp, sizeof(fut_timespec_t)) != 0) {
        fut_printf("[CLOCK_SETTIME] clock_settime(clock_id=%d) -> EFAULT (copy_from_user failed)\n",
                   local_clock_id);
        return -EFAULT;
    }

    /* Validate timespec */
    if (time.tv_sec < 0 || time.tv_nsec < 0 || time.tv_nsec >= 1000000000LL) {
        fut_printf("[CLOCK_SETTIME] clock_settime(clock_id=%d, sec=%lld, nsec=%lld) -> EINVAL "
                   "(invalid timespec)\n",
                   local_clock_id, time.tv_sec, time.tv_nsec);
        return -EINVAL;
    }

    const char *clock_name;
    int is_settable = 0;

    switch (local_clock_id) {
        case CLOCK_REALTIME:
            clock_name = "CLOCK_REALTIME";
            is_settable = 1;
            break;
        case CLOCK_MONOTONIC:
            clock_name = "CLOCK_MONOTONIC";
            break;
        case CLOCK_BOOTTIME:
            clock_name = "CLOCK_BOOTTIME";
            break;
        default:
            fut_printf("[CLOCK_SETTIME] clock_settime(clock_id=%d) -> EINVAL (unknown clock_id)\n",
                       local_clock_id);
            return -EINVAL;
    }

    if (!is_settable) {
        fut_printf("[CLOCK_SETTIME] clock_settime(clock_id=%s, sec=%lld, nsec=%lld) -> EINVAL "
                   "(%s is not settable)\n",
                   clock_name, time.tv_sec, time.tv_nsec, clock_name);
        return -EINVAL;
    }

    /* Phase 3: CAP_SYS_TIME required to set the realtime clock.
     * Non-root processes without this capability get EPERM. */
    if (task->uid != 0 && !(task->cap_effective & (1ULL << CAP_SYS_TIME))) {
        fut_printf("[CLOCK_SETTIME] clock_settime(clock_id=%s, pid=%llu) -> EPERM "
                   "(CAP_SYS_TIME required)\n",
                   clock_name, (unsigned long long)task->pid);
        return -EPERM;
    }

    /*
     * Compute and store realtime offset: the difference between the requested
     * wall-clock time and the current uptime. CLOCK_REALTIME = uptime + offset.
     */
    /* fut_get_ticks() returns ticks at 100 Hz (10ms each) */
    uint64_t now_ticks = fut_get_ticks();
    int64_t now_sec = (int64_t)(now_ticks / 100);
    g_realtime_offset_sec = time.tv_sec - now_sec;

    return 0;
}

/**
 * sys_clock_getres - Get clock resolution
 *
 * @param clock_id: Clock identifier
 * @param res: Output buffer for clock resolution
 *
 * Returns the resolution (precision) of the specified clock.
 *
 * Phase 1 (Completed): Return fixed resolution (1 millisecond) for all clocks
 * Phase 2 (Completed): Return accurate resolution per clock type based on FUT_TIMER_HZ
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL if clock_id invalid
 *   - -EFAULT if res invalid
 */
long sys_clock_getres(int clock_id, fut_timespec_t *res) {
    /* ARM64 FIX: Copy register params to local stack vars before blocking calls */
    int local_clock_id = clock_id;
    fut_timespec_t *local_res = res;

    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    const char *clock_name;

    switch (local_clock_id) {
        case CLOCK_REALTIME:
            clock_name = "CLOCK_REALTIME";
            break;
        case CLOCK_MONOTONIC:
            clock_name = "CLOCK_MONOTONIC";
            break;
        case CLOCK_BOOTTIME:
            clock_name = "CLOCK_BOOTTIME";
            break;
        case CLOCK_REALTIME_COARSE:
            clock_name = "CLOCK_REALTIME_COARSE";
            break;
        case CLOCK_MONOTONIC_COARSE:
            clock_name = "CLOCK_MONOTONIC_COARSE";
            break;
        case CLOCK_MONOTONIC_RAW:
            clock_name = "CLOCK_MONOTONIC_RAW";
            break;
        case CLOCK_PROCESS_CPUTIME_ID:
            clock_name = "CLOCK_PROCESS_CPUTIME_ID";
            break;
        case CLOCK_THREAD_CPUTIME_ID:
            clock_name = "CLOCK_THREAD_CPUTIME_ID";
            break;
        default:
            fut_printf("[CLOCK_GETRES] clock_getres(clock_id=%d) -> EINVAL (unknown clock_id)\n",
                       local_clock_id);
            return -EINVAL;
    }

    /*
     * Return accurate resolution based on timer tick rate (FUT_TIMER_HZ).
     * All clocks are driven by the same periodic interrupt, so their
     * resolution equals one tick period: 1,000,000,000 / FUT_TIMER_HZ ns.
     * CLOCK_PROCESS_CPUTIME_ID / CLOCK_THREAD_CPUTIME_ID report per-tick
     * accounting granularity, same tick period.
     */
    fut_timespec_t resolution;
    resolution.tv_sec  = 0;
    resolution.tv_nsec = (long)(1000000000UL / FUT_TIMER_HZ);

    if (local_res) {
        if (clock_copy_to_user(local_res, &resolution, sizeof(fut_timespec_t)) != 0) {
            fut_printf("[CLOCK_GETRES] clock_getres(clock_id=%s) -> EFAULT (copy_to_user failed)\n",
                       clock_name);
            return -EFAULT;
        }
    }

    return 0;
}

/**
 * sys_clock_nanosleep - High-resolution sleep on specific clock
 *
 * @param clock_id: Clock to use for sleep
 * @param flags: 0 = relative, TIMER_ABSTIME = absolute
 * @param req: Requested sleep time
 * @param rem: Remaining time if interrupted (relative mode only)
 *
 * Similar to nanosleep() but allows clock selection. Can sleep until
 * absolute time with TIMER_ABSTIME flag.
 *
 * Phase 1 (Completed): Delegate to nanosleep for relative sleep, reject absolute
 * Phase 2 (Completed): Implement absolute time sleep for CLOCK_REALTIME
 * Phase 3 (Completed): Correct clock domain for TIMER_ABSTIME (REALTIME vs MONOTONIC)
 *
 * Returns:
 *   - 0 on success
 *   - -EINTR if interrupted (rem set to remaining time)
 *   - -EINVAL if clock_id invalid or time invalid
 *   - -EFAULT if req/rem invalid
 */
long sys_clock_nanosleep(int clock_id, int flags,
                          const fut_timespec_t *req, fut_timespec_t *rem) {
    /* ARM64 FIX: Copy register params to local stack vars before blocking calls */
    int local_clock_id = clock_id;
    int local_flags = flags;
    const fut_timespec_t *local_req = req;
    fut_timespec_t *local_rem = rem;

    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    if (!local_req) {
        clock_nanosleep_printf("[CLOCK_NANOSLEEP] clock_nanosleep(clock_id=%d) -> EINVAL (req is NULL)\n",
                   local_clock_id);
        return -EINVAL;
    }

    /* Copy request from user */
    fut_timespec_t request;
    if (clock_copy_from_user(&request, local_req, sizeof(fut_timespec_t)) != 0) {
        clock_nanosleep_printf("[CLOCK_NANOSLEEP] clock_nanosleep(clock_id=%d) -> EFAULT (copy_from_user failed)\n",
                   local_clock_id);
        return -EFAULT;
    }

    /* Validate timespec */
    if (request.tv_sec < 0 || request.tv_nsec < 0 || request.tv_nsec >= 1000000000LL) {
        clock_nanosleep_printf("[CLOCK_NANOSLEEP] clock_nanosleep(clock_id=%d, sec=%lld, nsec=%lld) -> EINVAL "
                   "(invalid timespec)\n",
                   local_clock_id, request.tv_sec, request.tv_nsec);
        return -EINVAL;
    }

    const char *clock_name;

    /* Classify clock_id into REALTIME-domain or MONOTONIC-domain.
     * Extended clocks accepted (Linux 3.0+):
     *   Realtime domain: CLOCK_REALTIME(0), CLOCK_REALTIME_COARSE(5), CLOCK_TAI(11),
     *                    CLOCK_REALTIME_ALARM(8)
     *   Monotonic domain: CLOCK_MONOTONIC(1), CLOCK_MONOTONIC_RAW(4),
     *                     CLOCK_MONOTONIC_COARSE(6), CLOCK_BOOTTIME(7),
     *                     CLOCK_BOOTTIME_ALARM(9)
     * Futura has no suspend, so BOOTTIME == MONOTONIC and *_ALARM == base clock. */
    bool is_realtime_clock;
    switch (local_clock_id) {
        case CLOCK_REALTIME:
        case CLOCK_REALTIME_COARSE:   /* 5: low-res realtime */
        case CLOCK_TAI:               /* 11: TAI (no leap second offset in Futura) */
        case CLOCK_REALTIME_ALARM:    /* 8: realtime + wakeup (no alarm hw) */
            is_realtime_clock = true;
            clock_name = "CLOCK_REALTIME";
            break;
        case CLOCK_MONOTONIC:
        case CLOCK_MONOTONIC_RAW:     /* 4: raw hardware monotonic */
        case CLOCK_MONOTONIC_COARSE:  /* 6: low-res monotonic */
        case CLOCK_BOOTTIME:          /* 7: monotonic + suspend time (= monotonic here) */
        case CLOCK_BOOTTIME_ALARM:    /* 9: boottime + wakeup (no alarm hw) */
            is_realtime_clock = false;
            clock_name = "CLOCK_MONOTONIC";
            break;
        default:
            clock_nanosleep_printf("[CLOCK_NANOSLEEP] clock_nanosleep(clock_id=%d) -> EINVAL (unsupported clock)\n",
                       local_clock_id);
            return -EINVAL;
    }

    #define TIMER_ABSTIME 1
    const char *mode = (local_flags & TIMER_ABSTIME) ? "absolute" : "relative";

    /* Phase 2/3: Implement absolute time sleep with correct clock domain.
     *
     * fut_get_time_ns() returns nanoseconds since boot (monotonic).
     * For CLOCK_REALTIME, the caller supplies a wall-clock target_ns so we
     * must account for the wall-clock offset to compute the monotonic delay.
     * For CLOCK_MONOTONIC, no adjustment is needed.
     */
    if (local_flags & TIMER_ABSTIME) {
        uint64_t now_monotonic_ns = fut_get_time_ns();
        uint64_t target_ns = (uint64_t)request.tv_sec * 1000000000ULL
                           + (uint64_t)request.tv_nsec;

        /* For CLOCK_REALTIME: convert wall-clock target to monotonic by
         * subtracting the realtime offset so remain_ns is a pure monotonic delay. */
        uint64_t target_monotonic_ns = target_ns;
        if (is_realtime_clock) {
            int64_t offset_ns = g_realtime_offset_sec * (int64_t)1000000000LL;
            /* target_monotonic = target_wall - offset */
            if (offset_ns >= 0) {
                target_monotonic_ns = (target_ns > (uint64_t)offset_ns)
                    ? (target_ns - (uint64_t)offset_ns) : 0;
            } else {
                target_monotonic_ns = target_ns + (uint64_t)(-offset_ns);
            }
        }

        if (now_monotonic_ns >= target_monotonic_ns) {
            clock_nanosleep_printf("[CLOCK_NANOSLEEP] clock_nanosleep(clock_id=%s, mode=%s, "
                       "target=%lld.%09lld) -> 0 (time already passed)\n",
                       clock_name, mode, request.tv_sec, request.tv_nsec);
            return 0;
        }

        uint64_t remain_ns = target_monotonic_ns - now_monotonic_ns;
        fut_timespec_t rel = {
            .tv_sec  = (long long)(remain_ns / 1000000000ULL),
            .tv_nsec = (long long)(remain_ns % 1000000000ULL),
        };

        clock_nanosleep_printf("[CLOCK_NANOSLEEP] clock_nanosleep(clock_id=%s, mode=%s, "
                   "target=%lld.%09lld, remain=%lld.%09lld) -> sleeping\n",
                   clock_name, mode, request.tv_sec, request.tv_nsec,
                   rel.tv_sec, rel.tv_nsec);

        /* For absolute sleep, rem is not returned (POSIX) */
        return sys_nanosleep(&rel, NULL);
    }

    /* Delegate to regular nanosleep for relative sleep */
    clock_nanosleep_printf("[CLOCK_NANOSLEEP] clock_nanosleep(clock_id=%s, mode=%s, sec=%lld, nsec=%lld) "
               "(delegating to nanosleep)\n",
               clock_name, mode, request.tv_sec, request.tv_nsec);

    return sys_nanosleep(local_req, local_rem);
}

/**
 * sys_getitimer - Get interval timer value
 *
 * @param which: Timer type (ITIMER_REAL, ITIMER_VIRTUAL, ITIMER_PROF)
 * @param value: Output buffer for timer value
 *
 * Gets the current value and interval of an interval timer.
 *
 * Phase 1 (Completed): Return zero (timer disarmed) for all timer types
 * Phase 2 (Completed): Track and return actual timer state from task fields
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL if which invalid
 *   - -EFAULT if value invalid
 */
long sys_getitimer(int which, struct itimerval *value) {
    /* ARM64 FIX: Copy register params to local stack vars before blocking calls */
    int local_which = which;
    struct itimerval *local_value = value;

    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    if (!local_value) {
        fut_printf("[GETITIMER] getitimer(which=%d) -> EFAULT (value is NULL)\n", local_which);
        return -EFAULT;
    }

    const char *timer_name;
    switch (local_which) {
        case ITIMER_REAL:
            timer_name = "ITIMER_REAL";
            break;
        case ITIMER_VIRTUAL:
            timer_name = "ITIMER_VIRTUAL";
            break;
        case ITIMER_PROF:
            timer_name = "ITIMER_PROF";
            break;
        default:
            fut_printf("[GETITIMER] getitimer(which=%d) -> EINVAL (invalid timer type)\n", local_which);
            return -EINVAL;
    }

    struct itimerval timer;
    memset(&timer, 0, sizeof(timer));

    if (local_which == ITIMER_REAL) {
        /* Compute remaining value from alarm_expires_ms (stored in ticks, 10ms each) */
        uint64_t now_ticks = fut_get_ticks();
        if (task->alarm_expires_ms > 0 && task->alarm_expires_ms > now_ticks) {
            uint64_t rem_ticks = task->alarm_expires_ms - now_ticks;
            uint64_t rem_real_ms = rem_ticks * 10;  /* ticks → ms */
            timer.it_value.tv_sec  = (long)(rem_real_ms / 1000);
            timer.it_value.tv_usec = (long)((rem_real_ms % 1000) * 1000);
        }
        uint64_t intv_ticks = task->itimer_real_interval_ms;
        uint64_t intv_real_ms = intv_ticks * 10;  /* ticks → ms */
        timer.it_interval.tv_sec  = (long)(intv_real_ms / 1000);
        timer.it_interval.tv_usec = (long)((intv_real_ms % 1000) * 1000);
    } else if (local_which == ITIMER_VIRTUAL) {
        uint64_t val = task->itimer_virt_value_ms;
        timer.it_value.tv_sec  = (long)(val / 1000);
        timer.it_value.tv_usec = (long)((val % 1000) * 1000);
        uint64_t intv = task->itimer_virt_interval_ms;
        timer.it_interval.tv_sec  = (long)(intv / 1000);
        timer.it_interval.tv_usec = (long)((intv % 1000) * 1000);
    } else { /* ITIMER_PROF */
        uint64_t val = task->itimer_prof_value_ms;
        timer.it_value.tv_sec  = (long)(val / 1000);
        timer.it_value.tv_usec = (long)((val % 1000) * 1000);
        uint64_t intv = task->itimer_prof_interval_ms;
        timer.it_interval.tv_sec  = (long)(intv / 1000);
        timer.it_interval.tv_usec = (long)((intv % 1000) * 1000);
    }

    if (clock_copy_to_user(local_value, &timer, sizeof(struct itimerval)) != 0) {
        fut_printf("[GETITIMER] getitimer(which=%s) -> EFAULT (copy_to_user failed)\n",
                   timer_name);
        return -EFAULT;
    }

    return 0;
}

/**
 * sys_setitimer - Set interval timer value
 *
 * @param which: Timer type (ITIMER_REAL, ITIMER_VIRTUAL, ITIMER_PROF)
 * @param value: New timer value and interval
 * @param ovalue: Optional output for old timer value
 *
 * Sets an interval timer. When the timer expires, a signal is sent:
 * - ITIMER_REAL: SIGALRM (wall clock time)
 * - ITIMER_VIRTUAL: SIGVTALRM (user CPU time)
 * - ITIMER_PROF: SIGPROF (user + system CPU time)
 *
 * Phase 1 (Completed): Validate parameters, accept but don't arm timer
 * Phase 2 (Completed): Arm timer and schedule signal delivery via alarm_expires_ms
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL if which or time values invalid
 *   - -EFAULT if pointers invalid
 */
long sys_setitimer(int which, const struct itimerval *value, struct itimerval *ovalue) {
    /* ARM64 FIX: Copy register params to local stack vars before blocking calls */
    int local_which = which;
    const struct itimerval *local_value = value;
    struct itimerval *local_ovalue = ovalue;

    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    if (!local_value) {
        fut_printf("[SETITIMER] setitimer(which=%d) -> EFAULT (value is NULL)\n", local_which);
        return -EFAULT;
    }

    const char *timer_name;

    switch (local_which) {
        case ITIMER_REAL:
            timer_name = "ITIMER_REAL";
            break;
        case ITIMER_VIRTUAL:
            timer_name = "ITIMER_VIRTUAL";
            /* SIGVTALRM */
            break;
        case ITIMER_PROF:
            timer_name = "ITIMER_PROF";
            /* SIGPROF */
            break;
        default:
            fut_printf("[SETITIMER] setitimer(which=%d) -> EINVAL (invalid timer type)\n", local_which);
            return -EINVAL;
    }

    /* Copy timer value from user */
    struct itimerval new_timer;
    if (clock_copy_from_user(&new_timer, local_value, sizeof(struct itimerval)) != 0) {
        fut_printf("[SETITIMER] setitimer(which=%s) -> EFAULT (copy_from_user failed)\n",
                   timer_name);
        return -EFAULT;
    }

    /* Validate timer values */
    if (new_timer.it_value.tv_usec < 0 || new_timer.it_value.tv_usec >= 1000000 ||
        new_timer.it_interval.tv_usec < 0 || new_timer.it_interval.tv_usec >= 1000000) {
        fut_printf("[SETITIMER] setitimer(which=%s) -> EINVAL (invalid timeval)\n", timer_name);
        return -EINVAL;
    }

    uint64_t now_ticks = fut_get_ticks();

    /* Capture old timer value before modifying */
    if (local_ovalue) {
        struct itimerval old_timer;
        memset(&old_timer, 0, sizeof(old_timer));
        if (local_which == ITIMER_REAL) {
            /* alarm_expires_ms and itimer_real_interval_ms are in ticks (10ms each) */
            if (task->alarm_expires_ms > 0 && task->alarm_expires_ms > now_ticks) {
                uint64_t rem_ticks = task->alarm_expires_ms - now_ticks;
                uint64_t rem_real_ms = rem_ticks * 10;
                old_timer.it_value.tv_sec  = (long)(rem_real_ms / 1000);
                old_timer.it_value.tv_usec = (long)((rem_real_ms % 1000) * 1000);
            }
            uint64_t intv_ticks = task->itimer_real_interval_ms;
            uint64_t intv_real_ms = intv_ticks * 10;
            old_timer.it_interval.tv_sec  = (long)(intv_real_ms / 1000);
            old_timer.it_interval.tv_usec = (long)((intv_real_ms % 1000) * 1000);
        } else if (local_which == ITIMER_VIRTUAL) {
            old_timer.it_value.tv_sec  = (long)(task->itimer_virt_value_ms / 1000);
            old_timer.it_value.tv_usec = (long)((task->itimer_virt_value_ms % 1000) * 1000);
            old_timer.it_interval.tv_sec  = (long)(task->itimer_virt_interval_ms / 1000);
            old_timer.it_interval.tv_usec = (long)((task->itimer_virt_interval_ms % 1000) * 1000);
        } else {
            old_timer.it_value.tv_sec  = (long)(task->itimer_prof_value_ms / 1000);
            old_timer.it_value.tv_usec = (long)((task->itimer_prof_value_ms % 1000) * 1000);
            old_timer.it_interval.tv_sec  = (long)(task->itimer_prof_interval_ms / 1000);
            old_timer.it_interval.tv_usec = (long)((task->itimer_prof_interval_ms % 1000) * 1000);
        }
        if (clock_copy_to_user(local_ovalue, &old_timer, sizeof(struct itimerval)) != 0) {
            fut_printf("[SETITIMER] setitimer(which=%s) -> EFAULT (ovalue copy failed)\n",
                       timer_name);
            /* Continue anyway - old value write failure is not fatal per POSIX */
        }
    }

    /* Arm / disarm the timer.
     * Convert user-provided ms values to ticks (100 Hz = 10ms/tick). */
    uint64_t value_ms = (uint64_t)new_timer.it_value.tv_sec * 1000 +
                        ((uint64_t)new_timer.it_value.tv_usec + 999) / 1000;
    uint64_t intv_ms  = (uint64_t)new_timer.it_interval.tv_sec * 1000 +
                        ((uint64_t)new_timer.it_interval.tv_usec + 999) / 1000;

    if (local_which == ITIMER_REAL) {
        /* Convert ms to ticks for storage */
        uint64_t intv_ticks = intv_ms / 10;
        if (intv_ms % 10 != 0) intv_ticks++;
        task->itimer_real_interval_ms = intv_ticks;
        if (value_ms > 0) {
            uint64_t value_ticks = value_ms / 10;
            if (value_ms % 10 != 0) value_ticks++;
            if (value_ticks == 0) value_ticks = 1;
            task->alarm_expires_ms = now_ticks + value_ticks;
        } else {
            task->alarm_expires_ms     = 0;
            task->itimer_real_interval_ms = 0;
        }
    } else if (local_which == ITIMER_VIRTUAL) {
        task->itimer_virt_value_ms    = value_ms;
        task->itimer_virt_interval_ms = intv_ms;
    } else { /* ITIMER_PROF */
        task->itimer_prof_value_ms    = value_ms;
        task->itimer_prof_interval_ms = intv_ms;
    }

    return 0;
}

/**
 * sys_settimeofday - Set time of day
 *
 * @param tv: New time to set
 * @param tz: Timezone (not supported, should be NULL)
 *
 * Sets the system time. Requires CAP_SYS_TIME capability.
 *
 * Phase 1 (Completed): Validate parameters, accept but don't set time
 * Phase 2 (Completed): Store real-time clock offset
 * Phase 3 (Completed): CAP_SYS_TIME capability check
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL if tz non-NULL
 *   - -EFAULT if tv invalid
 *   - -EPERM if insufficient privileges (missing CAP_SYS_TIME)
 */
long sys_settimeofday(const fut_timeval_t *tv, const void *tz) {
    /* ARM64 FIX: Copy register params to local stack vars before blocking calls */
    const fut_timeval_t *local_tv = tv;
    const void *local_tz = tz;

    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    if (local_tz != NULL) {
        fut_printf("[SETTIMEOFDAY] settimeofday: timezone parameter not supported\n");
        return -EINVAL;
    }

    if (!local_tv) {
        fut_printf("[SETTIMEOFDAY] settimeofday(tv=%p) -> EFAULT (tv is NULL)\n", local_tv);
        return -EFAULT;
    }

    /* Phase 3: CAP_SYS_TIME required */
    if (task->uid != 0 && !(task->cap_effective & (1ULL << CAP_SYS_TIME))) {
        fut_printf("[SETTIMEOFDAY] settimeofday(pid=%llu) -> EPERM (CAP_SYS_TIME required)\n",
                   (unsigned long long)task->pid);
        return -EPERM;
    }

    /* Copy time from user */
    fut_timeval_t time;
    if (clock_copy_from_user(&time, local_tv, sizeof(fut_timeval_t)) != 0) {
        fut_printf("[SETTIMEOFDAY] settimeofday -> EFAULT (copy_from_user failed)\n");
        return -EFAULT;
    }

    /* Validate timeval */
    if (time.tv_usec < 0 || time.tv_usec >= 1000000) {
        fut_printf("[SETTIMEOFDAY] settimeofday(sec=%lld, usec=%lld) -> EINVAL (invalid timeval)\n",
                   time.tv_sec, time.tv_usec);
        return -EINVAL;
    }

    /* Store wall clock offset (seconds precision).
     * fut_get_ticks() returns ticks at 100 Hz (10ms each). */
    uint64_t now_ticks = fut_get_ticks();
    int64_t now_sec = (int64_t)(now_ticks / 100);
    g_realtime_offset_sec = (int64_t)time.tv_sec - now_sec;

    return 0;
}

/**
 * sys_adjtimex - Adjust kernel clock
 *
 * @param txc: Time adjustment structure
 *
 * Tunes kernel time variables. Used by NTP daemon for clock synchronization.
 *
 * Phase 1 (Completed): Validate and return default values (no adjustments)
 * Phase 2 (Completed): Apply ADJ_OFFSET and ADJ_SETOFFSET adjustments to g_realtime_offset_sec
 * Phase 3 (Completed): Sub-second ADJ_OFFSET accumulation, ADJ_FREQUENCY and ADJ_STATUS tracking
 *
 * Returns:
 *   - Clock state on success
 *   - -EINVAL if modes invalid
 *   - -EFAULT if txc invalid
 *   - -EPERM if insufficient privileges (Phase 3)
 */
long sys_adjtimex(struct timex *txc) {
    /* ARM64 FIX: Copy register params to local stack vars before blocking calls */
    struct timex *local_txc = txc;

    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    if (!local_txc) {
        fut_printf("[ADJTIMEX] adjtimex(txc=%p) -> EFAULT (txc is NULL)\n", local_txc);
        return -EFAULT;
    }

    /* Copy from user */
    struct timex tx;
    if (clock_copy_from_user(&tx, local_txc, sizeof(struct timex)) != 0) {
        fut_printf("[ADJTIMEX] adjtimex -> EFAULT (copy_from_user failed)\n");
        return -EFAULT;
    }

    /* adjtimex mode bits (Linux-compatible subset) */
    #define ADJ_OFFSET      0x0001   /* time offset */
    #define ADJ_FREQUENCY   0x0002   /* frequency offset */
    #define ADJ_STATUS      0x0010   /* clock status */
    #define ADJ_TICK        0x4000   /* tick value */
    #define ADJ_SETOFFSET   0x0100   /* add 'time' to current time */
    #define ADJ_OFFSET_SINGLESHOT 0x8001 /* old-style adjtime */
    #define TIME_OK         0        /* clock synchronized */
    #define TIME_ERROR      5        /* clock not synchronized */

    unsigned int modes = tx.modes;

    /* Linux: any modes != 0 (i.e., a write to the clock state) requires
     * CAP_SYS_TIME. Read-only adjtimex (modes == 0) returns the current
     * NTP state and is unprivileged. The previous code skipped this
     * gate so any process could shift the realtime clock or rewrite
     * the NTP frequency calibration. */
    {
        const unsigned int WRITE_MODES = (ADJ_OFFSET | ADJ_FREQUENCY |
                                          ADJ_STATUS | ADJ_TICK |
                                          ADJ_SETOFFSET |
                                          ADJ_OFFSET_SINGLESHOT);
        if ((modes & WRITE_MODES) &&
            task->uid != 0 &&
            !(task->cap_effective & (1ULL << CAP_SYS_TIME))) {
            fut_printf("[ADJTIMEX] adjtimex(modes=0x%x, pid=%llu) -> EPERM "
                       "(CAP_SYS_TIME required for clock-modifying modes)\n",
                       modes, (unsigned long long)task->pid);
            return -EPERM;
        }
    }

    /* Phase 2: Apply requested adjustments */
    if (modes & ADJ_SETOFFSET) {
        /* Add the specified offset directly to the realtime clock */
        int64_t delta_sec = (int64_t)tx.time.tv_sec;
        int64_t delta_us  = (int64_t)tx.time.tv_usec;
        /* Convert microsecond fraction to seconds (round toward zero) */
        delta_sec += delta_us / 1000000;
        g_realtime_offset_sec += delta_sec;
    } else if (modes & ADJ_OFFSET) {
        /* Phase 3: Accumulate full (whole + sub-second) NTP offset */
        int64_t delta_us = (int64_t)tx.offset;
        int64_t delta_sec = delta_us / 1000000;
        int64_t rem_us    = delta_us % 1000000;
        g_realtime_offset_sec += delta_sec;
        g_ntp_adj_usec += rem_us;
        /* Roll over sub-second accumulator */
        if (g_ntp_adj_usec >= 1000000) {
            g_realtime_offset_sec++;
            g_ntp_adj_usec -= 1000000;
        } else if (g_ntp_adj_usec <= -1000000) {
            g_realtime_offset_sec--;
            g_ntp_adj_usec += 1000000;
        }
    }

    /* Phase 3: ADJ_FREQUENCY — store frequency correction (ppm * FREQ_SCALE) */
    if (modes & ADJ_FREQUENCY) {
        g_ntp_freq_ppm = (int32_t)tx.freq;
    }

    /* Phase 3: ADJ_STATUS — update NTP clock status */
    if (modes & ADJ_STATUS) {
        g_ntp_status = (int32_t)tx.status;
    }
    /* ADJ_TICK: accepted, not acted on (kernel tick rate is fixed at HZ=100) */

    /* Fill in current read-back values */
    uint64_t ms = fut_get_ticks();
    uint64_t now_sec = ms / 1000 + (uint64_t)g_realtime_offset_sec;
    uint64_t now_us  = (ms % 1000) * 1000;

    /* Phase 3: Return current NTP state including stored freq and sub-second offset */
    tx.offset    = (long)g_ntp_adj_usec;
    tx.freq      = g_ntp_freq_ppm;
    tx.maxerror  = 0;
    tx.esterror  = 0;
    tx.status    = g_ntp_status;
    tx.constant  = 0;
    tx.precision = 1000;   /* 1 microsecond */
    tx.tolerance = 0;
    tx.tick      = 10000;  /* 10ms tick */
    tx.time.tv_sec  = (long)now_sec;
    tx.time.tv_usec = (long)now_us;

    /* Copy back to user */
    if (clock_copy_to_user(local_txc, &tx, sizeof(struct timex)) != 0) {
        fut_printf("[ADJTIMEX] adjtimex -> EFAULT (copy_to_user failed)\n");
        return -EFAULT;
    }

    fut_printf("[ADJTIMEX] adjtimex(modes=0x%x, freq=%d, status=%d, adj_usec=%lld) -> %d (Phase 3)\n",
               modes, g_ntp_freq_ppm, g_ntp_status, (long long)g_ntp_adj_usec, g_ntp_status);

    return g_ntp_status;
}
