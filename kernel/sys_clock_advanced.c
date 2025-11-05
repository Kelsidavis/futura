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
#include <shared/fut_timespec.h>
#include <shared/fut_timeval.h>
#include <stdint.h>
#include <string.h>

extern void fut_printf(const char *fmt, ...);
extern fut_task_t *fut_task_current(void);
extern int fut_copy_to_user(void *to, const void *from, size_t size);
extern int fut_copy_from_user(void *to, const void *from, size_t size);
extern uint64_t fut_get_ticks(void);

/* Clock IDs */
#define CLOCK_REALTIME           0
#define CLOCK_MONOTONIC          1
#define CLOCK_PROCESS_CPUTIME_ID 2
#define CLOCK_THREAD_CPUTIME_ID  3
#define CLOCK_MONOTONIC_RAW      4
#define CLOCK_REALTIME_COARSE    5
#define CLOCK_MONOTONIC_COARSE   6
#define CLOCK_BOOTTIME           7

/* Timer types for getitimer/setitimer */
#define ITIMER_REAL    0  /* Real time timer */
#define ITIMER_VIRTUAL 1  /* User time timer */
#define ITIMER_PROF    2  /* User + system time timer */

/* Interval timer structure */
struct itimerval {
    fut_timeval_t it_interval;  /* Timer interval */
    fut_timeval_t it_value;     /* Current value */
};

/* Time adjustment structure for adjtimex */
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

/**
 * sys_clock_settime - Set clock time
 *
 * @param clock_id: Clock identifier (CLOCK_REALTIME, etc.)
 * @param tp: New time to set
 *
 * Sets the specified clock to the given time. Most clocks are read-only;
 * only CLOCK_REALTIME can be set (and requires CAP_SYS_TIME capability).
 *
 * Phase 1: Validate parameters, accept but don't actually set time
 * Phase 2: Store real-time clock offset for CLOCK_REALTIME
 * Phase 3: Integrate with capability system for permission checks
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL if clock_id invalid or clock not settable
 *   - -EFAULT if tp invalid
 *   - -EPERM if insufficient privileges (Phase 3)
 */
long sys_clock_settime(int clock_id, const fut_timespec_t *tp) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    if (!tp) {
        fut_printf("[CLOCK_SETTIME] clock_settime(clock_id=%d, tp=%p) -> EFAULT (tp is NULL)\n",
                   clock_id, tp);
        return -EFAULT;
    }

    /* Copy time from user */
    fut_timespec_t time;
    if (fut_copy_from_user(&time, tp, sizeof(fut_timespec_t)) != 0) {
        fut_printf("[CLOCK_SETTIME] clock_settime(clock_id=%d) -> EFAULT (copy_from_user failed)\n",
                   clock_id);
        return -EFAULT;
    }

    /* Validate timespec */
    if (time.tv_sec < 0 || time.tv_nsec < 0 || time.tv_nsec >= 1000000000LL) {
        fut_printf("[CLOCK_SETTIME] clock_settime(clock_id=%d, sec=%lld, nsec=%lld) -> EINVAL "
                   "(invalid timespec)\n",
                   clock_id, time.tv_sec, time.tv_nsec);
        return -EINVAL;
    }

    const char *clock_name;
    int is_settable = 0;

    switch (clock_id) {
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
                       clock_id);
            return -EINVAL;
    }

    if (!is_settable) {
        fut_printf("[CLOCK_SETTIME] clock_settime(clock_id=%s, sec=%lld, nsec=%lld) -> EINVAL "
                   "(%s is not settable)\n",
                   clock_name, time.tv_sec, time.tv_nsec, clock_name);
        return -EINVAL;
    }

    /* Phase 1: Accept time but don't actually set it */
    /* Phase 2: Store offset to adjust CLOCK_REALTIME */
    /* Phase 3: Add CAP_SYS_TIME capability check */

    fut_printf("[CLOCK_SETTIME] clock_settime(clock_id=%s, sec=%lld, nsec=%lld) -> 0 "
               "(accepted, Phase 1 stub)\n",
               clock_name, time.tv_sec, time.tv_nsec);

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
 * Phase 1: Return fixed resolution (1 millisecond) for all clocks
 * Phase 2: Return accurate resolution per clock type
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL if clock_id invalid
 *   - -EFAULT if res invalid
 */
long sys_clock_getres(int clock_id, fut_timespec_t *res) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    const char *clock_name;

    switch (clock_id) {
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
        default:
            fut_printf("[CLOCK_GETRES] clock_getres(clock_id=%d) -> EINVAL (unknown clock_id)\n",
                       clock_id);
            return -EINVAL;
    }

    /* Phase 1: Return 1 millisecond resolution for all clocks */
    /* Phase 2: Return actual resolution (e.g., nanoseconds for high-res clocks) */
    fut_timespec_t resolution;
    resolution.tv_sec = 0;
    resolution.tv_nsec = 1000000;  /* 1 millisecond */

    if (res) {
        if (fut_copy_to_user(res, &resolution, sizeof(fut_timespec_t)) != 0) {
            fut_printf("[CLOCK_GETRES] clock_getres(clock_id=%s) -> EFAULT (copy_to_user failed)\n",
                       clock_name);
            return -EFAULT;
        }
    }

    fut_printf("[CLOCK_GETRES] clock_getres(clock_id=%s) -> 0 (resolution=1ms, Phase 1 stub)\n",
               clock_name);

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
 * Phase 1: Delegate to nanosleep for relative sleep, reject absolute
 * Phase 2: Implement absolute time sleep for CLOCK_REALTIME
 * Phase 3: Support CLOCK_MONOTONIC absolute sleep
 *
 * Returns:
 *   - 0 on success
 *   - -EINTR if interrupted (rem set to remaining time)
 *   - -EINVAL if clock_id invalid or time invalid
 *   - -EFAULT if req/rem invalid
 */
long sys_clock_nanosleep(int clock_id, int flags,
                          const fut_timespec_t *req, fut_timespec_t *rem) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    if (!req) {
        fut_printf("[CLOCK_NANOSLEEP] clock_nanosleep(clock_id=%d) -> EINVAL (req is NULL)\n",
                   clock_id);
        return -EINVAL;
    }

    /* Copy request from user */
    fut_timespec_t request;
    if (fut_copy_from_user(&request, req, sizeof(fut_timespec_t)) != 0) {
        fut_printf("[CLOCK_NANOSLEEP] clock_nanosleep(clock_id=%d) -> EFAULT (copy_from_user failed)\n",
                   clock_id);
        return -EFAULT;
    }

    /* Validate timespec */
    if (request.tv_sec < 0 || request.tv_nsec < 0 || request.tv_nsec >= 1000000000LL) {
        fut_printf("[CLOCK_NANOSLEEP] clock_nanosleep(clock_id=%d, sec=%lld, nsec=%lld) -> EINVAL "
                   "(invalid timespec)\n",
                   clock_id, request.tv_sec, request.tv_nsec);
        return -EINVAL;
    }

    const char *clock_name;

    switch (clock_id) {
        case CLOCK_REALTIME:
            clock_name = "CLOCK_REALTIME";
            break;
        case CLOCK_MONOTONIC:
            clock_name = "CLOCK_MONOTONIC";
            break;
        default:
            fut_printf("[CLOCK_NANOSLEEP] clock_nanosleep(clock_id=%d) -> EINVAL (unsupported clock)\n",
                       clock_id);
            return -EINVAL;
    }

    #define TIMER_ABSTIME 1
    const char *mode = (flags & TIMER_ABSTIME) ? "absolute" : "relative";

    /* Phase 1: Only support relative time sleep */
    if (flags & TIMER_ABSTIME) {
        fut_printf("[CLOCK_NANOSLEEP] clock_nanosleep(clock_id=%s, mode=%s, sec=%lld, nsec=%lld) -> EINVAL "
                   "(absolute time not yet supported, Phase 1)\n",
                   clock_name, mode, request.tv_sec, request.tv_nsec);
        return -EINVAL;
    }

    /* Phase 1: Delegate to regular nanosleep for relative sleep */
    /* Phase 2: Implement absolute time sleep */
    extern long sys_nanosleep(const fut_timespec_t *u_req, fut_timespec_t *u_rem);

    fut_printf("[CLOCK_NANOSLEEP] clock_nanosleep(clock_id=%s, mode=%s, sec=%lld, nsec=%lld) "
               "(delegating to nanosleep, Phase 1 stub)\n",
               clock_name, mode, request.tv_sec, request.tv_nsec);

    return sys_nanosleep(req, rem);
}

/**
 * sys_getitimer - Get interval timer value
 *
 * @param which: Timer type (ITIMER_REAL, ITIMER_VIRTUAL, ITIMER_PROF)
 * @param value: Output buffer for timer value
 *
 * Gets the current value and interval of an interval timer.
 *
 * Phase 1: Return zero (timer disarmed) for all timer types
 * Phase 2: Track and return actual timer state
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL if which invalid
 *   - -EFAULT if value invalid
 */
long sys_getitimer(int which, struct itimerval *value) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    if (!value) {
        fut_printf("[GETITIMER] getitimer(which=%d) -> EFAULT (value is NULL)\n", which);
        return -EFAULT;
    }

    const char *timer_name;
    switch (which) {
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
            fut_printf("[GETITIMER] getitimer(which=%d) -> EINVAL (invalid timer type)\n", which);
            return -EINVAL;
    }

    /* Phase 1: Return zero (timer disarmed) */
    struct itimerval timer;
    memset(&timer, 0, sizeof(timer));

    if (fut_copy_to_user(value, &timer, sizeof(struct itimerval)) != 0) {
        fut_printf("[GETITIMER] getitimer(which=%s) -> EFAULT (copy_to_user failed)\n",
                   timer_name);
        return -EFAULT;
    }

    fut_printf("[GETITIMER] getitimer(which=%s) -> 0 (timer disarmed, Phase 1 stub)\n",
               timer_name);

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
 * Phase 1: Validate parameters, accept but don't arm timer
 * Phase 2: Arm timer and schedule signal delivery
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL if which or time values invalid
 *   - -EFAULT if pointers invalid
 */
long sys_setitimer(int which, const struct itimerval *value, struct itimerval *ovalue) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    if (!value) {
        fut_printf("[SETITIMER] setitimer(which=%d) -> EFAULT (value is NULL)\n", which);
        return -EFAULT;
    }

    const char *timer_name;
    const char *signal_name;

    switch (which) {
        case ITIMER_REAL:
            timer_name = "ITIMER_REAL";
            signal_name = "SIGALRM";
            break;
        case ITIMER_VIRTUAL:
            timer_name = "ITIMER_VIRTUAL";
            signal_name = "SIGVTALRM";
            break;
        case ITIMER_PROF:
            timer_name = "ITIMER_PROF";
            signal_name = "SIGPROF";
            break;
        default:
            fut_printf("[SETITIMER] setitimer(which=%d) -> EINVAL (invalid timer type)\n", which);
            return -EINVAL;
    }

    /* Copy timer value from user */
    struct itimerval new_timer;
    if (fut_copy_from_user(&new_timer, value, sizeof(struct itimerval)) != 0) {
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

    /* Return old timer value if requested */
    if (ovalue) {
        struct itimerval old_timer;
        memset(&old_timer, 0, sizeof(old_timer));
        if (fut_copy_to_user(ovalue, &old_timer, sizeof(struct itimerval)) != 0) {
            fut_printf("[SETITIMER] setitimer(which=%s) -> EFAULT (copy_to_user for ovalue failed)\n",
                       timer_name);
            /* Continue anyway - old value is optional */
        }
    }

    /* Phase 1: Accept timer parameters but don't arm */
    /* Phase 2: Arm timer and schedule signal delivery */

    int is_oneshot = (new_timer.it_interval.tv_sec == 0 && new_timer.it_interval.tv_usec == 0);
    const char *timer_type = is_oneshot ? "one-shot" : "periodic";

    fut_printf("[SETITIMER] setitimer(which=%s, type=%s, signal=%s, value=%lld.%06llds, interval=%lld.%06llds) -> 0 "
               "(accepted, Phase 1 stub)\n",
               timer_name, timer_type, signal_name,
               new_timer.it_value.tv_sec, new_timer.it_value.tv_usec,
               new_timer.it_interval.tv_sec, new_timer.it_interval.tv_usec);

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
 * Phase 1: Validate parameters, accept but don't set time
 * Phase 2: Store real-time clock offset
 * Phase 3: Integrate with capability system
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL if tz non-NULL
 *   - -EFAULT if tv invalid
 *   - -EPERM if insufficient privileges (Phase 3)
 */
long sys_settimeofday(const fut_timeval_t *tv, const void *tz) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    if (tz != NULL) {
        fut_printf("[SETTIMEOFDAY] settimeofday: timezone parameter not supported\n");
        return -EINVAL;
    }

    if (!tv) {
        fut_printf("[SETTIMEOFDAY] settimeofday(tv=%p) -> EFAULT (tv is NULL)\n", tv);
        return -EFAULT;
    }

    /* Copy time from user */
    fut_timeval_t time;
    if (fut_copy_from_user(&time, tv, sizeof(fut_timeval_t)) != 0) {
        fut_printf("[SETTIMEOFDAY] settimeofday -> EFAULT (copy_from_user failed)\n");
        return -EFAULT;
    }

    /* Validate timeval */
    if (time.tv_usec < 0 || time.tv_usec >= 1000000) {
        fut_printf("[SETTIMEOFDAY] settimeofday(sec=%lld, usec=%lld) -> EINVAL (invalid timeval)\n",
                   time.tv_sec, time.tv_usec);
        return -EINVAL;
    }

    /* Phase 1: Accept time but don't actually set it */
    /* Phase 2: Store offset to adjust system time */
    /* Phase 3: Add CAP_SYS_TIME capability check */

    fut_printf("[SETTIMEOFDAY] settimeofday(sec=%lld, usec=%lld) -> 0 (accepted, Phase 1 stub)\n",
               time.tv_sec, time.tv_usec);

    return 0;
}

/**
 * sys_adjtimex - Adjust kernel clock
 *
 * @param txc: Time adjustment structure
 *
 * Tunes kernel time variables. Used by NTP daemon for clock synchronization.
 *
 * Phase 1: Validate and return default values (no adjustments)
 * Phase 2: Implement basic time adjustment
 * Phase 3: Full NTP support with PLL
 *
 * Returns:
 *   - Clock state on success
 *   - -EINVAL if modes invalid
 *   - -EFAULT if txc invalid
 *   - -EPERM if insufficient privileges (Phase 3)
 */
long sys_adjtimex(struct timex *txc) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    if (!txc) {
        fut_printf("[ADJTIMEX] adjtimex(txc=%p) -> EFAULT (txc is NULL)\n", txc);
        return -EFAULT;
    }

    /* Copy from user */
    struct timex tx;
    if (fut_copy_from_user(&tx, txc, sizeof(struct timex)) != 0) {
        fut_printf("[ADJTIMEX] adjtimex -> EFAULT (copy_from_user failed)\n");
        return -EFAULT;
    }

    /* Phase 1: Return default values (no adjustments) */
    tx.offset = 0;
    tx.freq = 0;
    tx.maxerror = 0;
    tx.esterror = 0;
    tx.status = 0;
    tx.constant = 0;
    tx.precision = 1000;  /* 1 microsecond */
    tx.tolerance = 0;
    tx.tick = 10000;  /* 10ms tick */

    /* Get current time */
    uint64_t ms = fut_get_ticks();
    tx.time.tv_sec = ms / 1000;
    tx.time.tv_usec = (ms % 1000) * 1000;

    /* Copy back to user */
    if (fut_copy_to_user(txc, &tx, sizeof(struct timex)) != 0) {
        fut_printf("[ADJTIMEX] adjtimex -> EFAULT (copy_to_user failed)\n");
        return -EFAULT;
    }

    fut_printf("[ADJTIMEX] adjtimex(modes=%u) -> 0 (no adjustments, Phase 1 stub)\n", tx.modes);

    #define TIME_OK 0  /* Clock synchronized */
    return TIME_OK;
}
