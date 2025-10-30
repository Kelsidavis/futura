#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <sys/time.h>
#include <errno.h>

#include <user/sys.h>
#include <user/time.h>

/**
 * Get the current time since the epoch in milliseconds.
 * Wrapper around sys_time_millis_call() for portability.
 */
static long get_millis(void) {
    return (long)sys_time_millis_call();
}

/**
 * Enhanced clock_gettime with support for CLOCK_REALTIME and CLOCK_MONOTONIC.
 * Both clocks report the same time (system uptime) since we don't have a RTC yet.
 */
int clock_gettime(int clock_id, struct timespec *tp) {
    if (!tp) {
        return -EINVAL;
    }

    /* Both CLOCK_REALTIME and CLOCK_MONOTONIC use system time */
    switch (clock_id) {
    case CLOCK_REALTIME:
    case CLOCK_MONOTONIC:
        break;
    default:
        return -EINVAL;  /* Unsupported clock */
    }

    long ms = get_millis();
    tp->tv_sec = ms / 1000;
    tp->tv_nsec = (ms % 1000) * 1000000L;
    return 0;
}

/**
 * Get current time of day (seconds and microseconds since epoch).
 * Converts millisecond precision to microsecond.
 * Note: tv is marked __nonnull in system headers, so we don't check for NULL.
 */
int gettimeofday(struct timeval *tv, void *tz) {
    (void)tz;  /* Timezone is not supported */

    long ms = get_millis();
    tv->tv_sec = ms / 1000;
    tv->tv_usec = (ms % 1000) * 1000L;
    return 0;
}

/**
 * Get current time (seconds since epoch).
 * Returns time_t, or (time_t)-1 on error.
 */
time_t time(time_t *tloc) {
    long ms = get_millis();
    time_t sec = (time_t)(ms / 1000);

    if (tloc) {
        *tloc = sec;
    }

    return sec;
}

/**
 * Sleep for the specified number of seconds and nanoseconds.
 * req points to the sleep duration; rem (optional) receives remaining time if interrupted.
 */
int nanosleep(const struct timespec *req, struct timespec *rem) {
    if (!req) {
        return -EINVAL;
    }

    /* Validate timespec values */
    if (req->tv_sec < 0 || req->tv_nsec < 0 || req->tv_nsec >= 1000000000L) {
        return -EINVAL;
    }

    /* Convert to fut_timespec_t for the syscall */
    fut_timespec_t fut_req;
    fut_req.tv_sec = req->tv_sec;
    fut_req.tv_nsec = req->tv_nsec;

    fut_timespec_t fut_rem;
    fut_rem.tv_sec = 0;
    fut_rem.tv_nsec = 0;

    /* Call the kernel nanosleep syscall */
    long result = sys_nanosleep_call(&fut_req, &fut_rem);

    /* Copy remaining time back if requested */
    if (rem && result == -EINTR) {
        rem->tv_sec = fut_rem.tv_sec;
        rem->tv_nsec = fut_rem.tv_nsec;
    }

    return (int)result;
}
