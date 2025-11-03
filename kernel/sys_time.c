// SPDX-License-Identifier: MPL-2.0

#include <kernel/fut_timer.h>
#include <kernel/errno.h>
#include <shared/fut_timeval.h>
#include <shared/fut_timespec.h>
#include <stdint.h>

extern int fut_copy_to_user(void *to, const void *from, size_t size);
extern void fut_printf(const char *fmt, ...);

/* Clock IDs for clock_gettime */
#define CLOCK_REALTIME           0
#define CLOCK_MONOTONIC          1
#define CLOCK_PROCESS_CPUTIME_ID 2
#define CLOCK_THREAD_CPUTIME_ID  3
#define CLOCK_MONOTONIC_RAW      4
#define CLOCK_REALTIME_COARSE    5
#define CLOCK_MONOTONIC_COARSE   6
#define CLOCK_BOOTTIME           7

long sys_time_millis(void) {
    return (long)fut_get_ticks();
}

/**
 * gettimeofday() - Get current time of day
 *
 * Returns the current time as seconds and microseconds since the Unix epoch.
 * The timezone parameter is not supported and should be NULL.
 *
 * @param tv  Pointer to timeval structure to receive time
 * @param tz  Timezone structure (not supported, should be NULL)
 *
 * Returns:
 *   - 0 on success
 *   - -EFAULT if tv is an invalid pointer
 *   - -EINVAL if tz is non-NULL (timezones not supported)
 */
/**
 * time() - Get time in seconds
 *
 * Returns the time as the number of seconds since the Epoch, 1970-01-01 00:00:00 +0000 (UTC).
 * If tloc is non-NULL, the return value is also stored in the location to which tloc points.
 *
 * @param tloc  Optional pointer to store the return value (may be NULL)
 *
 * Returns:
 *   - Time in seconds since the Unix epoch (always succeeds)
 *   - If tloc is non-NULL, also stores the result at *tloc
 *
 * Note: This is simpler than gettimeofday(), returning only seconds without microseconds.
 */
long sys_time(uint64_t *tloc) {
    /* Get current time in milliseconds */
    uint64_t ms = fut_get_ticks();

    /* Convert to seconds */
    uint64_t seconds = ms / 1000;

    /* If tloc is provided, store the result there */
    if (tloc != NULL) {
        if (fut_copy_to_user(tloc, &seconds, sizeof(uint64_t)) != 0) {
            return -EFAULT;
        }
    }

    fut_printf("[TIME] time() -> %llu seconds\n", seconds);

    return (long)seconds;
}

long sys_gettimeofday(fut_timeval_t *tv, void *tz) {
    if (!tv) {
        return -EFAULT;
    }

    if (tz != NULL) {
        fut_printf("[TIME] gettimeofday: timezone parameter not supported\n");
        return -EINVAL;
    }

    /* Get current time in milliseconds */
    uint64_t ms = fut_get_ticks();

    /* Convert to timeval (seconds + microseconds) */
    fut_timeval_t kernel_tv;
    kernel_tv.tv_sec = ms / 1000;
    kernel_tv.tv_usec = (ms % 1000) * 1000;

    /* Copy to userspace */
    if (fut_copy_to_user(tv, &kernel_tv, sizeof(fut_timeval_t)) != 0) {
        return -EFAULT;
    }

    fut_printf("[TIME] gettimeofday() -> %lld.%06lld\n",
               kernel_tv.tv_sec, kernel_tv.tv_usec);

    return 0;
}

/**
 * clock_gettime() - Get time with nanosecond precision
 *
 * Returns the current time for the specified clock with nanosecond precision.
 * This is the modern POSIX time interface that supports multiple clock sources.
 *
 * @param clock_id  Clock identifier (CLOCK_REALTIME, CLOCK_MONOTONIC, etc.)
 * @param tp        Pointer to timespec structure to receive time
 *
 * Returns:
 *   - 0 on success
 *   - -EFAULT if tp is an invalid pointer
 *   - -EINVAL if clock_id is not supported
 *
 * Supported clocks:
 *   - CLOCK_REALTIME: System-wide real-time clock (wall clock time)
 *   - CLOCK_MONOTONIC: Monotonic time (doesn't go backwards, not affected by time adjustments)
 *   - CLOCK_BOOTTIME: Like MONOTONIC but includes time spent in suspend
 *
 * Phase 1 (Completed): Both REALTIME and MONOTONIC use same clock source
 * Phase 2 (Current): Enhanced validation and clock type identification
 * Phase 3: Implement separate monotonic clock that survives time adjustments
 * Phase 4: Add PROCESS_CPUTIME_ID and THREAD_CPUTIME_ID for CPU time tracking
 */
long sys_clock_gettime(int clock_id, fut_timespec_t *tp) {
    if (!tp) {
        fut_printf("[TIME] clock_gettime(clock_id=%d, tp=%p) -> EFAULT (tp is NULL)\n",
                   clock_id, tp);
        return -EFAULT;
    }

    /* Phase 2: Identify clock type for logging */
    const char *clock_name = "UNKNOWN";
    const char *clock_desc = "unknown clock";
    const char *clock_characteristics = "";
    int is_supported = 1;

    switch (clock_id) {
        case CLOCK_REALTIME:
            clock_name = "CLOCK_REALTIME";
            clock_desc = "system-wide real-time clock";
            clock_characteristics = "wall clock time, affected by time adjustments";
            break;

        case CLOCK_MONOTONIC:
            clock_name = "CLOCK_MONOTONIC";
            clock_desc = "monotonic time";
            clock_characteristics = "never goes backwards, unaffected by time adjustments";
            break;

        case CLOCK_BOOTTIME:
            clock_name = "CLOCK_BOOTTIME";
            clock_desc = "monotonic time including suspend";
            clock_characteristics = "like MONOTONIC but includes time spent suspended";
            break;

        case CLOCK_REALTIME_COARSE:
            clock_name = "CLOCK_REALTIME_COARSE";
            clock_desc = "fast low-resolution real-time clock";
            clock_characteristics = "faster but less precise than CLOCK_REALTIME";
            break;

        case CLOCK_MONOTONIC_COARSE:
            clock_name = "CLOCK_MONOTONIC_COARSE";
            clock_desc = "fast low-resolution monotonic clock";
            clock_characteristics = "faster but less precise than CLOCK_MONOTONIC";
            break;

        case CLOCK_MONOTONIC_RAW:
            clock_name = "CLOCK_MONOTONIC_RAW";
            clock_desc = "hardware-based monotonic clock";
            clock_characteristics = "raw hardware time, not subject to NTP adjustments";
            break;

        case CLOCK_PROCESS_CPUTIME_ID:
            clock_name = "CLOCK_PROCESS_CPUTIME_ID";
            clock_desc = "per-process CPU time clock";
            clock_characteristics = "measures CPU time consumed by process";
            is_supported = 0;
            break;

        case CLOCK_THREAD_CPUTIME_ID:
            clock_name = "CLOCK_THREAD_CPUTIME_ID";
            clock_desc = "per-thread CPU time clock";
            clock_characteristics = "measures CPU time consumed by thread";
            is_supported = 0;
            break;

        default:
            fut_printf("[TIME] clock_gettime(clock_id=%d, tp=%p) -> EINVAL (unknown clock_id)\n",
                       clock_id, tp);
            return -EINVAL;
    }

    /* Check if clock is supported */
    if (!is_supported) {
        fut_printf("[TIME] clock_gettime(clock_id=%s [%s], tp=%p) -> EINVAL "
                   "(%s not yet supported, Phase 4)\n",
                   clock_name, clock_desc, tp, clock_characteristics);
        return -EINVAL;
    }

    /* Get current time in milliseconds from timer */
    uint64_t ms = fut_get_ticks();

    /* Convert to timespec (seconds + nanoseconds) */
    fut_timespec_t kernel_tp;
    kernel_tp.tv_sec = ms / 1000;
    kernel_tp.tv_nsec = (ms % 1000) * 1000000;  /* Convert ms to ns */

    /* Copy to userspace */
    if (fut_copy_to_user(tp, &kernel_tp, sizeof(fut_timespec_t)) != 0) {
        fut_printf("[TIME] clock_gettime(clock_id=%s [%s], tp=%p) -> EFAULT (copy_to_user failed)\n",
                   clock_name, clock_desc, tp);
        return -EFAULT;
    }

    /* Phase 2: Detailed logging with clock identification and characteristics */
    fut_printf("[TIME] clock_gettime(clock_id=%s [%s], tp=%p) -> 0 "
               "(%lld.%09lld s, %s, Phase 2: all use same source)\n",
               clock_name, clock_desc, tp, kernel_tp.tv_sec, kernel_tp.tv_nsec,
               clock_characteristics);

    return 0;
}
