/* kernel/sys_time.c - Time and clock syscall implementations
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements time(), gettimeofday(), clock_gettime(), and clock_getres().
 */

#include <kernel/fut_timer.h>
#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
#include <kernel/fut_stats.h>
#include <kernel/errno.h>
#include <shared/fut_timeval.h>
#include <shared/fut_timespec.h>
#include <stdint.h>

#include <kernel/kprintf.h>
#include <kernel/uaccess.h>
#include <time.h>
#ifdef __x86_64__
#include <platform/x86_64/memory/paging.h>
#elif defined(__aarch64__)
#include <platform/arm64/memory/paging.h>
#endif

/* CLOCK_* constants provided by time.h */

/*
 * Wall clock offset: seconds to add to uptime to get CLOCK_REALTIME.
 * Initialized to 0 (January 1, 1970 at boot). Updated by sys_clock_settime
 * and sys_settimeofday to provide real calendar time.
 */
volatile int64_t g_realtime_offset_sec = 0;

/* Kernel-pointer-safe copy helpers */
static inline int time_copy_to_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)dst >= KERNEL_VIRTUAL_BASE) {
        __builtin_memcpy(dst, src, n);
        return 0;
    }
#endif
    return fut_copy_to_user(dst, src, n);
}

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
    /* Validate tloc write permission early (kernel writes time value)
     * VULNERABILITY: Invalid Output Buffer Pointer
     * ATTACK: Attacker provides read-only or unmapped tloc buffer
     * IMPACT: Kernel page fault when writing time value
     * DEFENSE: Check write permission before processing */
    if (tloc && fut_access_ok(tloc, sizeof(uint64_t), 1) != 0) {
        fut_printf("[TIME] time(tloc=%p) -> EFAULT (tloc not writable for %zu bytes)\n",
                   tloc, sizeof(uint64_t));
        return -EFAULT;
    }

    /* Get current time in milliseconds, add realtime offset */
    uint64_t ms = fut_get_ticks();
    int64_t seconds = (int64_t)(ms / 1000) + g_realtime_offset_sec;

    /* If tloc is provided, store the result there */
    if (tloc != NULL) {
        if (time_copy_to_user(tloc, &seconds, sizeof(int64_t)) != 0) {
            return -EFAULT;
        }
    }

    fut_printf("[TIME] time() -> %lld seconds\n", (long long)seconds);

    return (long)seconds;
}

long sys_gettimeofday(fut_timeval_t *tv, void *tz) {
    if (!tv) {
        return -EFAULT;
    }

    /* Validate tv write permission early (kernel writes timeval)
     * VULNERABILITY: Invalid Output Buffer Pointer
     * ATTACK: Attacker provides read-only or unmapped tv buffer
     * IMPACT: Kernel page fault when writing timeval structure
     * DEFENSE: Check write permission before processing */
    if (fut_access_ok(tv, sizeof(fut_timeval_t), 1) != 0) {
        fut_printf("[TIME] gettimeofday(tv=%p) -> EFAULT (tv not writable for %zu bytes)\n",
                   tv, sizeof(fut_timeval_t));
        return -EFAULT;
    }

    if (tz != NULL) {
        fut_printf("[TIME] gettimeofday: timezone parameter not supported\n");
        return -EINVAL;
    }

    /* Get current time in milliseconds */
    uint64_t ms = fut_get_ticks();

    /* Convert to timeval (seconds + microseconds), add realtime offset */
    fut_timeval_t kernel_tv;
    kernel_tv.tv_sec  = (int64_t)(ms / 1000) + g_realtime_offset_sec;
    kernel_tv.tv_usec = (int64_t)((ms % 1000) * 1000);

    /* Copy to userspace (or kernel buffer for internal callers) */
    if (time_copy_to_user(tv, &kernel_tv, sizeof(fut_timeval_t)) != 0) {
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
 * Phase 2 (Completed): Enhanced validation and clock type identification
 * Phase 3: Separate monotonic clock implementation with NTP-independent tracking
 * Phase 4: Add PROCESS_CPUTIME_ID and THREAD_CPUTIME_ID for CPU time tracking
 */
long sys_clock_gettime(int clock_id, fut_timespec_t *tp) {
    if (!tp) {
        fut_printf("[TIME] clock_gettime(clock_id=%d, tp=%p) -> EFAULT (tp is NULL)\n",
                   clock_id, tp);
        return -EFAULT;
    }

    /* Validate tp write permission early (kernel writes timespec)
     * VULNERABILITY: Invalid Output Buffer Pointer
     * ATTACK: Attacker provides read-only or unmapped tp buffer
     * IMPACT: Kernel page fault when writing timespec structure
     * DEFENSE: Check write permission before processing */
    if (fut_access_ok(tp, sizeof(fut_timespec_t), 1) != 0) {
        fut_printf("[TIME] clock_gettime(clock_id=%d, tp=%p) -> EFAULT (tp not writable for %zu bytes)\n",
                   clock_id, tp, sizeof(fut_timespec_t));
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
            break;

        case CLOCK_THREAD_CPUTIME_ID:
            clock_name = "CLOCK_THREAD_CPUTIME_ID";
            clock_desc = "per-thread CPU time clock";
            clock_characteristics = "measures CPU time consumed by thread";
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

    fut_timespec_t kernel_tp;

    if (clock_id == CLOCK_PROCESS_CPUTIME_ID) {
        /* Sum cpu_ticks across all task threads; each tick = 1000000000/FUT_TIMER_HZ ns */
        fut_task_t *task = fut_task_current();
        uint64_t total_ticks = 0;
        if (task) {
            for (fut_thread_t *t = task->threads; t != nullptr; t = t->global_next)
                total_ticks += t->stats.cpu_ticks;
        }
        uint64_t ns_total = total_ticks * (1000000000UL / FUT_TIMER_HZ);
        kernel_tp.tv_sec  = (int64_t)(ns_total / 1000000000UL);
        kernel_tp.tv_nsec = (int64_t)(ns_total % 1000000000UL);
    } else if (clock_id == CLOCK_THREAD_CPUTIME_ID) {
        fut_thread_t *thread = fut_thread_current();
        uint64_t ticks = thread ? thread->stats.cpu_ticks : 0;
        uint64_t ns_total = ticks * (1000000000UL / FUT_TIMER_HZ);
        kernel_tp.tv_sec  = (int64_t)(ns_total / 1000000000UL);
        kernel_tp.tv_nsec = (int64_t)(ns_total % 1000000000UL);
    } else {
        /* All wall / monotonic clocks: get time in milliseconds from timer */
        uint64_t ms = fut_get_ticks();
        kernel_tp.tv_sec  = (int64_t)(ms / 1000);
        kernel_tp.tv_nsec = (int64_t)((ms % 1000) * 1000000);

        /* CLOCK_REALTIME and CLOCK_REALTIME_COARSE add the wall clock offset */
        if (clock_id == CLOCK_REALTIME || clock_id == CLOCK_REALTIME_COARSE) {
            kernel_tp.tv_sec += g_realtime_offset_sec;
        }
    }

    /* Copy to userspace (or kernel buffer for internal callers) */
    if (time_copy_to_user(tp, &kernel_tp, sizeof(fut_timespec_t)) != 0) {
        fut_printf("[TIME] clock_gettime(clock_id=%s [%s], tp=%p) -> EFAULT (copy_to_user failed)\n",
                   clock_name, clock_desc, tp);
        return -EFAULT;
    }

    fut_printf("[TIME] clock_gettime(clock_id=%s, tp=%p) -> 0 (%lld.%09lld s)\n",
               clock_name, tp, kernel_tp.tv_sec, kernel_tp.tv_nsec);

    return 0;
}
