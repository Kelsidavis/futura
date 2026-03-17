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

/* NTP sub-second adjustment accumulator (microseconds, -999999..+999999).
 * Applied additively to CLOCK_REALTIME nanoseconds. Updated by adjtimex(). */
volatile int64_t g_ntp_adj_usec = 0;

/* NTP frequency correction (ppm * FREQ_SCALE=65536, same encoding as Linux
 * struct timex::freq). Updated by adjtimex() ADJ_FREQUENCY. */
volatile int32_t g_ntp_freq_ppm = 0;

/* NTP clock status (TIME_OK=0, TIME_ERROR=5, etc.). Updated by adjtimex(). */
volatile int32_t g_ntp_status = 0;

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

    /* Get current time: convert ticks (100 Hz) to seconds, add realtime offset */
    uint64_t ticks = fut_get_ticks();
    int64_t seconds = (int64_t)(ticks / 100) + g_realtime_offset_sec;

    /* If tloc is provided, store the result there */
    if (tloc != NULL) {
        if (time_copy_to_user(tloc, &seconds, sizeof(int64_t)) != 0) {
            return -EFAULT;
        }
    }

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

    /* Get current time: convert ticks (100 Hz) to real time.
     * Each tick = 10ms = 10,000,000 ns. */
    uint64_t ticks = fut_get_ticks();
    uint64_t total_ns = ticks * 10000000ULL;

    /* Convert to timeval (seconds + microseconds), add realtime offset */
    fut_timeval_t kernel_tv;
    kernel_tv.tv_sec  = (int64_t)(total_ns / 1000000000ULL) + g_realtime_offset_sec;
    kernel_tv.tv_usec = (int64_t)((total_ns % 1000000000ULL) / 1000);

    /* Copy to userspace (or kernel buffer for internal callers) */
    if (time_copy_to_user(tv, &kernel_tv, sizeof(fut_timeval_t)) != 0) {
        return -EFAULT;
    }

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
 * Phase 3 (Completed): Monotonic/boot clocks use fut_get_ticks() independent of NTP offset; fix per-task thread iteration
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
    /* Skip access_ok for kernel-originated calls (selftests use kernel stack pointers) */
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)tp < KERNEL_VIRTUAL_BASE)
#endif
    if (fut_access_ok(tp, sizeof(fut_timespec_t), 1) != 0) {
        return -EFAULT;
    }

    /* Validate clock_id */
    switch (clock_id) {
        case CLOCK_REALTIME:
        case CLOCK_MONOTONIC:
        case CLOCK_BOOTTIME:
        case CLOCK_REALTIME_COARSE:
        case CLOCK_MONOTONIC_COARSE:
        case CLOCK_MONOTONIC_RAW:
        case CLOCK_PROCESS_CPUTIME_ID:
        case CLOCK_THREAD_CPUTIME_ID:
            break;
        default:
            return -EINVAL;
    }

    fut_timespec_t kernel_tp;

    if (clock_id == CLOCK_PROCESS_CPUTIME_ID) {
        /* Sum cpu_ticks across all task threads; each tick = 1000000000/FUT_TIMER_HZ ns */
        fut_task_t *task = fut_task_current();
        uint64_t total_ticks = 0;
        if (task) {
            for (fut_thread_t *t = task->threads; t != nullptr; t = t->next)
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
        /* All wall/monotonic/boottime clocks: use tick-based time (10ms granularity).
         * TSC-based fut_get_time_ns() has calibration issues in QEMU, so we use
         * the reliable tick counter for all clocks. Each tick = 10,000,000 ns. */
        uint64_t ticks = fut_get_ticks();
        uint64_t total_ns = ticks * 10000000ULL;
        kernel_tp.tv_sec  = (int64_t)(total_ns / 1000000000ULL);
        kernel_tp.tv_nsec = (int64_t)(total_ns % 1000000000ULL);

        /* CLOCK_REALTIME and CLOCK_REALTIME_COARSE add the wall clock offset */
        if (clock_id == CLOCK_REALTIME || clock_id == CLOCK_REALTIME_COARSE) {
            kernel_tp.tv_sec += g_realtime_offset_sec;
            /* Apply sub-second NTP offset from adjtimex() ADJ_OFFSET */
            int64_t adj_nsec = g_ntp_adj_usec * 1000LL;
            kernel_tp.tv_nsec += adj_nsec;
            if (kernel_tp.tv_nsec >= 1000000000LL) {
                kernel_tp.tv_sec++;
                kernel_tp.tv_nsec -= 1000000000LL;
            } else if (kernel_tp.tv_nsec < 0) {
                kernel_tp.tv_sec--;
                kernel_tp.tv_nsec += 1000000000LL;
            }
        }
    }

    /* Copy to userspace (or kernel buffer for internal callers) */
    if (time_copy_to_user(tp, &kernel_tp, sizeof(fut_timespec_t)) != 0) {
        return -EFAULT;
    }

    return 0;
}
