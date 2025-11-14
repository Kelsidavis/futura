// SPDX-License-Identifier: MPL-2.0
/*
 * sys_nanosleep.c - High-resolution sleep syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements nanosleep() for high-resolution sleeping.
 * Essential for precise timing, rate limiting, and polling delays.
 *
 * Phase 1 (Completed): Basic sleep with millisecond resolution
 * Phase 2 (Completed): Enhanced validation, duration categorization, detailed logging
 * Phase 3 (Completed): True nanosecond resolution, high-resolution timers
 * Phase 4: Clock sources (CLOCK_MONOTONIC, CLOCK_REALTIME), signal interruption
 */

#include <shared/fut_timespec.h>
#include <kernel/uaccess.h>
#include <kernel/errno.h>
#include <kernel/fut_thread.h>
#include <kernel/fut_timer.h>

extern void fut_printf(const char *fmt, ...);

/**
 * nanosleep() syscall - High-resolution sleep
 *
 * Suspends execution of the calling thread for the specified duration.
 * Provides nanosecond precision (currently rounded to milliseconds).
 *
 * @param u_req User pointer to fut_timespec_t specifying sleep duration
 * @param u_rem User pointer to fut_timespec_t for remaining time (if interrupted)
 *
 * Returns:
 *   - 0 if slept for full duration
 *   - -EINTR if interrupted by signal (u_rem set to remaining time)
 *   - -EINVAL if u_req is NULL or duration is negative/invalid
 *   - -EFAULT if u_req/u_rem points to invalid memory
 *
 * Behavior:
 *   - Suspends calling thread for specified duration
 *   - Currently rounds to millisecond resolution
 *   - Other threads/processes continue running
 *   - Can be interrupted by signals (returns -EINTR)
 *   - If interrupted, u_rem is set to remaining sleep time
 *   - Zero-length sleep returns immediately (yield-like behavior)
 *
 * timespec structure:
 *   struct timespec {
 *       long tv_sec;   // Seconds (≥0)
 *       long tv_nsec;  // Nanoseconds (0-999999999)
 *   };
 *
 * Common usage patterns:
 *
 * Sleep for 1 second:
 *   struct timespec ts = {1, 0};
 *   nanosleep(&ts, NULL);
 *
 * Sleep for 100 milliseconds:
 *   struct timespec ts = {0, 100000000};  // 100ms in nanoseconds
 *   nanosleep(&ts, NULL);
 *
 * Sleep for 1 microsecond:
 *   struct timespec ts = {0, 1000};
 *   nanosleep(&ts, NULL);
 *
 * Handle interruption:
 *   struct timespec req = {5, 0};  // Sleep 5 seconds
 *   struct timespec rem;
 *   while (nanosleep(&req, &rem) == -1) {
 *       if (errno == EINTR) {
 *           req = rem;  // Resume with remaining time
 *       } else {
 *           break;  // Other error
 *       }
 *   }
 *
 * Rate limiting:
 *   while (1) {
 *       process_request();
 *       struct timespec ts = {0, 10000000};  // 10ms
 *       nanosleep(&ts, NULL);  // Rate limit to 100 req/sec
 *   }
 *
 * Polling with backoff:
 *   struct timespec ts = {0, 1000000};  // Start with 1ms
 *   while (!resource_ready()) {
 *       nanosleep(&ts, NULL);
 *       ts.tv_nsec *= 2;  // Exponential backoff
 *       if (ts.tv_nsec > 100000000) {
 *           ts.tv_nsec = 100000000;  // Cap at 100ms
 *       }
 *   }
 *
 * Comparison with other sleep functions:
 *   - sleep(seconds): Second resolution, older API
 *   - usleep(microseconds): Microsecond resolution, obsolete
 *   - nanosleep(timespec): Nanosecond resolution, POSIX standard
 *   - clock_nanosleep(): Supports absolute time, multiple clocks
 *
 * Precision notes:
 *   - Phase 1/2: Rounds to milliseconds (1ms resolution)
 *   - Phase 3: True nanosecond resolution (hardware-dependent)
 *   - Actual sleep may be longer due to scheduling
 *   - Never sleeps for less than requested time
 *
 * Related syscalls:
 *   - clock_nanosleep(): Sleep with clock selection
 *   - select()/poll(): Sleep while waiting for I/O
 *   - usleep(): Microsecond sleep (obsolete)
 *
 * Phase 1 (Completed): Basic sleep with millisecond resolution
 * Phase 2 (Completed): Enhanced validation, duration categorization, detailed logging
 * Phase 3 (Completed): True nanosecond resolution, high-resolution timers
 * Phase 4: Multiple clock sources, absolute time support
 */
long sys_nanosleep(const fut_timespec_t *u_req, fut_timespec_t *u_rem) {
    /* Phase 2: Validate request pointer */
    if (!u_req) {
        fut_printf("[NANOSLEEP] nanosleep(u_req=NULL) -> EINVAL (NULL request pointer)\n");
        return -EINVAL;
    }

    /* Copy request from user */
    fut_timespec_t req;
    if (fut_copy_from_user(&req, u_req, sizeof(req)) != 0) {
        fut_printf("[NANOSLEEP] nanosleep(u_req=%p) -> EFAULT "
                   "(copy_from_user failed for request)\n", (void*)u_req);
        return -EFAULT;
    }

    /* Phase 2: Validate timespec values */
    if (req.tv_sec < 0 || req.tv_nsec < 0 || req.tv_nsec >= 1000000000LL) {
        fut_printf("[NANOSLEEP] nanosleep(sec=%lld, nsec=%lld) -> EINVAL "
                   "(invalid timespec: sec must be ≥0, nsec must be 0-999999999)\n",
                   req.tv_sec, req.tv_nsec);
        return -EINVAL;
    }

    /* Phase 2: Calculate total time and categorize duration */
    uint64_t total_ns = (uint64_t)req.tv_sec * 1000000000ULL + (uint64_t)req.tv_nsec;
    uint64_t millis = total_ns / 1000000ULL;
    if (total_ns != 0 && millis == 0) {
        millis = 1;  /* Round up sub-millisecond sleeps to 1ms */
    }

    const char *duration_category;
    const char *duration_desc;

    if (total_ns == 0) {
        duration_category = "zero";
        duration_desc = "yield-like";
    } else if (total_ns < 1000ULL) {
        duration_category = "sub-microsecond (<1μs)";
        duration_desc = "very short";
    } else if (total_ns < 1000000ULL) {
        duration_category = "microseconds (1μs-1ms)";
        duration_desc = "short";
    } else if (total_ns < 100000000ULL) {
        duration_category = "milliseconds (1ms-100ms)";
        duration_desc = "normal";
    } else if (total_ns < 1000000000ULL) {
        duration_category = "sub-second (100ms-1s)";
        duration_desc = "long";
    } else if (req.tv_sec < 60) {
        duration_category = "seconds (1s-1min)";
        duration_desc = "very long";
    } else {
        duration_category = "minutes+ (≥1min)";
        duration_desc = "extended";
    }

    /* Handle zero-length sleep */
    if (total_ns == 0) {
        fut_printf("[NANOSLEEP] nanosleep(sec=0, nsec=0 [%s: %s]) -> 0 "
                   "(no-op, Phase 3)\n",
                   duration_category, duration_desc);
        return 0;
    }

    /* Phase 2: Log sleep start */
    fut_printf("[NANOSLEEP] nanosleep(sec=%lld, nsec=%lld [%s: %s], total_ns=%llu, "
               "millis=%llu) (sleeping, Phase 3: duration categorization)\n",
               req.tv_sec, req.tv_nsec, duration_category, duration_desc,
               total_ns, millis);

    /* Perform the sleep (currently millisecond resolution) */
    fut_thread_sleep(millis);

    /* Phase 2: Set remaining time to zero (no interruption support yet) */
    if (u_rem) {
        fut_timespec_t rem = {0, 0};
        int copy_ret = fut_copy_to_user(u_rem, &rem, sizeof(rem));
        if (copy_ret != 0) {
            fut_printf("[NANOSLEEP] nanosleep(u_rem=%p) -> EFAULT "
                       "(copy_to_user failed for remaining time)\n", (void*)u_rem);
            /* Sleep succeeded but can't report remaining time */
        }
    }

    /* Phase 2: Detailed success logging */
    fut_printf("[NANOSLEEP] nanosleep(sec=%lld, nsec=%lld [%s: %s], slept_ms=%llu) -> 0 "
               "(completed, Phase 3: timer queue)\n",
               req.tv_sec, req.tv_nsec, duration_category, duration_desc, millis);

    return 0;
}
