/* kernel/sys_alarm.c - Process alarm timer syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the alarm() syscall for scheduling SIGALRM delivery.
 *
 * Phase 1 (Completed): Basic stub
 * Phase 2 (Completed): Track alarm expiration time
 * Phase 3 (Completed): Integrate with timer interrupt to deliver SIGALRM
 * Phase 4 (Completed): Support sub-second precision with setitimer()
 */

#include <kernel/fut_task.h>
#include <kernel/signal.h>
#include <kernel/errno.h>

#include <kernel/kprintf.h>
#include <kernel/fut_timer.h>

/* SIGALRM provided by kernel/signal.h */

/**
 * alarm() - Set an alarm clock for delivery of a signal
 *
 * Arranges for a SIGALRM signal to be delivered to the calling process
 * after 'seconds' seconds. If seconds is 0, any pending alarm is canceled.
 * Only one alarm can be scheduled at a time; calling alarm() again replaces
 * the previous alarm.
 *
 * @param seconds Number of seconds until SIGALRM delivery (0 to cancel)
 *
 * Returns:
 *   - Number of seconds remaining from previous alarm, or 0 if no alarm was set
 *
 * Use cases:
 *   - Timeout mechanisms: Set alarm before blocking operation
 *   - Periodic tasks: Use alarm with signal handler to schedule recurring work
 *   - Watchdog timers: Detect hung processes or infinite loops
 *
 * Phase 2 (Completed): Tracks alarm expiration time (per-task storage)
 * Phase 3 (Completed): Integrate with timer interrupt to deliver SIGALRM at expiration
 * Phase 4 (Completed): Support sub-second precision with setitimer()
 */
long sys_alarm(unsigned int seconds) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* POSIX: alarm() accepts any unsigned int value. No overflow concern because
     * seconds * 100 fits in uint64_t for all uint32_t values (max ≈ 4.29 × 10^11). */

    /* Get current time in ticks (100 Hz = 10ms/tick) */
    uint64_t current_ticks = fut_get_ticks();

    /* Calculate remaining time from previous alarm (if any) */
    unsigned int remaining_seconds = 0;
    if (task->alarm_expires_ms > 0) {
        if (task->alarm_expires_ms > current_ticks) {
            uint64_t remaining_ticks = task->alarm_expires_ms - current_ticks;
            /* Convert ticks to seconds, round up (POSIX requirement) */
            remaining_seconds = (unsigned int)((remaining_ticks + 99) / 100);
        }
        /* If alarm already expired, remaining_seconds stays 0 */
    }

    if (seconds > 0) {
        /* Schedule new alarm: convert seconds to ticks (100 ticks/sec) */
        task->alarm_expires_ms = current_ticks + ((uint64_t)seconds * 100);

        /* Immediate delivery if alarm already expired (clock adjustment scenario) */
        if (task->alarm_expires_ms <= current_ticks) {
            fut_signal_send(task, SIGALRM);
        }
    } else {
        /* Cancel pending alarm for this task */
        if (task->alarm_expires_ms > 0) {
            task->alarm_expires_ms = 0;
        }
    }

    /* Return remaining seconds from previous alarm */
    return (long)remaining_seconds;
}
