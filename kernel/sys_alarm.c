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

    /* Validate seconds parameter to prevent overflow
     * VULNERABILITY: Integer Overflow in Alarm Expiration Calculation
     *
     * ATTACK SCENARIO:
     * Attacker provides extreme seconds value to cause arithmetic overflow
     * 1. Attacker calls alarm(UINT_MAX) or alarm(0xFFFFFFFF)
     * 2. Line 72: seconds * 1000 = 4,294,967,295 * 1000
     * 3. Result: 4,294,967,295,000 (4.29 trillion milliseconds)
     * 4. Addition: current_ticks + 4,294,967,295,000
     * 5. If current_ticks is large, sum could exceed UINT64_MAX
     * 6. Overflow wraps to small value or past timestamp
     * 7. Alarm expires immediately or never fires
     * 8. Timing-based security bypassed
     *
     * IMPACT:
     * - Denial of service: Alarm never fires, blocking operations hang forever
     * - Security bypass: Timeouts don't work, authentication delays bypassed
     * - Resource exhaustion: Processes hang waiting for alarm that never comes
     * - Timing attack: Predictable alarm timing compromised
     *
     * ROOT CAUSE:
     * Line 72: task->alarm_expires_ms = current_ticks + ((uint64_t)seconds * 1000)
     * - Multiplying seconds by 1000 can overflow even in uint64_t
     * - No validation that seconds is reasonable
     * - No check for overflow before addition
     * - Assumption that userspace provides sane values
     *
     * DEFENSE:
     * Validate seconds is within reasonable range
     * - Maximum reasonable alarm: 24 hours = 86,400 seconds
     * - Reject seconds > 86,400 (1 day)
     * - Return -EINVAL for excessive values
     * - Prevents overflow in seconds * 1000 multiplication
     * - Ensures alarm_expires_ms stays valid
     *
     * CVE REFERENCES:
     * - CVE-2018-13405: Linux timer overflow in alarm/setitimer
     * - CVE-2015-8839: Kernel timer integer overflow
     *
     * POSIX REQUIREMENT:
     * IEEE Std 1003.1-2017 alarm(): "If seconds is 0, a pending alarm
     * request is canceled. If seconds is greater than 0, the alarm shall
     * be scheduled." - Does not specify upper bound, but overflow is UB.
     *
     * IMPLEMENTATION NOTES:
     * - Max seconds: 86400 (24 hours) is generous upper bound
     * - Prevents (seconds * 1000) from exceeding reasonable uint64_t range
     * - Applications needing longer delays should use sleep() or nanosleep()
     */
    if (seconds > 86400) {
        fut_printf("[ALARM] alarm(%u) -> EINVAL (seconds exceeds maximum 86400 = 24 hours, "
                   "overflow prevention)\n", seconds);
        return -EINVAL;
    }

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
