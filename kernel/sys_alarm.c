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
 * Phase 4 (Current): Support sub-second precision with setitimer()
 */

#include <kernel/fut_task.h>
#include <kernel/signal.h>
#include <kernel/errno.h>

extern void fut_printf(const char *fmt, ...);
extern fut_task_t *fut_task_current(void);
extern uint64_t fut_get_ticks(void);
extern int fut_signal_deliver(fut_task_t *task, int sig);

/* SIGALRM signal number */
#define SIGALRM 14


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
 * Phase 4 (Current): Support sub-second precision with setitimer()
 */
long sys_alarm(unsigned int seconds) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Get current time in milliseconds */
    uint64_t current_ms = fut_get_ticks();

    /* Calculate remaining time from previous alarm (if any) */
    unsigned int remaining_seconds = 0;
    if (task->alarm_expires_ms > 0) {
        /* Alarm is for this task, calculate remaining time */
        if (task->alarm_expires_ms > current_ms) {
            uint64_t remaining_ms = task->alarm_expires_ms - current_ms;
            /* Round up to nearest second (POSIX requirement) */
            remaining_seconds = (unsigned int)((remaining_ms + 999) / 1000);
        }
        /* If alarm already expired, remaining_seconds stays 0 */
    }

    if (seconds > 0) {
        /* Schedule new alarm */
        task->alarm_expires_ms = current_ms + ((uint64_t)seconds * 1000);

        /* Phase 3: Categorize alarm duration for logging */
        const char *duration_category;
        if (seconds < 1) {
            duration_category = "sub-second";
        } else if (seconds <= 10) {
            duration_category = "short (≤10s)";
        } else if (seconds <= 60) {
            duration_category = "medium (≤60s)";
        } else if (seconds <= 3600) {
            duration_category = "long (≤1h)";
        } else {
            duration_category = "very long (>1h)";
        }

        fut_printf("[ALARM] alarm(%u [%s]) set by task %llu, expires at %llu ms (previous remaining: %u s)\n",
                   seconds, duration_category, task->pid, task->alarm_expires_ms, remaining_seconds);

        /* Phase 3: Attempt immediate SIGALRM delivery if condition met
         * Check if alarm has already expired (clock adjustment scenario) */
        if (task->alarm_expires_ms <= current_ms) {
            fut_signal_deliver(task, SIGALRM);
            fut_printf("[ALARM] Signal delivery: SIGALRM delivered immediately (alarm expired during setup)\n");
        }
    } else {
        /* Cancel pending alarm for this task */
        if (task->alarm_expires_ms > 0) {
            /* Phase 3: Calculate and categorize previously scheduled duration */
            uint64_t prev_duration_ms = task->alarm_expires_ms - current_ms;
            unsigned int prev_duration_s = (unsigned int)((prev_duration_ms + 999) / 1000);
            const char *prev_category = (prev_duration_s > 3600) ? "very long" :
                                       (prev_duration_s > 60) ? "long" :
                                       (prev_duration_s > 10) ? "medium" : "short";

            fut_printf("[ALARM] alarm(0) - canceled %s alarm for task %llu (was %u s remaining)\n",
                       prev_category, task->pid, remaining_seconds);
            task->alarm_expires_ms = 0;
        } else {
            fut_printf("[ALARM] alarm(0) - no alarm to cancel for task %llu\n", task->pid);
        }
    }

    /* Return remaining seconds from previous alarm */
    return (long)remaining_seconds;
}
