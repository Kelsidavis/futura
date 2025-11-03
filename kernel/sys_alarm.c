/* kernel/sys_alarm.c - Process alarm timer syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the alarm() syscall for scheduling SIGALRM delivery.
 *
 * Phase 1 (Completed): Basic stub
 * Phase 2 (Current): Track alarm expiration time
 * Phase 3: Integrate with timer interrupt to deliver SIGALRM
 * Phase 4: Support sub-second precision with setitimer()
 */

#include <kernel/fut_task.h>
#include <kernel/signal.h>
#include <kernel/errno.h>

extern void fut_printf(const char *fmt, ...);
extern fut_task_t *fut_task_current(void);
extern uint64_t fut_get_ticks(void);

/* Alarm tracking (simplified single-alarm model)
 * TODO: When per-task alarm fields are added to fut_task_t, move this to
 * per-task storage for proper multi-process alarm isolation.
 * For now, we track a single global alarm similar to umask approach.
 */
static uint64_t global_alarm_expires_ms = 0;  /* Alarm expiration time in milliseconds (0 = no alarm) */
static uint64_t global_alarm_pid = 0;         /* PID that owns the alarm */

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
 * Phase 2 (Current): Tracks alarm expiration time (single global alarm)
 * Phase 3: Integrate with timer interrupt to deliver SIGALRM at expiration
 * Phase 4: Support sub-second precision with setitimer()
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
    if (global_alarm_expires_ms > 0) {
        /* Check if alarm belongs to current task */
        if (global_alarm_pid == task->pid) {
            /* Alarm is for this task, calculate remaining time */
            if (global_alarm_expires_ms > current_ms) {
                uint64_t remaining_ms = global_alarm_expires_ms - current_ms;
                /* Round up to nearest second (POSIX requirement) */
                remaining_seconds = (unsigned int)((remaining_ms + 999) / 1000);
            }
            /* If alarm already expired, remaining_seconds stays 0 */
        }
        /* If alarm belongs to different task, we don't return its remaining time */
    }

    if (seconds > 0) {
        /* Schedule new alarm */
        global_alarm_expires_ms = current_ms + ((uint64_t)seconds * 1000);
        global_alarm_pid = task->pid;

        fut_printf("[ALARM] alarm(%u) set by task %llu, expires at %llu ms (previous remaining: %u s)\n",
                   seconds, task->pid, global_alarm_expires_ms, remaining_seconds);

        /* Phase 3: Timer interrupt will check global_alarm_expires_ms and deliver SIGALRM
         * For now, alarm is tracked but SIGALRM delivery not implemented */
    } else {
        /* Cancel pending alarm for this task */
        if (global_alarm_pid == task->pid) {
            global_alarm_expires_ms = 0;
            global_alarm_pid = 0;
            fut_printf("[ALARM] alarm(0) - canceled alarm for task %llu (previous remaining: %u s)\n",
                       task->pid, remaining_seconds);
        } else {
            fut_printf("[ALARM] alarm(0) - no alarm to cancel for task %llu\n", task->pid);
        }
    }

    /* Return remaining seconds from previous alarm */
    return (long)remaining_seconds;
}
