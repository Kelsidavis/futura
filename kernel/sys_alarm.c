/* kernel/sys_alarm.c - Process alarm timer syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the alarm() syscall for scheduling SIGALRM delivery.
 */

#include <kernel/fut_task.h>
#include <kernel/signal.h>
#include <kernel/errno.h>

extern void fut_printf(const char *fmt, ...);
extern fut_task_t *fut_task_current(void);
extern uint64_t fut_get_ticks(void);

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
 * Phase 1 (Current): Records alarm time but doesn't deliver signal yet
 * Phase 2: Integrate with timer interrupt to deliver SIGALRM at expiration
 * Phase 3: Support sub-second precision with setitimer()
 */
long sys_alarm(unsigned int seconds) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Phase 1: No alarm tracking in task structure yet
     * Phase 2 will add: uint64_t alarm_expires to fut_task_t */

    if (seconds > 0) {
        /* Schedule new alarm */
        fut_printf("[ALARM] alarm(%u) requested by task %llu (stub - Phase 2 will deliver SIGALRM)\n",
                   seconds, task->pid);

        /* Phase 2: Will calculate expiration time and store in task->alarm_expires
         * Phase 2: Timer interrupt will check alarm_expires and deliver SIGALRM */
    } else {
        /* Cancel pending alarm */
        fut_printf("[ALARM] alarm(0) - cancel alarm for task %llu (stub)\n", task->pid);
    }

    /* Return 0 since we don't track previous alarms yet
     * Phase 2: Will return remaining seconds from previous alarm */
    return 0;
}
