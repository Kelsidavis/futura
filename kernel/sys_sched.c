/* kernel/sys_sched.c - Scheduler-related syscalls
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements syscalls for scheduler control including sched_yield.
 */

#include <kernel/fut_task.h>
#include <kernel/fut_sched.h>
#include <kernel/errno.h>

extern void fut_printf(const char *fmt, ...);
extern fut_task_t *fut_task_current(void);

/**
 * sched_yield() - Yield the processor to other threads
 *
 * Causes the calling thread to relinquish the CPU. The thread is moved to the
 * end of the queue for its priority and a new thread gets to run. This is useful
 * in multithreaded applications to avoid busy-waiting and allow other threads
 * to make progress.
 *
 * Returns:
 *   - 0 on success (always succeeds)
 *
 * Use cases:
 *   - Cooperative multitasking: Thread voluntarily yields when waiting for a condition
 *   - Spinlock backoff: Reduce contention by yielding instead of spinning
 *   - Fair scheduling: Allow other threads at same priority to run
 *
 * Phase 1 (Current): Calls fut_schedule() to trigger reschedule
 * Phase 2: Implement priority-aware yield (only yield to equal/higher priority)
 * Phase 3: Track yield statistics for scheduler debugging
 */
long sys_sched_yield(void) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        /* Should never happen, but be defensive */
        return -ESRCH;
    }

    fut_printf("[SCHED] sched_yield() called by task %llu\n", task->pid);

    /* Trigger a reschedule, allowing other threads to run
     * The scheduler will select the next runnable thread */
    fut_schedule();

    /* Always return success after yielding */
    return 0;
}
