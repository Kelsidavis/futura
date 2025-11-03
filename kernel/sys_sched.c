/* kernel/sys_sched.c - Scheduler-related syscalls
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements syscalls for scheduler control including sched_yield,
 * getpriority, and setpriority.
 */

#include <kernel/fut_task.h>
#include <kernel/fut_sched.h>
#include <kernel/errno.h>

extern void fut_printf(const char *fmt, ...);
extern fut_task_t *fut_task_current(void);

/* Priority (nice value) constants */
#define PRIO_PROCESS 0  /* Priority applies to process */
#define PRIO_PGRP    1  /* Priority applies to process group */
#define PRIO_USER    2  /* Priority applies to user */

/* Nice value range: -20 (highest priority) to +19 (lowest priority)
 * Default is 0 (normal priority) */
#define PRIO_MIN     -20
#define PRIO_MAX     19
#define PRIO_DEFAULT 0

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

/**
 * getpriority() - Get scheduling priority (nice value)
 *
 * Returns the highest priority (lowest nice value) of any process in the
 * specified group. The 'which' parameter determines if 'who' is interpreted
 * as a process ID, process group ID, or user ID.
 *
 * @param which Type of ID: PRIO_PROCESS, PRIO_PGRP, or PRIO_USER
 * @param who   ID to query (0 = calling process/group/user)
 *
 * Returns:
 *   - Nice value (20 to -19) on success
 *   - -EINVAL if which is invalid
 *   - -ESRCH if no process matches who
 *
 * Note: The return value is 20 - nice_value to avoid confusion with errors,
 *       since nice values can be negative. Use errno to distinguish errors.
 *
 * Phase 1 (Current): Returns default priority (0) for calling process
 * Phase 2: Store per-task nice value and return actual priority
 * Phase 3: Support PRIO_PGRP and PRIO_USER with process/user lookups
 */
long sys_getpriority(int which, int who) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Validate 'which' parameter */
    if (which < PRIO_PROCESS || which > PRIO_USER) {
        fut_printf("[SCHED] getpriority: invalid which=%d\n", which);
        return -EINVAL;
    }

    /* Phase 1: Only support PRIO_PROCESS for calling process */
    if (which == PRIO_PROCESS) {
        if (who != 0 && who != (int)task->pid) {
            /* Querying other process - not yet supported */
            fut_printf("[SCHED] getpriority: querying pid=%d not supported (Phase 2)\n", who);
            return -ESRCH;
        }

        /* Return default priority (0 = normal)
         * Phase 2 will return task->nice from task structure */
        int nice_value = PRIO_DEFAULT;

        fut_printf("[SCHED] getpriority(PRIO_PROCESS, %d) -> nice=%d\n", who, nice_value);

        /* Return 20 - nice_value to avoid confusion with negative nice values
         * This means: return value of 20 = nice -20 (highest priority)
         *            return value of 0  = nice 20  (lowest priority) */
        return 20 - nice_value;
    } else {
        /* PRIO_PGRP and PRIO_USER not yet implemented */
        fut_printf("[SCHED] getpriority: which=%d not yet supported (Phase 3)\n", which);
        return -EINVAL;
    }
}

/**
 * setpriority() - Set scheduling priority (nice value)
 *
 * Sets the nice value for processes specified by which and who.
 * Only privileged processes can decrease nice value (increase priority).
 *
 * @param which Type of ID: PRIO_PROCESS, PRIO_PGRP, or PRIO_USER
 * @param who   ID to modify (0 = calling process/group/user)
 * @param prio  Nice value to set (-20 to 19)
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL if which is invalid or prio out of range
 *   - -ESRCH if no process matches who
 *   - -EACCES if trying to decrease nice without privilege
 *   - -EPERM if trying to modify other user's processes
 *
 * Phase 1 (Current): Validates parameters but doesn't store value
 * Phase 2: Store nice value in task structure and apply to scheduler
 * Phase 3: Implement privilege checking and PRIO_PGRP/PRIO_USER support
 */
long sys_setpriority(int which, int who, int prio) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Validate 'which' parameter */
    if (which < PRIO_PROCESS || which > PRIO_USER) {
        fut_printf("[SCHED] setpriority: invalid which=%d\n", which);
        return -EINVAL;
    }

    /* Validate priority range */
    if (prio < PRIO_MIN || prio > PRIO_MAX) {
        fut_printf("[SCHED] setpriority: priority %d out of range [%d, %d]\n",
                   prio, PRIO_MIN, PRIO_MAX);
        return -EINVAL;
    }

    /* Phase 1: Only support PRIO_PROCESS for calling process */
    if (which == PRIO_PROCESS) {
        if (who != 0 && who != (int)task->pid) {
            /* Modifying other process - not yet supported */
            fut_printf("[SCHED] setpriority: modifying pid=%d not supported (Phase 2)\n", who);
            return -ESRCH;
        }

        /* Phase 1: Just validate and log, don't actually store
         * Phase 2 will store: task->nice = prio and update scheduler */

        fut_printf("[SCHED] setpriority(PRIO_PROCESS, %d, nice=%d) -> success (stub)\n",
                   who, prio);

        return 0;
    } else {
        /* PRIO_PGRP and PRIO_USER not yet implemented */
        fut_printf("[SCHED] setpriority: which=%d not yet supported (Phase 3)\n", which);
        return -EINVAL;
    }
}
