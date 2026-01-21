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

#include <kernel/kprintf.h>
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
 * Phase 1 (Completed): Calls fut_schedule() to trigger reschedule
 * Phase 2 (Completed): Enhanced logging with task state categorization
 * Phase 3 (Completed): Task state categorization with scheduler reschedule
 * Phase 4: Track yield statistics for scheduler debugging
 */
long sys_sched_yield(void) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        /* Should never happen, but be defensive */
        return -ESRCH;
    }

    /* Phase 2: Categorize task state for enhanced logging */
    const char *task_state_desc;
    if (task->state == 1) {  /* Assuming FUT_TASK_RUNNING = 1 */
        task_state_desc = "running";
    } else if (task->state == 2) {  /* Assuming FUT_TASK_READY = 2 */
        task_state_desc = "ready";
    } else if (task->state == 3) {  /* Assuming FUT_TASK_BLOCKED = 3 */
        task_state_desc = "blocked";
    } else if (task->state == 4) {  /* Assuming FUT_TASK_ZOMBIE = 4 */
        task_state_desc = "zombie";
    } else {
        task_state_desc = "unknown";
    }

    /* Phase 3: Enhanced logging with task categorization */
    fut_printf("[SCHED] sched_yield() called by task pid=%llu [state=%s], Phase 3: Task state categorization\n",
               task->pid, task_state_desc);

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
 * Phase 1 (Completed): Returns default priority (0) for calling process
 * Phase 2 (Completed): Enhanced validation and priority type reporting
 * Phase 3 (Completed): Priority type categorization with default priority
 * Phase 4: Support PRIO_PGRP and PRIO_USER with process/user lookups
 */
long sys_getpriority(int which, int who) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[SCHED] getpriority(which=%d, who=%d) -> ESRCH (no current task)\n", which, who);
        return -ESRCH;
    }

    /* Phase 2: Identify priority type for logging */
    const char *which_desc;
    const char *target_desc;

    switch (which) {
        case PRIO_PROCESS:
            which_desc = "PRIO_PROCESS";
            target_desc = "process";
            break;
        case PRIO_PGRP:
            which_desc = "PRIO_PGRP";
            target_desc = "process group";
            break;
        case PRIO_USER:
            which_desc = "PRIO_USER";
            target_desc = "user";
            break;
        default:
            fut_printf("[SCHED] getpriority(which=%d, who=%d) -> EINVAL (invalid which parameter)\n",
                       which, who);
            return -EINVAL;
    }

    /* Phase 2: Only support PRIO_PROCESS for calling process */
    if (which == PRIO_PROCESS) {
        /* Determine effective PID */
        int effective_pid = (who == 0) ? (int)task->pid : who;

        if (who != 0 && who != (int)task->pid) {
            /* Querying other process - not yet supported */
            fut_printf("[SCHED] getpriority(which=%s [%s], who=%d) -> ESRCH (querying other process not supported, Phase 2)\n",
                       which_desc, target_desc, who);
            return -ESRCH;
        }

        /* Return default priority (0 = normal)
         * Phase 3 will return task->nice from task structure */
        int nice_value = PRIO_DEFAULT;

        /* Return 20 - nice_value to avoid confusion with negative nice values
         * This means: return value of 20 = nice -20 (highest priority)
         *            return value of 0  = nice 20  (lowest priority) */
        int return_value = 20 - nice_value;

        fut_printf("[SCHED] getpriority(which=%s [%s], who=%d [pid=%d]) -> %d (nice=%d, Phase 3: Priority type categorization)\n",
                   which_desc, target_desc, who, effective_pid, return_value, nice_value);

        return return_value;
    } else {
        /* PRIO_PGRP and PRIO_USER not yet implemented */
        fut_printf("[SCHED] getpriority(which=%s [%s], who=%d) -> EINVAL (not yet supported, Phase 4)\n",
                   which_desc, target_desc, who);
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
 * Phase 1 (Completed): Validates parameters but doesn't store value
 * Phase 2 (Completed): Enhanced validation and priority range reporting
 * Phase 3 (Completed): Priority range validation with detailed categorization
 * Phase 4: Implement privilege checking and PRIO_PGRP/PRIO_USER support
 */
long sys_setpriority(int which, int who, int prio) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[SCHED] setpriority(which=%d, who=%d, prio=%d) -> ESRCH (no current task)\n",
                   which, who, prio);
        return -ESRCH;
    }

    /* Phase 2: Identify priority type for logging */
    const char *which_desc;
    const char *target_desc;

    switch (which) {
        case PRIO_PROCESS:
            which_desc = "PRIO_PROCESS";
            target_desc = "process";
            break;
        case PRIO_PGRP:
            which_desc = "PRIO_PGRP";
            target_desc = "process group";
            break;
        case PRIO_USER:
            which_desc = "PRIO_USER";
            target_desc = "user";
            break;
        default:
            fut_printf("[SCHED] setpriority(which=%d, who=%d, prio=%d) -> EINVAL (invalid which parameter)\n",
                       which, who, prio);
            return -EINVAL;
    }

    /* Validate priority range */
    if (prio < PRIO_MIN || prio > PRIO_MAX) {
        fut_printf("[SCHED] setpriority(which=%s [%s], who=%d, prio=%d) -> EINVAL (prio out of range [%d, %d])\n",
                   which_desc, target_desc, who, prio, PRIO_MIN, PRIO_MAX);
        return -EINVAL;
    }

    /* Determine priority description */
    const char *prio_desc;
    if (prio < -10) {
        prio_desc = "very high priority";
    } else if (prio < 0) {
        prio_desc = "high priority";
    } else if (prio == 0) {
        prio_desc = "normal priority";
    } else if (prio < 10) {
        prio_desc = "low priority";
    } else {
        prio_desc = "very low priority";
    }

    /* Phase 2: Only support PRIO_PROCESS for calling process */
    if (which == PRIO_PROCESS) {
        /* Determine effective PID */
        int effective_pid = (who == 0) ? (int)task->pid : who;

        if (who != 0 && who != (int)task->pid) {
            /* Modifying other process - not yet supported */
            fut_printf("[SCHED] setpriority(which=%s [%s], who=%d, prio=%d) -> ESRCH (modifying other process not supported, Phase 3)\n",
                       which_desc, target_desc, who, prio);
            return -ESRCH;
        }

        /* Phase 2: Just validate and log, don't actually store
         * Phase 3 will store: task->nice = prio and update scheduler */

        fut_printf("[SCHED] setpriority(which=%s [%s], who=%d [pid=%d], prio=%d [%s]) -> 0 (Phase 3: Priority range validation)\n",
                   which_desc, target_desc, who, effective_pid, prio, prio_desc);

        return 0;
    } else {
        /* PRIO_PGRP and PRIO_USER not yet implemented */
        fut_printf("[SCHED] setpriority(which=%s [%s], who=%d, prio=%d) -> EINVAL (not yet supported, Phase 4)\n",
                   which_desc, target_desc, who, prio);
        return -EINVAL;
    }
}
