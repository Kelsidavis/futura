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
#include <kernel/fut_thread.h>
#include <kernel/errno.h>

#include <kernel/kprintf.h>

/* Priority (nice value) constants */
#define PRIO_PROCESS 0  /* Priority applies to process */
#define PRIO_PGRP    1  /* Priority applies to process group */
#define PRIO_USER    2  /* Priority applies to user */
#define PRIO_THREAD  3  /* Priority applies to a specific thread by TID */

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
 * Phase 4 (Completed): Track yield statistics for scheduler debugging
 */
long sys_sched_yield(void) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        /* Should never happen, but be defensive */
        return -ESRCH;
    }

    /* Get current thread for yield statistics tracking */
    fut_thread_t *thread = fut_thread_current();

    /* Trigger a reschedule, allowing other threads to run.
     * The scheduler will select the next runnable thread. */
    fut_schedule();

    /* Phase 4: Increment voluntary yield counter after returning from reschedule */
    if (thread) {
        thread->stats.voluntary_yields++;
    }

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
 * Phase 4 (Completed): Read actual task->nice values, PRIO_PGRP/PRIO_USER lookups
 */
long sys_getpriority(int which, int who) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[SCHED] getpriority(which=%d, who=%d) -> ESRCH (no current task)\n", which, who);
        return -ESRCH;
    }

    /* Phase 2: Identify priority type for logging */
    const char *which_desc;

    switch (which) {
        case PRIO_PROCESS: which_desc = "PRIO_PROCESS"; break;
        case PRIO_PGRP:    which_desc = "PRIO_PGRP";    break;
        case PRIO_USER:    which_desc = "PRIO_USER";    break;
        case PRIO_THREAD:  which_desc = "PRIO_THREAD";  break;
        default:
            fut_printf("[SCHED] getpriority(which=%d, who=%d) -> EINVAL (invalid which parameter)\n",
                       which, who);
            return -EINVAL;
    }

    if (who < 0) {
        fut_printf("[SCHED] getpriority(%s, who=%d) -> EINVAL (negative who)\n",
                   which_desc, who);
        return -EINVAL;
    }

    /* Traverse task list without holding the lock (accepting benign races,
     * same pattern used by fut_timer.c).  For PRIO_PROCESS / PRIO_PGRP /
     * PRIO_USER / PRIO_THREAD the result is advisory and exact atomicity
     * is not required. */
    extern fut_task_t *fut_task_list;

    int best_nice = PRIO_MAX + 1; /* sentinel: no matching task yet */

    if (which == PRIO_THREAD) {
        /* PRIO_THREAD: who=0 means calling thread, who=tid means that thread.
         * nice is per-task in Futura; return the task's nice for the thread. */
        if (who == 0) {
            best_nice = task->nice;
        } else {
            /* Find the task that owns a thread with TID == who */
            for (fut_task_t *t = fut_task_list; t; t = t->next) {
                if (t->state == FUT_TASK_ZOMBIE) continue;
                for (fut_thread_t *th = t->threads; th; th = th->next) {
                    if (th->tid == (uint64_t)who) {
                        if (t->nice < best_nice) best_nice = t->nice;
                        break;
                    }
                }
            }
        }
    } else if (which == PRIO_PROCESS) {
        uint64_t target_pid = (who == 0) ? task->pid : (uint64_t)who;
        for (fut_task_t *t = fut_task_list; t; t = t->next) {
            if (t->pid == target_pid && t->state != FUT_TASK_ZOMBIE) {
                if (t->nice < best_nice) best_nice = t->nice;
            }
        }
    } else if (which == PRIO_PGRP) {
        uint64_t target_pgid = (who == 0) ? task->pgid : (uint64_t)who;
        for (fut_task_t *t = fut_task_list; t; t = t->next) {
            if (t->pgid == target_pgid && t->state != FUT_TASK_ZOMBIE) {
                if (t->nice < best_nice) best_nice = t->nice;
            }
        }
    } else { /* PRIO_USER */
        uint32_t target_uid = (who == 0) ? task->uid : (uint32_t)who;
        for (fut_task_t *t = fut_task_list; t; t = t->next) {
            if (t->uid == target_uid && t->state != FUT_TASK_ZOMBIE) {
                if (t->nice < best_nice) best_nice = t->nice;
            }
        }
    }

    if (best_nice == PRIO_MAX + 1) {
        fut_printf("[SCHED] getpriority(%s, who=%d) -> ESRCH\n", which_desc, who);
        return -ESRCH;
    }
    return 20 - best_nice;
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
 * Phase 4 (Completed): Actual nice storage, privilege checking, PRIO_PGRP/PRIO_USER
 */
#define CAP_SYS_NICE_BIT 23
#define HAS_CAP_SYS_NICE(t) ((t)->cap_effective & (1ULL << CAP_SYS_NICE_BIT))

long sys_setpriority(int which, int who, int prio) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[SCHED] setpriority(which=%d, who=%d, prio=%d) -> ESRCH (no current task)\n",
                   which, who, prio);
        return -ESRCH;
    }

    /* Phase 2: Identify priority type for logging */
    const char *which_desc;

    switch (which) {
        case PRIO_PROCESS: which_desc = "PRIO_PROCESS"; break;
        case PRIO_PGRP:    which_desc = "PRIO_PGRP";    break;
        case PRIO_USER:    which_desc = "PRIO_USER";    break;
        case PRIO_THREAD:  which_desc = "PRIO_THREAD";  break;
        default:
            fut_printf("[SCHED] setpriority(which=%d, who=%d, prio=%d) -> EINVAL (invalid which parameter)\n",
                       which, who, prio);
            return -EINVAL;
    }

    if (who < 0) {
        fut_printf("[SCHED] setpriority(%s, who=%d, prio=%d) -> EINVAL (negative who)\n",
                   which_desc, who, prio);
        return -EINVAL;
    }

    /* Validate priority range */
    if (prio < PRIO_MIN || prio > PRIO_MAX) {
        fut_printf("[SCHED] setpriority(which=%s, who=%d, prio=%d) -> EINVAL (prio out of range [%d, %d])\n",
                   which_desc, who, prio, PRIO_MIN, PRIO_MAX);
        return -EINVAL;
    }

    extern fut_task_t *fut_task_list;
    int matched = 0;
    int saw_uid_mismatch = 0;
    int saw_need_privilege = 0;

    if (which == PRIO_THREAD) {
        /* PRIO_THREAD: who=0 means calling task, who=tid means that thread's task */
        fut_task_t *target_task = NULL;
        if (who == 0) {
            target_task = task;
        } else {
            for (fut_task_t *t = fut_task_list; t; t = t->next) {
                if (t->state == FUT_TASK_ZOMBIE) continue;
                for (fut_thread_t *th = t->threads; th; th = th->next) {
                    if (th->tid == (uint64_t)who) {
                        target_task = t;
                        break;
                    }
                }
                if (target_task) break;
            }
        }
        if (!target_task) {
            fut_printf("[SCHED] setpriority(%s, who=%d, prio=%d) -> ESRCH\n",
                       which_desc, who, prio);
            return -ESRCH;
        }
        if (task->uid != 0 && !HAS_CAP_SYS_NICE(task) && task->uid != target_task->uid) {
            fut_printf("[SCHED] setpriority(%s, who=%d, prio=%d) -> EPERM (uid mismatch)\n",
                       which_desc, who, prio);
            return -EPERM;
        }
        if (prio < target_task->nice && task->uid != 0 && !HAS_CAP_SYS_NICE(task)) {
            fut_printf("[SCHED] setpriority(%s, who=%d, prio=%d) -> EACCES (not privileged)\n",
                       which_desc, who, prio);
            return -EACCES;
        }
        target_task->nice = prio;
        matched = 1;
    } else if (which == PRIO_PROCESS) {
        uint64_t target_pid = (who == 0) ? task->pid : (uint64_t)who;
        for (fut_task_t *t = fut_task_list; t; t = t->next) {
            if (t->pid != target_pid || t->state == FUT_TASK_ZOMBIE)
                continue;
            /* Permission check: only root or same-UID can change another's priority */
            if (task->uid != 0 && !HAS_CAP_SYS_NICE(task) && task->uid != t->uid) {
                fut_printf("[SCHED] setpriority(%s, who=%d, prio=%d) -> EPERM (uid mismatch)\n",
                           which_desc, who, prio);
                return -EPERM;
            }
            /* Privilege check: raising priority (lowering nice) requires root */
            if (prio < t->nice && task->uid != 0 && !HAS_CAP_SYS_NICE(task)) {
                fut_printf("[SCHED] setpriority(%s, who=%d, prio=%d) -> EACCES (not privileged)\n",
                           which_desc, who, prio);
                return -EACCES;
            }
            t->nice = prio;
            matched = 1;
        }
    } else if (which == PRIO_PGRP) {
        uint64_t target_pgid = (who == 0) ? task->pgid : (uint64_t)who;
        for (fut_task_t *t = fut_task_list; t; t = t->next) {
            if (t->pgid != target_pgid || t->state == FUT_TASK_ZOMBIE)
                continue;
            if (task->uid != 0 && !HAS_CAP_SYS_NICE(task) && task->uid != t->uid) {
                saw_uid_mismatch = 1;
                continue; /* skip tasks we don't own in group */
            }
            if (prio < t->nice && task->uid != 0 && !HAS_CAP_SYS_NICE(task)) {
                saw_need_privilege = 1;
                continue; /* skip tasks we can't raise priority for */
            }
            t->nice = prio;
            matched = 1;
        }
    } else { /* PRIO_USER */
        uint32_t target_uid = (who == 0) ? task->uid : (uint32_t)who;
        /* Non-root can only modify own user's tasks */
        if (task->uid != 0 && !HAS_CAP_SYS_NICE(task) && task->uid != target_uid) {
            fut_printf("[SCHED] setpriority(%s, who=%d, prio=%d) -> EPERM (uid mismatch)\n",
                       which_desc, who, prio);
            return -EPERM;
        }
        for (fut_task_t *t = fut_task_list; t; t = t->next) {
            if (t->uid != target_uid || t->state == FUT_TASK_ZOMBIE)
                continue;
            if (prio < t->nice && task->uid != 0 && !HAS_CAP_SYS_NICE(task)) {
                saw_need_privilege = 1;
                continue; /* skip tasks we can't raise priority for */
            }
            t->nice = prio;
            matched = 1;
        }
    }

    if (!matched) {
        if (saw_uid_mismatch) {
            fut_printf("[SCHED] setpriority(%s, who=%d, prio=%d) -> EPERM (uid mismatch)\n",
                       which_desc, who, prio);
            return -EPERM;
        }
        if (saw_need_privilege) {
            fut_printf("[SCHED] setpriority(%s, who=%d, prio=%d) -> EACCES (not privileged)\n",
                       which_desc, who, prio);
            return -EACCES;
        }
        fut_printf("[SCHED] setpriority(%s, who=%d, prio=%d) -> ESRCH\n",
                   which_desc, who, prio);
        return -ESRCH;
    }

    return 0;
}
