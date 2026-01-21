/* kernel/sys_sched_advanced.c - Advanced scheduler control syscalls for ARM64
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements advanced scheduler control syscalls for real-time scheduling,
 * scheduling parameters, and CPU affinity management. These syscalls provide
 * fine-grained control over process scheduling policies and priority ranges.
 */

#include <kernel/fut_task.h>
#include <kernel/fut_sched.h>
#include <kernel/errno.h>
#include <stdint.h>
#include <string.h>

#include <kernel/kprintf.h>
extern fut_task_t *fut_task_current(void);

/* Scheduling policies */
#define SCHED_OTHER    0  /* Standard round-robin time-sharing */
#define SCHED_FIFO     1  /* First in, first out real-time */
#define SCHED_RR       2  /* Round-robin real-time */
#define SCHED_BATCH    3  /* Batch style execution */
#define SCHED_IDLE     5  /* Very low priority background tasks */
#define SCHED_DEADLINE 6  /* Deadline scheduling */

/* sched_param structure for scheduler parameters */
struct sched_param {
    int sched_priority;  /* Scheduling priority (1-99 for RT) */
};

/**
 * sys_sched_setparam - Set scheduling parameters
 *
 * @param pid: Process ID (0 = calling process)
 * @param param: Scheduling parameters (priority)
 *
 * Sets scheduling parameters for a process. For SCHED_FIFO and SCHED_RR,
 * the priority must be in range 1-99. For SCHED_OTHER, priority must be 0.
 *
 * Phase 1: Validate parameters, accept but don't store
 * Phase 2: Store priority in task structure
 * Phase 3: Integrate with real-time scheduler
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL if parameters invalid
 *   - -ESRCH if pid not found
 *   - -EPERM if insufficient privileges
 */
long sys_sched_setparam(int pid, const struct sched_param *param) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Validate param pointer */
    if (!param) {
        fut_printf("[SCHED] sched_setparam(pid=%d) -> EINVAL (null param)\n", pid);
        return -EINVAL;
    }

    /* Phase 1: Only support pid=0 (self) for now */
    if (pid != 0) {
        fut_printf("[SCHED] sched_setparam(pid=%d, priority=%d) -> ESRCH "
                   "(setting other processes not yet supported)\n",
                   pid, param->sched_priority);
        return -ESRCH;
    }

    /* Validate priority range (1-99 for RT, 0 for SCHED_OTHER) */
    if (param->sched_priority < 0 || param->sched_priority > 99) {
        fut_printf("[SCHED] sched_setparam(pid=%d, priority=%d) -> EINVAL "
                   "(priority out of range 0-99)\n",
                   pid, param->sched_priority);
        return -EINVAL;
    }

    /* Phase 1: Accept parameters but don't store */
    /* Phase 2: Store task->sched_priority, validate against task->sched_policy */
    fut_printf("[SCHED] sched_setparam(pid=%d, priority=%d) -> 0 "
               "(accepted, Phase 1 stub)\n",
               pid, param->sched_priority);

    return 0;
}

/**
 * sys_sched_getparam - Get scheduling parameters
 *
 * @param pid: Process ID (0 = calling process)
 * @param param: Output buffer for scheduling parameters
 *
 * Retrieves scheduling parameters for a process.
 *
 * Phase 1: Return default priority (0 for SCHED_OTHER)
 * Phase 2: Return actual priority from task structure
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL if param is NULL
 *   - -ESRCH if pid not found
 */
long sys_sched_getparam(int pid, struct sched_param *param) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Validate param pointer */
    if (!param) {
        fut_printf("[SCHED] sched_getparam(pid=%d) -> EINVAL (null param)\n", pid);
        return -EINVAL;
    }

    /* Phase 1: Only support pid=0 (self) for now */
    if (pid != 0) {
        fut_printf("[SCHED] sched_getparam(pid=%d) -> ESRCH "
                   "(querying other processes not yet supported)\n", pid);
        return -ESRCH;
    }

    /* Phase 1: Return default priority (0 for SCHED_OTHER) */
    /* Phase 2: Return task->sched_priority */
    param->sched_priority = 0;

    fut_printf("[SCHED] sched_getparam(pid=%d) -> priority=%d (Phase 1 stub)\n",
               pid, param->sched_priority);

    return 0;
}

/**
 * sys_sched_setscheduler - Set scheduling policy and parameters
 *
 * @param pid: Process ID (0 = calling process)
 * @param policy: Scheduling policy (SCHED_OTHER, SCHED_FIFO, SCHED_RR, etc.)
 * @param param: Scheduling parameters (priority)
 *
 * Sets both scheduling policy and parameters in a single call. This is the
 * modern interface for scheduler control.
 *
 * Phase 1: Validate parameters, accept but don't store
 * Phase 2: Store policy and priority in task structure
 * Phase 3: Implement real-time scheduling (SCHED_FIFO, SCHED_RR)
 *
 * Returns:
 *   - Previous scheduling policy on success
 *   - -EINVAL if policy or parameters invalid
 *   - -ESRCH if pid not found
 *   - -EPERM if insufficient privileges for RT policies
 */
long sys_sched_setscheduler(int pid, int policy, const struct sched_param *param) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Validate param pointer */
    if (!param) {
        fut_printf("[SCHED] sched_setscheduler(pid=%d, policy=%d) -> EINVAL (null param)\n",
                   pid, policy);
        return -EINVAL;
    }

    /* Validate policy */
    const char *policy_name;
    switch (policy) {
        case SCHED_OTHER:   policy_name = "SCHED_OTHER"; break;
        case SCHED_FIFO:    policy_name = "SCHED_FIFO"; break;
        case SCHED_RR:      policy_name = "SCHED_RR"; break;
        case SCHED_BATCH:   policy_name = "SCHED_BATCH"; break;
        case SCHED_IDLE:    policy_name = "SCHED_IDLE"; break;
        case SCHED_DEADLINE: policy_name = "SCHED_DEADLINE"; break;
        default:
            fut_printf("[SCHED] sched_setscheduler(pid=%d, policy=%d) -> EINVAL "
                       "(invalid policy)\n", pid, policy);
            return -EINVAL;
    }

    /* Phase 1: Only support pid=0 (self) for now */
    if (pid != 0) {
        fut_printf("[SCHED] sched_setscheduler(pid=%d, policy=%s, priority=%d) -> ESRCH "
                   "(setting other processes not yet supported)\n",
                   pid, policy_name, param->sched_priority);
        return -ESRCH;
    }

    /* Validate priority for policy */
    if ((policy == SCHED_FIFO || policy == SCHED_RR) &&
        (param->sched_priority < 1 || param->sched_priority > 99)) {
        fut_printf("[SCHED] sched_setscheduler(pid=%d, policy=%s, priority=%d) -> EINVAL "
                   "(RT priority must be 1-99)\n",
                   pid, policy_name, param->sched_priority);
        return -EINVAL;
    }

    if (policy == SCHED_OTHER && param->sched_priority != 0) {
        fut_printf("[SCHED] sched_setscheduler(pid=%d, policy=%s, priority=%d) -> EINVAL "
                   "(SCHED_OTHER priority must be 0)\n",
                   pid, policy_name, param->sched_priority);
        return -EINVAL;
    }

    /* Phase 1: Accept parameters, return previous policy (SCHED_OTHER) */
    /* Phase 2: Store task->sched_policy and task->sched_priority */
    int old_policy = SCHED_OTHER;

    fut_printf("[SCHED] sched_setscheduler(pid=%d, policy=%s, priority=%d) -> %d "
               "(accepted, Phase 1 stub)\n",
               pid, policy_name, param->sched_priority, old_policy);

    return old_policy;
}

/**
 * sys_sched_getscheduler - Get scheduling policy
 *
 * @param pid: Process ID (0 = calling process)
 *
 * Returns the scheduling policy for a process.
 *
 * Phase 1: Return SCHED_OTHER for all processes
 * Phase 2: Return actual policy from task structure
 *
 * Returns:
 *   - Scheduling policy on success
 *   - -ESRCH if pid not found
 */
long sys_sched_getscheduler(int pid) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Phase 1: Only support pid=0 (self) for now */
    if (pid != 0) {
        fut_printf("[SCHED] sched_getscheduler(pid=%d) -> ESRCH "
                   "(querying other processes not yet supported)\n", pid);
        return -ESRCH;
    }

    /* Phase 1: Return SCHED_OTHER (default time-sharing policy) */
    /* Phase 2: Return task->sched_policy */
    int policy = SCHED_OTHER;

    fut_printf("[SCHED] sched_getscheduler(pid=%d) -> %d (SCHED_OTHER, Phase 1 stub)\n",
               pid, policy);

    return policy;
}

/**
 * sys_sched_get_priority_max - Get maximum priority for a scheduling policy
 *
 * @param policy: Scheduling policy
 *
 * Returns the maximum priority value that can be used with the specified
 * scheduling policy.
 *
 * Returns:
 *   - Maximum priority on success
 *   - -EINVAL if policy invalid
 */
long sys_sched_get_priority_max(int policy) {
    int max_priority;
    const char *policy_name;

    switch (policy) {
        case SCHED_OTHER:
        case SCHED_BATCH:
        case SCHED_IDLE:
            policy_name = (policy == SCHED_OTHER) ? "SCHED_OTHER" :
                         (policy == SCHED_BATCH) ? "SCHED_BATCH" : "SCHED_IDLE";
            max_priority = 0;  /* Non-RT policies only support priority 0 */
            break;

        case SCHED_FIFO:
        case SCHED_RR:
            policy_name = (policy == SCHED_FIFO) ? "SCHED_FIFO" : "SCHED_RR";
            max_priority = 99;  /* RT policies support 1-99 */
            break;

        default:
            fut_printf("[SCHED] sched_get_priority_max(policy=%d) -> EINVAL "
                       "(invalid policy)\n", policy);
            return -EINVAL;
    }

    fut_printf("[SCHED] sched_get_priority_max(policy=%s) -> %d\n",
               policy_name, max_priority);

    return max_priority;
}

/**
 * sys_sched_get_priority_min - Get minimum priority for a scheduling policy
 *
 * @param policy: Scheduling policy
 *
 * Returns the minimum priority value that can be used with the specified
 * scheduling policy.
 *
 * Returns:
 *   - Minimum priority on success
 *   - -EINVAL if policy invalid
 */
long sys_sched_get_priority_min(int policy) {
    int min_priority;
    const char *policy_name;

    switch (policy) {
        case SCHED_OTHER:
        case SCHED_BATCH:
        case SCHED_IDLE:
            policy_name = (policy == SCHED_OTHER) ? "SCHED_OTHER" :
                         (policy == SCHED_BATCH) ? "SCHED_BATCH" : "SCHED_IDLE";
            min_priority = 0;  /* Non-RT policies only support priority 0 */
            break;

        case SCHED_FIFO:
        case SCHED_RR:
            policy_name = (policy == SCHED_FIFO) ? "SCHED_FIFO" : "SCHED_RR";
            min_priority = 1;  /* RT policies support 1-99 */
            break;

        default:
            fut_printf("[SCHED] sched_get_priority_min(policy=%d) -> EINVAL "
                       "(invalid policy)\n", policy);
            return -EINVAL;
    }

    fut_printf("[SCHED] sched_get_priority_min(policy=%s) -> %d\n",
               policy_name, min_priority);

    return min_priority;
}
