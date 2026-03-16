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
#include <kernel/fut_thread.h>
#include <kernel/errno.h>
#include <shared/fut_timespec.h>
#include <sched.h>
#include <stdint.h>
#include <string.h>

#include <kernel/kprintf.h>
#include <kernel/uaccess.h>
#ifdef __x86_64__
#include <platform/x86_64/memory/paging.h>
#elif defined(__aarch64__)
#include <platform/arm64/memory/paging.h>
#endif

/* SCHED_* constants and struct sched_param provided by sched.h */

/* Kernel-pointer-safe copy helpers: if the pointer is a kernel virtual
 * address, bypass fut_copy_from/to_user (which assume user pages).     */
static inline int sched_copy_from_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)src >= KERNEL_VIRTUAL_BASE) {
        __builtin_memcpy(dst, src, n);
        return 0;
    }
#endif
    return fut_copy_from_user(dst, src, n);
}
static inline int sched_copy_to_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)dst >= KERNEL_VIRTUAL_BASE) {
        __builtin_memcpy(dst, src, n);
        return 0;
    }
#endif
    return fut_copy_to_user(dst, src, n);
}

/**
 * sys_sched_setparam - Set scheduling parameters
 *
 * @param pid: Process ID (0 = calling process)
 * @param param: Scheduling parameters (priority)
 *
 * Sets scheduling parameters for a process. For SCHED_FIFO and SCHED_RR,
 * the priority must be in range 1-99. For SCHED_OTHER, priority must be 0.
 *
 * Phase 1 (Completed): Validate parameters, accept but don't store
 * Phase 2 (Completed): Store priority in task structure
 * Phase 3 (Completed): Integrate with real-time scheduler
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL if parameters invalid
 *   - -ESRCH if pid not found
 *   - -EPERM if insufficient privileges
 */
long sys_sched_setparam(int pid, const struct sched_param *param) {
    /* Capture current thread once at entry; derive task from it.
     * Calling fut_thread_current() twice (once for task, once for thread)
     * risks a context switch between the two calls that stores rt_priority
     * in the wrong thread (idle or another), causing a getparam mismatch. */
    fut_thread_t *thread = fut_thread_current();
    fut_task_t *task = thread ? thread->task : NULL;
    if (!task) {
        return -ESRCH;
    }

    /* Validate param pointer */
    if (!param) {
        fut_printf("[SCHED] sched_setparam(pid=%d) -> EINVAL (null param)\n", pid);
        return -EINVAL;
    }

    /* Copy sched_param from userspace before accessing fields */
    struct sched_param kparam;
    if (sched_copy_from_user(&kparam, param, sizeof(kparam)) != 0) {
        fut_printf("[SCHED] sched_setparam(pid=%d) -> EFAULT (copy_from_user failed)\n", pid);
        return -EFAULT;
    }

    /* Validate priority range (1-99 for RT, 0 for SCHED_OTHER) */
    if (kparam.sched_priority < 0 || kparam.sched_priority > 99) {
        fut_printf("[SCHED] sched_setparam(pid=%d, priority=%d) -> EINVAL "
                   "(priority out of range 0-99)\n",
                   pid, kparam.sched_priority);
        return -EINVAL;
    }

    /* Find target thread: pid=0 means self, otherwise look up by PID */
    fut_thread_t *target_thread = thread;
    if (pid != 0) {
        fut_task_t *target_task = fut_task_by_pid((uint64_t)pid);
        if (!target_task) {
            return -ESRCH;
        }
        target_thread = target_task->threads;
    }

    if (target_thread) {
        target_thread->rt_priority = kparam.sched_priority;
    }

    fut_printf("[SCHED] sched_setparam(pid=%d, priority=%d) -> 0\n",
               pid, kparam.sched_priority);

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
 * Phase 1 (Completed): Return default priority (0 for SCHED_OTHER)
 * Phase 2 (Completed): Return actual priority from task structure
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL if param is NULL
 *   - -ESRCH if pid not found
 */
long sys_sched_getparam(int pid, struct sched_param *param) {
    /* Capture current thread once at entry; derive task from it. */
    fut_thread_t *thread = fut_thread_current();
    fut_task_t *task = thread ? thread->task : NULL;
    if (!task) {
        return -ESRCH;
    }

    /* Validate param pointer */
    if (!param) {
        fut_printf("[SCHED] sched_getparam(pid=%d) -> EINVAL (null param)\n", pid);
        return -EINVAL;
    }

    /* Find target thread: pid=0 means self, otherwise look up by PID */
    fut_thread_t *target_thread = thread;
    if (pid != 0) {
        fut_task_t *target_task = fut_task_by_pid((uint64_t)pid);
        if (!target_task) {
            return -ESRCH;
        }
        target_thread = target_task->threads;
    }

    /* Return RT priority from thread structure */
    struct sched_param kparam;
    kparam.sched_priority = target_thread ? target_thread->rt_priority : 0;

    /* Copy result to userspace */
    if (sched_copy_to_user(param, &kparam, sizeof(kparam)) != 0) {
        return -EFAULT;
    }

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
 * Phase 1 (Completed): Validate parameters, accept but don't store
 * Phase 2 (Completed): Store policy and priority in task structure
 * Phase 3 (Completed): Implement real-time scheduling (SCHED_FIFO, SCHED_RR)
 *
 * Returns:
 *   - Previous scheduling policy on success
 *   - -EINVAL if policy or parameters invalid
 *   - -ESRCH if pid not found
 *   - -EPERM if insufficient privileges for RT policies
 */
long sys_sched_setscheduler(int pid, int policy, const struct sched_param *param) {
    fut_thread_t *thread = fut_thread_current();
    fut_task_t *task = thread ? thread->task : NULL;
    if (!task) {
        return -ESRCH;
    }

    /* Validate param pointer */
    if (!param) {
        fut_printf("[SCHED] sched_setscheduler(pid=%d, policy=%d) -> EINVAL (null param)\n",
                   pid, policy);
        return -EINVAL;
    }

    /* Copy sched_param from userspace before accessing fields */
    struct sched_param kparam;
    if (sched_copy_from_user(&kparam, param, sizeof(kparam)) != 0) {
        fut_printf("[SCHED] sched_setscheduler(pid=%d, policy=%d) -> EFAULT (copy_from_user failed)\n",
                   pid, policy);
        return -EFAULT;
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

    /* Validate priority for policy */
    if ((policy == SCHED_FIFO || policy == SCHED_RR) &&
        (kparam.sched_priority < 1 || kparam.sched_priority > 99)) {
        fut_printf("[SCHED] sched_setscheduler(pid=%d, policy=%s, priority=%d) -> EINVAL "
                   "(RT priority must be 1-99)\n",
                   pid, policy_name, kparam.sched_priority);
        return -EINVAL;
    }

    if (policy == SCHED_OTHER && kparam.sched_priority != 0) {
        fut_printf("[SCHED] sched_setscheduler(pid=%d, policy=%s, priority=%d) -> EINVAL "
                   "(SCHED_OTHER priority must be 0)\n",
                   pid, policy_name, kparam.sched_priority);
        return -EINVAL;
    }

    /* Find target thread: pid=0 means self, otherwise look up by PID */
    fut_thread_t *target_thread = thread;
    if (pid != 0) {
        fut_task_t *target_task = fut_task_by_pid((uint64_t)pid);
        if (!target_task) {
            return -ESRCH;
        }
        target_thread = target_task->threads;
    }

    /* Store policy and RT priority, return previous policy */
    int old_policy = target_thread ? target_thread->sched_policy : SCHED_OTHER;
    if (target_thread) {
        target_thread->sched_policy = policy;
        target_thread->rt_priority  = kparam.sched_priority;
    }

    return old_policy;
}

/**
 * sys_sched_getscheduler - Get scheduling policy
 *
 * @param pid: Process ID (0 = calling process)
 *
 * Returns the scheduling policy for a process.
 *
 * Phase 1 (Completed): Return SCHED_OTHER for all processes
 * Phase 2 (Completed): Return actual policy from task structure
 *
 * Returns:
 *   - Scheduling policy on success
 *   - -ESRCH if pid not found
 */
long sys_sched_getscheduler(int pid) {
    fut_thread_t *thread = fut_thread_current();
    fut_task_t *task = thread ? thread->task : NULL;
    if (!task) {
        return -ESRCH;
    }

    /* Find target thread: pid=0 means self, otherwise look up by PID */
    fut_thread_t *target_thread = thread;
    if (pid != 0) {
        fut_task_t *target_task = fut_task_by_pid((uint64_t)pid);
        if (!target_task) {
            return -ESRCH;
        }
        target_thread = target_task->threads;
    }

    int policy = target_thread ? target_thread->sched_policy : SCHED_OTHER;

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

/**
 * sched_rr_get_interval - Get the round-robin time quantum
 *
 * Returns the time quantum for the SCHED_RR scheduling policy. For
 * SCHED_OTHER/SCHED_FIFO, the concept of a fixed quantum doesn't apply,
 * but Linux returns the actual scheduler timeslice for all policies.
 *
 * @param pid      Process ID (0 = calling process)
 * @param interval Pointer to timespec to receive the quantum
 *
 * Returns 0 on success, negative errno on failure.
 */
long sys_sched_rr_get_interval(int pid, fut_timespec_t *interval) {
    fut_task_t *current = fut_task_current();
    if (!current)
        return -ESRCH;

    /* Validate PID */
    if (pid < 0)
        return -EINVAL;

    /* Look up target task (pid=0 means self) */
    fut_task_t *target;
    if (pid == 0) {
        target = current;
    } else {
        target = fut_task_by_pid((uint64_t)pid);
        if (!target)
            return -ESRCH;
    }

    /* Validate output pointer */
    if (!interval)
        return -EFAULT;

    /* The quantum is 1/FUT_TIMER_HZ = 10ms for all policies.
     * Linux returns the timeslice for any policy, not just SCHED_RR. */
    fut_timespec_t quantum = {
        .tv_sec = 0,
        .tv_nsec = 10000000  /* 10ms = 1/100 Hz */
    };

    if (sched_copy_to_user(interval, &quantum, sizeof(quantum)) != 0)
        return -EFAULT;

    return 0;
}
