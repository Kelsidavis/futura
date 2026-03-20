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

    /* RLIMIT_RTPRIO enforcement for setparam:
     * If current thread is already on an RT policy, RLIMIT_RTPRIO limits
     * the priority that can be set. Root is exempt. */
    if (task->uid != 0 && kparam.sched_priority > 0) {
        /* Only enforce if current or target policy is RT — checked after lookup */
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

    /* Enforce RLIMIT_RTPRIO for RT policies */
    if (task->uid != 0 && target_thread &&
        (target_thread->sched_policy == SCHED_FIFO ||
         target_thread->sched_policy == SCHED_RR)) {
        uint64_t rtprio_limit = task->rlimits[14 /* RLIMIT_RTPRIO */].rlim_cur;
        if ((uint64_t)kparam.sched_priority > rtprio_limit) {
            return -EPERM;
        }
    }

    if (target_thread) {
        target_thread->rt_priority = kparam.sched_priority;
    }

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

    /* RLIMIT_RTPRIO enforcement (Linux semantics):
     * Unprivileged processes may only set RT priority up to RLIMIT_RTPRIO.
     * Root (uid=0) is exempt. */
    if (task->uid != 0 && (policy == SCHED_FIFO || policy == SCHED_RR)) {
        uint64_t rtprio_limit = task->rlimits[14 /* RLIMIT_RTPRIO */].rlim_cur;
        if ((uint64_t)kparam.sched_priority > rtprio_limit) {
            fut_printf("[SCHED] sched_setscheduler(pid=%d, policy=%s, priority=%d) -> EPERM "
                       "(RLIMIT_RTPRIO=%llu)\n",
                       pid, policy_name, kparam.sched_priority,
                       (unsigned long long)rtprio_limit);
            return -EPERM;
        }
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

    switch (policy) {
        case SCHED_OTHER:
        case SCHED_BATCH:
        case SCHED_IDLE:
            max_priority = 0;  /* Non-RT policies only support priority 0 */
            break;

        case SCHED_FIFO:
        case SCHED_RR:
            max_priority = 99;  /* RT policies support 1-99 */
            break;

        default:
            fut_printf("[SCHED] sched_get_priority_max(policy=%d) -> EINVAL "
                       "(invalid policy)\n", policy);
            return -EINVAL;
    }

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

    switch (policy) {
        case SCHED_OTHER:
        case SCHED_BATCH:
        case SCHED_IDLE:
            min_priority = 0;
            break;

        case SCHED_FIFO:
        case SCHED_RR:
            min_priority = 1;
            break;

        default:
            fut_printf("[SCHED] sched_get_priority_min(policy=%d) -> EINVAL "
                       "(invalid policy)\n", policy);
            return -EINVAL;
    }

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

/* ============================================================
 * sched_getattr / sched_setattr (Linux 3.14+)
 * Syscall numbers: 315 (getattr), 314 (setattr)
 * ============================================================ */

/* sched_attr is defined in <sched.h> (included above) */
#define SCHED_ATTR_SIZE_VER0   48  /* initial struct size (8 fields × 4/8 bytes) */

/**
 * sys_sched_getattr - Get extended scheduling attributes.
 *
 * @param pid     Target PID (0 = self)
 * @param uattr   Output sched_attr pointer
 * @param usize   Size of buffer provided by caller
 * @param flags   Must be 0
 * @return 0 on success, -errno on error
 */
long sys_sched_getattr(int pid, struct sched_attr *uattr, unsigned int usize,
                       unsigned int flags) {
    if (flags != 0)
        return -EINVAL;
    if (!uattr)
        return -EINVAL;
    if (usize < SCHED_ATTR_SIZE_VER0)
        return -EINVAL;

    fut_task_t *current = fut_task_current();
    if (!current) return -ESRCH;

    fut_task_t *target;
    if (pid == 0) {
        target = current;
    } else if (pid < 0) {
        return -EINVAL;
    } else {
        target = fut_task_by_pid((uint64_t)pid);
        if (!target)
            return -ESRCH;
    }

    /* Get scheduling info from the first thread */
    fut_thread_t *thr = target->threads;
    int policy = thr ? thr->sched_policy : 0;
    int prio   = thr ? thr->rt_priority  : 0;

    struct sched_attr attr;
    __builtin_memset(&attr, 0, sizeof(attr));
    attr.size           = SCHED_ATTR_SIZE_VER0;
    attr.sched_policy   = (uint32_t)policy;
    attr.sched_flags    = target->sched_flags;
    attr.sched_nice     = target->nice;
    attr.sched_priority = (uint32_t)(prio > 0 ? prio : 0);
    /* Deadline fields: 0 (not a DEADLINE task) */

    /* Write only min(usize, sizeof(attr)) bytes */
    size_t copy_size = usize < sizeof(attr) ? usize : sizeof(attr);
    if (sched_copy_to_user(uattr, &attr, copy_size) != 0)
        return -EFAULT;

    return 0;
}

/**
 * sys_sched_setattr - Set extended scheduling attributes.
 *
 * @param pid     Target PID (0 = self)
 * @param uattr   Input sched_attr pointer
 * @param flags   Must be 0
 * @return 0 on success, -errno on error
 */
long sys_sched_setattr(int pid, const struct sched_attr *uattr, unsigned int flags) {
    if (flags != 0)
        return -EINVAL;
    if (!uattr)
        return -EINVAL;

    struct sched_attr attr;
    __builtin_memset(&attr, 0, sizeof(attr));
    if (sched_copy_from_user(&attr, uattr, sizeof(attr)) != 0)
        return -EFAULT;

    /* Caller's size must be at least the version-0 struct size */
    if (attr.size < SCHED_ATTR_SIZE_VER0)
        return -EINVAL;

    fut_task_t *current = fut_task_current();
    if (!current) return -ESRCH;

    fut_task_t *target;
    if (pid == 0) {
        target = current;
    } else if (pid < 0) {
        return -EINVAL;
    } else {
        target = fut_task_by_pid((uint64_t)pid);
        if (!target)
            return -ESRCH;
    }

    /* Validate policy */
    int policy = (int)attr.sched_policy;
    if (policy != SCHED_OTHER && policy != SCHED_FIFO &&
        policy != SCHED_RR   && policy != SCHED_BATCH &&
        policy != SCHED_IDLE)
        return -EINVAL;

    /* Validate priority */
    int prio = (int)attr.sched_priority;
    if ((policy == SCHED_FIFO || policy == SCHED_RR) && (prio < 1 || prio > 99))
        return -EINVAL;
    if ((policy == SCHED_OTHER || policy == SCHED_BATCH || policy == SCHED_IDLE)
        && prio != 0)
        return -EINVAL;

    /* Validate sched_flags BEFORE applying any changes (Linux semantics: either
     * the whole call succeeds or nothing is modified). */
    #define SCHED_ATTR_VALID_FLAGS  ((uint64_t)SCHED_FLAG_RESET_ON_FORK)
    if (attr.sched_flags & ~SCHED_ATTR_VALID_FLAGS)
        return -EINVAL;

    /* All validation passed; apply atomically */

    /* Apply to all threads of the task */
    fut_thread_t *thr = target->threads;
    while (thr) {
        thr->sched_policy  = policy;
        thr->rt_priority   = prio;
        thr = thr->next;
    }

    /* Apply nice value (clamp to -20..19) */
    int nice = (int)attr.sched_nice;
    if (nice < -20) nice = -20;
    if (nice >  19) nice =  19;
    target->nice = nice;
    target->sched_flags = attr.sched_flags;

    return 0;
}
