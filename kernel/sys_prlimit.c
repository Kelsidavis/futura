/* kernel/sys_prlimit.c - prlimit64 syscall for ARM64
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements prlimit64, the modern interface for getting and setting
 * process resource limits. Supersedes getrlimit/setrlimit by adding
 * the ability to query/set limits for other processes (not just self).
 *
 * Note: Basic getrlimit/setrlimit are provided by shared kernel/sys_proc.c.
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <stdint.h>
#include <stdbool.h>

#include <kernel/kprintf.h>
#include <kernel/uaccess.h>
#include <sys/resource.h>

#include <platform/platform.h>

static inline int prlimit_copy_to_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)dst >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_to_user(dst, src, n);
}
static inline int prlimit_copy_from_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)src >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_from_user(dst, src, n);
}
static inline int prlimit_access_ok(const void *ptr, size_t n, int write) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)ptr >= KERNEL_VIRTUAL_BASE) return 0;
#endif
    return fut_access_ok(ptr, n, write);
}

/* RLIMIT_* constants provided by sys/resource.h */

/* Special limit value */
#define RLIM64_INFINITY   ((uint64_t)-1)

/* Capability for overriding resource limits (must match sys_capability.c) */
#define CAP_SYS_RESOURCE  24

/* Helper to get resource name for logging */
static const char *get_resource_name(int resource) {
    switch (resource) {
        case RLIMIT_CPU:        return "CPU";
        case RLIMIT_FSIZE:      return "FSIZE";
        case RLIMIT_DATA:       return "DATA";
        case RLIMIT_STACK:      return "STACK";
        case RLIMIT_CORE:       return "CORE";
        case RLIMIT_RSS:        return "RSS";
        case RLIMIT_NPROC:      return "NPROC";
        case RLIMIT_NOFILE:     return "NOFILE";
        case RLIMIT_MEMLOCK:    return "MEMLOCK";
        case RLIMIT_AS:         return "AS";
        case RLIMIT_LOCKS:      return "LOCKS";
        case RLIMIT_SIGPENDING: return "SIGPENDING";
        case RLIMIT_MSGQUEUE:   return "MSGQUEUE";
        case RLIMIT_NICE:       return "NICE";
        case RLIMIT_RTPRIO:     return "RTPRIO";
        case RLIMIT_RTTIME:     return "RTTIME";
        default:                return "UNKNOWN";
    }
}

/**
 * sys_prlimit64 - Get and/or set process resource limits
 *
 * @param pid:       Process ID (0 = calling process)
 * @param resource:  Resource type (RLIMIT_*)
 * @param new_limit: New limit to set (NULL = don't change)
 * @param old_limit: Output buffer for old limit (NULL = don't retrieve)
 *
 * Modern interface for resource limits that supersedes getrlimit/setrlimit.
 * Can query/set limits for other processes (if privileged).
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL if resource invalid
 *   - -EFAULT if pointer invalid
 *   - -ESRCH if pid not found
 *   - -EPERM if insufficient privileges to set limits or query other process
 */
long sys_prlimit64(int pid, int resource,
                   const struct rlimit64 *new_limit,
                   struct rlimit64 *old_limit) {
    /* ARM64 FIX: Copy register parameters to local stack variables */
    int local_pid = pid;
    int local_resource = resource;
    const struct rlimit64 *local_new_limit = new_limit;
    struct rlimit64 *local_old_limit = old_limit;

    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Validate resource */
    if (local_resource < 0 || local_resource >= RLIMIT_NLIMITS) {
        fut_printf("[PRLIMIT] prlimit64(pid=%d, resource=%d) -> EINVAL (invalid resource)\n",
                   local_pid, local_resource);
        return -EINVAL;
    }

    const char *resource_name = get_resource_name(local_resource);

    /* Find target task: pid=0 means self, otherwise look up by PID */
    fut_task_t *target = task;
    if (local_pid != 0) {
        target = fut_task_by_pid((uint64_t)local_pid);
        if (!target) {
            return -ESRCH;
        }

        /* Permission gate for cross-task prlimit: Linux's
         * check_prlimit_permission compares the caller's REAL uid
         * (not effective) against ALL THREE of the target's uids
         * (real, effective, saved):
         *
         *   id_match = uid_eq(cred->uid, tcred->euid) &&
         *              uid_eq(cred->uid, tcred->suid) &&
         *              uid_eq(cred->uid, tcred->uid);
         *   if (!id_match && !ns_capable(..., CAP_SYS_RESOURCE))
         *       return -EPERM;
         *
         * The previous Futura gate compared self->uid (effective)
         * against target->uid (effective) only, leaving two holes:
         *   1. A setuid-up helper (caller euid raised) bypassed the
         *      gate against arbitrary targets — Linux gates on real uid.
         *   2. A dropped-setuid victim (suid==0) was readable/writable
         *      by an unprivileged peer sharing only the effective uid.
         *
         * Same triple-uid match against caller's real uid as the
         * recent ptrace / process_vm / kcmp / pidfd_getfd /
         * get_robust_list / process_madvise sweep. */
        if (target != task) {
            bool has_cap = (task->cap_effective & (1ULL << CAP_SYS_RESOURCE)) != 0;
            bool is_root = (task->ruid == 0);
            if (!has_cap && !is_root &&
                (task->ruid != target->uid  ||
                 task->ruid != target->ruid ||
                 task->ruid != target->suid)) {
                fut_printf("[PRLIMIT] prlimit64(pid=%d, resource=%s) -> EPERM "
                           "(uid mismatch and no CAP_SYS_RESOURCE)\n",
                           local_pid, resource_name);
                return -EPERM;
            }
        }
    }

    /* Validate userspace pointers before accessing */
    if (local_old_limit && prlimit_access_ok(local_old_limit, sizeof(struct rlimit64), 1) != 0) {
        fut_printf("[PRLIMIT] prlimit64(pid=%d, resource=%s) -> EFAULT "
                   "(invalid old_limit pointer)\n",
                   local_pid, resource_name);
        return -EFAULT;
    }

    if (local_new_limit && prlimit_access_ok(local_new_limit, sizeof(struct rlimit64), 0) != 0) {
        fut_printf("[PRLIMIT] prlimit64(pid=%d, resource=%s) -> EFAULT "
                   "(invalid new_limit pointer)\n",
                   local_pid, resource_name);
        return -EFAULT;
    }

    /* Get current limits from task structure */
    struct rlimit64 current_limit = target->rlimits[local_resource];

    /* If new_limit provided, copy from userspace into kernel buffer to
     * avoid double-fetch TOCTOU vulnerabilities. */
    struct rlimit64 knl_new;
    if (local_new_limit) {
        if (prlimit_copy_from_user(&knl_new, local_new_limit, sizeof(struct rlimit64)) != 0) {
            fut_printf("[PRLIMIT] prlimit64(pid=%d, resource=%s) -> EFAULT "
                       "(copy_from_user new_limit failed)\n",
                       local_pid, resource_name);
            return -EFAULT;
        }

        /* Soft limit cannot exceed hard limit.
         * RLIM64_INFINITY is the maximum value, so soft=INFINITY is only valid
         * when hard=INFINITY. */
        if (knl_new.rlim_cur > knl_new.rlim_max) {
            fut_printf("[PRLIMIT] prlimit64(pid=%d, resource=%s) -> EINVAL "
                       "(cur=%llu > max=%llu)\n",
                       local_pid, resource_name,
                       (unsigned long long)knl_new.rlim_cur,
                       (unsigned long long)knl_new.rlim_max);
            return -EINVAL;
        }

        /* RLIM64_INFINITY is the documented 'unlimited' sentinel and is
         * accepted on every resource on Linux — allocations still fail at
         * the per-syscall accounting boundary (mlock against actual RAM,
         * fork against the global PID space) so the unbounded value is
         * harmless to store.  The previous Futura gate rejected
         * RLIM64_INFINITY for RLIMIT_MEMLOCK and RLIMIT_NPROC with EINVAL,
         * breaking systemd's 'LimitMEMLOCK=infinity' / 'LimitNPROC=infinity'
         * unit options that explicitly set the unlimited sentinel and
         * rely on Linux accepting it.  Match Linux's behaviour and let
         * the per-resource accounting paths enforce the real limit. */

        /* Validate against system-imposed maximums per resource */
        uint64_t system_max = RLIM64_INFINITY;
        switch (local_resource) {
            case RLIMIT_NOFILE:
                system_max = 1048576;  /* 1M file descriptors max */
                break;
            case RLIMIT_NPROC:
                system_max = 32768;    /* 32K processes max (PID_MAX) */
                break;
            case RLIMIT_MEMLOCK:
                system_max = 1ULL << 40;  /* 1 TB max locked memory */
                break;
            case RLIMIT_NICE:
                system_max = 40;  /* Nice range [-20, 19] encoded as [1, 40] */
                break;
            case RLIMIT_RTPRIO:
                system_max = 99;  /* MAX_RT_PRIO */
                break;
            default:
                break;
        }

        if (knl_new.rlim_max != RLIM64_INFINITY && knl_new.rlim_max > system_max) {
            /* Linux's do_prlimit gates RLIMIT_NOFILE > sysctl_nr_open with
             * -EPERM, not -EINVAL: 'if (resource == RLIMIT_NOFILE &&
             * new_rlim->rlim_max > sysctl_nr_open) return -EPERM;'
             * (kernel/sys.c).  The errno class matters for libc setrlimit
             * wrappers that branch on EPERM ('try with CAP_SYS_RESOURCE')
             * vs EINVAL ('parameter domain error, do not retry').  Other
             * resources (NICE/RTPRIO/MEMLOCK/NPROC) keep the EINVAL class
             * since Linux has no equivalent system_max gate for them at
             * setrlimit-time and Futura's defensive ceiling is a Futura-
             * local addition. */
            long err = (local_resource == RLIMIT_NOFILE) ? -EPERM : -EINVAL;
            fut_printf("[PRLIMIT] prlimit64(pid=%d, resource=%s) -> %s "
                       "(max=%llu exceeds system maximum %llu)\n",
                       local_pid, resource_name,
                       err == -EPERM ? "EPERM" : "EINVAL",
                       (unsigned long long)knl_new.rlim_max,
                       (unsigned long long)system_max);
            return err;
        }

        /* Capability check: raising hard limit requires CAP_SYS_RESOURCE or root */
        bool raising_hard_limit = (knl_new.rlim_max > current_limit.rlim_max);
        if (raising_hard_limit) {
            bool has_cap = (task->cap_effective & (1ULL << CAP_SYS_RESOURCE)) != 0;
            bool is_root = (task->uid == 0);

            if (!has_cap && !is_root) {
                fut_printf("[PRLIMIT] prlimit64(pid=%d, resource=%s) -> EPERM "
                           "(raising hard limit requires CAP_SYS_RESOURCE)\n",
                           local_pid, resource_name);
                return -EPERM;
            }
            fut_printf("[PRLIMIT] prlimit64(pid=%d, resource=%s) -> raising hard limit "
                       "(authorized: %s)\n",
                       local_pid, resource_name, is_root ? "root" : "CAP_SYS_RESOURCE");
        }

        /* Store validated limits in task structure */
        target->rlimits[local_resource].rlim_cur = knl_new.rlim_cur;
        target->rlimits[local_resource].rlim_max = knl_new.rlim_max;

        fut_printf("[PRLIMIT] prlimit64(pid=%d, resource=%s) -> new_limit: "
                   "cur=%llu, max=%llu (stored in target->rlimits[%d])\n",
                   local_pid, resource_name,
                   (unsigned long long)knl_new.rlim_cur,
                   (unsigned long long)knl_new.rlim_max,
                   local_resource);
    }

    /* Copy out pre-change limits to userspace via fut_copy_to_user */
    if (local_old_limit) {
        if (prlimit_copy_to_user(local_old_limit, &current_limit, sizeof(struct rlimit64)) != 0) {
            fut_printf("[PRLIMIT] prlimit64(pid=%d, resource=%s) -> EFAULT "
                       "(copy_to_user old_limit failed)\n",
                       local_pid, resource_name);
            return -EFAULT;
        }

        fut_printf("[PRLIMIT] prlimit64(pid=%d, resource=%s) -> old_limit: "
                   "cur=%llu, max=%llu\n",
                   local_pid, resource_name,
                   (unsigned long long)current_limit.rlim_cur,
                   (unsigned long long)current_limit.rlim_max);
    }

    if (!local_new_limit && !local_old_limit) {
        fut_printf("[PRLIMIT] prlimit64(pid=%d, resource=%s) -> 0 (no-op)\n",
                   local_pid, resource_name);
    }

    return 0;
}
