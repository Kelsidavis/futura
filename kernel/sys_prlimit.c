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

extern void fut_printf(const char *fmt, ...);
extern fut_task_t *fut_task_current(void);

/* Resource limit structure (64-bit version) */
struct rlimit64 {
    uint64_t rlim_cur;  /* Soft limit */
    uint64_t rlim_max;  /* Hard limit (ceiling for rlim_cur) */
};

/* Resource types */
#define RLIMIT_CPU        0   /* CPU time in seconds */
#define RLIMIT_FSIZE      1   /* Maximum file size */
#define RLIMIT_DATA       2   /* Max data size */
#define RLIMIT_STACK      3   /* Max stack size */
#define RLIMIT_CORE       4   /* Max core file size */
#define RLIMIT_RSS        5   /* Max resident set size */
#define RLIMIT_NPROC      6   /* Max number of processes */
#define RLIMIT_NOFILE     7   /* Max number of open files */
#define RLIMIT_MEMLOCK    8   /* Max locked-in-memory address space */
#define RLIMIT_AS         9   /* Address space limit */
#define RLIMIT_LOCKS      10  /* Max file locks */
#define RLIMIT_SIGPENDING 11  /* Max pending signals */
#define RLIMIT_MSGQUEUE   12  /* Max bytes in POSIX message queues */
#define RLIMIT_NICE       13  /* Max nice priority */
#define RLIMIT_RTPRIO     14  /* Max realtime priority */
#define RLIMIT_RTTIME     15  /* Timeout for RT tasks (microseconds) */
#define RLIMIT_NLIMITS    16  /* Number of limit types */

/* Special limit value */
#define RLIM64_INFINITY   ((uint64_t)-1)

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

/* Helper to get default limits for a resource */
static void get_default_limit(int resource, struct rlimit64 *limit) {
    switch (resource) {
        case RLIMIT_CPU:
            limit->rlim_cur = RLIM64_INFINITY;
            limit->rlim_max = RLIM64_INFINITY;
            break;

        case RLIMIT_FSIZE:
            limit->rlim_cur = RLIM64_INFINITY;
            limit->rlim_max = RLIM64_INFINITY;
            break;

        case RLIMIT_DATA:
            limit->rlim_cur = RLIM64_INFINITY;
            limit->rlim_max = RLIM64_INFINITY;
            break;

        case RLIMIT_STACK:
            limit->rlim_cur = 8 * 1024 * 1024;  /* 8 MB soft */
            limit->rlim_max = RLIM64_INFINITY;
            break;

        case RLIMIT_CORE:
            limit->rlim_cur = 0;  /* No core dumps by default */
            limit->rlim_max = RLIM64_INFINITY;
            break;

        case RLIMIT_RSS:
            limit->rlim_cur = RLIM64_INFINITY;
            limit->rlim_max = RLIM64_INFINITY;
            break;

        case RLIMIT_NPROC:
            limit->rlim_cur = 256;
            limit->rlim_max = 512;
            break;

        case RLIMIT_NOFILE:
            limit->rlim_cur = 1024;
            limit->rlim_max = 65536;
            break;

        case RLIMIT_MEMLOCK:
            limit->rlim_cur = 64 * 1024;  /* 64 KB */
            limit->rlim_max = 64 * 1024;
            break;

        case RLIMIT_AS:
            limit->rlim_cur = RLIM64_INFINITY;
            limit->rlim_max = RLIM64_INFINITY;
            break;

        case RLIMIT_LOCKS:
            limit->rlim_cur = RLIM64_INFINITY;
            limit->rlim_max = RLIM64_INFINITY;
            break;

        case RLIMIT_SIGPENDING:
            limit->rlim_cur = 1024;
            limit->rlim_max = 1024;
            break;

        case RLIMIT_MSGQUEUE:
            limit->rlim_cur = 800 * 1024;  /* 800 KB */
            limit->rlim_max = 800 * 1024;
            break;

        case RLIMIT_NICE:
            limit->rlim_cur = 0;
            limit->rlim_max = 0;
            break;

        case RLIMIT_RTPRIO:
            limit->rlim_cur = 0;
            limit->rlim_max = 0;
            break;

        case RLIMIT_RTTIME:
            limit->rlim_cur = RLIM64_INFINITY;
            limit->rlim_max = RLIM64_INFINITY;
            break;

        default:
            limit->rlim_cur = 0;
            limit->rlim_max = 0;
            break;
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
 * Phase 1: Stub - returns default limits, accepts new limits
 * Phase 2: Store limits in task structure, enforce in allocations
 * Phase 3: Support querying other processes, privilege checks
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
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Validate resource */
    if (resource < 0 || resource >= RLIMIT_NLIMITS) {
        fut_printf("[PRLIMIT] prlimit64(pid=%d, resource=%d) -> EINVAL (invalid resource)\n",
                   pid, resource);
        return -EINVAL;
    }

    const char *resource_name = get_resource_name(resource);

    /* Phase 1: Only support pid=0 (self) for now */
    if (pid != 0) {
        fut_printf("[PRLIMIT] prlimit64(pid=%d, resource=%s) -> ESRCH "
                   "(querying other processes not yet supported)\n",
                   pid, resource_name);
        return -ESRCH;
    }

    /* Get current (default) limits */
    struct rlimit64 current_limit;
    get_default_limit(resource, &current_limit);

    /* If old_limit requested, copy out current limits */
    if (old_limit) {
        old_limit->rlim_cur = current_limit.rlim_cur;
        old_limit->rlim_max = current_limit.rlim_max;

        fut_printf("[PRLIMIT] prlimit64(pid=%d, resource=%s) -> old_limit: "
                   "cur=%llu, max=%llu\n",
                   pid, resource_name,
                   (unsigned long long)old_limit->rlim_cur,
                   (unsigned long long)old_limit->rlim_max);
    }

    /* If new_limit provided, validate and "set" (stub for now) */
    if (new_limit) {
        /* Phase 1: Validate but don't actually enforce */
        if (new_limit->rlim_cur > new_limit->rlim_max &&
            new_limit->rlim_max != RLIM64_INFINITY) {
            fut_printf("[PRLIMIT] prlimit64(pid=%d, resource=%s) -> EINVAL "
                       "(cur=%llu > max=%llu)\n",
                       pid, resource_name,
                       (unsigned long long)new_limit->rlim_cur,
                       (unsigned long long)new_limit->rlim_max);
            return -EINVAL;
        }

        /* Phase 1: Accept limits but don't store */
        /* Phase 2: Store in task structure and enforce */
        fut_printf("[PRLIMIT] prlimit64(pid=%d, resource=%s) -> new_limit: "
                   "cur=%llu, max=%llu (accepted, Phase 1 stub)\n",
                   pid, resource_name,
                   (unsigned long long)new_limit->rlim_cur,
                   (unsigned long long)new_limit->rlim_max);
    }

    if (!new_limit && !old_limit) {
        fut_printf("[PRLIMIT] prlimit64(pid=%d, resource=%s) -> 0 (no-op)\n",
                   pid, resource_name);
    }

    return 0;
}
