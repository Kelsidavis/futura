/* kernel/sys_proc.c - Process information syscalls
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements syscalls for querying and managing process hierarchy,
 * process groups, and sessions for job control.
 */

#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
#include <kernel/errno.h>
#include <sys/resource.h>
#include <stdint.h>

#include <kernel/kprintf.h>
#include <kernel/uaccess.h>

#ifdef __x86_64__
#include <platform/x86_64/memory/paging.h>
#elif defined(__aarch64__)
#include <platform/arm64/memory/paging.h>
#endif

static inline int sys_proc_copy_from_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)src >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_from_user(dst, src, n);
}
static inline int sys_proc_copy_to_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)dst >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_to_user(dst, src, n);
}
#include <kernel/fut_thread.h>

/* Default resource limit values - named constants for clarity */
#define RLIMIT_NOFILE_SOFT_DEFAULT  1024      /* Default soft limit for open files */
#define RLIMIT_NOFILE_HARD_DEFAULT  65536     /* Default hard limit for open files */
#define RLIMIT_NPROC_SOFT_DEFAULT   256       /* Default soft limit for processes */
#define RLIMIT_NPROC_HARD_DEFAULT   512       /* Default hard limit for processes */
#define RLIMIT_STACK_SOFT_DEFAULT   (8 * 1024 * 1024)  /* 8 MB default stack */
#define RLIMIT_MEMLOCK_DEFAULT      (64 * 1024)        /* 64 KB default locked memory */
#define RLIMIT_MSGQUEUE_DEFAULT     819200    /* Default POSIX message queue bytes */
#define RLIMIT_NICE_DEFAULT         0         /* Default nice priority limit */
#define RLIMIT_RTPRIO_DEFAULT       0         /* Default real-time priority */
#define RLIMIT_SIGPENDING_DEFAULT   1024      /* Default pending signals */

/**
 * getpid() - Get process ID
 *
 * Returns the process ID (PID) of the calling process.
 * This is a permanent identifier for the process.
 *
 * Returns:
 *   - Process ID of the calling process (always succeeds)
 */
long sys_getpid(void) {
    fut_thread_t *thread = fut_thread_current();
    fut_task_t *task = fut_task_current();

    (void)thread;

    if (!task) {
        return 1;  /* Default to init PID for kernel threads */
    }

    return task->pid;
}

/**
 * gettid() - Get thread ID
 *
 * Returns the thread ID (TID) of the calling thread.
 * In Futura OS, threads are represented by tasks, and each task has a unique ID.
 * For single-threaded processes, TID equals PID.
 *
 * Returns:
 *   - Thread ID of the calling thread (always succeeds)
 */
long sys_gettid(void) {
    /* For multi-threaded processes (CLONE_THREAD), each thread has its own TID.
     * Return the current thread's TID, which differs from the task PID for
     * secondary threads. The main thread gets the same TID as the process PID
     * on the first task creation, but that's handled by the bootstrap path. */
    fut_thread_t *thread = fut_thread_current();
    if (thread)
        return (long)thread->tid;
    fut_task_t *task = fut_task_current();
    if (task)
        return (long)task->pid;
    return 1;
}

/**
 * getppid() - Get parent process ID
 *
 * Returns the process ID of the parent of the calling process.
 * The parent is the process that created this process via fork().
 *
 * Returns:
 *   - Parent process ID (always succeeds)
 *   - Returns 1 (init) if no parent is recorded
 */
long sys_getppid(void) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return 1;  /* Default to init */
    }

    return (task->parent) ? task->parent->pid : 1;
}

/**
 * getpgrp() - Get process group ID
 *
 * Returns the process group ID (PGID) of the calling process.
 * Process groups are used for job control in shells.
 *
 * Returns:
 *   - Process group ID of the calling process
 */
long sys_getpgrp(void) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return 1;  /* Default to init process group */
    }

    return task->pgid;
}

/**
 * getpgid(pid_t pid) - Get process group ID
 *
 * Returns the process group ID (PGID) of the process specified by pid.
 * Process groups are used for job control in shells and signal handling.
 *
 * @param pid  Process ID (0 = calling process)
 *
 * Returns:
 *   - Process group ID of the specified process
 *   - -ESRCH if pid not found
 */
long sys_getpgid(uint64_t pid) {
    fut_task_t *current = fut_task_current();
    if (!current) {
        return -ESRCH;
    }

    /* If pid is 0, use calling process */
    if (pid == 0) {
        return current->pgid;
    }

    /* Look up the target task */
    fut_task_t *target = fut_task_by_pid(pid);
    if (!target) {
        fut_printf("[PROC] getpgid(pid=%llu) -> ESRCH (not found)\n", pid);
        return -ESRCH;
    }

    return target->pgid;
}

/**
 * setpgrp() - Create new process group
 *
 * Makes the calling process the leader of a new process group.
 * Equivalent to setpgid(0, 0).
 *
 * Returns:
 *   - 0 on success
 *   - -EPERM if process is already a session leader
 */
long sys_setpgrp(void) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Cannot change process group if we are a session leader */
    if (task->pid == task->sid) {
        fut_printf("[PROC] setpgrp() -> EPERM (session leader cannot change pgrp)\n");
        return -EPERM;
    }

    task->pgid = task->pid;  /* Become leader of own process group */
    return 0;
}

/**
 * setpgid(pid_t pid, pid_t pgid) - Set process group ID
 *
 * Sets the process group ID of the process specified by pid.
 *
 * POSIX rules:
 * - A process can only set its own pgid or that of a child
 * - A process cannot change the pgid of a child that has called exec
 * - The target pgid must be in the same session
 * - A session leader cannot change its process group
 *
 * @param pid   Process ID to modify (0 = calling process)
 * @param pgid  Process group ID to set (0 = use pid as pgid)
 *
 * Returns:
 *   - 0 on success
 *   - -ESRCH if pid not found or not callable
 *   - -EINVAL if pgid is negative
 *   - -EPERM if operation not permitted
 *   - -EACCES if target has exec'd (simplified: we skip this check)
 */
long sys_setpgid(uint64_t pid, uint64_t pgid) {
    fut_task_t *current = fut_task_current();
    if (!current) {
        return -ESRCH;
    }

    /* If pid is 0, use calling process */
    if (pid == 0) {
        pid = current->pid;
    }

    /* If pgid is 0, set pgid = pid (make process its own group leader) */
    if (pgid == 0) {
        pgid = pid;
    }

    /* Validate pgid */
    if ((int64_t)pgid < 0) {
        fut_printf("[PROC] setpgid(pid=%llu, pgid=%llu) -> EINVAL (negative pgid)\n", pid, pgid);
        return -EINVAL;
    }

    /* Find target task */
    fut_task_t *target;
    if (pid == current->pid) {
        target = current;
    } else {
        target = fut_task_by_pid(pid);
        if (!target) {
            fut_printf("[PROC] setpgid(pid=%llu, pgid=%llu) -> ESRCH (not found)\n", pid, pgid);
            return -ESRCH;
        }

        /* Can only setpgid on our own children */
        if (target->parent != current) {
            fut_printf("[PROC] setpgid(pid=%llu, pgid=%llu) -> ESRCH (not our child)\n", pid, pgid);
            return -ESRCH;
        }
    }

    /* Session leader cannot change its process group */
    if (target->pid == target->sid) {
        fut_printf("[PROC] setpgid(pid=%llu, pgid=%llu) -> EPERM (session leader)\n", pid, pgid);
        return -EPERM;
    }

    /* Target pgid must be in the same session */
    if (pgid != target->pid) {
        /* Check if pgid exists and is in same session */
        fut_task_t *pgrp_leader = fut_task_by_pid(pgid);
        if (!pgrp_leader) {
            /* Creating new process group - pgid must match target pid */
            if (pgid != pid) {
                fut_printf("[PROC] setpgid(pid=%llu, pgid=%llu) -> EPERM (pgid doesn't exist)\n", pid, pgid);
                return -EPERM;
            }
        } else if (pgrp_leader->sid != target->sid) {
            fut_printf("[PROC] setpgid(pid=%llu, pgid=%llu) -> EPERM (different session)\n", pid, pgid);
            return -EPERM;
        }
    }

    target->pgid = pgid;
    return 0;
}

/**
 * getsid(pid_t pid) - Get session ID
 *
 * Returns the session ID of the process specified by pid.
 *
 * @param pid  Process ID (0 = calling process)
 *
 * Returns:
 *   - Session ID of the specified process
 *   - -ESRCH if pid not found
 */
long sys_getsid(uint64_t pid) {
    fut_task_t *current = fut_task_current();
    if (!current) {
        return -ESRCH;
    }

    /* If pid is 0, use calling process */
    if (pid == 0) {
        return current->sid;
    }

    /* Look up target task */
    fut_task_t *target = fut_task_by_pid(pid);
    if (!target) {
        fut_printf("[PROC] getsid(pid=%llu) -> ESRCH (not found)\n", pid);
        return -ESRCH;
    }

    return target->sid;
}

/**
 * setsid() - Create new session
 *
 * Creates a new session where the calling process becomes the session leader.
 * The calling process becomes:
 * - The session leader of the new session
 * - The process group leader of a new process group
 * - Detached from any controlling terminal
 *
 * POSIX rules:
 * - The calling process must not already be a process group leader
 *
 * Returns:
 *   - Session ID (same as process PID) on success
 *   - -EPERM if already a process group leader
 */
long sys_setsid(void) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Cannot create new session if we're already a process group leader */
    if (task->pid == task->pgid) {
        fut_printf("[PROC] setsid() -> EPERM (already process group leader)\n");
        return -EPERM;
    }

    uint64_t old_sid = task->sid;
    uint64_t old_pgid = task->pgid;

    /* Become session leader and process group leader */
    task->sid = task->pid;
    task->pgid = task->pid;

    (void)old_sid;
    (void)old_pgid;
    return task->sid;
}

/**
 * getrlimit() - Get resource limits
 *
 * Returns the current resource limits for the specified resource.
 * Resource limits control the maximum amount of system resources
 * a process can consume.
 *
 * @param resource  Resource type (RLIMIT_NOFILE, RLIMIT_NPROC, etc.)
 * @param rlim      Pointer to rlimit structure to receive limits
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL if resource is invalid
 *   - -EFAULT if rlim points to invalid memory
 *
 * Phase 1 (Completed): Returns reasonable default limits
 * Phase 2 (Completed): Enhanced validation and resource type reporting
 * Phase 3 (Completed): Resource type identification and limit categorization
 * Phase 4 (Completed): Read stored per-task limits; fall back to defaults if unset
 */
long sys_getrlimit(int resource, struct rlimit *rlim) {
    if (!rlim) {
        fut_printf("[PROC] getrlimit(resource=%d, rlim=%p) -> EFAULT (rlim is NULL)\n", resource, rlim);
        return -EFAULT;
    }

    /* Identify resource type for error logging */
    const char *resource_name = "UNKNOWN";

    struct rlimit limit;

    /* Return reasonable default limits based on resource type */
    switch (resource) {
        case RLIMIT_NOFILE:
            resource_name = "RLIMIT_NOFILE";
            limit.rlim_cur = RLIMIT_NOFILE_SOFT_DEFAULT;
            limit.rlim_max = RLIMIT_NOFILE_HARD_DEFAULT;
            break;

        case RLIMIT_NPROC:
            resource_name = "RLIMIT_NPROC";
            limit.rlim_cur = RLIMIT_NPROC_SOFT_DEFAULT;
            limit.rlim_max = RLIMIT_NPROC_HARD_DEFAULT;
            break;

        case RLIMIT_STACK:
            resource_name = "RLIMIT_STACK";
            limit.rlim_cur = RLIMIT_STACK_SOFT_DEFAULT;
            limit.rlim_max = RLIM_INFINITY;
            break;

        case RLIMIT_DATA:
            resource_name = "RLIMIT_DATA";
            limit.rlim_cur = RLIM_INFINITY;
            limit.rlim_max = RLIM_INFINITY;
            break;

        case RLIMIT_AS:
            resource_name = "RLIMIT_AS";
            limit.rlim_cur = RLIM_INFINITY;
            limit.rlim_max = RLIM_INFINITY;
            break;

        case RLIMIT_CORE:
            resource_name = "RLIMIT_CORE";
            limit.rlim_cur = 0;         /* Disabled by default */
            limit.rlim_max = RLIM_INFINITY;
            break;

        case RLIMIT_CPU:
            resource_name = "RLIMIT_CPU";
            limit.rlim_cur = RLIM_INFINITY;
            limit.rlim_max = RLIM_INFINITY;
            break;

        case RLIMIT_FSIZE:
            resource_name = "RLIMIT_FSIZE";
            limit.rlim_cur = RLIM_INFINITY;
            limit.rlim_max = RLIM_INFINITY;
            break;

        case RLIMIT_RSS:
            resource_name = "RLIMIT_RSS";
            limit.rlim_cur = RLIM_INFINITY;
            limit.rlim_max = RLIM_INFINITY;
            break;

        case RLIMIT_MEMLOCK:
            resource_name = "RLIMIT_MEMLOCK";
            limit.rlim_cur = RLIMIT_MEMLOCK_DEFAULT;
            limit.rlim_max = RLIMIT_MEMLOCK_DEFAULT;
            break;

        case RLIMIT_LOCKS:
            resource_name = "RLIMIT_LOCKS";
            limit.rlim_cur = RLIM_INFINITY;
            limit.rlim_max = RLIM_INFINITY;
            break;

        case RLIMIT_SIGPENDING:
            resource_name = "RLIMIT_SIGPENDING";
            limit.rlim_cur = RLIMIT_SIGPENDING_DEFAULT;
            limit.rlim_max = RLIMIT_SIGPENDING_DEFAULT;
            break;

        case RLIMIT_MSGQUEUE:
            resource_name = "RLIMIT_MSGQUEUE";
            limit.rlim_cur = RLIMIT_MSGQUEUE_DEFAULT;
            limit.rlim_max = RLIMIT_MSGQUEUE_DEFAULT;
            break;

        case RLIMIT_NICE:
            resource_name = "RLIMIT_NICE";
            limit.rlim_cur = RLIMIT_NICE_DEFAULT;
            limit.rlim_max = RLIMIT_NICE_DEFAULT;
            break;

        case RLIMIT_RTPRIO:
            resource_name = "RLIMIT_RTPRIO";
            limit.rlim_cur = RLIMIT_RTPRIO_DEFAULT;
            limit.rlim_max = RLIMIT_RTPRIO_DEFAULT;
            break;

        case RLIMIT_RTTIME:
            resource_name = "RLIMIT_RTTIME";
            limit.rlim_cur = RLIM_INFINITY;
            limit.rlim_max = RLIM_INFINITY;
            break;

        default:
            fut_printf("[PROC] getrlimit(resource=%d, rlim=%p) -> EINVAL (unknown resource)\n",
                       resource, rlim);
            return -EINVAL;
    }

    /* Phase 4: Use per-task stored limits (initialized with defaults at task creation) */
    fut_task_t *task = fut_task_current();
    if (task) {
        limit.rlim_cur = task->rlimits[resource].rlim_cur;
        limit.rlim_max = task->rlimits[resource].rlim_max;
    }

    /* Copy limits to userspace */
    if (sys_proc_copy_to_user(rlim, &limit, sizeof(struct rlimit)) != 0) {
        fut_printf("[PROC] getrlimit(resource=%s, rlim=%p) -> EFAULT (copy_to_user failed)\n",
                   resource_name, rlim);
        return -EFAULT;
    }

    return 0;
}

/**
 * setrlimit() - Set resource limits
 *
 * Sets resource limits for the calling process.
 * Resource limits control the maximum amount of system resources
 * a process can consume.
 *
 * @param resource  Resource type (RLIMIT_NOFILE, RLIMIT_NPROC, etc.)
 * @param rlim      Pointer to rlimit structure with new limits
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL if resource is invalid or limits are invalid
 *   - -EFAULT if rlim points to invalid memory
 *   - -EPERM if trying to raise hard limit without privilege
 *
 * Validation:
 *   - Soft limit must be <= hard limit
 *   - Hard limit cannot be raised above current value (requires privilege)
 *
 * Phase 1 (Completed): Validates limits but doesn't enforce them
 * Phase 2 (Completed): Enhanced validation and resource type reporting
 * Phase 3 (Completed): Limit validation and resource-specific constraints
 * Phase 4 (Completed): Store limits in task->rlimits; getrlimit reads them back
 */
long sys_setrlimit(int resource, const struct rlimit *rlim) {
    if (!rlim) {
        fut_printf("[PROC] setrlimit(resource=%d, rlim=%p) -> EFAULT (rlim is NULL)\n",
                   resource, rlim);
        return -EFAULT;
    }

    /* Phase 2: Identify resource type for logging */
    const char *resource_name = "UNKNOWN";
    const char *resource_desc = "unknown resource";

    switch (resource) {
        case RLIMIT_NOFILE:
            resource_name = "RLIMIT_NOFILE";
            resource_desc = "max open file descriptors";
            break;
        case RLIMIT_NPROC:
            resource_name = "RLIMIT_NPROC";
            resource_desc = "max number of processes";
            break;
        case RLIMIT_STACK:
            resource_name = "RLIMIT_STACK";
            resource_desc = "max stack size";
            break;
        case RLIMIT_DATA:
            resource_name = "RLIMIT_DATA";
            resource_desc = "max data segment size";
            break;
        case RLIMIT_AS:
            resource_name = "RLIMIT_AS";
            resource_desc = "max address space";
            break;
        case RLIMIT_CORE:
            resource_name = "RLIMIT_CORE";
            resource_desc = "max core file size";
            break;
        case RLIMIT_CPU:
            resource_name = "RLIMIT_CPU";
            resource_desc = "max CPU time (seconds)";
            break;
        case RLIMIT_FSIZE:
            resource_name = "RLIMIT_FSIZE";
            resource_desc = "max file size";
            break;
        case RLIMIT_RSS:
            resource_name = "RLIMIT_RSS";
            resource_desc = "max resident set size";
            break;
        case RLIMIT_MEMLOCK:
            resource_name = "RLIMIT_MEMLOCK";
            resource_desc = "max locked memory";
            break;
        case RLIMIT_LOCKS:
            resource_name = "RLIMIT_LOCKS";
            resource_desc = "max file locks";
            break;
        case RLIMIT_SIGPENDING:
            resource_name = "RLIMIT_SIGPENDING";
            resource_desc = "max pending signals";
            break;
        case RLIMIT_MSGQUEUE:
            resource_name = "RLIMIT_MSGQUEUE";
            resource_desc = "max POSIX message queue bytes";
            break;
        case RLIMIT_NICE:
            resource_name = "RLIMIT_NICE";
            resource_desc = "max nice priority";
            break;
        case RLIMIT_RTPRIO:
            resource_name = "RLIMIT_RTPRIO";
            resource_desc = "max real-time priority";
            break;
        case RLIMIT_RTTIME:
            resource_name = "RLIMIT_RTTIME";
            resource_desc = "max real-time CPU time (us)";
            break;
        default:
            fut_printf("[PROC] setrlimit(resource=%d, rlim=%p) -> EINVAL (unknown resource)\n",
                       resource, rlim);
            return -EINVAL;
    }

    /* Copy limits from userspace */
    struct rlimit new_limit;
    if (sys_proc_copy_from_user(&new_limit, rlim, sizeof(struct rlimit)) != 0) {
        fut_printf("[PROC] setrlimit(resource=%s [%s], rlim=%p) -> EFAULT (copy_from_user failed)\n",
                   resource_name, resource_desc, rlim);
        return -EFAULT;
    }

    /* Validate that soft limit <= hard limit.
     * RLIM_INFINITY is the maximum value, so soft=INFINITY is only valid
     * when hard=INFINITY. */
    if (new_limit.rlim_cur > new_limit.rlim_max) {
        fut_printf("[PROC] setrlimit(resource=%s [%s]) -> EINVAL (soft=%llu > hard=%llu)\n",
                   resource_name, resource_desc,
                   (unsigned long long)new_limit.rlim_cur,
                   (unsigned long long)new_limit.rlim_max);
        return -EINVAL;
    }

    /* Phase 2: Resource-specific validation */
    if (resource == RLIMIT_NOFILE && new_limit.rlim_cur == 0) {
        /* Cannot set NOFILE to 0 - process needs at least stdin/stdout/stderr */
        fut_printf("[PROC] setrlimit(resource=%s [%s]) -> EINVAL (cannot set to 0, need stdin/stdout/stderr)\n",
                   resource_name, resource_desc);
        return -EINVAL;
    }

    if (resource == RLIMIT_STACK &&
        new_limit.rlim_cur != RLIM_INFINITY &&
        new_limit.rlim_cur < 4096) {
        /* Stack too small to be useful */
        fut_printf("[PROC] setrlimit(resource=%s [%s]) -> EINVAL (soft=%llu too small, minimum 4096 bytes)\n",
                   resource_name, resource_desc, new_limit.rlim_cur);
        return -EINVAL;
    }

    /* Phase 4: Store limits in task->rlimits so getrlimit can retrieve them */
    fut_task_t *task = fut_task_current();
    if (task) {
        /* Raising hard limit requires root or CAP_SYS_RESOURCE.
         * RLIM_INFINITY is treated as the maximum possible value, so raising
         * to it also requires privilege. */
        if (new_limit.rlim_max > task->rlimits[resource].rlim_max) {
            if (task->uid != 0 &&
                !(task->cap_effective & (1ULL << 24 /* CAP_SYS_RESOURCE */))) {
                return -EPERM;
            }
        }
        task->rlimits[resource].rlim_cur = new_limit.rlim_cur;
        task->rlimits[resource].rlim_max = new_limit.rlim_max;
    }

    return 0;
}
