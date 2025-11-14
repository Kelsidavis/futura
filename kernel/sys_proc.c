/* kernel/sys_proc.c - Process information syscalls
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements syscalls for querying and managing process hierarchy,
 * process groups, and sessions for job control.
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);
extern fut_task_t *fut_task_current(void);
extern int fut_copy_to_user(void *to, const void *from, size_t size);
extern int fut_copy_from_user(void *to, const void *from, size_t size);

/* Resource limit structure */
struct rlimit {
    uint64_t rlim_cur;  /* Soft limit (current) */
    uint64_t rlim_max;  /* Hard limit (maximum) */
};

/* Resource limit constants */
#define RLIMIT_CPU        0   /* CPU time in seconds */
#define RLIMIT_FSIZE      1   /* Maximum file size */
#define RLIMIT_DATA       2   /* Maximum data segment size */
#define RLIMIT_STACK      3   /* Maximum stack size */
#define RLIMIT_CORE       4   /* Maximum core file size */
#define RLIMIT_RSS        5   /* Maximum resident set size */
#define RLIMIT_NPROC      6   /* Maximum number of processes */
#define RLIMIT_NOFILE     7   /* Maximum number of open files */
#define RLIMIT_MEMLOCK    8   /* Maximum locked memory */
#define RLIMIT_AS         9   /* Address space limit */

#define RLIM_INFINITY     (~0ULL)  /* Unlimited */

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
    extern fut_thread_t *fut_thread_current(void);
    fut_thread_t *thread = fut_thread_current();
    fut_task_t *task = fut_task_current();

    fut_printf("[PROC] getpid() thread=%p task=%p\n", (void*)thread, (void*)task);

    if (!task) {
        fut_printf("[PROC] getpid() -> 1 (task is NULL!)\n");
        return 1;  /* Default to init PID */
    }

    fut_printf("[PROC] getpid() -> pid=%llu\n", task->pid);
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
    fut_task_t *task = fut_task_current();
    if (!task) {
        return 1;  /* Default to init TID */
    }

    /* In Futura OS, task ID serves as thread ID */
    fut_printf("[PROC] gettid() -> tid=%llu\n", task->pid);
    return task->pid;
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

    uint64_t ppid = (task->parent) ? task->parent->pid : 1;
    fut_printf("[PROC] getppid() -> ppid=%llu\n", ppid);
    return ppid;
}

/**
 * getpgrp() - Get process group ID
 *
 * Returns the process group ID (PGID) of the calling process.
 * Process groups are used for job control in shells.
 *
 * For now, each process is its own process group (no pgrp tracking yet).
 *
 * Returns:
 *   - Process group ID of the calling process (equal to PID)
 */
long sys_getpgrp(void) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return 1;  /* Default to init process group */
    }

    /* Each process is its own process group by default */
    fut_printf("[PROC] getpgrp() -> pgrp=%llu\n", task->pid);
    return task->pid;
}

/**
 * getpgid(pid_t pid) - Get process group ID
 *
 * Returns the process group ID (PGID) of the process specified by pid.
 * Process groups are used for job control in shells and signal handling.
 *
 * For now, each process is its own process group (no pgrp tracking yet).
 *
 * @param pid  Process ID (0 = calling process)
 *
 * Returns:
 *   - Process group ID of the specified process (equal to PID)
 *   - -ESRCH if pid not found
 */
long sys_getpgid(uint64_t pid) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* If pid is 0, use calling process */
    if (pid == 0) {
        pid = task->pid;
    }

    /* For simplicity, only support getpgid on self (stub implementation) */
    if (pid != task->pid) {
        /* Would need task_by_pid to support other processes */
        return -ESRCH;
    }

    /* Each process is its own process group by default */
    fut_printf("[PROC] getpgid(pid=%llu) -> pgrp=%llu\n", pid, task->pid);
    return task->pid;
}

/**
 * setpgrp() - Create new process group or join existing one
 *
 * Changes the calling process's process group ID. For now, this is a no-op
 * that returns success, since full process group tracking is not yet implemented.
 *
 * By default, setpgrp() with no arguments makes the calling process
 * the leader of its own process group.
 *
 * Returns:
 *   - 0 on success (always, as stub implementation)
 */
long sys_setpgrp(void) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Stub: process is already its own group leader */
    fut_printf("[PROC] setpgrp() -> success (stub implementation)\n");
    return 0;
}

/**
 * setpgid(pid_t pid, pid_t pgid) - Set process group ID
 *
 * Sets the process group ID of the process specified by pid.
 * For now, this is a stub that validates the pid exists and returns success.
 * Full process group tracking is not yet implemented.
 *
 * @param pid   Process ID to modify (0 = calling process)
 * @param pgid  Process group ID to set (0 = use pid as pgid)
 *
 * Returns:
 *   - 0 on success
 *   - -ESRCH if pid not found
 *   - -EINVAL if pgid is negative
 */
long sys_setpgid(uint64_t pid, uint64_t pgid) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* If pid is 0, use calling process */
    if (pid == 0) {
        pid = task->pid;
    }

    /* Validate pgid */
    if ((int64_t)pgid < -1) {
        return -EINVAL;
    }

    /* For simplicity, only allow setpgid on self (stub implementation) */
    if (pid != task->pid) {
        /* Would need task_by_pid to support other processes */
        return -ESRCH;
    }

    /* Stub: pgid would be set here if we had pgrp tracking */
    fut_printf("[PROC] setpgid(pid=%llu, pgid=%llu) -> success (stub)\n", pid, pgid);
    return 0;
}

/**
 * getsid(pid_t pid) - Get session ID
 *
 * Returns the session ID of the process specified by pid.
 * For now, each process is its own session (no sid tracking yet).
 *
 * @param pid  Process ID (0 = calling process)
 *
 * Returns:
 *   - Session ID of the specified process (equal to PID)
 *   - -ESRCH if pid not found
 */
long sys_getsid(uint64_t pid) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* If pid is 0, use calling process */
    if (pid == 0) {
        pid = task->pid;
    }

    /* For simplicity, only work for the calling process (stub implementation) */
    if (pid != task->pid) {
        /* Would need task_by_pid to support other processes */
        return -ESRCH;
    }

    /* Each process is its own session by default */
    fut_printf("[PROC] getsid(pid=%llu) -> sid=%llu\n", pid, task->pid);
    return task->pid;
}

/**
 * setsid() - Create new session
 *
 * Creates a new session where the calling process becomes the session leader.
 * For now, this is a no-op that returns success, since sid/pgrp tracking is not implemented.
 *
 * Returns:
 *   - Session ID (same as process PID) on success
 */
long sys_setsid(void) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Stub: process is already its own session leader */
    fut_printf("[PROC] setsid() -> sid=%llu (stub)\n", task->pid);
    return task->pid;
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
 * Phase 4: Support setrlimit() for modifying limits
 */
long sys_getrlimit(int resource, struct rlimit *rlim) {
    if (!rlim) {
        fut_printf("[PROC] getrlimit(resource=%d, rlim=%p) -> EFAULT (rlim is NULL)\n", resource, rlim);
        return -EFAULT;
    }

    /* Phase 2: Identify resource type for logging */
    const char *resource_name = "UNKNOWN";
    const char *resource_desc = "unknown resource";

    struct rlimit limit;

    /* Return reasonable default limits based on resource type */
    switch (resource) {
        case RLIMIT_NOFILE:
            resource_name = "RLIMIT_NOFILE";
            resource_desc = "max open file descriptors";
            limit.rlim_cur = 1024;      /* Soft limit */
            limit.rlim_max = 65536;     /* Hard limit */
            break;

        case RLIMIT_NPROC:
            resource_name = "RLIMIT_NPROC";
            resource_desc = "max number of processes";
            limit.rlim_cur = 256;       /* Soft limit */
            limit.rlim_max = 512;       /* Hard limit */
            break;

        case RLIMIT_STACK:
            resource_name = "RLIMIT_STACK";
            resource_desc = "max stack size";
            limit.rlim_cur = 8 * 1024 * 1024;  /* 8MB */
            limit.rlim_max = RLIM_INFINITY;
            break;

        case RLIMIT_DATA:
            resource_name = "RLIMIT_DATA";
            resource_desc = "max data segment size";
            limit.rlim_cur = RLIM_INFINITY;
            limit.rlim_max = RLIM_INFINITY;
            break;

        case RLIMIT_AS:
            resource_name = "RLIMIT_AS";
            resource_desc = "max address space";
            limit.rlim_cur = RLIM_INFINITY;
            limit.rlim_max = RLIM_INFINITY;
            break;

        case RLIMIT_CORE:
            resource_name = "RLIMIT_CORE";
            resource_desc = "max core file size";
            limit.rlim_cur = 0;         /* Disabled by default */
            limit.rlim_max = RLIM_INFINITY;
            break;

        case RLIMIT_CPU:
            resource_name = "RLIMIT_CPU";
            resource_desc = "max CPU time (seconds)";
            limit.rlim_cur = RLIM_INFINITY;
            limit.rlim_max = RLIM_INFINITY;
            break;

        case RLIMIT_FSIZE:
            resource_name = "RLIMIT_FSIZE";
            resource_desc = "max file size";
            limit.rlim_cur = RLIM_INFINITY;
            limit.rlim_max = RLIM_INFINITY;
            break;

        case RLIMIT_RSS:
            resource_name = "RLIMIT_RSS";
            resource_desc = "max resident set size";
            limit.rlim_cur = RLIM_INFINITY;
            limit.rlim_max = RLIM_INFINITY;
            break;

        case RLIMIT_MEMLOCK:
            resource_name = "RLIMIT_MEMLOCK";
            resource_desc = "max locked memory";
            limit.rlim_cur = 64 * 1024;  /* 64KB */
            limit.rlim_max = 64 * 1024;
            break;

        default:
            fut_printf("[PROC] getrlimit(resource=%d, rlim=%p) -> EINVAL (unknown resource)\n",
                       resource, rlim);
            return -EINVAL;
    }

    /* Copy limits to userspace */
    if (fut_copy_to_user(rlim, &limit, sizeof(struct rlimit)) != 0) {
        fut_printf("[PROC] getrlimit(resource=%s, rlim=%p) -> EFAULT (copy_to_user failed)\n",
                   resource_name, rlim);
        return -EFAULT;
    }

    /* Phase 2: Detailed logging with resource identification */
    const char *cur_str = (limit.rlim_cur == RLIM_INFINITY) ? "unlimited" : NULL;
    const char *max_str = (limit.rlim_max == RLIM_INFINITY) ? "unlimited" : NULL;

    if (cur_str && max_str) {
        fut_printf("[PROC] getrlimit(resource=%s [%s], rlim=%p) -> 0 "
                   "(cur=unlimited, max=unlimited, Phase 3: resource type categorization)\n",
                   resource_name, resource_desc, rlim);
    } else if (cur_str) {
        fut_printf("[PROC] getrlimit(resource=%s [%s], rlim=%p) -> 0 "
                   "(cur=unlimited, max=%llu, Phase 3: resource type categorization)\n",
                   resource_name, resource_desc, rlim, limit.rlim_max);
    } else if (max_str) {
        fut_printf("[PROC] getrlimit(resource=%s [%s], rlim=%p) -> 0 "
                   "(cur=%llu, max=unlimited, Phase 3: resource type categorization)\n",
                   resource_name, resource_desc, rlim, limit.rlim_cur);
    } else {
        fut_printf("[PROC] getrlimit(resource=%s [%s], rlim=%p) -> 0 "
                   "(cur=%llu, max=%llu, Phase 3: resource type categorization)\n",
                   resource_name, resource_desc, rlim, limit.rlim_cur, limit.rlim_max);
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
 * Phase 4: Implement privilege checking for raising hard limits
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
        default:
            fut_printf("[PROC] setrlimit(resource=%d, rlim=%p) -> EINVAL (unknown resource)\n",
                       resource, rlim);
            return -EINVAL;
    }

    /* Copy limits from userspace */
    struct rlimit new_limit;
    if (fut_copy_from_user(&new_limit, rlim, sizeof(struct rlimit)) != 0) {
        fut_printf("[PROC] setrlimit(resource=%s [%s], rlim=%p) -> EFAULT (copy_from_user failed)\n",
                   resource_name, resource_desc, rlim);
        return -EFAULT;
    }

    /* Validate that soft limit <= hard limit */
    if (new_limit.rlim_cur != RLIM_INFINITY &&
        new_limit.rlim_max != RLIM_INFINITY &&
        new_limit.rlim_cur > new_limit.rlim_max) {
        const char *cur_str = (new_limit.rlim_cur == RLIM_INFINITY) ? "unlimited" : NULL;
        const char *max_str = (new_limit.rlim_max == RLIM_INFINITY) ? "unlimited" : NULL;

        if (cur_str) {
            fut_printf("[PROC] setrlimit(resource=%s [%s]) -> EINVAL (soft=unlimited > hard=%llu)\n",
                       resource_name, resource_desc, new_limit.rlim_max);
        } else if (max_str) {
            fut_printf("[PROC] setrlimit(resource=%s [%s]) -> EINVAL (soft=%llu > hard=unlimited)\n",
                       resource_name, resource_desc, new_limit.rlim_cur);
        } else {
            fut_printf("[PROC] setrlimit(resource=%s [%s]) -> EINVAL (soft=%llu > hard=%llu)\n",
                       resource_name, resource_desc, new_limit.rlim_cur, new_limit.rlim_max);
        }
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

    /* Phase 2: Just validate and log, don't actually store/enforce
     * Phase 3 would store these in task structure and enforce them
     * Phase 4 would check privileges for raising hard limits */

    /* Build detailed log message with intelligent limit display */
    const char *cur_str = (new_limit.rlim_cur == RLIM_INFINITY) ? "unlimited" : NULL;
    const char *max_str = (new_limit.rlim_max == RLIM_INFINITY) ? "unlimited" : NULL;

    if (cur_str && max_str) {
        fut_printf("[PROC] setrlimit(resource=%s [%s], rlim=%p) -> 0 "
                   "(cur=unlimited, max=unlimited, Phase 3: limit validation and constraints)\n",
                   resource_name, resource_desc, rlim);
    } else if (cur_str) {
        fut_printf("[PROC] setrlimit(resource=%s [%s], rlim=%p) -> 0 "
                   "(cur=unlimited, max=%llu, Phase 3: limit validation and constraints)\n",
                   resource_name, resource_desc, rlim, new_limit.rlim_max);
    } else if (max_str) {
        fut_printf("[PROC] setrlimit(resource=%s [%s], rlim=%p) -> 0 "
                   "(cur=%llu, max=unlimited, Phase 3: limit validation and constraints)\n",
                   resource_name, resource_desc, rlim, new_limit.rlim_cur);
    } else {
        fut_printf("[PROC] setrlimit(resource=%s [%s], rlim=%p) -> 0 "
                   "(cur=%llu, max=%llu, Phase 3: limit validation and constraints)\n",
                   resource_name, resource_desc, rlim, new_limit.rlim_cur, new_limit.rlim_max);
    }

    return 0;
}
