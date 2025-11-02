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
    fut_task_t *task = fut_task_current();
    if (!task) {
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
 * Phase 1 (Current): Returns reasonable default limits
 * Phase 2: Track per-process resource usage and enforce limits
 * Phase 3: Support setrlimit() for modifying limits
 */
long sys_getrlimit(int resource, struct rlimit *rlim) {
    if (!rlim) {
        return -EFAULT;
    }

    struct rlimit limit;

    /* Return reasonable default limits based on resource type */
    switch (resource) {
        case RLIMIT_NOFILE:
            /* Maximum number of open file descriptors */
            limit.rlim_cur = 1024;      /* Soft limit */
            limit.rlim_max = 65536;     /* Hard limit */
            break;

        case RLIMIT_NPROC:
            /* Maximum number of processes */
            limit.rlim_cur = 256;       /* Soft limit */
            limit.rlim_max = 512;       /* Hard limit */
            break;

        case RLIMIT_STACK:
            /* Maximum stack size (8MB default, unlimited max) */
            limit.rlim_cur = 8 * 1024 * 1024;
            limit.rlim_max = RLIM_INFINITY;
            break;

        case RLIMIT_DATA:
            /* Maximum data segment size */
            limit.rlim_cur = RLIM_INFINITY;
            limit.rlim_max = RLIM_INFINITY;
            break;

        case RLIMIT_AS:
            /* Maximum address space */
            limit.rlim_cur = RLIM_INFINITY;
            limit.rlim_max = RLIM_INFINITY;
            break;

        case RLIMIT_CORE:
            /* Maximum core file size (disabled by default) */
            limit.rlim_cur = 0;
            limit.rlim_max = RLIM_INFINITY;
            break;

        case RLIMIT_CPU:
            /* CPU time limit in seconds */
            limit.rlim_cur = RLIM_INFINITY;
            limit.rlim_max = RLIM_INFINITY;
            break;

        case RLIMIT_FSIZE:
            /* Maximum file size */
            limit.rlim_cur = RLIM_INFINITY;
            limit.rlim_max = RLIM_INFINITY;
            break;

        case RLIMIT_RSS:
            /* Maximum resident set size */
            limit.rlim_cur = RLIM_INFINITY;
            limit.rlim_max = RLIM_INFINITY;
            break;

        case RLIMIT_MEMLOCK:
            /* Maximum locked memory */
            limit.rlim_cur = 64 * 1024;  /* 64KB */
            limit.rlim_max = 64 * 1024;
            break;

        default:
            fut_printf("[PROC] getrlimit: unknown resource %d\n", resource);
            return -EINVAL;
    }

    /* Copy limits to userspace */
    if (fut_copy_to_user(rlim, &limit, sizeof(struct rlimit)) != 0) {
        return -EFAULT;
    }

    fut_printf("[PROC] getrlimit(resource=%d) -> cur=%llu, max=%llu\n",
               resource, limit.rlim_cur, limit.rlim_max);

    return 0;
}
