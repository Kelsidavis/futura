/* kernel/sys_rusage.c - Resource usage statistics syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements getrusage() for retrieving process resource usage statistics.
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <shared/fut_timeval.h>
#include <string.h>

extern void fut_printf(const char *fmt, ...);
extern fut_task_t *fut_task_current(void);
extern int fut_copy_to_user(void *to, const void *from, size_t size);
extern uint64_t fut_get_ticks(void);

/* rusage structure - resource usage statistics */
struct rusage {
    fut_timeval_t ru_utime;    /* User CPU time used */
    fut_timeval_t ru_stime;    /* System CPU time used */
    long ru_maxrss;            /* Maximum resident set size (KB) */
    long ru_ixrss;             /* Integral shared memory size */
    long ru_idrss;             /* Integral unshared data size */
    long ru_isrss;             /* Integral unshared stack size */
    long ru_minflt;            /* Page reclaims (soft page faults) */
    long ru_majflt;            /* Page faults (hard page faults) */
    long ru_nswap;             /* Swaps */
    long ru_inblock;           /* Block input operations */
    long ru_oublock;           /* Block output operations */
    long ru_msgsnd;            /* IPC messages sent */
    long ru_msgrcv;            /* IPC messages received */
    long ru_nsignals;          /* Signals received */
    long ru_nvcsw;             /* Voluntary context switches */
    long ru_nivcsw;            /* Involuntary context switches */
};

/* getrusage() 'who' parameter values */
#define RUSAGE_SELF     0   /* Calling process */
#define RUSAGE_CHILDREN -1  /* Terminated and waited-for children */
#define RUSAGE_THREAD   1   /* Calling thread (Linux extension) */

/**
 * getrusage() - Get resource usage statistics
 *
 * Returns resource usage measures for the specified process, its children,
 * or the calling thread. Includes CPU time, memory usage, and I/O counters.
 *
 * @param who   Target: RUSAGE_SELF, RUSAGE_CHILDREN, or RUSAGE_THREAD
 * @param usage Pointer to rusage structure to receive statistics
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL if who is invalid
 *   - -EFAULT if usage points to invalid memory
 *
 * Phase 1 (Current): Returns zeroed statistics
 * Phase 2: Track CPU time (user/system) per task
 * Phase 3: Track memory usage (maxrss, page faults)
 * Phase 4: Track I/O statistics (inblock, oublock)
 * Phase 5: Track context switches (nvcsw, nivcsw)
 */
long sys_getrusage(int who, struct rusage *usage) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    if (!usage) {
        return -EFAULT;
    }

    /* Validate 'who' parameter */
    if (who != RUSAGE_SELF && who != RUSAGE_CHILDREN && who != RUSAGE_THREAD) {
        fut_printf("[RUSAGE] getrusage: invalid who=%d\n", who);
        return -EINVAL;
    }

    /* Phase 1: Return zeroed statistics
     * Phase 2+: Will populate from task structure and scheduler stats */
    struct rusage ru;
    memset(&ru, 0, sizeof(ru));

    /* Future phases will populate:
     * - ru_utime: task->cpu_time_user (from scheduler)
     * - ru_stime: task->cpu_time_system (from scheduler)
     * - ru_maxrss: task->mm->max_rss (from memory manager)
     * - ru_minflt/majflt: task->mm->page_faults (from VMM)
     * - ru_inblock/oublock: task->io_stats (from VFS/block layer)
     * - ru_nvcsw/nivcsw: task->ctx_switches (from scheduler)
     */

    /* Copy to userspace */
    if (fut_copy_to_user(usage, &ru, sizeof(struct rusage)) != 0) {
        return -EFAULT;
    }

    fut_printf("[RUSAGE] getrusage(who=%d) -> success (zeroed statistics - Phase 1)\n", who);

    return 0;
}
