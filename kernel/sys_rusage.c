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
 * Phase 1 (Completed): Returns zeroed statistics
 * Phase 2 (Completed): Enhanced validation and detailed reporting
 * Phase 3 (Completed): Zeroed statistics with who parameter categorization
 * Phase 4: Track CPU time (user/system) per task
 * Phase 5: Track memory usage (maxrss, page faults)
 * Phase 6: Track I/O statistics (inblock, oublock)
 */
long sys_getrusage(int who, struct rusage *usage) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[RUSAGE] getrusage(who=%d, usage=%p) -> ESRCH (no current task)\n", who, usage);
        return -ESRCH;
    }

    if (!usage) {
        fut_printf("[RUSAGE] getrusage(who=%d, usage=%p) -> EFAULT (usage is NULL)\n", who, usage);
        return -EFAULT;
    }

    /* Phase 2: Validate and identify 'who' parameter */
    const char *who_desc;
    const char *target_desc;

    switch (who) {
        case RUSAGE_SELF:
            who_desc = "RUSAGE_SELF";
            target_desc = "calling process";
            break;
        case RUSAGE_CHILDREN:
            who_desc = "RUSAGE_CHILDREN";
            target_desc = "terminated children";
            break;
        case RUSAGE_THREAD:
            who_desc = "RUSAGE_THREAD";
            target_desc = "calling thread";
            break;
        default:
            fut_printf("[RUSAGE] getrusage(who=%d, usage=%p) -> EINVAL (invalid who parameter)\n",
                       who, usage);
            return -EINVAL;
    }

    /* Phase 2: Return zeroed statistics with detailed reporting
     * Phase 3+: Will populate from task structure and scheduler stats */
    struct rusage ru;
    memset(&ru, 0, sizeof(ru));

    /* Future phases will populate from task statistics:
     *
     * Phase 3: CPU time tracking
     * - ru_utime: task->cpu_time_user (from scheduler)
     * - ru_stime: task->cpu_time_system (from scheduler)
     *
     * Phase 4: Memory usage tracking
     * - ru_maxrss: task->mm->max_rss (from memory manager)
     * - ru_minflt: task->mm->page_faults_minor (soft page faults)
     * - ru_majflt: task->mm->page_faults_major (hard page faults)
     *
     * Phase 5: I/O statistics tracking
     * - ru_inblock: task->io_stats->blocks_read (from VFS/block layer)
     * - ru_oublock: task->io_stats->blocks_written (from VFS/block layer)
     *
     * Phase 6: Context switch tracking
     * - ru_nvcsw: task->sched_stats->voluntary_switches (from scheduler)
     * - ru_nivcsw: task->sched_stats->involuntary_switches (from scheduler)
     *
     * For RUSAGE_CHILDREN: Aggregate stats from all waited-for children
     * For RUSAGE_THREAD: Use thread-specific counters instead of process-wide
     */

    /* Copy to userspace */
    if (fut_copy_to_user(usage, &ru, sizeof(struct rusage)) != 0) {
        fut_printf("[RUSAGE] getrusage(who=%s, usage=%p) -> EFAULT (copy_to_user failed)\n",
                   who_desc, usage);
        return -EFAULT;
    }

    /* Phase 3: Detailed logging with zeroed statistics report */
    fut_printf("[RUSAGE] getrusage(who=%s [%s], usage=%p) -> 0 "
               "(Phase 3: Zeroed statistics with who parameter categorization)\n",
               who_desc, target_desc, usage);

    return 0;
}
