/* kernel/sys_rusage.c - Resource usage statistics syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements getrusage() for retrieving process resource usage statistics.
 */

#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
#include <kernel/fut_stats.h>
#include <kernel/fut_mm.h>
#include <kernel/errno.h>
#include <shared/fut_timeval.h>
#include <string.h>

#include <kernel/kprintf.h>
#include <kernel/uaccess.h>
#include <kernel/fut_timer.h>
#include <platform/platform.h>

static inline int rusage_access_ok_write(const void *ptr, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)ptr >= KERNEL_VIRTUAL_BASE)
        return 0;  /* Kernel pointer: always accessible */
#endif
    return fut_access_ok(ptr, n, 1);
}

static inline int rusage_copy_to_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)dst >= KERNEL_VIRTUAL_BASE) {
        __builtin_memcpy(dst, src, n);
        return 0;
    }
#endif
    return fut_copy_to_user(dst, src, n);
}

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
 * Phase 4 (Completed): CPU time from thread stats; fix per-task vs global thread list
 * Phase 5 (Completed): Compute ru_maxrss from mm VMA list (total mapped bytes / 1024)
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

    /* Validate usage write permission early (kernel writes statistics)
     * VULNERABILITY: Invalid Output Buffer Pointer
     * ATTACK: Attacker provides read-only or unmapped usage buffer
     * IMPACT: Kernel page fault when writing resource usage statistics
     * DEFENSE: Check write permission before processing */
    if (rusage_access_ok_write(usage, sizeof(struct rusage)) != 0) {
        fut_printf("[RUSAGE] getrusage(who=%d, usage=%p) -> EFAULT (buffer not writable for %zu bytes)\n",
                   who, usage, sizeof(struct rusage));
        return -EFAULT;
    }

    /* Phase 2: Validate and identify 'who' parameter */
    const char *who_desc;

    switch (who) {
        case RUSAGE_SELF:
            who_desc = "RUSAGE_SELF";
            break;
        case RUSAGE_CHILDREN:
            who_desc = "RUSAGE_CHILDREN";
            break;
        case RUSAGE_THREAD:
            who_desc = "RUSAGE_THREAD";
            break;
        default:
            fut_printf("[RUSAGE] getrusage(who=%d, usage=%p) -> EINVAL (invalid who parameter)\n",
                       who, usage);
            return -EINVAL;
    }

    /*
     * Phase 3 (Completed): Populate CPU time and context switch counts from scheduler stats.
     * cpu_ticks is in timer ticks (FUT_TIMER_HZ = 100 Hz, so each tick = 10ms).
     * Since user/kernel time is not tracked separately, all attributed to ru_utime.
     * context_switches is used for ru_nvcsw (voluntary not separated from involuntary).
     */
    struct rusage ru;
    memset(&ru, 0, sizeof(ru));

    if (who == RUSAGE_SELF || who == RUSAGE_THREAD) {
        uint64_t total_ticks = 0;
        uint64_t total_switches = 0;

        if (who == RUSAGE_THREAD) {
            /* Single calling thread */
            fut_thread_t *t = fut_thread_current();
            if (t) {
                total_ticks   = t->stats.cpu_ticks;
                total_switches = t->stats.context_switches;
            }
        } else {
            /* All threads of the task — use per-task ->next link, not global list */
            for (fut_thread_t *t = task->threads; t != nullptr; t = t->next) {
                total_ticks   += t->stats.cpu_ticks;
                total_switches += t->stats.context_switches;
            }
        }

        /* Convert ticks to timeval (10ms per tick at 100Hz) */
        uint64_t usec_total = total_ticks * (1000000UL / FUT_TIMER_HZ);
        ru.ru_utime.tv_sec  = (long)(usec_total / 1000000UL);
        ru.ru_utime.tv_usec = (long)(usec_total % 1000000UL);
        ru.ru_nvcsw = (long)total_switches;
    }
    if (who == RUSAGE_CHILDREN) {
        /* Accumulated by waitpid when reaping zombie children */
        uint64_t child_ticks = task->child_cpu_ticks;
        uint64_t child_usec = child_ticks * (1000000UL / FUT_TIMER_HZ);
        ru.ru_utime.tv_sec  = (long)(child_usec / 1000000UL);
        ru.ru_utime.tv_usec = (long)(child_usec % 1000000UL);
        ru.ru_nvcsw  = (long)task->child_context_switches;
        ru.ru_maxrss = (long)task->child_maxrss_kb;
    }

    /*
     * Phase 5: Compute ru_maxrss from the task's VMA list.
     * ru_maxrss is in kilobytes on Linux. Since this kernel has no swap, all
     * mapped pages are resident, so total VMA size is a good approximation.
     * We sum (vma->end - vma->start) across all VMAs and divide by 1024.
     */
    if (who == RUSAGE_SELF || who == RUSAGE_THREAD) {
        fut_mm_t *mm = fut_task_get_mm(task);
        if (mm) {
            size_t total_bytes = 0;
            for (struct fut_vma *vma = mm->vma_list; vma != nullptr; vma = vma->next) {
                if (vma->end > vma->start)
                    total_bytes += vma->end - vma->start;
            }
            ru.ru_maxrss = (long)(total_bytes / 1024);
        }
    }

    /* Phase 6: Populate I/O block accounting from per-task syscall counters.
     * Linux uses disk block operations; we approximate with syscall counts. */
    if (who == RUSAGE_SELF || who == RUSAGE_THREAD) {
        ru.ru_inblock  = (long)task->io_syscr;
        ru.ru_oublock  = (long)task->io_syscw;
    }

    /* Phase 7: Page fault counters from per-task accounting. */
    if (who == RUSAGE_SELF || who == RUSAGE_THREAD) {
        ru.ru_minflt = (long)task->minflt;
        ru.ru_majflt = (long)task->majflt;
    }
    if (who == RUSAGE_CHILDREN) {
        ru.ru_minflt = (long)task->child_minflt;
        ru.ru_majflt = (long)task->child_majflt;
    }

    /* Copy to userspace */
    if (rusage_copy_to_user(usage, &ru, sizeof(struct rusage)) != 0) {
        fut_printf("[RUSAGE] getrusage(who=%s, usage=%p) -> EFAULT (copy_to_user failed)\n",
                   who_desc, usage);
        return -EFAULT;
    }

    return 0;
}
