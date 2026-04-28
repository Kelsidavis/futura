/* kernel/sys_times.c - Process time accounting syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements times() for retrieving process CPU times in clock ticks.
 */

#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
#include <kernel/fut_stats.h>
#include <kernel/errno.h>
#include <string.h>
#include <sys/times.h>

#include <kernel/kprintf.h>
#include <kernel/uaccess.h>
#include <kernel/fut_timer.h>
#include <platform/platform.h>

static inline int times_access_ok_write(const void *ptr, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)ptr >= KERNEL_VIRTUAL_BASE)
        return 0;  /* Kernel pointer: always accessible */
#endif
    return fut_access_ok(ptr, n, 1);
}

static inline int times_copy_to_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)dst >= KERNEL_VIRTUAL_BASE) {
        __builtin_memcpy(dst, src, n);
        return 0;
    }
#endif
    return fut_copy_to_user(dst, src, n);
}

/* clock_t and struct tms provided by sys/times.h */

/* Clock ticks per second (user hertz) - typically 100 */
#define USER_HZ 100

/**
 * times() - Get process times
 *
 * Stores the current process times (in clock ticks) in the tms structure
 * and returns the elapsed time since an arbitrary point in the past.
 * This is simpler than getrusage() but provides similar CPU time information.
 *
 * @param buf Pointer to tms structure to receive time values
 *
 * Returns:
 *   - Elapsed clock ticks since arbitrary point (typically boot)
 *   - -EFAULT if buf points to invalid memory
 *
 * Note: Unlike most syscalls, times() returns elapsed ticks on success,
 *       not 0. It may return (clock_t)-1 on error, but this is also a
 *       valid elapsed time, so errno must be checked.
 *
 * Times are measured in clock ticks (USER_HZ per second, typically 100).
 * To convert to seconds: seconds = ticks / USER_HZ
 *
 * Phase 1 (Completed): Returns zero times and current tick count
 * Phase 2 (Completed): Enhanced validation and detailed time reporting
 * Phase 3 (Completed): Track and return actual CPU times from scheduler
 * Phase 4 (Completed): Accumulate child times from reaped children via child_cpu_ticks
 */
long sys_times(struct tms *buf) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[TIMES] times(buf=%p) -> ESRCH (no current task)\n", buf);
        return -ESRCH;
    }

    /* Linux's sys_times accepts buf == NULL — when no struct is
     * supplied the syscall still returns the elapsed clock ticks.
     * The previous EFAULT gate broke that documented contract
     * (times(2) man page: 'tms is NULL ... just returns the
     * elapsed time'). Skip the access_ok / copy_to_user steps
     * entirely when buf is NULL, but still compute and return
     * the elapsed-tick value below. */
    if (buf && times_access_ok_write(buf, sizeof(struct tms)) != 0) {
        fut_printf("[TIMES] times(buf=%p) -> EFAULT (buffer not writable for %zu bytes)\n",
                   buf, sizeof(struct tms));
        return -EFAULT;
    }

    /*
     * Phase 3 (Completed): Sum cpu_ticks across all threads of this task.
     * cpu_ticks is incremented every timer tick while the thread runs.
     * Since user/kernel time is not tracked separately, attribute all to
     * utime (stime = 0); this matches common kernel stubs for early-stage OSes.
     * Phase 4 (Completed): Accumulate child times from reaped children via
     * child_cpu_ticks, which is incremented in fut_task_waitpid().
     */
    uint64_t total_cpu_ticks = 0;
    for (fut_thread_t *t = task->threads; t != NULL; t = t->next) {
        total_cpu_ticks += t->stats.cpu_ticks;
    }

    struct tms times;
    memset(&times, 0, sizeof(times));
    times.tms_utime  = (clock_t)total_cpu_ticks;
    times.tms_cutime = (clock_t)task->child_cpu_ticks;

    /* Copy to userspace (only when caller provided a struct). */
    if (buf && times_copy_to_user(buf, &times, sizeof(struct tms)) != 0) {
        fut_printf("[TIMES] times(buf=%p) -> EFAULT (copy_to_user failed)\n", buf);
        return -EFAULT;
    }

    /* Return elapsed time in clock ticks since boot.
     * fut_get_ticks() returns ticks at 100 Hz (10ms each).
     * USER_HZ is the userspace tick rate (typically 100). */
    uint64_t kernel_ticks = fut_get_ticks();
    clock_t elapsed_ticks = (clock_t)((kernel_ticks * USER_HZ) / 100);

    /* Phase 2: Categorize elapsed time for better diagnostics */
    const char *elapsed_category;
    uint64_t elapsed_seconds = kernel_ticks / 100;

    if (elapsed_seconds < 10) {
        elapsed_category = "very recent boot";
    } else if (elapsed_seconds < 60) {
        elapsed_category = "recent boot";
    } else if (elapsed_seconds < 3600) {
        elapsed_category = "moderate uptime";
    } else if (elapsed_seconds < 86400) {
        elapsed_category = "long uptime";
    } else {
        elapsed_category = "very long uptime";
    }

    /* Phase 2: Detailed logging with time breakdown */
    uint64_t hours = elapsed_seconds / 3600;
    uint64_t minutes = (elapsed_seconds % 3600) / 60;
    uint64_t seconds = elapsed_seconds % 60;

    if (hours > 0) {
        fut_printf("[TIMES] times(buf=%p) -> %ld ticks "
                   "(%luh %lum %lus elapsed [%s], utime=%ld stime=0)\n",
                   buf, elapsed_ticks, hours, minutes, seconds, elapsed_category,
                   (long)times.tms_utime);
    } else if (minutes > 0) {
        fut_printf("[TIMES] times(buf=%p) -> %ld ticks "
                   "(%lum %lus elapsed [%s], utime=%ld stime=0)\n",
                   buf, elapsed_ticks, minutes, seconds, elapsed_category,
                   (long)times.tms_utime);
    } else {
        fut_printf("[TIMES] times(buf=%p) -> %ld ticks "
                   "(%lus elapsed [%s], utime=%ld stime=0)\n",
                   buf, elapsed_ticks, seconds, elapsed_category,
                   (long)times.tms_utime);
    }

    return elapsed_ticks;
}
