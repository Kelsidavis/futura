/* kernel/sys_times.c - Process time accounting syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements times() for retrieving process CPU times in clock ticks.
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <string.h>

#include <kernel/kprintf.h>
extern fut_task_t *fut_task_current(void);
extern int fut_copy_to_user(void *to, const void *from, size_t size);
extern uint64_t fut_get_ticks(void);

/* clock_t is typically long for clock ticks */
typedef long clock_t;

/* tms structure - process times in clock ticks */
struct tms {
    clock_t tms_utime;   /* User CPU time */
    clock_t tms_stime;   /* System CPU time */
    clock_t tms_cutime;  /* User CPU time of terminated children */
    clock_t tms_cstime;  /* System CPU time of terminated children */
};

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
 * Phase 4: Accumulate child times from wait4()/waitpid()
 */
long sys_times(struct tms *buf) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[TIMES] times(buf=%p) -> ESRCH (no current task)\n", buf);
        return -ESRCH;
    }

    if (!buf) {
        fut_printf("[TIMES] times(buf=%p) -> EFAULT (buf is NULL)\n", buf);
        return -EFAULT;
    }

    /* Phase 5: Validate buf write permission early (kernel writes process times)
     * VULNERABILITY: Invalid Output Buffer Pointer
     * ATTACK: Attacker provides unmapped or read-only buffer
     * IMPACT: Kernel page fault when writing time statistics
     * DEFENSE: Check write permission before processing */
    extern int fut_access_ok(const void *u_ptr, size_t size, int write);
    if (fut_access_ok(buf, sizeof(struct tms), 1) != 0) {
        fut_printf("[TIMES] times(buf=%p) -> EFAULT (buffer not writable for %zu bytes, Phase 5)\n",
                   buf, sizeof(struct tms));
        return -EFAULT;
    }

    /* Phase 2: Return zeroed times with enhanced reporting
     * Phase 3: Will populate from task->cpu_time_user, task->cpu_time_system
     * Phase 4: Will track child times and populate cutime/cstime */
    struct tms times;
    memset(&times, 0, sizeof(times));

    /* Future Phase 3 implementation will convert from milliseconds to clock ticks:
     * times.tms_utime = (task->cpu_time_user_ms * USER_HZ) / 1000;
     * times.tms_stime = (task->cpu_time_system_ms * USER_HZ) / 1000;
     *
     * Future Phase 4 implementation will accumulate child times:
     * times.tms_cutime = (task->child_cpu_time_user_ms * USER_HZ) / 1000;
     * times.tms_cstime = (task->child_cpu_time_system_ms * USER_HZ) / 1000;
     */

    /* Copy to userspace */
    if (fut_copy_to_user(buf, &times, sizeof(struct tms)) != 0) {
        fut_printf("[TIMES] times(buf=%p) -> EFAULT (copy_to_user failed)\n", buf);
        return -EFAULT;
    }

    /* Return elapsed time in clock ticks since boot
     * Current time is in milliseconds, convert to clock ticks */
    uint64_t current_ms = fut_get_ticks();
    clock_t elapsed_ticks = (clock_t)((current_ms * USER_HZ) / 1000);

    /* Phase 2: Categorize elapsed time for better diagnostics */
    const char *elapsed_category;
    uint64_t elapsed_seconds = current_ms / 1000;

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
                   "(%luh %lum %lus elapsed [%s], utime=0, stime=0, cutime=0, cstime=0, Phase 2: zeroed)\n",
                   buf, elapsed_ticks, hours, minutes, seconds, elapsed_category);
    } else if (minutes > 0) {
        fut_printf("[TIMES] times(buf=%p) -> %ld ticks "
                   "(%lum %lus elapsed [%s], utime=0, stime=0, cutime=0, cstime=0, Phase 2: zeroed)\n",
                   buf, elapsed_ticks, minutes, seconds, elapsed_category);
    } else {
        fut_printf("[TIMES] times(buf=%p) -> %ld ticks "
                   "(%lus elapsed [%s], utime=0, stime=0, cutime=0, cstime=0, Phase 2: zeroed)\n",
                   buf, elapsed_ticks, seconds, elapsed_category);
    }

    return elapsed_ticks;
}
