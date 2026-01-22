/* kernel/sys_timer.c - POSIX timer syscalls
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements POSIX interval timer syscalls for per-process timers.
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/uaccess.h>
#include <shared/fut_timespec.h>
#include <shared/fut_sigevent.h>  /* For struct sigevent, timer_t, SIGEV_* */

#include <kernel/kprintf.h>

/**
 * sys_timer_create - Create a POSIX per-process timer
 *
 * @param clockid:  Clock to use (CLOCK_REALTIME, CLOCK_MONOTONIC, etc.)
 * @param sevp:     Signal event structure (how to notify on expiration)
 * @param timerid:  Output parameter for timer ID
 *
 * Phase 1: Stub - accepts parameters, returns dummy timer ID
 * Phase 2: Implement timer creation with kernel timer infrastructure
 * Phase 3: Add signal delivery on timer expiration
 *
 * Returns:
 *   - 0 on success, timer ID written to *timerid
 *   - -EINVAL if parameters invalid
 *   - -ENOMEM if unable to allocate timer
 */
long sys_timer_create(int clockid, struct sigevent *sevp, timer_t *timerid) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    fut_printf("[TIMER_CREATE] clockid=%d sevp=%p timerid=%p\n",
               clockid, sevp, timerid);

    /* Validate parameters */
    if (!timerid) {
        return -EINVAL;
    }

    /* Validate userspace pointer is writable */
    if (fut_access_ok(timerid, sizeof(timer_t), 1) != 0) {
        fut_printf("[TIMER_CREATE] EFAULT: timerid pointer not writable\n");
        return -EFAULT;
    }

    /* Phase 1: Stub - return dummy timer ID */
    /* Phase 2: Allocate timer structure, link to task */
    /* Phase 3: Configure signal delivery mechanism */

    timer_t dummy_id = 1;
    if (fut_copy_to_user(timerid, &dummy_id, sizeof(timer_t)) != 0) {
        fut_printf("[TIMER_CREATE] EFAULT: failed to copy timer ID to userspace\n");
        return -EFAULT;
    }

    fut_printf("[TIMER_CREATE] Stub implementation - returning timer ID 1\n");
    return 0;
}

/**
 * sys_timer_settime - Arm/disarm a POSIX per-process timer
 *
 * @param timerid:   Timer ID (from timer_create)
 * @param flags:     0 = relative time, TIMER_ABSTIME = absolute time
 * @param new_value: New timer settings (interval + initial expiration)
 * @param old_value: Optional output for previous timer settings
 *
 * Phase 1: Stub - accepts parameters, returns success
 * Phase 2: Implement timer arming with kernel timer infrastructure
 * Phase 3: Support one-shot and periodic timers
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL if timer ID invalid or time values invalid
 *   - -EFAULT if pointers invalid
 */
long sys_timer_settime(timer_t timerid, int flags,
                        const struct itimerspec *new_value,
                        struct itimerspec *old_value) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    fut_printf("[TIMER_SETTIME] timerid=%d flags=%d new_value=%p old_value=%p\n",
               timerid, flags, new_value, old_value);

    /* Validate parameters */
    if (!new_value) {
        return -EINVAL;
    }

    if (timerid <= 0) {
        return -EINVAL;
    }

    /* Validate new_value is readable from userspace */
    if (fut_access_ok(new_value, sizeof(struct itimerspec), 0) != 0) {
        fut_printf("[TIMER_SETTIME] EFAULT: new_value pointer not readable\n");
        return -EFAULT;
    }

    /* Copy new_value from userspace (for future use when timer is implemented) */
    struct itimerspec new_timer;
    if (fut_copy_from_user(&new_timer, new_value, sizeof(struct itimerspec)) != 0) {
        fut_printf("[TIMER_SETTIME] EFAULT: failed to copy new_value from userspace\n");
        return -EFAULT;
    }

    /* Validate old_value is writable if provided */
    if (old_value) {
        if (fut_access_ok(old_value, sizeof(struct itimerspec), 1) != 0) {
            fut_printf("[TIMER_SETTIME] EFAULT: old_value pointer not writable\n");
            return -EFAULT;
        }

        /* Return previous timer state (stub: zero = disarmed) */
        struct itimerspec zero_timer = {
            .it_interval = { .tv_sec = 0, .tv_nsec = 0 },
            .it_value = { .tv_sec = 0, .tv_nsec = 0 }
        };
        if (fut_copy_to_user(old_value, &zero_timer, sizeof(struct itimerspec)) != 0) {
            fut_printf("[TIMER_SETTIME] EFAULT: failed to copy old_value to userspace\n");
            return -EFAULT;
        }
    }

    /* Phase 1: Stub - accept parameters */
    /* Phase 2: Arm timer with specified interval/value */
    /* Phase 3: Implement absolute vs relative time handling */

    (void)flags;
    (void)new_timer;  /* Will be used when timer is implemented */

    fut_printf("[TIMER_SETTIME] Stub implementation - returning success\n");
    return 0;
}

/**
 * sys_timer_gettime - Get current setting of a timer
 *
 * @param timerid: Timer ID (from timer_create)
 * @param curr_value: Output parameter for current timer settings
 *
 * Phase 1: Stub - returns zero interval/value (timer disarmed)
 * Phase 2: Return actual timer state
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL if timer ID invalid
 *   - -EFAULT if pointer invalid
 */
long sys_timer_gettime(timer_t timerid, struct itimerspec *curr_value) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    fut_printf("[TIMER_GETTIME] timerid=%d curr_value=%p\n", timerid, curr_value);

    /* Validate parameters */
    if (!curr_value) {
        return -EINVAL;
    }

    if (timerid <= 0) {
        return -EINVAL;
    }

    /* Validate userspace pointer is writable */
    if (fut_access_ok(curr_value, sizeof(struct itimerspec), 1) != 0) {
        fut_printf("[TIMER_GETTIME] EFAULT: curr_value pointer not writable\n");
        return -EFAULT;
    }

    /* Phase 1: Stub - return zero (timer disarmed) */
    /* Phase 2: Return actual timer state */

    struct itimerspec zero_timer = {
        .it_interval = { .tv_sec = 0, .tv_nsec = 0 },
        .it_value = { .tv_sec = 0, .tv_nsec = 0 }
    };

    if (fut_copy_to_user(curr_value, &zero_timer, sizeof(struct itimerspec)) != 0) {
        fut_printf("[TIMER_GETTIME] EFAULT: failed to copy timer state to userspace\n");
        return -EFAULT;
    }

    fut_printf("[TIMER_GETTIME] Stub implementation - returning zero interval/value\n");
    return 0;
}

/**
 * sys_timer_getoverrun - Get overrun count for a timer
 *
 * @param timerid: Timer ID (from timer_create)
 *
 * Overrun count tracks how many timer expirations occurred before
 * the signal was delivered (for periodic timers).
 *
 * Phase 1: Stub - returns 0 (no overruns)
 * Phase 2: Track and return actual overrun count
 *
 * Returns:
 *   - Overrun count on success (>= 0)
 *   - -EINVAL if timer ID invalid
 */
long sys_timer_getoverrun(timer_t timerid) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    fut_printf("[TIMER_GETOVERRUN] timerid=%d\n", timerid);

    /* Validate timer ID */
    if (timerid <= 0) {
        return -EINVAL;
    }

    /* Phase 1: Stub - return 0 (no overruns) */
    /* Phase 2: Return actual overrun count from timer structure */

    fut_printf("[TIMER_GETOVERRUN] Stub implementation - returning 0\n");
    return 0;
}

/**
 * sys_timer_delete - Delete a POSIX per-process timer
 *
 * @param timerid: Timer ID (from timer_create)
 *
 * Phase 1: Stub - accepts timer ID, returns success
 * Phase 2: Disarm timer and free timer structure
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL if timer ID invalid
 */
long sys_timer_delete(timer_t timerid) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    fut_printf("[TIMER_DELETE] timerid=%d\n", timerid);

    /* Validate timer ID */
    if (timerid <= 0) {
        return -EINVAL;
    }

    /* Phase 1: Stub - accept timer ID */
    /* Phase 2: Disarm timer, unlink from task, free structure */

    fut_printf("[TIMER_DELETE] Stub implementation - returning success\n");
    return 0;
}
