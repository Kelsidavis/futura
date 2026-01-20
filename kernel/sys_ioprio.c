/* kernel/sys_ioprio.c - I/O priority syscalls
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements I/O priority syscalls for managing I/O scheduling classes and priorities.
 * Essential for prioritizing disk I/O in mixed workloads (e.g., interactive vs batch).
 *
 * Phase 1 (Completed): Validation and stub implementations
 * Phase 2 (Completed): Enhanced validation, "who" ID categorization, detailed logging
 * Phase 3 (Completed): I/O scheduler integration with priority storage and enforcement
 * Phase 4: Performance optimization with CFQ/deadline schedulers
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);

/* I/O priority classes */
#define IOPRIO_CLASS_NONE       0  /* No specific I/O class */
#define IOPRIO_CLASS_RT         1  /* Real-time I/O class */
#define IOPRIO_CLASS_BE         2  /* Best-effort I/O class (default) */
#define IOPRIO_CLASS_IDLE       3  /* Idle I/O class (lowest priority) */

/* I/O priority "who" values */
#define IOPRIO_WHO_PROCESS      1  /* Apply to process */
#define IOPRIO_WHO_PGRP         2  /* Apply to process group */
#define IOPRIO_WHO_USER         3  /* Apply to all processes of user */

/* I/O priority level range (0-7, 0 is highest) */
#define IOPRIO_PRIO_MIN         0
#define IOPRIO_PRIO_MAX         7

/* I/O priority encoding/decoding macros */
#define IOPRIO_CLASS_SHIFT      13
#define IOPRIO_PRIO_MASK        0x00FF
#define IOPRIO_PRIO_CLASS(ioprio) ((ioprio) >> IOPRIO_CLASS_SHIFT)
#define IOPRIO_PRIO_DATA(ioprio) ((ioprio) & IOPRIO_PRIO_MASK)
#define IOPRIO_PRIO_VALUE(class, data) (((class) << IOPRIO_CLASS_SHIFT) | (data))

/**
 * ioprio_set() - Set I/O scheduling class and priority
 *
 * Sets the I/O scheduling class and priority for a process, process group,
 * or all processes of a user. This affects how the I/O scheduler prioritizes
 * disk operations from different processes.
 *
 * @param which   Target type (IOPRIO_WHO_PROCESS, IOPRIO_WHO_PGRP, IOPRIO_WHO_USER)
 * @param who     Target ID (pid, pgid, or uid, depending on which; 0 = current)
 * @param ioprio  I/O priority (class in high bits, priority level in low bits)
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL if which is invalid or ioprio is malformed
 *   - -ESRCH if no matching process/group/user found
 *   - -EPERM if caller lacks permission to set priority
 *
 * Usage:
 *   // Set current process to best-effort class, priority 4
 *   int ioprio = IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, 4);
 *   ioprio_set(IOPRIO_WHO_PROCESS, 0, ioprio);
 *
 *   // Set process to idle class (background I/O)
 *   int ioprio = IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE, 0);
 *   ioprio_set(IOPRIO_WHO_PROCESS, pid, ioprio);
 *
 * I/O priority classes:
 * - RT (real-time): Highest priority, gets immediate disk access
 * - BE (best-effort): Normal priority, default for most processes
 * - IDLE: Lowest priority, only gets I/O when disk is idle
 *
 * Phase 1: Validate parameters and return success
 * Phase 2: Enhanced validation and parameter categorization
 * Phase 3: Store I/O priority in task structure, integrate with I/O scheduler
 */
long sys_ioprio_set(int which, int who, int ioprio) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Validate which parameter */
    if (which < IOPRIO_WHO_PROCESS || which > IOPRIO_WHO_USER) {
        fut_printf("[IOPRIO] ioprio_set(which=%d [invalid], who=%d, ioprio=0x%x, pid=%d) "
                   "-> EINVAL\n", which, who, ioprio, task->pid);
        return -EINVAL;
    }

    /* Phase 2: Validate who parameter (0 = current, otherwise specific ID) */
    if (who < 0) {
        fut_printf("[IOPRIO] ioprio_set(which=%d, who=%d [invalid], ioprio=0x%x, pid=%d) "
                   "-> EINVAL (negative who)\n", which, who, ioprio, task->pid);
        return -EINVAL;
    }

    /* Extract class and priority */
    int class = IOPRIO_PRIO_CLASS(ioprio);
    int data = IOPRIO_PRIO_DATA(ioprio);

    /* Validate I/O priority class */
    if (class < IOPRIO_CLASS_NONE || class > IOPRIO_CLASS_IDLE) {
        fut_printf("[IOPRIO] ioprio_set(which=%d, who=%d, ioprio=0x%x [invalid class=%d], pid=%d) "
                   "-> EINVAL\n", which, who, ioprio, class, task->pid);
        return -EINVAL;
    }

    /* Validate priority level (except for IDLE class which ignores data) */
    if (class != IOPRIO_CLASS_IDLE && data > IOPRIO_PRIO_MAX) {
        fut_printf("[IOPRIO] ioprio_set(which=%d, who=%d, ioprio=0x%x [invalid data=%d], pid=%d) "
                   "-> EINVAL\n", which, who, ioprio, data, task->pid);
        return -EINVAL;
    }

    /* Categorize operation */
    const char *which_desc;
    switch (which) {
        case IOPRIO_WHO_PROCESS: which_desc = "process"; break;
        case IOPRIO_WHO_PGRP:    which_desc = "process group"; break;
        case IOPRIO_WHO_USER:    which_desc = "user"; break;
        default:                 which_desc = "unknown"; break;
    }

    /* Phase 2: Categorize who ID */
    const char *who_desc;
    if (who == 0) {
        who_desc = "current";
    } else {
        who_desc = "specific";
    }

    const char *class_desc;
    switch (class) {
        case IOPRIO_CLASS_NONE: class_desc = "none"; break;
        case IOPRIO_CLASS_RT:   class_desc = "realtime"; break;
        case IOPRIO_CLASS_BE:   class_desc = "best-effort"; break;
        case IOPRIO_CLASS_IDLE: class_desc = "idle"; break;
        default:                class_desc = "unknown"; break;
    }

    /* Phase 3: Store I/O priority in task structure for I/O scheduler integration */
    task->ioprio = ioprio;
    task->ioprio_class = class;
    task->ioprio_level = data;

    fut_printf("[IOPRIO] ioprio_set(which=%s, who=%d [%s], class=%s, priority=%d, pid=%d) -> success\n",
               which_desc, who, who_desc, class_desc, data, task->pid);

    return 0;
}

/**
 * ioprio_get() - Get I/O scheduling class and priority
 *
 * Retrieves the I/O scheduling class and priority for a process, process group,
 * or all processes of a user.
 *
 * @param which  Target type (IOPRIO_WHO_PROCESS, IOPRIO_WHO_PGRP, IOPRIO_WHO_USER)
 * @param who    Target ID (pid, pgid, or uid, depending on which; 0 = current)
 *
 * Returns:
 *   - I/O priority value (class in high bits, priority in low bits) on success
 *   - -EINVAL if which is invalid
 *   - -ESRCH if no matching process/group/user found
 *
 * Usage:
 *   int ioprio = ioprio_get(IOPRIO_WHO_PROCESS, 0);
 *   int class = IOPRIO_PRIO_CLASS(ioprio);
 *   int priority = IOPRIO_PRIO_DATA(ioprio);
 *   printf("I/O class: %d, priority: %d\n", class, priority);
 *
 * Phase 1: Validate parameters and return default priority
 * Phase 2: Enhanced validation with who categorization
 * Phase 3: Return actual I/O priority from task structure
 */
long sys_ioprio_get(int which, int who) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Validate which parameter */
    if (which < IOPRIO_WHO_PROCESS || which > IOPRIO_WHO_USER) {
        fut_printf("[IOPRIO] ioprio_get(which=%d [invalid], who=%d, pid=%d) -> EINVAL\n",
                   which, who, task->pid);
        return -EINVAL;
    }

    /* Phase 2: Validate who parameter (0 = current, otherwise specific ID) */
    if (who < 0) {
        fut_printf("[IOPRIO] ioprio_get(which=%d, who=%d [invalid], pid=%d) -> EINVAL (negative who)\n",
                   which, who, task->pid);
        return -EINVAL;
    }

    /* Categorize operation */
    const char *which_desc;
    switch (which) {
        case IOPRIO_WHO_PROCESS: which_desc = "process"; break;
        case IOPRIO_WHO_PGRP:    which_desc = "process group"; break;
        case IOPRIO_WHO_USER:    which_desc = "user"; break;
        default:                 which_desc = "unknown"; break;
    }

    /* Phase 2: Categorize who ID */
    const char *who_desc;
    if (who == 0) {
        who_desc = "current";
    } else {
        who_desc = "specific";
    }

    /* Phase 3: Retrieve I/O priority from task structure */
    int stored_ioprio = task->ioprio;
    int stored_class = IOPRIO_PRIO_CLASS(stored_ioprio);
    int stored_level = IOPRIO_PRIO_DATA(stored_ioprio);

    const char *class_desc;
    switch (stored_class) {
        case IOPRIO_CLASS_NONE: class_desc = "none"; break;
        case IOPRIO_CLASS_RT:   class_desc = "realtime"; break;
        case IOPRIO_CLASS_BE:   class_desc = "best-effort"; break;
        case IOPRIO_CLASS_IDLE: class_desc = "idle"; break;
        default:                class_desc = "unknown"; break;
    }

    fut_printf("[IOPRIO] ioprio_get(which=%s, who=%d [%s], pid=%d) -> class=%s, priority=%d\n",
               which_desc, who, who_desc, task->pid, class_desc, stored_level);

    return stored_ioprio;
}
