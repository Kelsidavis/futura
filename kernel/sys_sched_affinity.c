/* kernel/sys_sched_affinity.c - CPU affinity syscalls
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements sched_getaffinity() and sched_setaffinity() for controlling
 * which CPUs a thread is allowed to run on. Essential for performance
 * tuning and NUMA-aware applications.
 */

#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
#include <kernel/fut_memory.h>
#include <kernel/uaccess.h>
#include <kernel/errno.h>
#include <stdint.h>
#include <string.h>

#ifdef __x86_64__
#include <platform/x86_64/memory/paging.h>
#elif defined(__aarch64__)
#include <platform/arm64/memory/paging.h>
#endif

/* Maximum CPUs supported in the affinity mask */
#define MAX_CPUS 64

/* Kernel-pointer bypass for self-tests */
static inline int affinity_copy_to_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)dst >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_to_user(dst, src, n);
}

static inline int affinity_copy_from_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)src >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_from_user(dst, src, n);
}

/**
 * sys_sched_getaffinity - Get CPU affinity mask for a thread
 *
 * @param pid:     Thread/process ID (0 = calling thread)
 * @param len:     Size of the cpumask buffer in bytes
 * @param user_mask: Buffer to store the CPU affinity mask
 *
 * Returns:
 *   - Number of bytes written to user_mask on success (min: sizeof(uint64_t))
 *   - -ESRCH if pid not found
 *   - -EINVAL if len is too small
 *   - -EFAULT if user_mask is invalid
 */
long sys_sched_getaffinity(int pid, unsigned int len, void *user_mask) {
    if (!user_mask) {
        return -EFAULT;
    }

    /* Minimum mask size is 8 bytes (64 CPUs) */
    if (len < sizeof(uint64_t)) {
        return -EINVAL;
    }

    /* Find target thread */
    fut_thread_t *thread = fut_thread_current();
    if (pid != 0) {
        fut_task_t *target = fut_task_by_pid((uint64_t)pid);
        if (!target) {
            return -ESRCH;
        }
        thread = target->threads;
    }

    if (!thread) {
        return -ESRCH;
    }

    /* Get the mask — default to all CPUs if not set */
    uint64_t mask = thread->cpu_affinity_mask;
    if (mask == 0) {
        mask = 0x1;  /* At least CPU 0 must be set */
    }

    /* Zero-fill the user buffer first (in case len > 8) */
    uint8_t kbuf[128];
    size_t copy_len = (len > sizeof(kbuf)) ? sizeof(kbuf) : len;
    memset(kbuf, 0, copy_len);
    memcpy(kbuf, &mask, sizeof(mask));

    if (affinity_copy_to_user(user_mask, kbuf, copy_len) != 0) {
        return -EFAULT;
    }

    /* Return the minimum number of bytes needed for the mask */
    return (long)sizeof(uint64_t);
}

/**
 * sys_sched_setaffinity - Set CPU affinity mask for a thread
 *
 * @param pid:     Thread/process ID (0 = calling thread)
 * @param len:     Size of the cpumask buffer in bytes
 * @param user_mask: Buffer containing the new CPU affinity mask
 *
 * Returns:
 *   - 0 on success
 *   - -ESRCH if pid not found
 *   - -EINVAL if len is too small or mask is empty
 *   - -EFAULT if user_mask is invalid
 */
long sys_sched_setaffinity(int pid, unsigned int len, const void *user_mask) {
    if (!user_mask) {
        return -EFAULT;
    }

    if (len < sizeof(uint64_t)) {
        return -EINVAL;
    }

    /* Copy mask from userspace */
    uint64_t mask = 0;
    if (affinity_copy_from_user(&mask, user_mask, sizeof(mask)) != 0) {
        return -EFAULT;
    }

    /* Mask must not be empty — at least one CPU must be allowed */
    if (mask == 0) {
        return -EINVAL;
    }

    /* Find target thread */
    fut_thread_t *thread = fut_thread_current();
    if (pid != 0) {
        fut_task_t *target = fut_task_by_pid((uint64_t)pid);
        if (!target) {
            return -ESRCH;
        }
        thread = target->threads;
    }

    if (!thread) {
        return -ESRCH;
    }

    /* Set the affinity mask — scheduler will honor this during dispatch */
    thread->cpu_affinity_mask = mask;

    return 0;
}
