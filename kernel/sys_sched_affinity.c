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

#include <platform/platform.h>

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
    /* Linux's kernel/sched/syscalls.c:SYSCALL_DEFINE3(sched_getaffinity)
     * validates len BEFORE the user pointer:
     *   if ((len & (sizeof(unsigned long)-1)) ||
     *       (len < sizeof(unsigned long)))
     *       return -EINVAL;
     *   ...
     *   ret = copy_to_user(user_mask_ptr, &mask, ...);
     * The previous Futura order rejected NULL user_mask before len,
     * inverting the errno class for callers that probe with
     * deliberately bad pointers to detect kernel-supported lengths.
     * Same EINVAL-before-EFAULT reorder pattern as the matching
     * clock_gettime / clock_settime / getitimer / getrlimit /
     * settimeofday fixes. */
    if (len < sizeof(uint64_t)) {
        return -EINVAL;
    }

    /* Linux's sys_sched_getaffinity additionally requires len to be a
     * multiple of sizeof(unsigned long): 'if (len & (sizeof(unsigned
     * long)-1)) return -EINVAL'. The cpumask is exposed as a long-array
     * to userspace; an unaligned len means the trailing bytes
     * straddle a long boundary that the kernel never writes,
     * leaving them with stale stack/heap content. Futura accepted
     * any len >= 8, which violated the user-space contract that
     * affinity buffers be unsigned-long-aligned. */
    if (len & (sizeof(unsigned long) - 1)) {
        return -EINVAL;
    }

    if (!user_mask) {
        return -EFAULT;
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
    /* Same EINVAL-before-EFAULT reorder as sys_sched_getaffinity above:
     * Linux validates len first, then copy_from_user surfaces NULL as
     * EFAULT.  The previous order returned EFAULT for sched_setaffinity
     * (pid, 4, NULL) where Linux returns EINVAL. */
    if (len < sizeof(uint64_t)) {
        return -EINVAL;
    }

    /* Same alignment requirement Linux enforces on the matching
     * sched_getaffinity entry — the kernel walks the cpumask as
     * unsigned-long-sized chunks, so non-aligned lengths produce
     * undefined high bits. */
    if (len & (sizeof(unsigned long) - 1)) {
        return -EINVAL;
    }

    if (!user_mask) {
        return -EFAULT;
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
    fut_task_t *current = thread ? thread->task : NULL;
    fut_task_t *target_task = current;
    if (pid != 0) {
        target_task = fut_task_by_pid((uint64_t)pid);
        if (!target_task) {
            return -ESRCH;
        }
        thread = target_task->threads;
    }

    if (!thread) {
        return -ESRCH;
    }

    /* Cross-task permission gate: only the target's owner, root, or
     * CAP_SYS_NICE may change another task's affinity. Without this an
     * unprivileged caller could pin another user's CPU-bound process
     * to a single core (DoS) or strip a system daemon's affinity to
     * prevent it from running on any CPU.
     *
     * Linux's check_same_owner accepts the call when the caller's
     * EFFECTIVE uid matches EITHER the target's effective uid OR the
     * target's REAL uid:
     *
     *   match = uid_eq(cred->euid, pcred->euid) ||
     *           uid_eq(cred->euid, pcred->uid);   // pcred->uid == real uid
     *
     * The previous Futura gate only compared effective-vs-effective, so
     * a setuid wrapper that had dropped its effective uid back to its
     * real uid couldn't sched_setaffinity a child whose effective uid
     * was still elevated.  CAP_SYS_NICE = bit 23. */
    if (current && target_task && target_task != current &&
        current->uid != 0 &&
        !(current->cap_effective & (1ULL << 23 /* CAP_SYS_NICE */)) &&
        current->uid != target_task->uid &&
        current->uid != target_task->ruid) {
        return -EPERM;
    }

    /* Set the affinity mask — scheduler will honor this during dispatch */
    thread->cpu_affinity_mask = mask;

    return 0;
}
