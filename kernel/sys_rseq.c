/* kernel/sys_rseq.c - Restartable sequences registration
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements rseq() for per-CPU data access optimization.
 * Used by modern libc (glibc 2.35+) for efficient per-CPU
 * memory allocators and lock-free counters.
 *
 * Current implementation: tracks registration per-thread and
 * initializes the cpu_id field. On uniprocessor, rseq critical
 * sections are never interrupted by CPU migration, so the
 * restartable sequence mechanism is effectively a no-op.
 */

#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
#include <kernel/uaccess.h>
#include <kernel/errno.h>
#include <stdint.h>
#include <stddef.h>

#include <platform/platform.h>

/* rseq flags */
#define RSEQ_FLAG_UNREGISTER  (1 << 0)

/* rseq struct size expected by glibc */
#define RSEQ_STRUCT_SIZE_V1  32

/* Offsets within struct rseq (Linux UAPI) */
#define RSEQ_OFFSET_CPU_ID_START  4   /* __u32 cpu_id_start */
#define RSEQ_OFFSET_CPU_ID        8   /* __u32 cpu_id */

/* Kernel-pointer bypass helper */
static inline int rseq_copy_to_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)dst >= KERNEL_VIRTUAL_BASE) {
        __builtin_memcpy(dst, src, n);
        return 0;
    }
#endif
    return fut_copy_to_user(dst, src, n);
}

/**
 * sys_rseq - Register/unregister restartable sequences
 *
 * @param rseq:       Pointer to userspace rseq struct
 * @param rseq_len:   Size of rseq struct
 * @param flags:      0 to register, RSEQ_FLAG_UNREGISTER to unregister
 * @param sig:        Signature expected at abort handler (for validation)
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL for invalid parameters
 *   - -EBUSY if already registered (register) or not registered (unregister)
 *   - -EFAULT for invalid rseq pointer
 */
long sys_rseq(void *rseq, uint32_t rseq_len, int flags, uint32_t sig) {
    fut_task_t *task = fut_task_current();
    if (!task)
        return -ESRCH;

    fut_thread_t *thread = fut_thread_current();
    if (!thread)
        return -ESRCH;

    /* Validate flags */
    if (flags & ~RSEQ_FLAG_UNREGISTER)
        return -EINVAL;

    /* Validate struct size */
    if (rseq_len < RSEQ_STRUCT_SIZE_V1)
        return -EINVAL;

    if (flags & RSEQ_FLAG_UNREGISTER) {
        /* Unregister: must match the registered pointer and signature */
        if (!thread->rseq_ptr)
            return -EINVAL;  /* Not registered */
        if (thread->rseq_ptr != rseq || thread->rseq_sig != sig)
            return -EINVAL;  /* Mismatched pointer or signature */
        thread->rseq_ptr = NULL;
        thread->rseq_sig = 0;
        return 0;
    }

    /* Register */
    if (!rseq)
        return -EFAULT;

    /* Already registered → -EBUSY (glibc checks for this) */
    if (thread->rseq_ptr)
        return -EBUSY;

    /* Initialize cpu_id and cpu_id_start fields in the userspace rseq
     * struct BEFORE storing the registration. If the user pointer faults
     * we must return -EFAULT without leaving the thread half-registered
     * (which would later prevent re-registration with -EBUSY and orphan
     * the rseq_sig validation). On uniprocessor Futura, CPU is always 0. */
    uint32_t cpu_id = 0;
    if (rseq_copy_to_user((char *)rseq + RSEQ_OFFSET_CPU_ID_START,
                          &cpu_id, sizeof(cpu_id)) != 0)
        return -EFAULT;
    if (rseq_copy_to_user((char *)rseq + RSEQ_OFFSET_CPU_ID,
                          &cpu_id, sizeof(cpu_id)) != 0)
        return -EFAULT;

    /* Store registration only after the user struct is initialized. */
    thread->rseq_ptr = rseq;
    thread->rseq_sig = sig;

    return 0;
}
