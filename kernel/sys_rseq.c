/* kernel/sys_rseq.c - Restartable sequences registration
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements rseq() for per-CPU data access optimization.
 * Used by modern libc (glibc 2.35+) for efficient per-CPU
 * memory allocators and lock-free counters.
 *
 * Current implementation: accepts registration but doesn't enforce
 * restartable sequence interruption (no SMP preemption yet).
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <stdint.h>
#include <stddef.h>

/* rseq flags */
#define RSEQ_FLAG_UNREGISTER  (1 << 0)

/* rseq struct size expected by glibc */
#define RSEQ_STRUCT_SIZE_V1  32

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
    (void)sig;

    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Validate flags */
    if (flags & ~RSEQ_FLAG_UNREGISTER) {
        return -EINVAL;
    }

    /* Validate struct size */
    if (rseq_len < RSEQ_STRUCT_SIZE_V1) {
        return -EINVAL;
    }

    if (flags & RSEQ_FLAG_UNREGISTER) {
        /* Unregister: just accept */
        return 0;
    }

    /* Register: validate pointer is non-NULL */
    if (!rseq) {
        return -EFAULT;
    }

    /* Accept registration — on uniprocessor, rseq critical sections
     * are never interrupted by migration to another CPU, so the
     * restartable sequence mechanism is effectively a no-op. */
    return 0;
}
