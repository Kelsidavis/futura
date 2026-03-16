/* kernel/sys_membarrier.c - Memory barrier syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements membarrier() for cross-CPU memory ordering.
 * Used by modern libc for efficient RCU-like synchronization
 * and lock-free data structure updates.
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <stdint.h>

/* membarrier commands (Linux ABI) */
#define MEMBARRIER_CMD_QUERY                        0
#define MEMBARRIER_CMD_GLOBAL                       (1 << 0)
#define MEMBARRIER_CMD_GLOBAL_EXPEDITED             (1 << 1)
#define MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED    (1 << 4)
#define MEMBARRIER_CMD_PRIVATE_EXPEDITED            (1 << 3)
#define MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED   (1 << 5)
#define MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE  (1 << 6)
#define MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE (1 << 7)
#define MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ       (1 << 8)
#define MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ (1 << 9)

/* Commands we support */
#define MEMBARRIER_SUPPORTED_CMDS ( \
    MEMBARRIER_CMD_GLOBAL | \
    MEMBARRIER_CMD_GLOBAL_EXPEDITED | \
    MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED | \
    MEMBARRIER_CMD_PRIVATE_EXPEDITED | \
    MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED \
)

/**
 * sys_membarrier - Issue memory barriers across CPUs
 *
 * @param cmd:   Command (MEMBARRIER_CMD_*)
 * @param flags: Must be 0
 * @param cpu_id: Target CPU (-1 for all, used with some commands)
 *
 * On a uniprocessor system (current Futura), all membarrier commands
 * are effectively no-ops since there's only one CPU — the compiler
 * barrier is sufficient. When SMP is added, CMD_GLOBAL will need
 * to send IPIs to all CPUs.
 *
 * Returns:
 *   - Bitmask of supported commands (for CMD_QUERY)
 *   - 0 on success (for other commands)
 *   - -EINVAL for unknown command or non-zero flags
 */
long sys_membarrier(int cmd, unsigned int flags, int cpu_id) {
    (void)cpu_id;

    if (flags != 0) {
        return -EINVAL;
    }

    switch (cmd) {
    case MEMBARRIER_CMD_QUERY:
        /* Return bitmask of supported commands */
        return MEMBARRIER_SUPPORTED_CMDS;

    case MEMBARRIER_CMD_GLOBAL:
    case MEMBARRIER_CMD_GLOBAL_EXPEDITED:
    case MEMBARRIER_CMD_PRIVATE_EXPEDITED:
        /* On uniprocessor: compiler barrier is sufficient.
         * On SMP: would need to IPI all/relevant CPUs. */
        __asm__ volatile("" ::: "memory");
        return 0;

    case MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED:
    case MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED:
        /* Registration is a no-op on uniprocessor */
        return 0;

    default:
        return -EINVAL;
    }
}
