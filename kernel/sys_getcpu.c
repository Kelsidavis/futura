/* kernel/sys_getcpu.c - Get current CPU and NUMA node
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements getcpu() syscall to return the CPU and NUMA node the
 * calling thread is running on. Used by runtimes (glibc, musl) to
 * implement sched_getcpu() and for CPU-local optimizations.
 *
 * Linux syscall number: 309 (x86_64), 168 (ARM64)
 */

#include <kernel/fut_percpu.h>
#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/uaccess.h>
#include <stdint.h>

#include <platform/platform.h>

/* Kernel-pointer bypass helper */
static inline int getcpu_copy_to_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)dst >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_to_user(dst, src, n);
}

/**
 * getcpu() - Get CPU and NUMA node of calling thread
 *
 * @param cpup    Pointer to unsigned int to receive CPU number (or NULL)
 * @param nodep   Pointer to unsigned int to receive NUMA node (or NULL)
 * @param unused  Historically tcache pointer, now unused (must be NULL)
 *
 * Returns 0 on success, negative errno on failure.
 * NULL pointers for cpup/nodep are allowed (field simply not returned).
 */
long sys_getcpu(unsigned int *cpup, unsigned int *nodep, void *unused) {
    (void)unused;

    fut_percpu_t *percpu = fut_percpu_get();
    unsigned int cpu = percpu ? percpu->cpu_index : 0;

    if (cpup) {
        if (getcpu_copy_to_user(cpup, &cpu, sizeof(unsigned int)) != 0)
            return -EFAULT;
    }

    if (nodep) {
        /* Single NUMA node for now */
        unsigned int node = 0;
        if (getcpu_copy_to_user(nodep, &node, sizeof(unsigned int)) != 0)
            return -EFAULT;
    }

    return 0;
}
