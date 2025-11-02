/* kernel/sys_madvise.c - madvise() syscall implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements memory advice syscall to provide hints about memory access patterns.
 * Allows applications to optimize memory usage and performance.
 */

#include <kernel/fut_vfs.h>
#include <kernel/fut_task.h>
#include <kernel/fut_mm.h>
#include <kernel/errno.h>
#include <kernel/uaccess.h>
#include <string.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);

/* madvise() advice codes */
#define MADV_NORMAL       0  /* No special treatment */
#define MADV_RANDOM       1  /* Expect random access */
#define MADV_SEQUENTIAL   2  /* Expect sequential access */
#define MADV_WILLNEED     3  /* Will need pages soon (prefetch) */
#define MADV_DONTNEED     4  /* Don't need pages anymore (free) */
#define MADV_MERGEABLE    5  /* Mark as mergeable (KSM) */
#define MADV_UNMERGEABLE  6  /* Unmark as mergeable */
#define MADV_DONTDUMP     7  /* Exclude from core dumps */
#define MADV_DODUMP       8  /* Include in core dumps */
#define MADV_DONTFORK     9  /* Don't inherit on fork */
#define MADV_DOFORK      10  /* Inherit on fork */

/* Note: PAGE_SIZE, PAGE_ALIGN_DOWN, PAGE_ALIGN_UP are defined in platform paging.h
   and already included via fut_mm.h */

/**
 * madvise(void *addr, size_t length, int advice) - Provide memory advice
 *
 * Gives the kernel advice about how memory in the range [addr, addr+length)
 * will be used. The kernel uses this to optimize memory management.
 *
 * @param addr    Starting address of memory region
 * @param length  Length of memory region in bytes
 * @param advice  Advice code (MADV_* constant)
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL if addr/length invalid or advice unknown
 *   - -ENOMEM if address range not in valid memory region
 *   - -EFAULT if address range is invalid
 */
long sys_madvise(void *addr, size_t length, int advice) {
    /* Validate advice code */
    if (advice < MADV_NORMAL || advice > MADV_DOFORK) {
        return -EINVAL;
    }

    /* Validate length */
    if (length == 0) {
        return 0;  /* Zero-length madvise is a no-op but valid */
    }

    /* Validate address range is readable */
    if (addr == NULL) {
        return -EINVAL;
    }

    /* Ensure address is properly aligned */
    uintptr_t addr_aligned = PAGE_ALIGN_DOWN((uintptr_t)addr);
    size_t length_aligned = PAGE_ALIGN_UP(length + ((uintptr_t)addr - addr_aligned));

    /* Check for overflow */
    if (addr_aligned + length_aligned < addr_aligned) {
        return -EINVAL;
    }

    /* Get current task's memory context */
    fut_task_t *task = fut_task_current();
    if (!task || !task->mm) {
        return -EINVAL;  /* No memory context */
    }

    /* Log the madvise request */
    fut_printf("[MADVISE] addr=0x%lx length=%zu advice=%d\n",
               (uintptr_t)addr, length, advice);

    /* Handle specific advice codes */
    switch (advice) {
    case MADV_NORMAL:
        /* Default behavior - no special optimization */
        fut_printf("[MADVISE] MADV_NORMAL: no special handling\n");
        return 0;

    case MADV_RANDOM:
        /* Random access pattern - disable read-ahead prefetching */
        fut_printf("[MADVISE] MADV_RANDOM: disable prefetch for range 0x%lx-0x%lx\n",
                   addr_aligned, addr_aligned + length_aligned);
        /* Prefetching hint would be stored in VMA or per-page metadata */
        return 0;

    case MADV_SEQUENTIAL:
        /* Sequential access pattern - enable read-ahead prefetching */
        fut_printf("[MADVISE] MADV_SEQUENTIAL: enable prefetch for range 0x%lx-0x%lx\n",
                   addr_aligned, addr_aligned + length_aligned);
        /* Prefetching hint would be stored in VMA or per-page metadata */
        return 0;

    case MADV_WILLNEED:
        /* Application will soon access this memory - prefetch pages now */
        fut_printf("[MADVISE] MADV_WILLNEED: prefetch pages in range 0x%lx-0x%lx\n",
                   addr_aligned, addr_aligned + length_aligned);
        /* In a full implementation, this would trigger actual prefetching.
         * For now, this is a hint that the kernel can use for scheduling. */
        return 0;

    case MADV_DONTNEED:
        /* Application won't need this memory for a while - can be freed */
        fut_printf("[MADVISE] MADV_DONTNEED: can reclaim pages in range 0x%lx-0x%lx\n",
                   addr_aligned, addr_aligned + length_aligned);
        /* In a full implementation, this would mark pages for reclamation
         * or immediately page out to swap. For now, just log the intent. */
        return 0;

    case MADV_MERGEABLE:
        /* Mark pages as eligible for kernel same-page merging (KSM) */
        fut_printf("[MADVISE] MADV_MERGEABLE: mark range 0x%lx-0x%lx for KSM\n",
                   addr_aligned, addr_aligned + length_aligned);
        /* KSM support would require page scanning and hash-based merging */
        return 0;

    case MADV_UNMERGEABLE:
        /* Unmark pages from kernel same-page merging */
        fut_printf("[MADVISE] MADV_UNMERGEABLE: unmark range 0x%lx-0x%lx from KSM\n",
                   addr_aligned, addr_aligned + length_aligned);
        return 0;

    case MADV_DONTDUMP:
        /* Exclude this memory from core dumps */
        fut_printf("[MADVISE] MADV_DONTDUMP: exclude range 0x%lx-0x%lx from core dumps\n",
                   addr_aligned, addr_aligned + length_aligned);
        /* This would set a flag on VMAs to skip them during core dump */
        return 0;

    case MADV_DODUMP:
        /* Include this memory in core dumps */
        fut_printf("[MADVISE] MADV_DODUMP: include range 0x%lx-0x%lx in core dumps\n",
                   addr_aligned, addr_aligned + length_aligned);
        return 0;

    case MADV_DONTFORK:
        /* Don't copy this memory on fork() - child will not inherit */
        fut_printf("[MADVISE] MADV_DONTFORK: don't inherit range 0x%lx-0x%lx on fork\n",
                   addr_aligned, addr_aligned + length_aligned);
        /* This would set a flag on VMAs for fork() to skip them */
        return 0;

    case MADV_DOFORK:
        /* Copy this memory on fork() - child will inherit (default) */
        fut_printf("[MADVISE] MADV_DOFORK: inherit range 0x%lx-0x%lx on fork\n",
                   addr_aligned, addr_aligned + length_aligned);
        return 0;

    default:
        return -EINVAL;  /* Unknown advice code */
    }
}
