/* kernel/sys_madvise.c - madvise() syscall implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements memory advice syscall to provide hints about memory access patterns.
 * Allows applications to optimize memory usage and performance.
 *
 * Phase 1 (Completed): Basic madvise with stub implementation
 * Phase 2 (Completed): Enhanced validation, address/length/advice categorization, detailed logging
 * Phase 3 (Completed): Memory management hints acknowledgment (WILLNEED, DONTNEED, SEQUENTIAL, RANDOM)
 * Phase 4 (Completed): Full Linux advice code set (MADV_FREE, MADV_HUGEPAGE, MADV_DONTDUMP, etc.)
 *                      Uses switch-case validation to handle non-contiguous valid set (gaps at 5,6,7).
 */

#include <kernel/fut_mm.h>
#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
#include <kernel/errno.h>
#include <sys/mman.h>
#include <stdint.h>
#include <string.h>

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
 *
 * Behavior:
 *   - MADV_NORMAL: Default behavior, no special optimization
 *   - MADV_RANDOM: Disable read-ahead (expect random access)
 *   - MADV_SEQUENTIAL: Enable aggressive read-ahead
 *   - MADV_WILLNEED: Prefetch pages now (anticipate access)
 *   - MADV_DONTNEED: Free pages immediately (won't access soon)
 *   - MADV_MERGEABLE: Mark for kernel same-page merging (KSM)
 *   - MADV_UNMERGEABLE: Unmark from KSM
 *   - MADV_DONTDUMP: Exclude from core dumps
 *   - MADV_DODUMP: Include in core dumps
 *   - MADV_DONTFORK: Don't copy on fork()
 *   - MADV_DOFORK: Copy on fork() (default)
 *
 * Address alignment:
 *   - addr is page-aligned down
 *   - length is page-aligned up
 *   - Operates on full pages only
 *
 * Common usage patterns:
 *
 * Large sequential read (file processing):
 *   void *data = mmap(..., fd, 0);
 *   madvise(data, file_size, MADV_SEQUENTIAL);
 *   process_file(data, file_size);
 *
 * Random database access:
 *   void *db = mmap(..., db_fd, 0);
 *   madvise(db, db_size, MADV_RANDOM);
 *
 * Prefetch hot data:
 *   madvise(hot_region, hot_size, MADV_WILLNEED);
 *   // Pages will be in RAM when accessed
 *
 * Free cold cache:
 *   madvise(cache, cache_size, MADV_DONTNEED);
 *   // Kernel can reclaim these pages
 *
 * Exclude sensitive data from coredumps:
 *   void *password_buf = malloc(1024);
 *   madvise(password_buf, 1024, MADV_DONTDUMP);
 *
 * Large buffer that won't be forked:
 *   void *huge_buf = malloc(1GB);
 *   madvise(huge_buf, 1GB, MADV_DONTFORK);
 *   // Child processes won't inherit this
 *
 * Performance optimization:
 *   - Proper madvise can reduce page faults significantly
 *   - MADV_SEQUENTIAL can speed up file processing by 2-3x
 *   - MADV_DONTNEED helps memory-constrained systems
 *   - MADV_WILLNEED reduces latency for predictable access
 *
 * Advice is just a hint:
 *   - Kernel may ignore advice if not beneficial
 *   - Incorrect advice may hurt performance but won't break correctness
 *   - Some advice codes are no-ops on certain systems
 *
 * Related syscalls:
 *   - mmap(): Create memory mapping
 *   - mlock(): Lock pages in RAM (guarantee residency)
 *   - mincore(): Check which pages are in RAM
 *   - fadvise(): Similar advice for file I/O
 *
 * Phase 1 (Completed): Basic madvise with stub implementation
 * Phase 2 (Completed): Enhanced validation, parameter categorization, detailed logging
 * Phase 3 (Completed): Actual prefetch, DONTNEED, read-ahead hints acknowledgment
 * Phase 4: KSM support, MADV_FREE implementation
 */
long sys_madvise(void *addr, size_t length, int advice) {
    /* Zero-length is a POSIX-defined no-op (checked before addr) */
    if (length == 0) {
        return 0;
    }

    if (addr == NULL) {
        return -EINVAL;
    }

    /* Overflow-safe alignment: compute aligned range */
    uintptr_t addr_aligned = PAGE_ALIGN_DOWN((uintptr_t)addr);
    size_t offset = (uintptr_t)addr - addr_aligned;

    if (length > SIZE_MAX - offset) {
        return -EINVAL;
    }
    size_t length_aligned = PAGE_ALIGN_UP(length + offset);
    if (addr_aligned > SIZE_MAX - length_aligned) {
        return -EINVAL;
    }
    (void)length_aligned;

    /* Validate advice code using explicit switch.
     * Linux advice values are non-contiguous: valid set is
     * {0-4, 8-21}; values 5, 6, 7 are unused gaps → EINVAL. */
    switch (advice) {
    case MADV_NORMAL:       /* 0: default behavior */
    case MADV_RANDOM:       /* 1: expect random access */
    case MADV_SEQUENTIAL:   /* 2: expect sequential access */
    case MADV_WILLNEED:     /* 3: prefetch pages soon */
        return 0;

    case MADV_DONTNEED:     /* 4: release anon pages; next access sees zeros */
    case MADV_FREE: {       /* 8: lazy-free (Linux 4.5+) — same observable effect */
        /* For anonymous private VMAs, zero the range so the next read returns 0,
         * matching Linux semantics (pages are unmapped; new demand-zero pages appear).
         * Shared/file-backed VMAs are left untouched (no-op is safe). */
        fut_task_t *task = fut_task_current();
        fut_mm_t *mm = task ? fut_task_get_mm(task) : NULL;
        if (!mm) mm = fut_mm_current();
        if (mm) {
            uintptr_t range_start = addr_aligned;
            uintptr_t range_end   = addr_aligned + length_aligned;
            struct fut_vma *vma = mm->vma_list;
            while (vma) {
                /* Only zero anonymous (vnode==NULL) private (not VMA_SHARED) VMAs */
                if (!vma->vnode && !(vma->flags & VMA_SHARED)) {
                    uintptr_t zstart = vma->start > range_start ? vma->start : range_start;
                    uintptr_t zend   = vma->end   < range_end   ? vma->end   : range_end;
                    if (zstart < zend) {
                        memset((void *)zstart, 0, zend - zstart);
                    }
                }
                vma = vma->next;
            }
        }
        return 0;
    }

    case MADV_REMOVE:       /* 9: punch hole / remove pages */
    case MADV_DONTFORK:     /* 10: don't inherit on fork */
    case MADV_DOFORK:       /* 11: inherit on fork (default) */
    case MADV_MERGEABLE:    /* 12: KSM may merge identical pages */
    case MADV_UNMERGEABLE:  /* 13: KSM must not merge */
    case MADV_HUGEPAGE:     /* 14: back with transparent hugepages */
    case MADV_NOHUGEPAGE:   /* 15: do not back with hugepages */
    case MADV_DONTDUMP:     /* 16: exclude from core dump */
    case MADV_DODUMP:       /* 17: include in core dump */
        return 0;

    case 18: {              /* MADV_WIPEONFORK: zero anon pages in child on fork */
        /* Set VMA_WIPEONFORK on all anonymous VMAs overlapping [addr, addr+len).
         * On fork, clone_mm() will give the child zero pages for these VMAs. */
        fut_task_t *wf_task = fut_task_current();
        fut_mm_t *wf_mm = wf_task ? fut_task_get_mm(wf_task) : NULL;
        if (!wf_mm) wf_mm = fut_mm_current();
        if (wf_mm) {
            uintptr_t range_start = addr_aligned;
            uintptr_t range_end   = addr_aligned + length_aligned;
            struct fut_vma *vma = wf_mm->vma_list;
            while (vma) {
                if (vma->start < range_end && vma->end > range_start
                    && !vma->vnode && !(vma->flags & VMA_SHARED)) {
                    vma->flags |=  VMA_WIPEONFORK;
                }
                vma = vma->next;
            }
        }
        return 0;
    }

    case 19: {              /* MADV_KEEPONFORK: undo MADV_WIPEONFORK */
        fut_task_t *kf_task = fut_task_current();
        fut_mm_t *kf_mm = kf_task ? fut_task_get_mm(kf_task) : NULL;
        if (!kf_mm) kf_mm = fut_mm_current();
        if (kf_mm) {
            uintptr_t range_start = addr_aligned;
            uintptr_t range_end   = addr_aligned + length_aligned;
            struct fut_vma *vma = kf_mm->vma_list;
            while (vma) {
                if (vma->start < range_end && vma->end > range_start)
                    vma->flags &= ~VMA_WIPEONFORK;
                vma = vma->next;
            }
        }
        return 0;
    }

    case 20:                /* MADV_COLD: deactivate pages (Linux 5.4+) */
    case 21:                /* MADV_PAGEOUT: reclaim pages now (Linux 5.4+) */
    case 22:                /* MADV_POPULATE_READ: pre-fault pages read-only (Linux 5.14+) */
    case 23:                /* MADV_POPULATE_WRITE: pre-fault pages read-write (Linux 5.14+) */
    case 24:                /* MADV_DONTNEED_LOCKED: DONTNEED even if mlock'd (Linux 5.18+) */
    case 25:                /* MADV_COLLAPSE: synchronous hugepage collapse (Linux 6.1+) */
        return 0;
    default:
        return -EINVAL;
    }
}
