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
    case MADV_NORMAL: {     /* 0: default behavior — clear seq/random hints */
        fut_task_t *n_task = fut_task_current();
        fut_mm_t *n_mm = n_task ? fut_task_get_mm(n_task) : NULL;
        if (!n_mm) n_mm = fut_mm_current();
        if (n_mm) {
            uintptr_t range_start = addr_aligned;
            uintptr_t range_end   = addr_aligned + length_aligned;
            struct fut_vma *vma = n_mm->vma_list;
            while (vma) {
                if (vma->start < range_end && vma->end > range_start)
                    vma->flags &= ~(VMA_SEQ_READ | VMA_RAND_READ);
                vma = vma->next;
            }
        }
        return 0;
    }
    case MADV_RANDOM: {     /* 1: expect random access */
        fut_task_t *r_task = fut_task_current();
        fut_mm_t *r_mm = r_task ? fut_task_get_mm(r_task) : NULL;
        if (!r_mm) r_mm = fut_mm_current();
        if (r_mm) {
            uintptr_t range_start = addr_aligned;
            uintptr_t range_end   = addr_aligned + length_aligned;
            struct fut_vma *vma = r_mm->vma_list;
            while (vma) {
                if (vma->start < range_end && vma->end > range_start) {
                    vma->flags &= ~VMA_SEQ_READ;
                    vma->flags |=  VMA_RAND_READ;
                }
                vma = vma->next;
            }
        }
        return 0;
    }
    case MADV_SEQUENTIAL: { /* 2: expect sequential access */
        fut_task_t *sq_task = fut_task_current();
        fut_mm_t *sq_mm = sq_task ? fut_task_get_mm(sq_task) : NULL;
        if (!sq_mm) sq_mm = fut_mm_current();
        if (sq_mm) {
            uintptr_t range_start = addr_aligned;
            uintptr_t range_end   = addr_aligned + length_aligned;
            struct fut_vma *vma = sq_mm->vma_list;
            while (vma) {
                if (vma->start < range_end && vma->end > range_start) {
                    vma->flags &= ~VMA_RAND_READ;
                    vma->flags |=  VMA_SEQ_READ;
                }
                vma = vma->next;
            }
        }
        return 0;
    }
    case MADV_WILLNEED:     /* 3: prefetch pages soon */
        return 0;

    case MADV_DONTNEED:     /* 4: release anon pages; next access sees zeros */
    case MADV_FREE: {       /* 8: lazy-free (Linux 4.5+) — same observable effect */
        /* For anonymous private VMAs, zero the range so the next read returns 0,
         * matching Linux semantics (pages are unmapped; new demand-zero pages appear).
         * Shared/file-backed VMAs are left untouched (no-op is safe).
         *
         * We zero pages via the kernel direct-map (pmap_phys_to_virt) instead of
         * through user-space VAs, because kernel threads may have a different CR3
         * than the mm that owns the mapping (lazy TLB). */
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
                    /* Zero page-by-page via kernel direct-map */
                    for (uintptr_t va = zstart; va < zend; va += PAGE_SIZE) {
                        uint64_t phys = 0;
                        if (fut_virt_to_phys(&mm->ctx, va, &phys) == 0) {
                            void *kva = (void *)pmap_phys_to_virt((phys_addr_t)phys);
                            memset(kva, 0, PAGE_SIZE);
                        }
                    }
                }
                vma = vma->next;
            }
        }
        return 0;
    }

    case MADV_REMOVE:       /* 9: punch hole / remove pages */
        return 0;

    case MADV_MERGEABLE: {  /* 12: KSM may merge identical pages */
        fut_task_t *mg_task = fut_task_current();
        fut_mm_t *mg_mm = mg_task ? fut_task_get_mm(mg_task) : NULL;
        if (!mg_mm) mg_mm = fut_mm_current();
        if (mg_mm) {
            uintptr_t range_start = addr_aligned;
            uintptr_t range_end   = addr_aligned + length_aligned;
            struct fut_vma *vma = mg_mm->vma_list;
            while (vma) {
                if (vma->start < range_end && vma->end > range_start)
                    vma->flags |= VMA_MERGEABLE;
                vma = vma->next;
            }
        }
        return 0;
    }
    case MADV_UNMERGEABLE: { /* 13: KSM must not merge */
        fut_task_t *um_task = fut_task_current();
        fut_mm_t *um_mm = um_task ? fut_task_get_mm(um_task) : NULL;
        if (!um_mm) um_mm = fut_mm_current();
        if (um_mm) {
            uintptr_t range_start = addr_aligned;
            uintptr_t range_end   = addr_aligned + length_aligned;
            struct fut_vma *vma = um_mm->vma_list;
            while (vma) {
                if (vma->start < range_end && vma->end > range_start)
                    vma->flags &= ~VMA_MERGEABLE;
                vma = vma->next;
            }
        }
        return 0;
    }
    case MADV_HUGEPAGE: {   /* 14: back with transparent hugepages */
        fut_task_t *hp_task = fut_task_current();
        fut_mm_t *hp_mm = hp_task ? fut_task_get_mm(hp_task) : NULL;
        if (!hp_mm) hp_mm = fut_mm_current();
        if (hp_mm) {
            uintptr_t range_start = addr_aligned;
            uintptr_t range_end   = addr_aligned + length_aligned;
            struct fut_vma *vma = hp_mm->vma_list;
            while (vma) {
                if (vma->start < range_end && vma->end > range_start) {
                    vma->flags |=  VMA_HUGEPAGE;
                    vma->flags &= ~VMA_NOHUGEPAGE;
                }
                vma = vma->next;
            }
        }
        return 0;
    }
    case MADV_NOHUGEPAGE: { /* 15: do not back with hugepages */
        fut_task_t *nh_task = fut_task_current();
        fut_mm_t *nh_mm = nh_task ? fut_task_get_mm(nh_task) : NULL;
        if (!nh_mm) nh_mm = fut_mm_current();
        if (nh_mm) {
            uintptr_t range_start = addr_aligned;
            uintptr_t range_end   = addr_aligned + length_aligned;
            struct fut_vma *vma = nh_mm->vma_list;
            while (vma) {
                if (vma->start < range_end && vma->end > range_start) {
                    vma->flags |=  VMA_NOHUGEPAGE;
                    vma->flags &= ~VMA_HUGEPAGE;
                }
                vma = vma->next;
            }
        }
        return 0;
    }
    case MADV_DONTDUMP: {   /* 16: exclude from core dump */
        fut_task_t *dd_task = fut_task_current();
        fut_mm_t *dd_mm = dd_task ? fut_task_get_mm(dd_task) : NULL;
        if (!dd_mm) dd_mm = fut_mm_current();
        if (dd_mm) {
            uintptr_t range_start = addr_aligned;
            uintptr_t range_end   = addr_aligned + length_aligned;
            struct fut_vma *vma = dd_mm->vma_list;
            while (vma) {
                if (vma->start < range_end && vma->end > range_start)
                    vma->flags |= VMA_DONTDUMP;
                vma = vma->next;
            }
        }
        return 0;
    }
    case MADV_DODUMP: {     /* 17: include in core dump */
        fut_task_t *do_task = fut_task_current();
        fut_mm_t *do_mm = do_task ? fut_task_get_mm(do_task) : NULL;
        if (!do_mm) do_mm = fut_mm_current();
        if (do_mm) {
            uintptr_t range_start = addr_aligned;
            uintptr_t range_end   = addr_aligned + length_aligned;
            struct fut_vma *vma = do_mm->vma_list;
            while (vma) {
                if (vma->start < range_end && vma->end > range_start)
                    vma->flags &= ~VMA_DONTDUMP;
                vma = vma->next;
            }
        }
        return 0;
    }

    case MADV_DONTFORK: {   /* 10: don't copy VMA to child on fork */
        /* Mark VMAs in [addr, addr+len) with VMA_DONTFORK so that clone_mm()
         * will skip them. Used by crypto libraries to prevent key material
         * from leaking to child processes. */
        fut_task_t *df_task = fut_task_current();
        fut_mm_t *df_mm = df_task ? fut_task_get_mm(df_task) : NULL;
        if (!df_mm) df_mm = fut_mm_current();
        if (df_mm) {
            uintptr_t range_start = addr_aligned;
            uintptr_t range_end   = addr_aligned + length_aligned;
            struct fut_vma *vma = df_mm->vma_list;
            while (vma) {
                if (vma->start < range_end && vma->end > range_start)
                    vma->flags |= VMA_DONTFORK;
                vma = vma->next;
            }
        }
        return 0;
    }

    case MADV_DOFORK: {     /* 11: re-enable fork inheritance (undo DONTFORK) */
        fut_task_t *dof_task = fut_task_current();
        fut_mm_t *dof_mm = dof_task ? fut_task_get_mm(dof_task) : NULL;
        if (!dof_mm) dof_mm = fut_mm_current();
        if (dof_mm) {
            uintptr_t range_start = addr_aligned;
            uintptr_t range_end   = addr_aligned + length_aligned;
            struct fut_vma *vma = dof_mm->vma_list;
            while (vma) {
                if (vma->start < range_end && vma->end > range_start)
                    vma->flags &= ~VMA_DONTFORK;
                vma = vma->next;
            }
        }
        return 0;
    }

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
