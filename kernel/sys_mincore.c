/* kernel/sys_mincore.c - Memory residency query syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements mincore() for determining which pages are resident in memory.
 * Useful for understanding memory access patterns and optimizing I/O.
 */

#include <kernel/fut_task.h>
#include <kernel/fut_mm.h>
#include <kernel/errno.h>
#include <stdint.h>
#include <string.h>

extern void fut_printf(const char *fmt, ...);
extern fut_task_t *fut_task_current(void);
extern int fut_copy_to_user(void *to, const void *from, size_t size);

/* Architecture-specific page size */
#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

/**
 * mincore() - Determine whether pages are resident in memory
 *
 * Reports which pages of a memory mapping are currently in RAM (resident)
 * versus paged out to disk or not yet faulted in. This is useful for:
 * - Performance monitoring and profiling
 * - Prefetching decisions in database systems
 * - Memory usage analysis
 * - Determining working set size
 *
 * The output is a byte vector where each byte corresponds to one page.
 * The least significant bit of each byte is set if the page is resident.
 *
 * @param addr   Starting address (must be page-aligned)
 * @param length Number of bytes to query (rounded up to page boundary)
 * @param vec    Output vector of bytes (one byte per page)
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL if addr is not page-aligned
 *   - -ENOMEM if address range is not mapped
 *   - -EFAULT if vec pointer is invalid
 *   - -EAGAIN if page table lock cannot be acquired (rare)
 *
 * Output vector format:
 * - Each byte represents one page (4096 bytes on most systems)
 * - Bit 0 (LSB): 1 = page resident in memory, 0 = not resident
 * - Bits 1-7: Reserved (currently 0, may be used in future)
 *
 * Number of bytes needed:
 *   vec_length = (length + PAGE_SIZE - 1) / PAGE_SIZE
 *
 * Example:
 *   void *map = mmap(NULL, 16384, PROT_READ|PROT_WRITE,
 *                    MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
 *   // 16384 bytes = 4 pages, need 4 bytes in vec
 *   unsigned char vec[4];
 *   mincore(map, 16384, vec);
 *
 *   if (vec[0] & 1) { printf("Page 0 is resident\n"); }
 *   if (vec[1] & 1) { printf("Page 1 is resident\n"); }
 *   // etc.
 *
 * Phase 1 (Completed): Validates parameters, returns all pages resident
 * Phase 2 (Current): Validate VMA coverage and return residency
 * Phase 3: Check page table entries for present bit
 * Phase 4: Distinguish file-backed vs anonymous pages
 * Phase 5: Support swap tracking (pages swapped out)
 *
 * Common use cases:
 *
 * 1. Database buffer pool monitoring:
 *    Check which pages of a memory-mapped database file are in RAM
 *    to optimize query plans and prefetching strategies.
 *
 * 2. Working set calculation:
 *    Determine how much of a large mapping is actually being used
 *    (resident pages indicate active use).
 *
 * 3. Prefetch optimization:
 *    Before reading data, check if it's resident to avoid blocking.
 *    If not resident, may want to prefetch or reorganize access pattern.
 *
 * 4. Memory pressure detection:
 *    Repeatedly call mincore to detect when kernel is paging out
 *    application memory (resident count decreasing).
 *
 * 5. mlock verification:
 *    After mlocking memory, verify all pages are actually resident
 *    and not being paged out.
 *
 * Performance characteristics:
 * - Very fast: Just reads page table entries (no I/O)
 * - O(n) where n = number of pages queried
 * - Typically <1 microsecond per page on modern CPUs
 * - No side effects (doesn't fault in pages or change state)
 *
 * Interaction with other syscalls:
 *
 * - mmap: Pages initially not resident (faulted in on access)
 * - mlock: All locked pages will show as resident
 * - munlock: Pages may become non-resident if memory pressure
 * - msync: Doesn't affect residency (just writes dirty pages)
 * - madvise(MADV_WILLNEED): Prefaults pages, making them resident
 * - madvise(MADV_DONTNEED): May make pages non-resident
 *
 * File-backed vs anonymous pages:
 * - File-backed: Non-resident means data is on disk
 * - Anonymous: Non-resident means either:
 *   * Not yet allocated (first access will zero-fill)
 *   * Swapped out to swap space
 *
 * Limitations and caveats:
 *
 * - Snapshot at time of call (pages can be evicted immediately after)
 * - No atomicity guarantee across entire range
 * - Doesn't indicate if page is dirty (use other mechanisms)
 * - Doesn't show page access pattern (use perf counters)
 * - Can't force pages to be resident (use mlock for that)
 * - Race conditions: Page may be evicted between mincore and access
 *
 * Security and privacy:
 * - Originally allowed probing any address (security issue)
 * - Modern kernels (Linux 5.14+) restrict to own mappings
 * - Can leak information about other processes in shared mappings
 * - Some systems disable mincore entirely for security
 *
 * Example: Working set calculator
 *
 *   size_t calculate_resident_size(void *addr, size_t length) {
 *       size_t num_pages = (length + PAGE_SIZE - 1) / PAGE_SIZE;
 *       unsigned char *vec = malloc(num_pages);
 *       if (!vec) return 0;
 *
 *       if (mincore(addr, length, vec) < 0) {
 *           free(vec);
 *           return 0;
 *       }
 *
 *       size_t resident_pages = 0;
 *       for (size_t i = 0; i < num_pages; i++) {
 *           if (vec[i] & 1) resident_pages++;
 *       }
 *
 *       free(vec);
 *       return resident_pages * PAGE_SIZE;
 *   }
 *
 * Example: Prefetch decision
 *
 *   bool should_prefetch(void *addr, size_t length) {
 *       size_t num_pages = (length + PAGE_SIZE - 1) / PAGE_SIZE;
 *       unsigned char vec[num_pages];
 *
 *       if (mincore(addr, length, vec) < 0) return false;
 *
 *       // If <50% resident, consider prefetching
 *       size_t resident = 0;
 *       for (size_t i = 0; i < num_pages; i++) {
 *           if (vec[i] & 1) resident++;
 *       }
 *
 *       return (resident * 100 / num_pages) < 50;
 *   }
 *
 * Portability notes:
 * - POSIX doesn't standardize mincore
 * - Linux, BSD, Solaris all have slightly different semantics
 * - Some systems use different bit definitions in vec
 * - Page size varies across architectures
 * - Always use sysconf(_SC_PAGESIZE) in portable code
 */
long sys_mincore(void *addr, size_t length, unsigned char *vec) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Validate address alignment (must be page-aligned) */
    if ((uintptr_t)addr % PAGE_SIZE != 0) {
        fut_printf("[MINCORE] mincore(%p, %zu, %p) -> EINVAL (addr not page-aligned)\n",
                   addr, length, vec);
        return -EINVAL;
    }

    /* Validate vec pointer */
    if (!vec) {
        fut_printf("[MINCORE] mincore(%p, %zu, %p) -> EFAULT (vec is NULL)\n",
                   addr, length, vec);
        return -EFAULT;
    }

    /* Calculate number of pages and round length */
    size_t num_pages = (length + PAGE_SIZE - 1) / PAGE_SIZE;
    size_t aligned_len = num_pages * PAGE_SIZE;

    /* Phase 2: Validate VMA coverage */
    fut_mm_t *mm = fut_task_get_mm(task);
    if (!mm) {
        fut_printf("[MINCORE] mincore(%p, %zu, %p) -> ENOMEM (no MM context)\n",
                   addr, length, vec);
        return -ENOMEM;
    }

    /* Check if address range is covered by VMAs */
    uintptr_t start = (uintptr_t)addr;
    uintptr_t end = start + aligned_len;
    size_t mapped_pages = 0;

    /* Iterate through VMA list to find coverage */
    struct fut_vma *vma = mm->vma_list;
    while (vma) {
        /* Check if this VMA overlaps with our range */
        if (vma->start < end && vma->end > start) {
            /* Calculate overlap */
            uintptr_t overlap_start = (vma->start > start) ? vma->start : start;
            uintptr_t overlap_end = (vma->end < end) ? vma->end : end;
            size_t overlap_pages = (overlap_end - overlap_start) / PAGE_SIZE;
            mapped_pages += overlap_pages;
        }
        vma = vma->next;
    }

    /* Check if entire range is mapped */
    if (mapped_pages < num_pages) {
        fut_printf("[MINCORE] mincore(%p, %zu, %p) -> ENOMEM (range not fully mapped: %zu/%zu pages)\n",
                   addr, aligned_len, vec, mapped_pages, num_pages);
        return -ENOMEM;
    }

    /* Allocate temporary buffer to hold residency info */
    unsigned char *kernel_vec = (unsigned char *)__builtin_alloca(num_pages);
    if (!kernel_vec) {
        return -ENOMEM;
    }

    /* Phase 2: Mark pages as resident if in mapped VMA
     * For now, all pages in valid VMAs are considered resident.
     * Phase 3 will check actual PTE present bits. */
    uintptr_t page_addr = start;
    for (size_t i = 0; i < num_pages; i++, page_addr += PAGE_SIZE) {
        int page_resident = 0;

        /* Find VMA covering this page */
        vma = mm->vma_list;
        while (vma) {
            if (page_addr >= vma->start && page_addr < vma->end) {
                /* Page is in a VMA, consider it resident */
                page_resident = 1;
                break;
            }
            vma = vma->next;
        }

        kernel_vec[i] = page_resident ? 0x01 : 0x00;
    }

    /* Copy result to userspace */
    if (fut_copy_to_user(vec, kernel_vec, num_pages) != 0) {
        fut_printf("[MINCORE] mincore(%p, %zu, %p) -> EFAULT (copy_to_user failed)\n",
                   addr, aligned_len, vec);
        return -EFAULT;
    }

    fut_printf("[MINCORE] mincore(%p, %zu, %p) -> 0 (%zu pages, Phase 2: VMA validated)\n",
               addr, aligned_len, vec, num_pages);

    /* Phase 3-5 future implementation (check actual page table entries):
     *
     * // Check each page's PTE present bit
     * uintptr_t current_addr = (uintptr_t)addr;
     * for (size_t i = 0; i < num_pages; i++, current_addr += PAGE_SIZE) {
     *     // Look up page table entry
     *     pte_t *pte = fut_mm_lookup_pte(mm, current_addr);
     *
     *     if (pte && (*pte & PTE_PRESENT)) {
     *         // Page is resident in physical memory
     *         kernel_vec[i] = 0x01;
     *     } else if (pte && (*pte & PTE_SWAPPED)) {
     *         // Page is swapped out
     *         kernel_vec[i] = 0x00;
     *     } else {
     *         // Page not allocated yet (demand paging)
     *         kernel_vec[i] = 0x00;
     *     }
     * }
     *
     * // Future bits (reserved for now):
     * // Bit 1: Page is dirty
     * // Bit 2: Page is referenced/accessed
     * // Bit 3: Page is file-backed (vs anonymous)
     * // Bit 4: Page is locked (mlock)
     * // Bits 5-7: Reserved
     */

    return 0;
}
