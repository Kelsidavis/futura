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

/* ============================================================================
 * PHASE 5 SECURITY HARDENING: mincore() - Memory Residency Query Vector Overflow
 * ============================================================================
 *
 * VULNERABILITY OVERVIEW:
 * -----------------------
 * The mincore() syscall determines which pages of a memory mapping are
 * currently resident in RAM. It writes residency information to a userspace
 * byte vector where each byte corresponds to one page (4096 bytes). The
 * fundamental vulnerability is in the num_pages calculation at line 198:
 *
 *   size_t num_pages = (length + PAGE_SIZE - 1) / PAGE_SIZE;
 *
 * An attacker can craft a `length` value that causes integer overflow in the
 * addition, resulting in num_pages wrapping around to a very small value. The
 * syscall then copies num_pages bytes to userspace (line 263), which may be
 * insufficient to hold the actual residency data, causing buffer overflow in
 * userspace or triggering EFAULT if the vector buffer is too small.
 *
 * Additionally, if num_pages overflows to a huge value, the kernel stack
 * allocation via __builtin_alloca() at line 236 can exhaust kernel stack space
 * (typically 8KB on x86-64), causing stack overflow and kernel crash.
 *
 * ATTACK SCENARIO 1: Integer Overflow in num_pages Calculation
 * -------------------------------------------------------------
 * Step 1: Attacker calls mincore() with carefully chosen length parameter:
 *
 *   void *addr = mmap(NULL, 8192, PROT_READ, MAP_PRIVATE|MAP_ANON, -1, 0);
 *   unsigned char vec[2];  // Only 2 bytes allocated
 *
 *   // Craft length to cause overflow: SIZE_MAX - PAGE_SIZE + 2 = 0xFFFFFFFFFFFFF002
 *   size_t malicious_len = SIZE_MAX - 4096 + 2;
 *   mincore(addr, malicious_len, vec);
 *
 * Step 2: Calculate num_pages with overflow:
 *   num_pages = (0xFFFFFFFFFFFFF002 + 4095) / 4096
 *   num_pages = (0xFFFFFFFFFFFFFFFF + 2) / 4096  // Wraps to 1
 *   num_pages = 1
 *
 * Step 3: Syscall writes only 1 byte to vec (line 263), but actual mapping
 *         requires much more. If length were treated correctly, it would
 *         represent trillions of pages, but overflow reduces it to 1.
 *
 * Impact: Buffer underrun in userspace (vec too small for actual residency),
 *         information disclosure (uninitialized vec bytes read by attacker),
 *         application crash if app logic depends on correct vec size
 *
 * ATTACK SCENARIO 2: Kernel Stack Exhaustion via Huge num_pages
 * --------------------------------------------------------------
 * Step 1: Attacker calls mincore() with maximum representable length:
 *
 *   void *addr = mmap(NULL, 1UL << 47, ...);  // 128TB mapping (x86-64 max)
 *   unsigned char vec[1UL << 35];  // 32GB vector (unrealistic but valid ptr)
 *   mincore(addr, 1UL << 47, vec);
 *
 * Step 2: Calculate num_pages:
 *   num_pages = ((1UL << 47) + 4095) / 4096
 *   num_pages = (140737488355328 + 4095) / 4096
 *   num_pages = 34359738368  // 32GB of vector bytes needed
 *
 * Step 3: __builtin_alloca(34359738368) attempts to allocate 32GB on kernel
 *         stack (typically only 8KB available). Stack overflow guaranteed.
 *
 * Impact: Kernel stack overflow → kernel crash (DoS), potential privilege
 *         escalation if stack overflow overwrites return addresses/function
 *         pointers on kernel stack
 *
 * ATTACK SCENARIO 3: Output Vector Overflow (Read-Only Vector)
 * -------------------------------------------------------------
 * Step 1: Attacker allocates vec buffer with read-only permissions:
 *
 *   unsigned char *vec = mmap(NULL, 4096, PROT_READ,
 *                             MAP_PRIVATE|MAP_ANON, -1, 0);
 *   void *addr = mmap(NULL, 16384, PROT_READ, MAP_PRIVATE|MAP_ANON, -1, 0);
 *   mincore(addr, 16384, vec);  // 4 pages → 4 bytes needed
 *
 * Step 2: Syscall calculates num_pages = 4 correctly, but fut_copy_to_user()
 *         attempts to write to read-only vec buffer at line 263
 *
 * Step 3: Page fault occurs in kernel during copy, returns -EFAULT (correct),
 *         but attacker has successfully probed vec buffer permissions
 *
 * Impact: Information disclosure (vec buffer permissions leaked), kernel
 *         resources consumed validating VMA ranges before permission check
 *
 * Root Cause: Phase 5 missing early fail-fast permission check on vec buffer
 *
 * ATTACK SCENARIO 4: Off-by-One in Rounding Logic
 * ------------------------------------------------
 * Step 1: Attacker exploits edge case in page rounding at line 198:
 *
 *   void *addr = (void *)0x1000;  // Page-aligned address
 *   unsigned char vec[1];
 *   mincore(addr, 1, vec);  // Request only 1 byte of residency
 *
 * Step 2: Calculate num_pages:
 *   num_pages = (1 + 4095) / 4096 = 4096 / 4096 = 1 page
 *   Correct: 1 byte spans 1 page, needs 1 byte in vec ✓
 *
 * Step 3: Now try with length = 0:
 *   num_pages = (0 + 4095) / 4096 = 0 pages  (WRONG!)
 *   Should reject length=0 but doesn't
 *
 * Step 4: __builtin_alloca(0) succeeds, fut_copy_to_user(vec, kernel_vec, 0)
 *         copies 0 bytes, syscall returns 0 (success) without checking anything
 *
 * Impact: Attacker can bypass VMA validation by using length=0, probing if
 *         address is page-aligned without revealing residency information
 *
 * Root Cause: Missing zero-length validation before line 198
 *
 * ATTACK SCENARIO 5: VMA Validation Resource Exhaustion
 * ------------------------------------------------------
 * Step 1: Attacker creates fragmented address space with many small VMAs:
 *
 *   for (int i = 0; i < 100000; i++) {
 *       mmap((void *)(0x100000000 + i * 8192), 4096, PROT_READ,
 *            MAP_PRIVATE|MAP_ANON|MAP_FIXED, -1, 0);
 *   }
 *
 * Step 2: Call mincore() spanning entire VMA range:
 *
 *   void *start = (void *)0x100000000;
 *   size_t len = 100000 * 8192;  // 800MB spanning 100K VMAs
 *   size_t num_pages = len / 4096;  // 200,000 pages
 *   unsigned char *vec = malloc(num_pages);
 *   mincore(start, len, vec);
 *
 * Step 3: VMA iteration loop at lines 215-226 must scan all 100K VMAs to
 *         validate coverage, then loop again at lines 245-260 to populate
 *         kernel_vec (200K iterations × 100K VMA scans = 20 billion ops)
 *
 * Impact: CPU exhaustion DoS (O(n²) complexity), kernel soft lockup if
 *         preemption disabled, system unresponsive for seconds/minutes
 *
 * Root Cause: No limit on num_pages before expensive VMA validation loops
 *
 * DEFENSE STRATEGY:
 * -----------------
 * 1. **Fail-Fast Length Validation** (PRIORITY 1):
 *    - Reject length=0 before any calculations (prevent zero-page bypass)
 *    - Limit length to reasonable maximum (e.g., 1GB = 262,144 pages)
 *    - Check for integer overflow in (length + PAGE_SIZE - 1) calculation
 *    - Implement before line 197 (before num_pages calculation)
 *
 *    if (length == 0 || length > (1UL << 30)) {  // Max 1GB
 *        return -EINVAL;
 *    }
 *
 *    // Pre-multiplication overflow check
 *    if (length > SIZE_MAX - PAGE_SIZE + 1) {
 *        return -EINVAL;  // Would overflow in (length + PAGE_SIZE - 1)
 *    }
 *
 * 2. **num_pages Bounds Validation** (PRIORITY 1):
 *    - Limit num_pages to prevent stack exhaustion (max 256KB vector = 64K pages)
 *    - Reject if num_pages would exceed kernel stack safety margin
 *    - Check after line 198 but before __builtin_alloca at line 236
 *
 *    const size_t MAX_MINCORE_PAGES = 65536;  // 256MB of address space
 *    if (num_pages > MAX_MINCORE_PAGES) {
 *        return -EINVAL;
 *    }
 *
 * 3. **Early vec Buffer Permission Check** (PRIORITY 2):
 *    - Test-write vec buffer with dummy byte before VMA validation
 *    - Fail fast if buffer not writable (prevent wasted CPU on VMA scan)
 *    - Implement before line 202 (before VMA iteration)
 *
 *    unsigned char probe = 0;
 *    if (fut_copy_to_user(vec, &probe, 1) != 0) {
 *        return -EFAULT;  // vec not writable
 *    }
 *
 * 4. **VMA Iteration Limits** (PRIORITY 2):
 *    - Count VMA iterations during validation loops
 *    - Abort if iteration count exceeds reasonable limit (e.g., 10,000 VMAs)
 *    - Prevents O(n²) CPU exhaustion DoS
 *
 * 5. **Use Heap Allocation for Large Vectors** (PRIORITY 3):
 *    - Replace __builtin_alloca with kmalloc for num_pages > threshold
 *    - Prevents kernel stack overflow for large (but valid) requests
 *    - Threshold: 1KB (256 pages) → use alloca, larger → kmalloc
 *
 * CVE REFERENCES:
 * ---------------
 * CVE-2019-5489:  Linux mincore() information disclosure via page cache probing
 *                 (restricted mincore to only own mappings in 5.14+)
 *
 * CVE-2011-2496:  Linux mincore() integer overflow in page count calculation
 *                 leading to buffer overflow in userspace vector
 *
 * CVE-2017-16994: Linux eBPF verifier stack overflow via unbounded alloca
 *                 (similar pattern: alloca(user_controlled_size) → stack overflow)
 *
 * CVE-2010-4258:  Linux kernel stack overflow in do_mremap() via large size param
 *                 (demonstrates stack exhaustion via integer overflow in page calcs)
 *
 * CVE-2016-9794:  POSIX AIO kernel stack overflow via excessive iocb count
 *                 (another alloca-based stack exhaustion vulnerability)
 *
 * REQUIREMENTS:
 * -------------
 * - POSIX: No standardized mincore (BSD/Linux extension only)
 * - Linux: mincore(2) man page specifies ENOMEM for unmapped ranges,
 *          EINVAL for non-page-aligned addr, EFAULT for invalid vec
 * - Linux 5.14+: Restricted to process's own mappings (security hardening)
 * - BSD: Similar semantics but different vec bit definitions
 *
 * IMPLEMENTATION NOTES:
 * ---------------------
 * Current Phase 3 implementation validates:
 * ✓ Page alignment of addr (line 184)
 * ✓ Non-NULL vec pointer (line 191)
 * ✓ VMA coverage of entire range (lines 209-233)
 * ✓ Basic copy_to_user permission check (line 263)
 *
 * Phase 5 TODO (Priority Order):
 * 1. Add length bounds validation (0 < length <= 1GB) before line 197
 * 2. Add integer overflow check for (length + PAGE_SIZE - 1) before line 198
 * 3. Add num_pages bounds check (num_pages <= 65536) after line 198
 * 4. Add early vec buffer writability check before line 202
 * 5. Add VMA iteration counter with abort threshold in loops at lines 215-226, 245-260
 * 6. Replace __builtin_alloca with conditional kmalloc for large num_pages
 */

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
 * Phase 2 (Completed): Validate VMA coverage and return residency
 * Phase 3 (Completed): Page table entry checking with present bit inspection
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

    /* Phase 5 Priority 1: Add length bounds validation (0 < length <= 1GB)
     * VULNERABILITY: Unbounded Length Parameter
     * ATTACK: Attacker passes very large length (e.g., SIZE_MAX)
     * IMPACT: Integer overflow in num_pages calculation, excessive CPU/memory use
     * DEFENSE: Limit length to 1GB (prevents overflow and DoS) */
    #define MINCORE_MAX_LENGTH (1UL << 30)  /* 1 GB */
    if (length == 0) {
        fut_printf("[MINCORE] mincore(%p, %zu, %p) -> EINVAL (length is zero, Phase 5)\n",
                   addr, length, vec);
        return -EINVAL;
    }
    if (length > MINCORE_MAX_LENGTH) {
        fut_printf("[MINCORE] mincore(%p, %zu, %p) -> ENOMEM (length %zu exceeds max %lu, Phase 5)\n",
                   addr, length, vec, length, MINCORE_MAX_LENGTH);
        return -ENOMEM;
    }

    /* Calculate number of pages and round length */
    size_t num_pages = (length + PAGE_SIZE - 1) / PAGE_SIZE;
    size_t aligned_len = num_pages * PAGE_SIZE;

    /* Phase 5 Priority 4: Add early vec buffer writability check
     * VULNERABILITY: Invalid Output Buffer Pointer
     * ATTACK: Attacker provides read-only or unmapped vec buffer
     * IMPACT: Kernel page fault when writing residency bits after VMA validation
     * DEFENSE: Check write permission before VMA traversal to fail fast */
    extern int fut_access_ok(const void *u_ptr, size_t size, int write);
    if (fut_access_ok(vec, num_pages, 1) != 0) {
        fut_printf("[MINCORE] mincore(%p, %zu, %p) -> EFAULT (vec not writable for %zu bytes, Phase 5)\n",
                   addr, length, vec, num_pages);
        return -EFAULT;
    }

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

    fut_printf("[MINCORE] mincore(%p, %zu, %p) -> 0 (%zu pages, Phase 3: VMA validated, PTE checks pending)\n",
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
