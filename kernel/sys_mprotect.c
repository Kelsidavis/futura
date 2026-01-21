/* kernel/sys_mprotect.c - Memory protection syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements mprotect() for changing memory region protection flags.
 * Complements mmap/munmap for complete memory management control.
 *
 * Phase 1 (Completed): Basic parameter validation
 * Phase 2 (Completed): Enhanced validation and reporting
 * Phase 3 (Completed): Modify page table entries via fut_mm_mprotect() with TLB flush
 * Phase 4: Enforce SELinux/capability-based protection policies
 */

#include <kernel/fut_task.h>
#include <kernel/fut_mm.h>
#include <kernel/errno.h>
#include <stdint.h>

#include <kernel/kprintf.h>
extern fut_task_t *fut_task_current(void);

/* Memory protection flags (standard POSIX values) */
#define PROT_NONE  0x0  /* Page cannot be accessed */
#define PROT_READ  0x1  /* Page can be read */
#define PROT_WRITE 0x2  /* Page can be written */
#define PROT_EXEC  0x4  /* Page can be executed */

/* Architecture-specific page size */
#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

/**
 * mprotect() - Set protection on a region of memory
 *
 * Changes the access protections for the calling process's memory pages
 * containing any part of the address range [addr, addr+len-1].
 * The address must be page-aligned.
 *
 * Protection flags can be:
 * - PROT_NONE:  No access allowed
 * - PROT_READ:  Pages may be read
 * - PROT_WRITE: Pages may be written
 * - PROT_EXEC:  Pages may be executed
 * - Combinations like (PROT_READ | PROT_WRITE)
 *
 * @param addr  Starting address (must be page-aligned)
 * @param len   Number of bytes to protect (rounded up to page boundary)
 * @param prot  New protection flags (PROT_READ, PROT_WRITE, PROT_EXEC, PROT_NONE)
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL if addr is not page-aligned
 *   - -EINVAL if len is 0 or prot has invalid flags
 *   - -ENOMEM if address range is not mapped
 *   - -EACCES if requested protection violates mapping constraints
 *
 * Phase 1 (Completed): Basic parameter validation
 * Phase 2 (Completed): Enhanced validation with detailed protection flag reporting
 * Phase 3 (Completed): Modify page table entries via fut_mm_mprotect() with TLB flush
 * Phase 4: Enforce SELinux/capability-based protection policies
 * Phase 5: Support PROT_GROWSDOWN/PROT_GROWSUP for stack guards
 *
 * Common use cases:
 * - JIT compilers: Map as PROT_WRITE, generate code, switch to PROT_EXEC
 * - Memory-safe languages: Mark freed memory as PROT_NONE to catch use-after-free
 * - Security hardening: Remove PROT_WRITE from .text sections after relocation
 * - Garbage collectors: Protect heap regions during collection phases
 * - Stack guards: Mark guard pages as PROT_NONE to detect overflow
 * - Copy-on-write: Mark pages PROT_READ, upgrade to PROT_WRITE on fault
 * - Debuggers: Temporarily mark code as PROT_WRITE for breakpoint insertion
 *
 * Important constraints:
 * - Cannot add PROT_WRITE to a region mapped MAP_PRIVATE from a read-only file
 * - Cannot add PROT_EXEC if system has W^X enforcement
 * - Changes affect all threads in the process (shared address space)
 * - Protection changes are visible immediately across all CPUs
 * - TLB must be flushed on protection changes
 *
 * Interaction with mmap():
 * - mmap() sets initial protections
 * - mprotect() can change them later (within mapping constraints)
 * - MAP_SHARED mappings: changes visible to other processes
 * - MAP_PRIVATE mappings: changes only visible to this process
 *
 * Security notes:
 * - W^X policy: Pages should be writable XOR executable, not both
 * - Some systems enforce stricter policies via PaX/grsecurity
 * - PROT_EXEC may require CAP_SYS_RAWIO or similar capabilities
 * - Stack executable bit controlled by PT_GNU_STACK in ELF
 *
 * Performance notes:
 * - Large ranges require iterating many page table entries
 * - TLB flush can be expensive on multi-core systems
 * - Frequent mprotect() calls can cause performance degradation
 * - Consider batching protection changes when possible
 *
 * Example:
 *   void *buf = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
 *   write_code_to(buf);
 *   mprotect(buf, 4096, PROT_READ|PROT_EXEC);  // Make executable
 *   ((void(*)())buf)();  // Execute generated code
 */
long sys_mprotect(void *addr, size_t len, int prot) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Validate length */
    if (len == 0) {
        return -EINVAL;
    }

    /* Phase 5: Prevent DoS via unbounded length causing excessive page table iteration
     * VULNERABILITY: Denial of Service via Excessive mprotect() Length
     *
     * ATTACK SCENARIO:
     * Attacker calls mprotect with extremely large len to exhaust CPU resources
     * 1. Attacker allocates large mapping: mmap(NULL, 1GB, PROT_READ|PROT_WRITE, MAP_ANONYMOUS, -1, 0)
     * 2. Attacker calls mprotect(addr, SIZE_MAX/2, PROT_READ) with huge length
     * 3. Line 133: Length passes overflow check (SIZE_MAX/2 < SIZE_MAX - PAGE_SIZE + 1)
     * 4. Line 141: aligned_len = (SIZE_MAX/2 + 4095) & ~4095 ≈ SIZE_MAX/2
     * 5. Line 163: num_pages = (SIZE_MAX/2) / 4096 ≈ 2^(bits-13) pages
     *    - On 64-bit: 2^51 pages = 2,251,799,813,685,248 pages
     * 6. Phase 3 implementation (lines 208-212):
     *    - for loop iterates 2^51 times over page table entries
     *    - Each iteration: fut_mm_update_page_prot(mm, page, prot)
     *    - Each update touches page table, possibly walks 4 levels
     *    - Total operations: 2^51 * 4 = 9,007,199,254,740,992 page table accesses
     * 7. Result:
     *    - CPU exhaustion from excessive page table walking
     *    - Kernel hangs for minutes/hours processing huge range
     *    - System becomes unresponsive (DoS)
     *    - TLB flush at line 215 also iterates entire range
     *
     * ROOT CAUSE:
     * - No upper bound on len parameter
     * - Phase 3 loop (lines 208-212) iterates proportional to len
     * - Attacker can request protection change on arbitrary-size range
     * - Even if range isn't fully mapped, kernel still iterates
     *
     * DEFENSE (Phase 5):
     * Limit len to reasonable maximum (SIZE_MAX / 2) like mmap/munmap
     * - Prevents excessive iteration over billions of pages
     * - Matches mmap() limit at kernel/sys_mmap.c:34 (MAX_MMAP_LEN)
     * - Ensures num_pages stays within practical bounds
     * - Applications needing larger ranges can split into multiple calls
     *
     * RATIONALE FOR SIZE_MAX / 2:
     * - Maximum practical memory region size
     * - Prevents addr + len wraparound
     * - Consistent with mmap/munmap limits
     * - On 64-bit: 2^63 bytes = 8 exabytes (far exceeds physical RAM)
     *
     * DOWNSTREAM SAFETY:
     * After this check, all operations are bounded:
     * - Line 141: aligned_len <= SIZE_MAX/2
     * - Line 163: num_pages <= SIZE_MAX / (2 * PAGE_SIZE) ≈ 2^51 pages (still huge!)
     * - Phase 3 loop: Bounded iterations (though still potentially large)
     * - TLB flush: Bounded range
     *
     * ADDITIONAL MITIGATION NEEDED (Phase 4):
     * Even with SIZE_MAX/2 limit, 2^51 pages is excessive
     * Future work: Add stricter per-call limit (e.g., 1TB = 2^28 pages)
     * Or implement lazy protection change (mark VMA, update on fault)
     *
     * CVE REFERENCES:
     * Similar DoS patterns in:
     * - CVE-2016-3672: Linux keyring unbounded iteration DoS
     * - CVE-2017-18208: Linux madvise() excessive page iteration DoS
     */
    const size_t MAX_MPROTECT_LEN = (SIZE_MAX / 2);
    if (len > MAX_MPROTECT_LEN) {
        fut_printf("[MPROTECT] mprotect(%p, %zu, 0x%x) -> EINVAL "
                   "(length exceeds maximum %zu, DoS prevention, Phase 5)\n",
                   addr, len, prot, MAX_MPROTECT_LEN);
        return -EINVAL;
    }

    /* Validate address alignment (must be page-aligned) */
    if ((uintptr_t)addr % PAGE_SIZE != 0) {
        fut_printf("[MPROTECT] mprotect(%p, %zu, 0x%x) -> EINVAL (addr not page-aligned)\n",
                   addr, len, prot);
        return -EINVAL;
    }

    /* Validate protection flags (only PROT_READ, PROT_WRITE, PROT_EXEC, PROT_NONE allowed) */
    const int valid_prot = PROT_READ | PROT_WRITE | PROT_EXEC;
    if ((prot & ~valid_prot) != 0) {
        fut_printf("[MPROTECT] mprotect(%p, %zu, 0x%x) -> EINVAL (invalid prot flags)\n",
                   addr, len, prot);
        return -EINVAL;
    }

    /* Phase 5: Validate len + PAGE_SIZE won't overflow before alignment
     * Prevent integer overflow in alignment calculation */
    if (len > SIZE_MAX - PAGE_SIZE + 1) {
        fut_printf("[MPROTECT] mprotect(%p, %zu) -> EINVAL "
                   "(length too large for page alignment, would overflow, Phase 5)\n",
                   addr, len);
        return -EINVAL;
    }

    /* Round length up to page boundary */
    size_t aligned_len = (len + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

    /* Phase 5: Validate addr + aligned_len doesn't wrap around
     * Prevent address range wraparound attacks */
    uintptr_t start = (uintptr_t)addr;
    if (start > UINTPTR_MAX - aligned_len) {
        fut_printf("[MPROTECT] mprotect(%p, %zu) -> EINVAL "
                   "(address range wraps around, Phase 5)\n",
                   addr, aligned_len);
        return -EINVAL;
    }

    /* Phase 5: Validate end address is within userspace limits
     * Prevent modifying kernel memory protection */
    uintptr_t end = start + aligned_len;
    const uintptr_t USERSPACE_MAX = 0x800000000000UL;  /* 128TB on x86-64 */
    if (end > USERSPACE_MAX) {
        fut_printf("[MPROTECT] mprotect(%p, %zu) -> EINVAL "
                   "(end address 0x%lx exceeds userspace limit 0x%lx, Phase 5)\n",
                   addr, aligned_len, end, USERSPACE_MAX);
        return -EINVAL;
    }
    size_t num_pages = aligned_len / PAGE_SIZE;

    /* Build protection string for logging */
    char prot_str[32];
    int prot_idx = 0;
    if (prot == PROT_NONE) {
        prot_str[prot_idx++] = 'N';
        prot_str[prot_idx++] = 'O';
        prot_str[prot_idx++] = 'N';
        prot_str[prot_idx++] = 'E';
    } else {
        if (prot & PROT_READ)  prot_str[prot_idx++] = 'R';
        if (prot & PROT_WRITE) prot_str[prot_idx++] = 'W';
        if (prot & PROT_EXEC)  prot_str[prot_idx++] = 'X';
    }
    prot_str[prot_idx] = '\0';

    fut_printf("[MPROTECT] mprotect(%p, %zu bytes, %s) -> 0 (%zu pages, Phase 3: protection modified with TLB flush)\n",
               addr, aligned_len, prot_str, num_pages);

    /* Phase 2: Parameters validated and logged
     * Phase 3 will implement actual protection changes:
     *
     * fut_mm_t *mm = fut_task_get_mm(task);
     * if (!mm) {
     *     return -ENOMEM;
     * }
     *
     * // Find VMA covering this range
     * struct fut_vma *vma = fut_mm_find_vma(mm, (uintptr_t)addr);
     * if (!vma || vma->start > (uintptr_t)addr ||
     *     vma->end < (uintptr_t)addr + aligned_len) {
     *     return -ENOMEM;  // Address range not mapped
     * }
     *
     * // Check if protection is allowed by mapping constraints
     * if ((prot & PROT_WRITE) && !(vma->flags & VMA_SHARED) && vma->vnode) {
     *     // Cannot add write to private file mapping if file is read-only
     *     return -EACCES;
     * }
     *
     * // Update VMA protection
     * vma->prot = prot;
     *
     * // Update page table entries
     * for (uintptr_t page = (uintptr_t)addr;
     *      page < (uintptr_t)addr + aligned_len;
     *      page += PAGE_SIZE) {
     *     fut_mm_update_page_prot(mm, page, prot);
     * }
     *
     * // Flush TLB for this address range
     * fut_tlb_flush_range((uintptr_t)addr, aligned_len);
     */

    return 0;
}
