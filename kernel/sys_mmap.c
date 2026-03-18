/* kernel/sys_mmap.c - Memory mapping syscall implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements mmap, munmap, mprotect, and related memory mapping operations.
 */

#include <stddef.h>
#include <stdint.h>
#include <limits.h>

#include <kernel/errno.h>
#include <kernel/fut_mm.h>
#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
#include <kernel/fut_vfs.h>
#include <platform/platform.h>
#include <sys/mman.h>

/* MAP_*, PROT_* flags provided by sys/mman.h */

/* Maximum number of VMAs per process (DoS protection) */
#define MAX_VMA_COUNT   65536

#include <kernel/kprintf.h>

/**
 * Count the number of VMAs in a memory map.
 * Used to enforce VMA count limits against VMA fragmentation attacks.
 */
static int fut_mm_vma_count(fut_mm_t *mm) {
    if (!mm || !mm->vma_list) {
        return 0;
    }
    int count = 0;
    struct fut_vma *vma = mm->vma_list;
    while (vma) {
        count++;
        vma = vma->next;
    }
    return count;
}

long sys_mmap(void *addr, size_t len, int prot, int flags, int fd, long offset) {
    if (len == 0) {
        return -EINVAL;
    }

    /* Validate length is within reasonable bounds before overflow arithmetic
     * Limit to half of address space to prevent integer overflow in subsequent checks.
     * This ensures len can be safely used in offset+len calculations. */
    const size_t MAX_MMAP_LEN = (SIZE_MAX / 2);
    if (len > MAX_MMAP_LEN) {
        fut_printf("[MMAP] mmap(addr=%p, len=%zu) -> EINVAL "
                   "(length exceeds maximum %zu)\n",
                   addr, len, MAX_MMAP_LEN);
        return -EINVAL;
    }

    /* Validate prot flags don't contain unsupported bits */
    int valid_prot = PROT_NONE | PROT_READ | PROT_WRITE | PROT_EXEC;
    if (prot & ~valid_prot) {
        int invalid_bits = prot & ~valid_prot;
        fut_printf("[MMAP] mmap(addr=%p, len=%zu, prot=0x%x) -> EINVAL "
                   "(invalid prot bits 0x%x detected, valid=0x%x)\n",
                   addr, len, prot, invalid_bits, valid_prot);
        return -EINVAL;
    }

    /* Validate MAP_SHARED/MAP_PRIVATE: exactly one must be set */
    if ((flags & MAP_SHARED) && (flags & MAP_PRIVATE)) {
        fut_printf("[MMAP] mmap(addr=%p, len=%zu, flags=0x%x) -> EINVAL "
                   "(MAP_SHARED and MAP_PRIVATE are mutually exclusive)\n",
                   addr, len, flags);
        return -EINVAL;
    }
    if (!(flags & (MAP_SHARED | MAP_PRIVATE))) {
        fut_printf("[MMAP] mmap(addr=%p, len=%zu, flags=0x%x) -> EINVAL "
                   "(neither MAP_SHARED nor MAP_PRIVATE set)\n",
                   addr, len, flags);
        return -EINVAL;
    }

    /* Validate offset is non-negative and won't overflow */
    if (offset < 0) {
        fut_printf("[MMAP] mmap(addr=%p, len=%zu, offset=%ld) -> EINVAL "
                   "(offset is negative)\n",
                   addr, len, offset);
        return -EINVAL;
    }

    /* Check for offset + len overflow with proper SIZE_MAX validation
     * VULNERABILITY: LONG_MAX vs SIZE_MAX Mismatch in Overflow Detection
     *
     * ATTACK SCENARIO:
     * Attacker exploits signed/unsigned mismatch to bypass overflow check
     * 1. On 64-bit system: LONG_MAX = 2^63-1, SIZE_MAX = 2^64-1
     * 2. Attacker calls sys_mmap(addr, len=2^63, PROT_READ|PROT_WRITE, MAP_ANONYMOUS, -1, offset=2^62)
     * 3. Line 35: len (2^63) passes MAX_MMAP_LEN check (SIZE_MAX/2 = 2^63-1) - PASSES
     * 4. WITHOUT fix:
     *    - Old line 69: Cast (long)len = (long)(2^63) = -2^63 (signed overflow!)
     *    - Old check: offset > LONG_MAX - (-2^63)
     *                 2^62 > 2^63-1 - (-2^63) = 2^63-1 + 2^63 (wraps!)
     *    - Check fails to detect overflow due to signed arithmetic
     * 5. Line 87: fut_mm_map_anonymous(mm, addr, 2^63, prot, flags)
     *    - Memory subsystem receives huge length
     *    - offset + len = 2^62 + 2^63 = 1.5 * 2^63 (no overflow check passed!)
     *    - Result: Map overlaps kernel space or wraps address space
     *
     * ROOT CAUSE:
     * - Line 34: MAX_MMAP_LEN uses SIZE_MAX (unsigned)
     * - Old line 69: Check uses LONG_MAX (signed, smaller range)
     * - Cast to `long` causes signed overflow for large len
     * - LONG_MAX is half of SIZE_MAX on 64-bit systems
     *
     * DEFENSE:
     * Check offset + len against SIZE_MAX using unsigned arithmetic ONLY
     * - No cast to `long` (avoids signed overflow)
     * - Check: (size_t)offset > SIZE_MAX - len (both operands unsigned)
     * - Handles all edge cases: offset near SIZE_MAX, len near SIZE_MAX/2
     * - Consistent with len validation at line 35 (SIZE_MAX/2 limit)
     *
     * EDGE CASES:
     * 1. offset = SIZE_MAX - 1, len = 1: SIZE_MAX - 1 > SIZE_MAX - 1? FALSE (valid)
     * 2. offset = SIZE_MAX - 1, len = 2: SIZE_MAX - 1 > SIZE_MAX - 2? TRUE (overflow detected)
     * 3. offset = SIZE_MAX/2, len = SIZE_MAX/2: SIZE_MAX/2 > SIZE_MAX/2? FALSE (valid at boundary)
     *
     * CVE REFERENCES:
     * Similar signed/unsigned mismatch in CVE-2017-16995 (eBPF array bounds)
     */
    if ((size_t)offset > SIZE_MAX - len) {
        fut_printf("[MMAP] mmap(addr=%p, len=%zu, offset=%ld) -> EINVAL "
                   "(offset + len would overflow SIZE_MAX)\n",
                   addr, len, offset);
        return -EINVAL;
    }

    /* File-backed mappings require page-aligned offset */
    if (!(flags & MAP_ANONYMOUS) && (offset % PAGE_SIZE != 0)) {
        fut_printf("[MMAP] mmap(offset=%ld) -> EINVAL (offset not page-aligned)\n", offset);
        return -EINVAL;
    }

    if (flags & MAP_ANONYMOUS) {
        fut_task_t *task = fut_task_current();
        if (!task) {
            return -EPERM;
        }

        fut_mm_t *mm = fut_task_get_mm(task);
        if (!mm) {
            /* Fall back to kernel_mm for kernel threads (same as fut_mm_current()) */
            mm = fut_mm_current();
        }
        if (!mm) {
            return -ENOMEM;
        }

        /* MAP_FIXED_NOREPLACE: fail with EEXIST if range [addr, addr+len) overlaps
         * any existing VMA, instead of silently unmapping the existing mapping. */
        if ((flags & MAP_FIXED_NOREPLACE) && addr) {
            uintptr_t req_start = (uintptr_t)addr;
            uintptr_t req_end   = req_start + len;
            struct fut_vma *vma = mm->vma_list;
            while (vma) {
                if (vma->start < req_end && vma->end > req_start) {
                    /* Overlap detected */
                    return -EEXIST;
                }
                vma = vma->next;
            }
            /* No overlap: treat as MAP_FIXED */
            flags = (flags & ~MAP_FIXED_NOREPLACE) | MAP_FIXED;
        }

        /* Check VMA count limit to prevent VMA fragmentation attacks.
         * An attacker could create millions of tiny mappings to:
         * - Exhaust kernel memory with VMA structures
         * - Cause O(n) slowdowns in VMA list operations
         * - Trigger OOM conditions during fork (must clone all VMAs)
         * Limit to MAX_VMA_COUNT (65536) VMAs per process. */
        int vma_count = fut_mm_vma_count(mm);
        if (vma_count >= MAX_VMA_COUNT) {
            fut_printf("[MMAP] mmap(addr=%p, len=%zu) -> ENOMEM "
                       "(VMA count %d exceeds maximum %d, DoS prevention)\n",
                       addr, len, vma_count, MAX_VMA_COUNT);
            return -ENOMEM;
        }

        void *res = fut_mm_map_anonymous(mm, (uintptr_t)addr, len, prot, flags);
        if ((intptr_t)res < 0) {
            return (long)(intptr_t)res;
        }
        return (long)(intptr_t)res;
    }

    void *mapped = fut_vfs_mmap(fd, addr, len, prot, flags, (off_t)offset);
    return (long)(intptr_t)mapped;
}

long sys_munmap(void *addr, size_t len) {
    if (!addr || len == 0) {
        return -EINVAL;
    }

    /* Address must be page-aligned */
    if ((uintptr_t)addr % PAGE_SIZE != 0) {
        return -EINVAL;
    }

    /* Validate length is within reasonable bounds (matching mmap)
     * Without size limits, attacker can request unbounded unmap operations:
     *   - munmap(addr, SIZE_MAX)
     *   - Causes fut_mm_unmap to iterate over entire address space
     *   - CPU exhaustion DoS from excessive page table walking
     *   - Potential memory corruption if overlapping unmapped regions
     * Defense: Limit to same maximum as mmap (SIZE_MAX / 2) */
    const size_t MAX_MUNMAP_LEN = (SIZE_MAX / 2);
    if (len > MAX_MUNMAP_LEN) {
        fut_printf("[MUNMAP] munmap(addr=%p, len=%zu) -> EINVAL "
                   "(length exceeds maximum %zu, DoS prevention)\n",
                   addr, len, MAX_MUNMAP_LEN);
        return -EINVAL;
    }

    fut_task_t *task = fut_task_current();
    if (!task) {
        return -EPERM;
    }

    fut_mm_t *mm = fut_task_get_mm(task);
    if (!mm) {
        return -ENOMEM;
    }

    return fut_mm_unmap(mm, (uintptr_t)addr, len);
}
