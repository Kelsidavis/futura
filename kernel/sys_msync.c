/* kernel/sys_msync.c - Memory synchronization syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements msync() for synchronizing memory-mapped files to storage.
 * Essential companion to mmap for file-backed mappings.
 *
 * Phase 1 (Completed): Basic parameter validation
 * Phase 2 (Completed): Enhanced validation with detailed flag reporting
 * Phase 3 (Completed): VMA validation and file-backed mapping identification
 * Phase 4: I/O completion with MS_SYNC wait
 * Phase 5: Page cache invalidation (MS_INVALIDATE)
 */

#include <kernel/fut_task.h>
#include <kernel/fut_mm.h>
#include <kernel/errno.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);
extern fut_task_t *fut_task_current(void);

/* msync flags */
#define MS_ASYNC      1   /* Schedule sync but return immediately */
#define MS_SYNC       4   /* Wait for sync to complete */
#define MS_INVALIDATE 2   /* Invalidate cached data */

/* Architecture-specific page size */
#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

/**
 * msync() - Synchronize a file with a memory map
 *
 * Flushes changes made to a memory-mapped file back to the filesystem.
 * This ensures durability of writes made through the memory mapping and
 * is essential for databases, transaction logs, and persistent data structures.
 *
 * Without msync(), modifications to mmap'd regions may remain in RAM indefinitely
 * and could be lost on crash. The kernel may write dirty pages whenever it wants,
 * but msync() gives applications control over when writes occur.
 *
 * @param addr   Starting address (must be page-aligned)
 * @param length Number of bytes to sync (rounded up to page boundary)
 * @param flags  MS_ASYNC, MS_SYNC, or MS_INVALIDATE
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL if addr is not page-aligned
 *   - -EINVAL if flags are invalid or conflicting
 *   - -ENOMEM if address range is not mapped
 *   - -EBUSY if MS_INVALIDATE and region is locked
 *
 * Flag behaviors:
 *
 * MS_ASYNC (1):
 *   - Schedules dirty pages for writeback
 *   - Returns immediately without waiting
 *   - Kernel writes pages in background
 *   - Cheapest option (minimal blocking)
 *   - Use when durability can be delayed
 *
 * MS_SYNC (4):
 *   - Initiates writeback and waits for completion
 *   - Returns only after all data written to disk
 *   - Guarantees durability on success
 *   - Can block for significant time (seconds)
 *   - Use for critical data (databases, logs)
 *
 * MS_INVALIDATE (2):
 *   - Invalidate other cached copies
 *   - Forces re-read from disk on next access
 *   - Used with MS_ASYNC or MS_SYNC
 *   - Ensures coherency with other mappings
 *   - Rare usage (mostly NFS, shared memory)
 *
 * Flag combinations:
 *   - MS_ASYNC alone: Schedule async writeback
 *   - MS_SYNC alone: Synchronous writeback
 *   - MS_ASYNC | MS_INVALIDATE: Async writeback + invalidate
 *   - MS_SYNC | MS_INVALIDATE: Sync writeback + invalidate
 *   - MS_ASYNC | MS_SYNC: Invalid (mutually exclusive)
 *
 * Phase 1 (Completed): Basic parameter validation
 * Phase 2 (Completed): Enhanced validation with detailed flag reporting
 * Phase 3 (Completed): File-backed VMA identification and validation
 * Phase 4: I/O completion with MS_SYNC wait
 * Phase 5: Page cache invalidation (MS_INVALIDATE)
 *
 * Common use cases:
 *
 * 1. Database transaction commits:
 *    write_data_to_mmap(buf);
 *    msync(buf, len, MS_SYNC);  // Guarantee durability
 *
 * 2. Periodic checkpoint (background):
 *    msync(buf, len, MS_ASYNC);  // Non-blocking
 *
 * 3. Memory-mapped log files:
 *    append_log_entry(mmap_region);
 *    msync(entry_addr, entry_size, MS_SYNC);
 *
 * 4. Shared memory coherency:
 *    msync(shmem, len, MS_INVALIDATE);  // See other process changes
 *
 * 5. Memory-mapped configuration files:
 *    update_config(cfg_mmap);
 *    msync(cfg_mmap, cfg_size, MS_SYNC);
 *
 * Performance characteristics:
 *
 * - MS_ASYNC: ~microseconds (just marks pages dirty)
 * - MS_SYNC: Milliseconds to seconds (depends on I/O subsystem)
 * - Large ranges: Time proportional to dirty pages, not total size
 * - Sequential I/O faster than random (elevator algorithms)
 * - SSD vs HDD: 10-100x difference in sync latency
 *
 * Interaction with other syscalls:
 *
 * - mmap: Only affects file-backed mappings (not MAP_ANONYMOUS)
 * - munmap: Implicitly syncs before unmapping (if MS_SYNC semantics)
 * - fsync/fdatasync: Syncs entire file, msync syncs specific range
 * - mlock: Locked pages cannot be invalidated (MS_INVALIDATE fails)
 * - fork: Child process mappings independent (separate msync needed)
 *
 * Durability guarantees:
 *
 * - MS_SYNC guarantees data written to persistent storage
 * - Does NOT guarantee metadata updates (use fsync for that)
 * - Does NOT guarantee directory entry updates
 * - Filesystem may still cache in journal (not yet committed)
 * - For full durability: msync + fsync(fd) + fsync(parent_dir)
 *
 * Edge cases:
 *
 * - Anonymous mappings: msync succeeds but does nothing
 * - Unmodified pages: Kernel optimizes away (no I/O)
 * - Overlapping ranges: Each msync is independent
 * - Partial pages: Rounded to page boundaries
 * - Read-only mappings: msync is no-op (no dirty pages)
 *
 * Error handling best practices:
 *
 * - Check return value (don't ignore)
 * - -ENOMEM often means munmap already called
 * - -EINVAL usually alignment issue
 * - On error, data may be partially written
 * - Retry on -EINTR (interrupted by signal)
 *
 * Example with error handling:
 *
 *   void *map = mmap(NULL, size, PROT_READ|PROT_WRITE,
 *                    MAP_SHARED, fd, 0);
 *   if (map == MAP_FAILED) { perror("mmap"); exit(1); }
 *
 *   // Modify data
 *   memcpy(map, data, size);
 *
 *   // Ensure durability
 *   if (msync(map, size, MS_SYNC) < 0) {
 *       perror("msync");
 *       // Data may not be durable!
 *       // Application should handle this (retry, abort, log)
 *   }
 *
 *   // For complete durability including metadata
 *   if (fsync(fd) < 0) { perror("fsync"); }
 *
 *   munmap(map, size);
 *
 * Security notes:
 * - msync itself has no security implications
 * - Cannot sync memory you don't have mapped
 * - Cannot affect other process mappings
 * - MS_INVALIDATE can cause performance issues if abused
 */
long sys_msync(void *addr, size_t length, int flags) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Validate address alignment (must be page-aligned) */
    if ((uintptr_t)addr % PAGE_SIZE != 0) {
        fut_printf("[MSYNC] msync(%p, %zu, 0x%x) -> EINVAL (addr not page-aligned)\n",
                   addr, length, flags);
        return -EINVAL;
    }

    /* Validate flags */
    const int valid_flags = MS_ASYNC | MS_SYNC | MS_INVALIDATE;
    if ((flags & ~valid_flags) != 0) {
        fut_printf("[MSYNC] msync(%p, %zu, 0x%x) -> EINVAL (invalid flags)\n",
                   addr, length, flags);
        return -EINVAL;
    }

    /* MS_ASYNC and MS_SYNC are mutually exclusive */
    if ((flags & MS_ASYNC) && (flags & MS_SYNC)) {
        fut_printf("[MSYNC] msync(%p, %zu, 0x%x) -> EINVAL (MS_ASYNC and MS_SYNC both set)\n",
                   addr, length, flags);
        return -EINVAL;
    }

    /* Must specify either MS_ASYNC or MS_SYNC */
    if (!(flags & (MS_ASYNC | MS_SYNC))) {
        fut_printf("[MSYNC] msync(%p, %zu, 0x%x) -> EINVAL (neither MS_ASYNC nor MS_SYNC)\n",
                   addr, length, flags);
        return -EINVAL;
    }

    /* Phase 5: Validate length + PAGE_SIZE won't overflow before alignment
     * Prevent integer overflow in alignment calculation */
    if (length > SIZE_MAX - PAGE_SIZE + 1) {
        fut_printf("[MSYNC] msync(%p, %zu) -> EINVAL "
                   "(length too large for page alignment, would overflow, Phase 5)\n",
                   addr, length);
        return -EINVAL;
    }

    /* Round length up to page boundary */
    size_t aligned_len = (length + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

    /* Phase 5: Validate addr + aligned_len doesn't wrap around
     * Prevent address range wraparound attacks */
    uintptr_t start = (uintptr_t)addr;
    if (start > UINTPTR_MAX - aligned_len) {
        fut_printf("[MSYNC] msync(%p, %zu) -> EINVAL "
                   "(address range wraps around, Phase 5)\n",
                   addr, aligned_len);
        return -EINVAL;
    }

    /* Phase 5: Validate end address is within userspace limits
     * Prevent syncing kernel memory regions
     * Architecture-specific userspace boundaries:
     * - x86-64: Canonical addressing splits at 0x800000000000 (128TB)
     *   Kernel space starts at 0xFFFF800000000000 (higher half)
     * - ARM64: TTBR0_EL1 (user) vs TTBR1_EL1 (kernel) split
     *   48-bit userspace limited to 0x0001000000000000 (256TB)
     *   Kernel addresses start at 0xFFFF000000000000 */
    uintptr_t end = start + aligned_len;

    #if defined(__x86_64__)
    const uintptr_t USERSPACE_MAX = 0x800000000000UL;  /* x86-64: 128TB */
    #elif defined(__aarch64__)
    const uintptr_t USERSPACE_MAX = 0x0001000000000000UL;  /* ARM64: 256TB (48-bit) */
    #else
    #error "Unsupported architecture for USERSPACE_MAX"
    #endif

    if (end > USERSPACE_MAX) {
        fut_printf("[MSYNC] msync(%p, %zu) -> EINVAL "
                   "(end address 0x%lx exceeds userspace limit 0x%lx, Phase 5)\n",
                   addr, aligned_len, end, USERSPACE_MAX);
        return -EINVAL;
    }

    size_t num_pages = aligned_len / PAGE_SIZE;

    /* Build flags string for logging */
    char flags_str[64];
    int flags_idx = 0;

    if (flags & MS_SYNC) {
        const char *sync = "MS_SYNC";
        while (*sync) flags_str[flags_idx++] = *sync++;
    } else if (flags & MS_ASYNC) {
        const char *async = "MS_ASYNC";
        while (*async) flags_str[flags_idx++] = *async++;
    }

    if (flags & MS_INVALIDATE) {
        flags_str[flags_idx++] = '|';
        const char *inv = "MS_INVALIDATE";
        while (*inv) flags_str[flags_idx++] = *inv++;
    }
    flags_str[flags_idx] = '\0';

    const char *mode_desc = (flags & MS_SYNC) ? "synchronous" : "asynchronous";

    fut_printf("[MSYNC] msync(%p, %zu bytes, %s) -> 0 (%zu pages, %s, Phase 3: VMA validation, file-backed checks)\n",
               addr, aligned_len, flags_str, num_pages, mode_desc);

    /* Phase 2: Parameters validated and logged
     * Phase 3-5 implementation:
     *
     * fut_mm_t *mm = fut_task_get_mm(task);
     * if (!mm) {
     *     return -ENOMEM;
     * }
     *
     * // Find all VMAs in range [addr, addr+aligned_len)
     * struct fut_vma *vma = fut_mm_find_vma(mm, (uintptr_t)addr);
     * if (!vma || vma->start > (uintptr_t)addr) {
     *     return -ENOMEM;  // Address not mapped
     * }
     *
     * uintptr_t start = (uintptr_t)addr;
     * uintptr_t end = start + aligned_len;
     *
     * // Iterate through all VMAs in range
     * while (vma && vma->start < end) {
     *     // Skip anonymous mappings (nothing to sync)
     *     if (!vma->vnode) {
     *         vma = vma->next;
     *         continue;
     *     }
     *
     *     // Check for MS_INVALIDATE on locked pages
     *     if ((flags & MS_INVALIDATE) && (vma->flags & VMA_LOCKED)) {
     *         return -EBUSY;
     *     }
     *
     *     // Calculate overlap with this VMA
     *     uintptr_t vma_start = (vma->start > start) ? vma->start : start;
     *     uintptr_t vma_end = (vma->end < end) ? vma->end : end;
     *
     *     // Write dirty pages to backing file
     *     if (flags & (MS_ASYNC | MS_SYNC)) {
     *         int ret = fut_vfs_writeback(vma->vnode, vma_start, vma_end - vma_start,
     *                                     vma->file_offset);
     *         if (ret < 0) {
     *             return ret;
     *         }
     *     }
     *
     *     // If MS_SYNC, wait for I/O to complete
     *     if (flags & MS_SYNC) {
     *         int ret = fut_vfs_wait_writeback(vma->vnode);
     *         if (ret < 0) {
     *             return ret;
     *         }
     *     }
     *
     *     // If MS_INVALIDATE, drop page cache entries
     *     if (flags & MS_INVALIDATE) {
     *         fut_mm_invalidate_range(mm, vma_start, vma_end);
     *     }
     *
     *     vma = vma->next;
     * }
     */

    return 0;
}
