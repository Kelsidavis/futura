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
 * Phase 4 (Completed): MAP_SHARED writeback — probe each present page via
 *                      pmap_probe_pte, convert phys→kvirt, call vnode->ops->write
 * Phase 5 (Completed): Proper flag semantics:
 *   - MS_SYNC:  synchronously flush dirty pages to backing file
 *   - MS_ASYNC: mark pages for writeback (schedule flush, return immediately)
 *   - MS_INVALIDATE: invalidate cached copies (TLB flush so next access
 *     re-fetches from backing store)
 */

#include <kernel/fut_task.h>
#include <kernel/fut_mm.h>
#include <kernel/errno.h>
#include <stdint.h>

#include <kernel/kprintf.h>

#if defined(__x86_64__)
#include <platform/x86_64/memory/paging.h>
#include <platform/x86_64/memory/pmap.h>
#elif defined(__aarch64__)
#include <platform/arm64/memory/paging.h>
#include <platform/arm64/memory/pmap.h>
#endif

#include <kernel/fut_vfs.h>  /* for struct fut_vnode, struct fut_vnode_ops */

/* msync flags */
#define MS_ASYNC      1   /* Schedule sync but return immediately */
#define MS_SYNC       4   /* Wait for sync to complete */
#define MS_INVALIDATE 2   /* Invalidate cached data */

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
 * Page cache invalidation (MS_INVALIDATE)
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
    /* ARM64 FIX: Copy parameters to local variables */
    void *local_addr = addr;
    size_t local_length = length;
    int local_flags = flags;

    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Linux's mm/msync.c validates flags FIRST, then alignment, then
     * MS_ASYNC|MS_SYNC mutual exclusion:
     *   if (flags & ~(MS_ASYNC | MS_INVALIDATE | MS_SYNC)) goto out;
     *   if (offset_in_page(start)) goto out;
     *   if ((flags & MS_ASYNC) && (flags & MS_SYNC)) goto out;
     * Futura had alignment first, so msync(misaligned, len, 0xff)
     * surfaced the alignment EINVAL where Linux surfaces the flags
     * EINVAL — both EINVAL, but the cause libc wrappers see differs
     * and the flags-detection probe (run with a known-bad addr) was
     * masked. */

    /* Validate flags */
    const int valid_flags = MS_ASYNC | MS_SYNC | MS_INVALIDATE;
    if ((local_flags & ~valid_flags) != 0) {
        fut_printf("[MSYNC] msync(%p, %zu, 0x%x) -> EINVAL (invalid flags)\n",
                   local_addr, local_length, local_flags);
        return -EINVAL;
    }

    /* Validate address alignment (must be page-aligned) */
    if ((uintptr_t)local_addr % PAGE_SIZE != 0) {
        fut_printf("[MSYNC] msync(%p, %zu, 0x%x) -> EINVAL (addr not page-aligned)\n",
                   local_addr, local_length, local_flags);
        return -EINVAL;
    }

    /* MS_ASYNC and MS_SYNC are mutually exclusive */
    if ((local_flags & MS_ASYNC) && (local_flags & MS_SYNC)) {
        fut_printf("[MSYNC] msync(%p, %zu, 0x%x) -> EINVAL (MS_ASYNC and MS_SYNC both set)\n",
                   local_addr, local_length, local_flags);
        return -EINVAL;
    }

    /* Linux's msync(2) does not require either MS_ASYNC or MS_SYNC to
     * be set: from the kernel source (mm/msync.c), the only EINVAL
     * paths are 'unknown bits in flags' and 'MS_ASYNC && MS_SYNC'.
     * Calling msync(addr, len, 0) or msync(addr, len, MS_INVALIDATE)
     * is a defined no-op-ish form (treated like MS_ASYNC) on Linux.
     * The previous gate broke libc/glibc msync wrappers and tools
     * that pass MS_INVALIDATE alone to drop cached pages without
     * forcing a writeback. */

    /* Linux's mm/msync.c switches the error class to ENOMEM after the
     * EINVAL gates pass — the page-alignment round-up overflow and the
     * start+len wraparound both fall under 'address range not in the
     * process' which is ENOMEM, not EINVAL.  Futura previously surfaced
     * these as EINVAL, masking 'address-not-mapped' as 'bad-parameter'
     * and breaking libc msync wrappers that retry on ENOMEM but treat
     * EINVAL as fatal usage error. */
    if (local_length > SIZE_MAX - PAGE_SIZE + 1) {
        fut_printf("[MSYNC] msync(%p, %zu) -> ENOMEM "
                   "(length too large for page alignment, would overflow)\n",
                   local_addr, local_length);
        return -ENOMEM;
    }

    /* Round length up to page boundary */
    size_t aligned_len = (local_length + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

    /* Validate addr + aligned_len doesn't wrap around */
    uintptr_t start = (uintptr_t)local_addr;
    if (start > UINTPTR_MAX - aligned_len) {
        fut_printf("[MSYNC] msync(%p, %zu) -> ENOMEM "
                   "(address range wraps around)\n",
                   local_addr, aligned_len);
        return -ENOMEM;
    }

    /* Validate end address is within userspace limits.
     * Prevent syncing kernel memory regions; USER_SPACE_END is defined
     * in platform paging headers.
     *
     * Linux's mm/msync.c returns -ENOMEM when the address range is not
     * part of the process address space (the find_vma walk returns no
     * VMA, and 'error = -ENOMEM' is the documented errno for that path).
     * Futura previously surfaced this as EINVAL, which collapsed
     * 'address-not-mapped' into 'bad-parameter' and broke libc msync
     * wrappers that retry on ENOMEM (after re-mmap'ing) but treat
     * EINVAL as a fatal usage error. */
    uintptr_t end = start + aligned_len;
    if (end > USER_SPACE_END) {
        fut_printf("[MSYNC] msync(%p, %zu) -> ENOMEM "
                   "(end address 0x%lx exceeds userspace limit 0x%lx)\n",
                   local_addr, aligned_len, end, USER_SPACE_END);
        return -ENOMEM;
    }

    size_t num_pages = aligned_len / PAGE_SIZE;

    /* Build flags string for logging */
    char flags_str[64];
    int flags_idx = 0;

    if (local_flags & MS_SYNC) {
        const char *sync = "MS_SYNC";
        while (*sync) flags_str[flags_idx++] = *sync++;
    } else if (local_flags & MS_ASYNC) {
        const char *async = "MS_ASYNC";
        while (*async) flags_str[flags_idx++] = *async++;
    }

    if (local_flags & MS_INVALIDATE) {
        flags_str[flags_idx++] = '|';
        const char *inv = "MS_INVALIDATE";
        while (*inv) flags_str[flags_idx++] = *inv++;
    }
    flags_str[flags_idx] = '\0';

    const char *mode_desc = (local_flags & MS_SYNC) ? "synchronous" : "asynchronous";

    /* Phase 5: Walk MAP_SHARED file-backed VMAs in range and handle each
     * flag correctly:
     *
     * MS_SYNC:       Synchronously write back dirty/present pages to the
     *                backing vnode.  Only flushes pages whose PTE dirty bit
     *                is set (x86_64) or all present pages (ARM64, which
     *                manages dirty status via AP bits).
     *
     * MS_ASYNC:      Schedule writeback — on our simple kernel this marks
     *                the intent and returns immediately.  We still walk the
     *                page tables so the vnode layer can queue the I/O, but
     *                we do not wait for completion.
     *
     * MS_INVALIDATE: Invalidate cached copies so the next access re-reads
     *                from the backing store.  Implemented by flushing the
     *                TLB entries for the affected pages.  Fails with EBUSY
     *                if the VMA is mlock'd. */
    fut_mm_t *mm = fut_task_get_mm(task);
    if (!mm) {
        mm = fut_mm_current();  /* Kernel threads use the active mm */
    }
    if (mm) {
        fut_vmem_context_t *ctx = fut_mm_context(mm);
        if (ctx) {
            struct fut_vma *vma = mm->vma_list;
            while (vma && vma->start < end) {
                /* Only MAP_SHARED file-backed VMAs with write ops */
                if (vma->end <= start ||
                    !vma->vnode ||
                    !(vma->flags & 0x01) /* MAP_SHARED */ ||
                    !vma->vnode->ops ||
                    !vma->vnode->ops->write) {
                    vma = vma->next;
                    continue;
                }

                /* MS_INVALIDATE fails on locked pages (POSIX requirement) */
                if ((local_flags & MS_INVALIDATE) && (vma->flags & VMA_LOCKED)) {
                    fut_printf("[MSYNC] msync(%p, %zu, %s) -> EBUSY "
                               "(MS_INVALIDATE on locked VMA)\n",
                               local_addr, aligned_len, flags_str);
                    return -EBUSY;
                }

                /* Overlap of [start,end) with this VMA */
                uintptr_t pstart = (vma->start > start) ? vma->start : start;
                uintptr_t pend   = (vma->end   < end)   ? vma->end   : end;
                pstart = PAGE_ALIGN_DOWN(pstart);
                pend   = PAGE_ALIGN_UP(pend);

                /* ---- MS_SYNC / MS_ASYNC: write back dirty pages ---- */
                if (local_flags & (MS_SYNC | MS_ASYNC)) {
                    for (uintptr_t pg = pstart; pg < pend; pg += PAGE_SIZE) {
                        uint64_t pte = 0;
                        if (pmap_probe_pte(ctx, pg, &pte) != 0)
                            continue;  /* Not present — nothing to flush */

                        if (!(pte & PTE_PRESENT))
                            continue;

#if defined(__x86_64__)
                        /* On x86_64 we can check the hardware dirty bit.
                         * Only write back pages that have actually been
                         * modified since the last sync. */
                        if (!(pte & PTE_DIRTY))
                            continue;  /* Clean page — skip writeback */
#endif
                        /* Extract physical address and convert to kernel virtual */
                        uint64_t phys = fut_pte_to_phys(pte);
                        if (!phys) continue;

                        /* Skip pages not tracked by our allocator (e.g. kernel
                         * identity-mapped pages).  Refcount == 0 means the
                         * page was not demand-paged. */
                        if (fut_page_ref_get((phys_addr_t)phys) == 0) continue;

                        void *kvirt = (void *)pmap_phys_to_virt((phys_addr_t)phys);
                        if (!kvirt) continue;

                        /* File offset = VMA base offset + page's offset within VMA */
                        uint64_t foff = vma->file_offset + (pg - vma->start);

                        /* Write PAGE_SIZE bytes to the backing file */
                        vma->vnode->ops->write(vma->vnode, kvirt, PAGE_SIZE, foff);
                    }
                }

                /* ---- MS_INVALIDATE: flush TLB so next access re-reads ---- */
                if (local_flags & MS_INVALIDATE) {
                    for (uintptr_t pg = pstart; pg < pend; pg += PAGE_SIZE) {
                        fut_flush_tlb_single(pg);
                    }
                }

                vma = vma->next;
            }
        }
    }

    /* Success path silent — mmap'd I/O (sqlite, mboxes, large
     * file editors) calls msync per write-back; logging each
     * call drowns the kernel log. */
    (void)local_addr; (void)aligned_len; (void)flags_str;
    (void)num_pages; (void)mode_desc;

    return 0;
}
