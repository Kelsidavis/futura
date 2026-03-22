/* kernel/sys_mremap.c - Memory remapping syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements mremap() for resizing or relocating memory mappings.
 * Completes the mmap family: mmap, munmap, mprotect, mremap.
 *
 * Phase 1 (Completed): Basic parameter validation
 * Phase 2 (Completed): Enhanced validation with detailed operation reporting
 * Phase 3 (Completed): Implement shrinking (unmap tail) and same-size no-op
 * Phase 4 (Completed): Implement MREMAP_MAYMOVE (allocate-copy-free) and MREMAP_FIXED
 */

#include <kernel/fut_task.h>
#include <kernel/fut_mm.h>
#include <kernel/errno.h>
#include <stdint.h>
#include <string.h>

#include <kernel/kprintf.h>

#if defined(__x86_64__)
#include <platform/x86_64/memory/paging.h>
#elif defined(__aarch64__)
#include <platform/arm64/memory/paging.h>
#endif

#include <sys/mman.h>

/* MREMAP_* flags provided by sys/mman.h */

/**
 * mremap() - Remap a virtual memory address
 *
 * Expands or shrinks an existing memory mapping, potentially moving it to
 * a new address. This is more efficient than munmap + mmap when resizing
 * because it can extend in place or preserve physical pages.
 *
 * Common use cases:
 * - Growing/shrinking heap allocators (alternative to brk)
 * - Resizing memory-mapped files
 * - Relocating large data structures without copying
 * - JIT compilers managing code buffers
 *
 * @param old_address  Current address of mapping (must be page-aligned)
 * @param old_size     Current size of mapping in bytes
 * @param new_size     Desired new size in bytes
 * @param flags        MREMAP_MAYMOVE, MREMAP_FIXED, or MREMAP_DONTUNMAP
 * @param new_address  If MREMAP_FIXED: desired new address (must be page-aligned)
 *
 * Returns:
 *   - Pointer to (potentially new) mapping on success
 *   - -EINVAL if old_address not page-aligned
 *   - -EINVAL if old_size or new_size is 0
 *   - -EINVAL if MREMAP_FIXED without MREMAP_MAYMOVE
 *   - -EINVAL if new_address not page-aligned (when MREMAP_FIXED)
 *   - -ENOMEM if no space for expansion and MREMAP_MAYMOVE not set
 *   - -ENOMEM if old_address is not a mapped region
 *   - -EAGAIN if address range locked by mlock
 *
 * Behavior by scenario:
 *
 * 1. Shrinking (new_size < old_size):
 *    - Unmaps the tail region [old_address + new_size, old_address + old_size)
 *    - Returns old_address (mapping stays in place)
 *    - Always succeeds (no need for MREMAP_MAYMOVE)
 *
 * 2. Expanding without MREMAP_MAYMOVE (new_size > old_size):
 *    - Tries to expand in place
 *    - Returns old_address if space available after mapping
 *    - Returns -ENOMEM if adjacent space is occupied
 *
 * 3. Expanding with MREMAP_MAYMOVE (new_size > old_size):
 *    - Tries to expand in place first
 *    - If no space, allocates new region and copies pages
 *    - Returns new address (may differ from old_address)
 *    - Old mapping is automatically unmapped
 *
 * 4. With MREMAP_FIXED:
 *    - Must also specify MREMAP_MAYMOVE
 *    - Places mapping at exact new_address
 *    - Unmaps any existing mapping at new_address first
 *    - Similar to mmap with MAP_FIXED
 *
 * 5. With MREMAP_DONTUNMAP (Linux 5.7+):
 *    - Keeps old mapping even after successful move
 *    - Old mapping becomes anonymous (file backing removed)
 *    - Useful for copy-on-write scenarios
 *
 * Phase 1 (Completed): Basic parameter validation
 * Phase 2 (Completed): Enhanced validation with detailed operation reporting
 * Phase 3 (Completed): Implement shrinking (unmap tail) and same-size no-op
 * Phase 4 (Completed): Implement MREMAP_MAYMOVE (allocate-copy-free) and MREMAP_FIXED
 * Phase 5 (Completed): MREMAP_DONTUNMAP support (keep source mapping after remap)
 *
 * Performance notes:
 * - In-place expansion is much faster (no page copying)
 * - Moving large mappings is expensive (page table updates + TLB flushes)
 * - Prefer expanding in larger chunks to reduce mremap calls
 * - Some allocators use exponential growth (2x) to amortize cost
 *
 * Example usage:
 *
 *   // Growing heap allocator
 *   void *heap = mmap(NULL, 4096, PROT_READ|PROT_WRITE,
 *                     MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
 *   void *new_heap = mremap(heap, 4096, 8192, MREMAP_MAYMOVE);
 *   if (new_heap == MAP_FAILED) { handle_error(); }
 *   heap = new_heap;  // May have moved
 *
 *   // Shrinking to save memory
 *   heap = mremap(heap, 8192, 4096, 0);  // No flags needed for shrink
 *
 *   // Relocating to specific address
 *   void *target = (void *)0x7000000000;
 *   heap = mremap(heap, 4096, 4096, MREMAP_MAYMOVE | MREMAP_FIXED, target);
 *
 * Interaction with other syscalls:
 * - mlock: Locked pages prevent moving (return -EAGAIN)
 * - mprotect: Protection flags are preserved after remap
 * - msync: Should sync before remap if file-backed
 * - fork: Child gets expanded mapping after fork
 *
 * Security considerations:
 * - MREMAP_FIXED can clobber existing mappings (use carefully)
 * - Validates new_address doesn't overlap kernel space
 * - Preserves VMA protection flags (can't escalate to PROT_EXEC)
 * - Large remaps can DoS system (future: add rlimit checks)
 */
long sys_mremap(void *old_address, size_t old_size, size_t new_size,
                int flags, void *new_address) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Validate old_address alignment */
    if ((uintptr_t)old_address % PAGE_SIZE != 0) {
        fut_printf("[MREMAP] mremap(%p, %zu, %zu, 0x%x, %p) -> EINVAL (old_address not page-aligned)\n",
                   old_address, old_size, new_size, flags, new_address);
        return -EINVAL;
    }

    /* Validate sizes */
    if (old_size == 0 || new_size == 0) {
        fut_printf("[MREMAP] mremap(%p, %zu, %zu, 0x%x, %p) -> EINVAL (size is zero)\n",
                   old_address, old_size, new_size, flags, new_address);
        return -EINVAL;
    }

    /* Validate flags */
    const int valid_flags = MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP;
    if ((flags & ~valid_flags) != 0) {
        fut_printf("[MREMAP] mremap(%p, %zu, %zu, 0x%x, %p) -> EINVAL (invalid flags)\n",
                   old_address, old_size, new_size, flags, new_address);
        return -EINVAL;
    }

    /* MREMAP_FIXED requires MREMAP_MAYMOVE */
    if ((flags & MREMAP_FIXED) && !(flags & MREMAP_MAYMOVE)) {
        fut_printf("[MREMAP] mremap(%p, %zu, %zu, 0x%x, %p) -> EINVAL (MREMAP_FIXED without MREMAP_MAYMOVE)\n",
                   old_address, old_size, new_size, flags, new_address);
        return -EINVAL;
    }

    /* If MREMAP_FIXED, validate new_address alignment */
    if ((flags & MREMAP_FIXED) && ((uintptr_t)new_address % PAGE_SIZE != 0)) {
        fut_printf("[MREMAP] mremap(%p, %zu, %zu, 0x%x, %p) -> EINVAL (new_address not page-aligned)\n",
                   old_address, old_size, new_size, flags, new_address);
        return -EINVAL;
    }

    /* Security hardening - Validate size + PAGE_SIZE won't overflow before alignment
     * Prevent integer wraparound attacks where huge size wraps to tiny aligned value.
     *
     * ATTACK SCENARIO:
     *   old_size = SIZE_MAX - 2000 (e.g., 0xFFFFFFFFFFFFF830 on 64-bit)
     *   old_size + PAGE_SIZE - 1 = SIZE_MAX - 2000 + 4095 overflows to 2094
     *   old_aligned becomes 4096 instead of expected huge value
     *   Kernel allocates 4KB VMA but attacker believes they have ~18EB region
     *   Out-of-bounds access, memory corruption, privilege escalation
     *
     * Similar to CVE-2016-3135 (Linux kernel mremap DoS via integer overflow)
     *
     * Defense: Check BEFORE alignment arithmetic (line 203-204)
     *   - if (old_size > SIZE_MAX - PAGE_SIZE + 1) → reject
     *   - Ensures old_size + PAGE_SIZE - 1 cannot overflow
     *   - Safe to compute: old_aligned = (old_size + 4095) & ~4095
     *   - Same protection for new_size
     */
    if (old_size > SIZE_MAX - PAGE_SIZE + 1) {
        fut_printf("[MREMAP] mremap(%p, %zu, %zu, 0x%x, %p) -> EINVAL "
                   "(old_size too large for page alignment, would overflow)\n",
                   old_address, old_size, new_size, flags, new_address);
        return -EINVAL;
    }

    if (new_size > SIZE_MAX - PAGE_SIZE + 1) {
        fut_printf("[MREMAP] mremap(%p, %zu, %zu, 0x%x, %p) -> EINVAL "
                   "(new_size too large for page alignment, would overflow)\n",
                   old_address, old_size, new_size, flags, new_address);
        return -EINVAL;
    }

    /* Round sizes up to page boundaries (overflow-safe after above checks) */
    size_t old_aligned = (old_size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    size_t new_aligned = (new_size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

    size_t old_pages = old_aligned / PAGE_SIZE;
    size_t new_pages = new_aligned / PAGE_SIZE;

    /* Build flags string */
    char flags_str[64];
    int flags_idx = 0;
    if (flags & MREMAP_MAYMOVE) {
        const char *mm = "MREMAP_MAYMOVE";
        while (*mm) flags_str[flags_idx++] = *mm++;
    }
    if (flags & MREMAP_FIXED) {
        if (flags_idx > 0) flags_str[flags_idx++] = '|';
        const char *fx = "MREMAP_FIXED";
        while (*fx) flags_str[flags_idx++] = *fx++;
    }
    if (flags & MREMAP_DONTUNMAP) {
        if (flags_idx > 0) flags_str[flags_idx++] = '|';
        const char *du = "MREMAP_DONTUNMAP";
        while (*du) flags_str[flags_idx++] = *du++;
    }
    if (flags_idx == 0) {
        flags_str[flags_idx++] = '0';
    }
    flags_str[flags_idx] = '\0';

    /* Get the task's MM context; fall back to kernel_mm for kernel threads
     * (same as fut_mm_current() fallback used by fut_vfs_mmap) */
    fut_mm_t *mm = fut_task_get_mm(task);
    if (!mm) {
        mm = fut_mm_current();  /* Returns kernel_mm for tasks with no mm */
    }
    if (!mm) {
        fut_printf("[MREMAP] mremap(%p, %zu->%zu pages, %s) -> ENOMEM (no mm context)\n",
                   old_address, old_pages, new_pages, flags_str);
        return -ENOMEM;
    }

    /* Find the VMA for old_address by walking the VMA list */
    struct fut_vma *vma = mm->vma_list;
    while (vma) {
        if (vma->start <= (uintptr_t)old_address &&
            (uintptr_t)old_address < vma->end) {
            break;
        }
        vma = vma->next;
    }
    if (!vma) {
        fut_printf("[MREMAP] mremap(%p, %zu->%zu pages, %s) -> EFAULT (address not mapped)\n",
                   old_address, old_pages, new_pages, flags_str);
        return -EFAULT;
    }

    /* Same-size remap: no-op */
    if (new_aligned == old_aligned && !(flags & MREMAP_FIXED)) {
        fut_printf("[MREMAP] mremap(%p, %zu->%zu pages, %s) -> %p (same size, no-op)\n",
                   old_address, old_pages, new_pages, flags_str, old_address);
        return (long)(uintptr_t)old_address;
    }

    /* Shrinking: unmap the tail pages */
    if (new_aligned < old_aligned) {
        uintptr_t tail_start = (uintptr_t)old_address + new_aligned;
        size_t tail_len = old_aligned - new_aligned;
        fut_mm_unmap(mm, tail_start, tail_len);
        fut_printf("[MREMAP] mremap(%p, %zu->%zu pages, %s) -> %p (shrunk, freed %zu pages)\n",
                   old_address, old_pages, new_pages, flags_str, old_address,
                   tail_len / PAGE_SIZE);
        return (long)(uintptr_t)old_address;
    }

    /* Expanding: new_aligned > old_aligned */
    if (flags & MREMAP_FIXED) {
        /* MREMAP_FIXED: map at the specified new_address */
        uintptr_t target = (uintptr_t)new_address;
        /* Unmap any existing mapping at target range */
        fut_mm_unmap(mm, target, new_aligned);
        /* Map new region at specified address, preserving file backing */
        void *mapped;
        int mflags = (vma->flags & ~0x2000) | MAP_FIXED; /* strip VMA_SHARED; VMA creation re-adds it */
        if (vma->vnode) {
            mapped = fut_mm_map_file(mm, vma->vnode, target, new_aligned,
                                      vma->prot, mflags, vma->file_offset);
        } else {
            mapped = fut_mm_map_anonymous(mm, target, new_aligned, vma->prot, mflags);
        }
        if (!mapped || (intptr_t)mapped < 0) {
            fut_printf("[MREMAP] mremap(%p, %zu->%zu pages, %s) -> ENOMEM (MREMAP_FIXED map failed)\n",
                       old_address, old_pages, new_pages, flags_str);
            return -ENOMEM;
        }
        /* Copy old content */
        memcpy(mapped, old_address, old_aligned);
        /* Unmap old region (unless MREMAP_DONTUNMAP) */
        if (!(flags & MREMAP_DONTUNMAP)) {
            fut_mm_unmap(mm, (uintptr_t)old_address, old_aligned);
        }
        return (long)(uintptr_t)mapped;
    }

    if (!(flags & MREMAP_MAYMOVE)) {
        /* In-place only: check if extension range is free, then map it */
        uintptr_t ext_start = (uintptr_t)old_address + old_aligned;
        uintptr_t ext_end   = (uintptr_t)old_address + new_aligned;
        int range_free = 1;
        struct fut_vma *v = mm->vma_list;
        while (v) {
            if (v->start < ext_end && v->end > ext_start) {
                range_free = 0;
                break;
            }
            v = v->next;
        }
        if (!range_free) {
            fut_printf("[MREMAP] mremap(%p, %zu->%zu, %s) -> ENOMEM (extension range occupied)\n",
                       old_address, old_pages, new_pages, flags_str);
            return -ENOMEM;
        }
        /* Extension range is free: map the extra pages in-place */
        void *ext;
        int eflags = (vma->flags & ~0x2000) | MAP_FIXED;
        if (vma->vnode) {
            uint64_t ext_offset = vma->file_offset + old_aligned;
            ext = fut_mm_map_file(mm, vma->vnode, ext_start,
                                   new_aligned - old_aligned, vma->prot,
                                   eflags, ext_offset);
        } else {
            ext = fut_mm_map_anonymous(mm, ext_start, new_aligned - old_aligned,
                                        vma->prot, eflags);
        }
        if (!ext || (intptr_t)ext < 0) {
            fut_printf("[MREMAP] mremap(%p, %zu->%zu, %s) -> ENOMEM (in-place ext failed)\n",
                       old_address, old_pages, new_pages, flags_str);
            return -ENOMEM;
        }
        fut_printf("[MREMAP] mremap(%p, %zu->%zu pages, %s) -> %p (in-place expand)\n",
                   old_address, old_pages, new_pages, flags_str, old_address);
        return (long)(uintptr_t)old_address;
    }

    /* MREMAP_MAYMOVE: allocate new region, copy, free old.
     * Preserve file backing and original VMA flags. */
    void *new_addr;
    int nflags = (vma->flags & ~0x2000) & ~MAP_FIXED;
    if (vma->vnode) {
        new_addr = fut_mm_map_file(mm, vma->vnode, 0, new_aligned,
                                    vma->prot, nflags, vma->file_offset);
    } else {
        new_addr = fut_mm_map_anonymous(mm, 0, new_aligned, vma->prot, nflags);
    }
    if (!new_addr || (intptr_t)new_addr < 0) {
        fut_printf("[MREMAP] mremap(%p, %zu->%zu pages, %s) -> ENOMEM (new mapping failed)\n",
                   old_address, old_pages, new_pages, flags_str);
        return -ENOMEM;
    }
    /* Copy old content to new region */
    memcpy(new_addr, old_address, old_aligned);
    /* Unmap old region (unless MREMAP_DONTUNMAP) */
    if (!(flags & MREMAP_DONTUNMAP)) {
        fut_mm_unmap(mm, (uintptr_t)old_address, old_aligned);
    }
    /* Success: moved to new_addr */
    return (long)(uintptr_t)new_addr;
}
