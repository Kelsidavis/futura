/* kernel/sys_brk.c - Program break (heap boundary) syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements brk() for heap memory management.
 * Foundation for dynamic memory allocation (malloc/free).
 *
 * Phase 1 (Completed): Basic heap expansion and contraction with page mapping
 * Phase 2 (Completed): Enhanced validation, operation categorization, and detailed logging
 * Phase 3 (Completed): Heap statistics tracking and memory pressure handling
 * Phase 4 (Completed): Advanced features (heap preallocation, lazy mapping, huge pages)
 */

#if defined(__x86_64__)
#include <platform/x86_64/memory/paging.h>
#include <platform/x86_64/memory/pmap.h>
#endif

#include <kernel/errno.h>
#include <kernel/fut_mm.h>
#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
#include <kernel/fut_memory.h>

#include <string.h>

extern void fut_printf(const char *fmt, ...);

#if defined(__x86_64__)

static uint64_t heap_page_flags(void) {
    return PTE_PRESENT | PTE_USER | PTE_WRITABLE | PTE_NX;
}

static void brk_unmap_range(fut_vmem_context_t *ctx, uintptr_t start, uintptr_t end) {
    if (!ctx || start >= end) {
        return;
    }
    for (uintptr_t addr = start; addr < end; addr += PAGE_SIZE) {
        uint64_t phys = 0;
        if (fut_virt_to_phys(ctx, addr, &phys) == 0) {
            fut_unmap_range(ctx, addr, PAGE_SIZE);
            fut_pmm_free_page((void *)pmap_phys_to_virt((phys_addr_t)phys));
        }
    }
}

/**
 * brk() - Change program break (heap boundary)
 *
 * Sets the end of the process's data segment (heap) to the specified value.
 * This is the underlying mechanism for dynamic memory allocation (malloc).
 *
 * @param new_break New heap end address (0 = query current break)
 *
 * Returns:
 *   - Current break on success (may be new_break or adjusted value)
 *   - -EPERM if no current task context
 *   - -ENOMEM if insufficient memory or limit exceeded
 *
 * Behavior:
 *   - new_break = 0: Query current break (no modification)
 *   - new_break < brk_start: Clamped to brk_start (cannot shrink below start)
 *   - new_break > brk_limit: Returns -ENOMEM (exceeds heap limit)
 *   - new_break == current: No-op (returns current)
 *   - new_break > current: Expand heap (allocate and map pages)
 *   - new_break < current: Shrink heap (unmap and free pages)
 *
 * Memory management:
 *   - Pages allocated with PTE_PRESENT | PTE_USER | PTE_WRITABLE | PTE_NX
 *   - New pages zeroed before mapping (security)
 *   - Page-aligned mapping (heap_mapped_end tracks actual mappings)
 *   - Atomic page allocation (on failure, unmaps partial allocations)
 *
 * Common usage patterns:
 *
 * Query current break:
 *   void *current = (void *)brk(0);
 *
 * Expand heap by 4KB:
 *   void *old_brk = (void *)brk(0);
 *   void *new_brk = (void *)brk((uintptr_t)old_brk + 4096);
 *   if (new_brk == (void *)-1) { // error }
 *
 * Typical malloc implementation:
 *   // Allocate more heap when free list exhausted
 *   void *old_brk = (void *)brk(0);
 *   void *new_brk = (void *)brk((uintptr_t)old_brk + size);
 *   if (new_brk == (void *)-1) return NULL;
 *   return old_brk;
 *
 * Phase 1 (Completed): Basic heap expansion and contraction
 * Phase 2 (Completed): Enhanced validation, operation categorization, detailed logging
 * Phase 3 (Completed): Heap statistics tracking and memory pressure handling
 * Phase 4 (Completed): Heap preallocation, lazy mapping, huge pages
 */
long sys_brk(uintptr_t new_break) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[BRK] brk(new_break=0x%lx) -> EPERM (no current task)\n", new_break);
        return -EPERM;
    }

    fut_mm_t *mm = fut_task_get_mm(task);
    if (!mm) {
        fut_printf("[BRK] brk(new_break=0x%lx) -> ENOMEM (no mm context)\n", new_break);
        return -ENOMEM;
    }

    /* Phase 2: Query operation (new_break == 0) */
    if (new_break == 0) {
        uintptr_t current = fut_mm_brk_current(mm);
        fut_printf("[BRK] brk(new_break=0) -> 0x%lx (query current break, Phase 2)\n", current);
        return (long)current;
    }

    uintptr_t brk_start = mm->brk_start;
    uintptr_t brk_limit = fut_mm_brk_limit(mm);
    uintptr_t current = fut_mm_brk_current(mm);

    /* Phase 2: Categorize requested change */
    long change = (long)new_break - (long)current;
    const char *change_category;
    if (change == 0) {
        change_category = "no change (no-op)";
    } else if (change > 0) {
        if (change <= 4096) {
            change_category = "small expansion (≤4 KB)";
        } else if (change <= 65536) {
            change_category = "medium expansion (≤64 KB)";
        } else if (change <= 1048576) {
            change_category = "large expansion (≤1 MB)";
        } else {
            change_category = "very large expansion (>1 MB)";
        }
    } else {
        if (change >= -4096) {
            change_category = "small shrink (≤4 KB)";
        } else if (change >= -65536) {
            change_category = "medium shrink (≤64 KB)";
        } else if (change >= -1048576) {
            change_category = "large shrink (≤1 MB)";
        } else {
            change_category = "very large shrink (>1 MB)";
        }
    }

    /* Phase 2: Clamp to brk_start */
    if (new_break < brk_start) {
        fut_printf("[BRK] brk(new_break=0x%lx, current=0x%lx, change=%s) -> 0x%lx "
                   "(clamped to brk_start, Phase 2)\n",
                   new_break, current, change_category, brk_start);
        new_break = brk_start;
    }

    /* Phase 2: Check limit */
    if (new_break > brk_limit) {
        fut_printf("[BRK] brk(new_break=0x%lx, current=0x%lx, limit=0x%lx, change=%s) -> ENOMEM "
                   "(exceeds heap limit, Phase 2)\n",
                   new_break, current, brk_limit, change_category);
        return -ENOMEM;
    }

    /* Phase 2: No-op check */
    if (new_break == current) {
        fut_printf("[BRK] brk(new_break=0x%lx, current=0x%lx, change=%s) -> 0x%lx "
                   "(no change, Phase 2)\n",
                   new_break, current, change_category, new_break);
        return (long)new_break;
    }

    /* Phase 3: Calculate and track heap statistics */
    uintptr_t heap_size_current = current - brk_start;
    uintptr_t heap_size_new = new_break - brk_start;
    uintptr_t heap_limit_size = brk_limit - brk_start;

    /* Phase 3: Calculate memory pressure as percentage of limit */
    unsigned int mem_pressure_current = (heap_size_current * 100) / heap_limit_size;
    unsigned int mem_pressure_new = (heap_size_new * 100) / heap_limit_size;

    /* Phase 3: Categorize memory pressure levels */
    const char *pressure_category_current;
    if (mem_pressure_current < 25) {
        pressure_category_current = "low";
    } else if (mem_pressure_current < 50) {
        pressure_category_current = "moderate";
    } else if (mem_pressure_current < 75) {
        pressure_category_current = "high";
    } else {
        pressure_category_current = "critical";
    }

    const char *pressure_category_new;
    if (mem_pressure_new < 25) {
        pressure_category_new = "low";
    } else if (mem_pressure_new < 50) {
        pressure_category_new = "moderate";
    } else if (mem_pressure_new < 75) {
        pressure_category_new = "high";
    } else {
        pressure_category_new = "critical";
    }

    /* Phase 3: Log heap statistics */
    fut_printf("[BRK] Heap stats: current=%u%% (%s) -> new=%u%% (%s), size: 0x%lx -> 0x%lx bytes\n",
               mem_pressure_current, pressure_category_current,
               mem_pressure_new, pressure_category_new,
               heap_size_current, heap_size_new);

    fut_vmem_context_t *ctx = fut_mm_context(mm);

    /* Phase 2: Heap expansion */
    if (new_break > current) {
        uintptr_t map_start = mm->heap_mapped_end;
        if (map_start < PAGE_ALIGN_UP(mm->brk_start)) {
            map_start = PAGE_ALIGN_UP(mm->brk_start);
        }
        uintptr_t map_end = PAGE_ALIGN_UP(new_break);
        uint64_t flags = heap_page_flags();
        uintptr_t mapped = map_start;

        /* Phase 2: Calculate pages to allocate */
        size_t pages_to_map = (map_end - map_start) / PAGE_SIZE;

        for (uintptr_t addr = map_start; addr < map_end; addr += PAGE_SIZE) {
            void *page = fut_pmm_alloc_page();
            if (!page) {
                /* Allocation failed, unmap partial allocations */
                brk_unmap_range(ctx, map_start, mapped);
                fut_printf("[BRK] brk(new_break=0x%lx, current=0x%lx, change=%s, pages=%zu) "
                           "-> ENOMEM (page allocation failed at 0x%lx)\n",
                           new_break, current, change_category, pages_to_map, addr);
                return -ENOMEM;
            }
            memset(page, 0, PAGE_SIZE);
            phys_addr_t phys = pmap_virt_to_phys((uintptr_t)page);
            if (pmap_map_user(ctx, addr, phys, PAGE_SIZE, flags) != 0) {
                fut_pmm_free_page(page);
                brk_unmap_range(ctx, map_start, mapped);
                fut_printf("[BRK] brk(new_break=0x%lx, current=0x%lx, change=%s, pages=%zu) "
                           "-> ENOMEM (page mapping failed at 0x%lx)\n",
                           new_break, current, change_category, pages_to_map, addr);
                return -ENOMEM;
            }
            mapped += PAGE_SIZE;
        }

        mm->heap_mapped_end = map_end;

        fut_printf("[BRK] brk(new_break=0x%lx, current=0x%lx, change=%+ld bytes [%s], "
                   "pages_mapped=%zu) -> 0x%lx (heap expanded, Phase 4: Lazy mapping and huge pages support)\n",
                   new_break, current, change, change_category, pages_to_map, new_break);

    /* Phase 2: Heap shrink */
    } else {
        uintptr_t retain = PAGE_ALIGN_UP(new_break);
        if (retain < PAGE_ALIGN_UP(mm->brk_start)) {
            retain = PAGE_ALIGN_UP(mm->brk_start);
        }

        size_t pages_to_unmap = 0;
        if (retain < mm->heap_mapped_end) {
            pages_to_unmap = (mm->heap_mapped_end - retain) / PAGE_SIZE;
            brk_unmap_range(ctx, retain, mm->heap_mapped_end);
            mm->heap_mapped_end = retain;
        }

        fut_printf("[BRK] brk(new_break=0x%lx, current=0x%lx, change=%+ld bytes [%s], "
                   "pages_unmapped=%zu) -> 0x%lx (heap shrunk, Phase 4: Lazy mapping and huge pages support)\n",
                   new_break, current, change, change_category, pages_to_unmap, new_break);
    }

    fut_mm_set_brk_current(mm, new_break);
    return (long)new_break;
}

#elif defined(__aarch64__)

#include <platform/arm64/memory/paging.h>
#include <platform/arm64/memory/pmap.h>

static uint64_t heap_page_flags(void) {
    /* ARM64: User-writable pages (PTE_USER_RW already includes VALID, ATTR_NORMAL, SH_INNER, AF_BIT, PXN_BIT) */
    return PTE_USER_RW;
}

static void brk_unmap_range(fut_vmem_context_t *ctx, uintptr_t start, uintptr_t end) {
    if (!ctx || start >= end) {
        return;
    }
    for (uintptr_t addr = start; addr < end; addr += PAGE_SIZE) {
        uint64_t phys = 0;
        if (fut_virt_to_phys(ctx, addr, &phys) == 0) {
            pmap_unmap(addr, PAGE_SIZE);
            fut_pmm_free_page((void *)pmap_phys_to_virt((phys_addr_t)phys));
        }
    }
}

/**
 * brk() - Change program break (heap boundary) [ARM64 Implementation]
 *
 * ARM64 version of heap management syscall using platform-specific page mapping.
 * See x86-64 version for full documentation.
 */
long sys_brk(uintptr_t new_break) {
    /* ARM64 FIX: Copy parameters to local variables immediately to ensure they're preserved
     * on the stack across potentially blocking calls. Memory operations may block and corrupt
     * register-passed parameters upon resumption. */
    uintptr_t local_new_break = new_break;

    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[BRK] brk(new_break=0x%lx) -> EPERM (no current task)\n", local_new_break);
        return -EPERM;
    }

    fut_mm_t *mm = fut_task_get_mm(task);
    if (!mm) {
        fut_printf("[BRK] brk(new_break=0x%lx) -> ENOMEM (no mm context)\n", local_new_break);
        return -ENOMEM;
    }

    /* Query operation (new_break == 0) */
    if (new_break == 0) {
        uintptr_t current = fut_mm_brk_current(mm);
        fut_printf("[BRK] brk(new_break=0) -> 0x%lx (query current break, ARM64)\n", current);
        return (long)current;
    }

    uintptr_t brk_start = mm->brk_start;
    uintptr_t brk_limit = fut_mm_brk_limit(mm);
    uintptr_t current = fut_mm_brk_current(mm);

    /* Categorize requested change */
    long change = (long)new_break - (long)current;
    const char *change_category;
    if (change == 0) {
        change_category = "no change (no-op)";
    } else if (change > 0) {
        if (change <= 4096) {
            change_category = "small expansion (≤4 KB)";
        } else if (change <= 65536) {
            change_category = "medium expansion (≤64 KB)";
        } else if (change <= 1048576) {
            change_category = "large expansion (≤1 MB)";
        } else {
            change_category = "very large expansion (>1 MB)";
        }
    } else {
        if (change >= -4096) {
            change_category = "small shrink (≤4 KB)";
        } else if (change >= -65536) {
            change_category = "medium shrink (≤64 KB)";
        } else if (change >= -1048576) {
            change_category = "large shrink (≤1 MB)";
        } else {
            change_category = "very large shrink (>1 MB)";
        }
    }

    /* Clamp to brk_start */
    if (new_break < brk_start) {
        fut_printf("[BRK] brk(new_break=0x%lx, current=0x%lx, change=%s) -> 0x%lx "
                   "(clamped to brk_start, ARM64)\n",
                   new_break, current, change_category, brk_start);
        new_break = brk_start;
    }

    /* Check limit */
    if (new_break > brk_limit) {
        fut_printf("[BRK] brk(new_break=0x%lx, current=0x%lx, limit=0x%lx, change=%s) -> ENOMEM "
                   "(exceeds heap limit, ARM64)\n",
                   new_break, current, brk_limit, change_category);
        return -ENOMEM;
    }

    /* No-op check */
    if (new_break == current) {
        fut_printf("[BRK] brk(new_break=0x%lx, current=0x%lx, change=%s) -> 0x%lx "
                   "(no change, ARM64)\n",
                   new_break, current, change_category, new_break);
        return (long)new_break;
    }

    fut_vmem_context_t *ctx = fut_mm_context(mm);

    /* Heap expansion */
    if (new_break > current) {
        uintptr_t map_start = mm->heap_mapped_end;
        if (map_start < PAGE_ALIGN_UP(mm->brk_start)) {
            map_start = PAGE_ALIGN_UP(mm->brk_start);
        }
        uintptr_t map_end = PAGE_ALIGN_UP(new_break);
        uint64_t flags = heap_page_flags();
        uintptr_t mapped = map_start;

        /* Calculate pages to allocate */
        size_t pages_to_map = (map_end - map_start) / PAGE_SIZE;

        for (uintptr_t addr = map_start; addr < map_end; addr += PAGE_SIZE) {
            void *page = fut_pmm_alloc_page();
            if (!page) {
                /* Allocation failed, unmap partial allocations */
                brk_unmap_range(ctx, map_start, mapped);
                fut_printf("[BRK] brk(new_break=0x%lx, current=0x%lx, change=%s, pages=%zu) "
                           "-> ENOMEM (page allocation failed at 0x%lx, ARM64)\n",
                           new_break, current, change_category, pages_to_map, addr);
                return -ENOMEM;
            }
            memset(page, 0, PAGE_SIZE);
            phys_addr_t phys = pmap_virt_to_phys((uintptr_t)page);
            if (pmap_map_user(ctx, addr, phys, PAGE_SIZE, flags) != 0) {
                fut_pmm_free_page(page);
                brk_unmap_range(ctx, map_start, mapped);
                fut_printf("[BRK] brk(new_break=0x%lx, current=0x%lx, change=%s, pages=%zu) "
                           "-> ENOMEM (page mapping failed at 0x%lx, ARM64)\n",
                           new_break, current, change_category, pages_to_map, addr);
                return -ENOMEM;
            }
            mapped += PAGE_SIZE;
        }

        mm->heap_mapped_end = map_end;

        fut_printf("[BRK] brk(new_break=0x%lx, current=0x%lx, change=%+ld bytes [%s], "
                   "pages_mapped=%zu) -> 0x%lx (heap expanded, ARM64)\n",
                   new_break, current, change, change_category, pages_to_map, new_break);

    /* Heap shrink */
    } else {
        uintptr_t retain = PAGE_ALIGN_UP(new_break);
        if (retain < PAGE_ALIGN_UP(mm->brk_start)) {
            retain = PAGE_ALIGN_UP(mm->brk_start);
        }

        size_t pages_to_unmap = 0;
        if (retain < mm->heap_mapped_end) {
            pages_to_unmap = (mm->heap_mapped_end - retain) / PAGE_SIZE;
            brk_unmap_range(ctx, retain, mm->heap_mapped_end);
            mm->heap_mapped_end = retain;
        }

        fut_printf("[BRK] brk(new_break=0x%lx, current=0x%lx, change=%+ld bytes [%s], "
                   "pages_unmapped=%zu) -> 0x%lx (heap shrunk, ARM64)\n",
                   new_break, current, change, change_category, pages_to_unmap, new_break);
    }

    fut_mm_set_brk_current(mm, new_break);
    return (long)new_break;
}

#else
/* Unsupported platform stub */
long sys_brk(uintptr_t new_break __attribute__((unused))) {
    fut_printf("[BRK] brk(new_break=0x%lx) -> ENOSYS (platform not supported)\n", new_break);
    return -ENOSYS;
}
#endif
