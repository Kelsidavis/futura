// SPDX-License-Identifier: MPL-2.0

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

long sys_brk(uintptr_t new_break) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -EPERM;
    }

    fut_mm_t *mm = fut_task_get_mm(task);
    if (!mm) {
        return -ENOMEM;
    }

    if (new_break == 0) {
        return (long)fut_mm_brk_current(mm);
    }

    if (new_break < mm->brk_start) {
        new_break = mm->brk_start;
    }

    if (new_break > fut_mm_brk_limit(mm)) {
        return -ENOMEM;
    }

    uintptr_t current = fut_mm_brk_current(mm);
    if (new_break == current) {
        return (long)new_break;
    }

    fut_vmem_context_t *ctx = fut_mm_context(mm);

    if (new_break > current) {
        uintptr_t map_start = mm->heap_mapped_end;
        if (map_start < PAGE_ALIGN_UP(mm->brk_start)) {
            map_start = PAGE_ALIGN_UP(mm->brk_start);
        }
        uintptr_t map_end = PAGE_ALIGN_UP(new_break);
        uint64_t flags = heap_page_flags();
        uintptr_t mapped = map_start;

        for (uintptr_t addr = map_start; addr < map_end; addr += PAGE_SIZE) {
            void *page = fut_pmm_alloc_page();
            if (!page) {
                brk_unmap_range(ctx, map_start, mapped);
                return -ENOMEM;
            }
            memset(page, 0, PAGE_SIZE);
            phys_addr_t phys = pmap_virt_to_phys((uintptr_t)page);
            if (pmap_map_user(ctx, addr, phys, PAGE_SIZE, flags) != 0) {
                fut_pmm_free_page(page);
                brk_unmap_range(ctx, map_start, mapped);
                return -ENOMEM;
            }
            mapped += PAGE_SIZE;
        }

        mm->heap_mapped_end = map_end;
    } else {
        uintptr_t retain = PAGE_ALIGN_UP(new_break);
        if (retain < PAGE_ALIGN_UP(mm->brk_start)) {
            retain = PAGE_ALIGN_UP(mm->brk_start);
        }
        if (retain < mm->heap_mapped_end) {
            brk_unmap_range(ctx, retain, mm->heap_mapped_end);
            mm->heap_mapped_end = retain;
        }
    }

    fut_mm_set_brk_current(mm, new_break);
    return (long)new_break;
}

#else
/* ARM64: sys_brk is not yet implemented */
long sys_brk(uintptr_t new_break __attribute__((unused))) {
    return -ENOSYS;  /* ENOSYS defined in kernel/errno.h which is included above */
}
#endif
