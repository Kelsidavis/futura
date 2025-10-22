// SPDX-License-Identifier: MPL-2.0
/*
 * fut_mm.c - Per-task memory context management
 *
 * Establishes a minimal MM container around fut_vmem_context_t so the kernel
 * can track process address spaces, switch CR3 during scheduling, and expose
 * the active page tables to uaccess helpers.
 */

#include "../../include/kernel/fut_mm.h"

#include "../../include/kernel/fut_memory.h"
#include "../../include/kernel/fut_task.h"
#include "../../include/kernel/fut_thread.h"

#include <arch/x86_64/paging.h>
#include <arch/x86_64/pmap.h>
#include <arch/x86_64/regs.h>

#include <kernel/errno.h>

#include <string.h>
#include <stdbool.h>
#include <stdint.h>

static fut_mm_t kernel_mm;
static fut_mm_t *active_mm = NULL;

#define USER_STACK_TOP      0x00007FFF00000000ULL
#define USER_VMA_MAX        (USER_STACK_TOP - (16ULL << 20))
#define USER_MMAP_BASE      0x00006000000000ULL

typedef struct fut_vma {
    uintptr_t start;
    uintptr_t end;
    int prot;
    int flags;
    struct fut_vma *next;
} fut_vma_t;

static inline fut_mm_t *mm_fallback(fut_mm_t *mm) {
    return mm ? mm : &kernel_mm;
}

static uint64_t mm_pte_flags(int prot) {
    uint64_t flags = PTE_PRESENT | PTE_USER;
    if (prot & 0x2) {
        flags |= PTE_WRITABLE;
    }
    if ((prot & 0x4) == 0) {
        flags |= PTE_NX;
    }
    return flags;
}

static void mm_unmap_and_free(fut_mm_t *mm, uintptr_t start, uintptr_t end) {
    if (!mm || start >= end) {
        return;
    }

    fut_vmem_context_t *ctx = fut_mm_context(mm);
    for (uintptr_t va = start; va < end; va += PAGE_SIZE) {
        uint64_t phys = 0;
        if (fut_virt_to_phys(ctx, va, &phys) == 0) {
            fut_unmap_range(ctx, va, PAGE_SIZE);
            fut_pmm_free_page((void *)pmap_phys_to_virt((phys_addr_t)phys));
        }
    }
}

void fut_mm_system_init(void) {
    memset(&kernel_mm, 0, sizeof(kernel_mm));

    kernel_mm.ctx.pml4 = fut_get_kernel_pml4();
    kernel_mm.ctx.cr3_value = pmap_virt_to_phys((uintptr_t)kernel_mm.ctx.pml4);
    kernel_mm.ctx.ref_count = 1;
    atomic_store_explicit(&kernel_mm.refcnt, 1, memory_order_relaxed);
    kernel_mm.flags = FUT_MM_KERNEL;
    kernel_mm.brk_start = 0;
    kernel_mm.brk_current = 0;
    kernel_mm.heap_limit = USER_VMA_MAX;
    kernel_mm.heap_mapped_end = 0;
    kernel_mm.mmap_base = USER_MMAP_BASE;
    kernel_mm.vma_list = NULL;

    active_mm = &kernel_mm;
}

fut_mm_t *fut_mm_kernel(void) {
    return &kernel_mm;
}

static void copy_kernel_half(pte_t *dst) {
    pte_t *src = fut_get_kernel_pml4();
    /* Kernel occupies upper half entries (256-511). */
    for (size_t idx = 256; idx < 512; ++idx) {
        dst[idx] = src[idx];
    }
}

fut_mm_t *fut_mm_create(void) {
    extern void fut_printf(const char *, ...);

    fut_printf("[MM-CREATE] Allocating MM structure...\n");
    fut_mm_t *mm = (fut_mm_t *)fut_malloc(sizeof(*mm));
    if (!mm) {
        fut_printf("[MM-CREATE] FAILED: malloc returned NULL\n");
        return NULL;
    }
    memset(mm, 0, sizeof(*mm));

    fut_printf("[MM-CREATE] Allocating PML4 page...\n");
    void *pml4_page = fut_pmm_alloc_page();
    if (!pml4_page) {
        fut_printf("[MM-CREATE] FAILED: pmm_alloc_page returned NULL (out of physical pages)\n");
        fut_free(mm);
        return NULL;
    }
    fut_printf("[MM-CREATE] PML4 allocated successfully\n");

    memset(pml4_page, 0, PAGE_SIZE);
    pte_t *pml4 = (pte_t *)pml4_page;
    copy_kernel_half(pml4);

    mm->ctx.pml4 = pml4;
    mm->ctx.cr3_value = pmap_virt_to_phys((uintptr_t)pml4);
    mm->ctx.ref_count = 1;
    atomic_store_explicit(&mm->refcnt, 1, memory_order_relaxed);
    mm->flags = FUT_MM_USER;
    mm->brk_start = 0;
    mm->brk_current = 0;
    mm->heap_limit = USER_VMA_MAX;
    mm->heap_mapped_end = 0;
    mm->mmap_base = USER_MMAP_BASE;
    mm->vma_list = NULL;

    return mm;
}

void fut_mm_retain(fut_mm_t *mm) {
    if (!mm) {
        return;
    }
    atomic_fetch_add_explicit(&mm->refcnt, 1, memory_order_acq_rel);
}

void fut_mm_release(fut_mm_t *mm) {
    if (!mm || mm == &kernel_mm) {
        return;
    }
    if (atomic_fetch_sub_explicit(&mm->refcnt, 1, memory_order_acq_rel) != 1) {
        return;
    }

    if (mm->heap_mapped_end > mm->brk_start) {
        uintptr_t start = PAGE_ALIGN_DOWN(mm->brk_start);
        uintptr_t end = PAGE_ALIGN_UP(mm->heap_mapped_end);
        if (end > start) {
            mm_unmap_and_free(mm, start, end);
        }
    }

    fut_vma_t *vma = mm->vma_list;
    while (vma) {
        fut_vma_t *next = vma->next;
        mm_unmap_and_free(mm, vma->start, vma->end);
        fut_free(vma);
        vma = next;
    }
    mm->vma_list = NULL;

    if (mm->ctx.pml4) {
        fut_pmm_free_page(mm->ctx.pml4);
        mm->ctx.pml4 = NULL;
    }

    fut_free(mm);
}

void fut_mm_switch(fut_mm_t *mm) {
    mm = mm_fallback(mm);
    if (active_mm == mm) {
        return;
    }

    active_mm = mm;
    fut_write_cr3(mm->ctx.cr3_value);
}

static fut_mm_t *mm_from_current_thread(void) {
    fut_thread_t *thread = fut_thread_current();
    if (!thread || !thread->task) {
        return active_mm ? active_mm : &kernel_mm;
    }

    fut_mm_t *task_mm = fut_task_get_mm(thread->task);
    if (task_mm) {
        return task_mm;
    }
    return &kernel_mm;
}

fut_mm_t *fut_mm_current(void) {
    return mm_from_current_thread();
}

fut_vmem_context_t *fut_mm_context(fut_mm_t *mm) {
    mm = mm_fallback(mm);
    return &mm->ctx;
}

void fut_mm_set_heap_base(fut_mm_t *mm, uintptr_t base, uintptr_t limit) {
    if (!mm) {
        return;
    }

    uintptr_t capped_limit = limit;
    if (capped_limit == 0 || capped_limit > USER_VMA_MAX) {
        capped_limit = USER_VMA_MAX;
    }
    if (capped_limit <= base) {
        capped_limit = base + (16ULL << 20);
        if (capped_limit > USER_VMA_MAX) {
            capped_limit = USER_VMA_MAX;
        }
    }

    mm->brk_start = base;
    mm->brk_current = base;
    mm->heap_mapped_end = PAGE_ALIGN_UP(base);
    mm->heap_limit = capped_limit;
    if (mm->mmap_base < capped_limit) {
        mm->mmap_base = capped_limit;
    }
}

uintptr_t fut_mm_brk_current(const fut_mm_t *mm) {
    return mm ? mm->brk_current : 0;
}

uintptr_t fut_mm_brk_limit(const fut_mm_t *mm) {
    return mm ? mm->heap_limit : 0;
}

void fut_mm_set_brk_current(fut_mm_t *mm, uintptr_t current) {
    if (mm) {
        mm->brk_current = current;
    }
}

void *fut_mm_map_anonymous(fut_mm_t *mm, uintptr_t hint, size_t len, int prot, int flags) {
    if (!mm || len == 0) {
        return (void *)(intptr_t)(-EINVAL);
    }

    size_t aligned = PAGE_ALIGN_UP(len);
    if (aligned == 0) {
        return (void *)(intptr_t)(-EINVAL);
    }

    uintptr_t base;
    if ((flags & 0x10) && hint) { /* MAP_FIXED */
        base = PAGE_ALIGN_DOWN(hint);
    } else {
        uintptr_t candidate = mm->mmap_base ? mm->mmap_base : USER_MMAP_BASE;
        if (candidate < USER_MMAP_BASE) {
            candidate = USER_MMAP_BASE;
        }
        candidate = PAGE_ALIGN_UP(candidate);
        if (candidate < mm->heap_mapped_end) {
            candidate = PAGE_ALIGN_UP(mm->heap_mapped_end);
        }
        base = candidate;
    }

    uintptr_t end = base + aligned;
    if (end < base || end > USER_VMA_MAX) {
        return (void *)(intptr_t)(-ENOMEM);
    }

    size_t pages = aligned / PAGE_SIZE;
    void **page_cache = fut_malloc(pages * sizeof(void *));
    if (!page_cache) {
        return (void *)(intptr_t)(-ENOMEM);
    }

    uint64_t pte_flags = mm_pte_flags(prot);
    size_t mapped = 0;
    fut_vmem_context_t *ctx = fut_mm_context(mm);
    int err = -ENOMEM;

    for (uintptr_t addr = base; addr < end; addr += PAGE_SIZE) {
        void *page = fut_pmm_alloc_page();
        if (!page) {
            mapped = (addr - base) / PAGE_SIZE;
            err = -ENOMEM;
            goto fail;
        }
        memset(page, 0, PAGE_SIZE);
        phys_addr_t phys = pmap_virt_to_phys((uintptr_t)page);
        if (pmap_map_user(ctx, addr, phys, PAGE_SIZE, pte_flags) != 0) {
            fut_pmm_free_page(page);
            mapped = (addr - base) / PAGE_SIZE;
            err = -ENOMEM;
            goto fail;
        }
        page_cache[(addr - base) / PAGE_SIZE] = page;
    }

    fut_vma_t *vma = fut_malloc(sizeof(*vma));
    if (!vma) {
        mapped = pages;
        err = -ENOMEM;
        goto fail;
    }

    vma->start = base;
    vma->end = end;
    vma->prot = prot;
    vma->flags = flags;
    vma->next = mm->vma_list;
    mm->vma_list = vma;

    mm->mmap_base = end;

    fut_free(page_cache);
    return (void *)(uintptr_t)base;

fail:
    for (size_t i = 0; i < mapped; ++i) {
        uintptr_t addr = base + (uintptr_t)i * PAGE_SIZE;
        fut_unmap_range(ctx, addr, PAGE_SIZE);
        if (page_cache[i]) {
            fut_pmm_free_page(page_cache[i]);
        }
    }
    fut_free(page_cache);
    return (void *)(intptr_t)err;
}

int fut_mm_unmap(fut_mm_t *mm, uintptr_t addr, size_t len) {
    if (!mm || len == 0) {
        return -EINVAL;
    }

    uintptr_t start = PAGE_ALIGN_DOWN(addr);
    uintptr_t aligned = PAGE_ALIGN_UP(len);
    uintptr_t end = start + aligned;
    if (end < start) {
        return -EINVAL;
    }

    fut_vma_t **link = &mm->vma_list;
    fut_vma_t *vma = mm->vma_list;
    while (vma) {
        if (vma->start == start && vma->end == end) {
            *link = vma->next;
            mm_unmap_and_free(mm, vma->start, vma->end);
            fut_free(vma);
            return 0;
        }
        link = &vma->next;
        vma = vma->next;
    }

    return -EINVAL;
}
