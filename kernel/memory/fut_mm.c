// SPDX-License-Identifier: MPL-2.0
/*
 * fut_mm.c - Per-task memory context management
 *
 * Establishes a minimal MM container around fut_vmem_context_t so the kernel
 * can track process address spaces, switch CR3 during scheduling, and expose
 * the active page tables to uaccess helpers.
 *
 * NOTE: This is currently an x86_64-specific implementation.
 */

#ifdef __x86_64__

#include "../../include/kernel/fut_mm.h"

#include "../../include/kernel/fut_memory.h"
#include "../../include/kernel/fut_task.h"
#include "../../include/kernel/fut_thread.h"
#include "../../include/kernel/fut_vfs.h"

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

/* Note: struct fut_vma is now defined in fut_mm.h */
typedef struct fut_vma fut_vma_t;

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

            /* Check if this is a COW page with references */
            int refcount = fut_page_ref_get((phys_addr_t)phys);
            if (refcount > 1) {
                /* Decrement reference count, don't free yet */
                fut_page_ref_dec((phys_addr_t)phys);
            } else {
                /* Last reference or not COW - free the page */
                if (refcount == 1) {
                    fut_page_ref_dec((phys_addr_t)phys);  /* Remove from tracking */
                }
                fut_pmm_free_page((void *)pmap_phys_to_virt((phys_addr_t)phys));
            }
        }
    }
}

/**
 * Insert a VMA into the mm's VMA list in sorted order by start address.
 * This maintains the invariant that VMAs are sorted and non-overlapping.
 */
/**
 * Check if two VMAs can be merged (adjacent and compatible).
 */
static bool vma_can_merge(const fut_vma_t *vma1, const fut_vma_t *vma2) {
    if (!vma1 || !vma2) {
        return false;
    }

    /* Must be adjacent */
    if (vma1->end != vma2->start) {
        return false;
    }

    /* Must have same protection and flags */
    if (vma1->prot != vma2->prot || vma1->flags != vma2->flags) {
        return false;
    }

    /* Must have same file backing (or both anonymous) */
    if (vma1->vnode != vma2->vnode) {
        return false;
    }

    /* If file-backed, file offsets must be contiguous */
    if (vma1->vnode) {
        uint64_t expected_offset = vma1->file_offset + (vma1->end - vma1->start);
        if (expected_offset != vma2->file_offset) {
            return false;
        }
    }

    return true;
}

/**
 * Merge adjacent compatible VMAs. Combines vma1 and vma2 into vma1,
 * freeing vma2. Returns merged VMA pointer.
 */
static fut_vma_t *vma_merge(fut_vma_t *vma1, fut_vma_t *vma2) {
    if (!vma1 || !vma2) {
        return vma1;
    }

    /* Extend vma1 to include vma2 */
    vma1->end = vma2->end;
    vma1->next = vma2->next;

    /* Release vnode reference from vma2 if present */
    if (vma2->vnode) {
        extern void fut_vnode_unref(struct fut_vnode *);
        fut_vnode_unref(vma2->vnode);
    }

    fut_free(vma2);
    return vma1;
}

/**
 * Try to merge VMA with neighbors (left/right) after modifications.
 */
static void vma_try_merge_neighbors(fut_mm_t *mm, fut_vma_t *vma) {
    if (!mm || !vma) {
        return;
    }

    /* Try merging with right neighbor */
    if (vma->next && vma_can_merge(vma, vma->next)) {
        vma_merge(vma, vma->next);
    }

    /* Try merging with left neighbor - search backwards */
    if (mm->vma_list != vma) {
        fut_vma_t *prev = mm->vma_list;
        while (prev && prev->next != vma) {
            prev = prev->next;
        }

        if (prev && vma_can_merge(prev, vma)) {
            vma_merge(prev, vma);
        }
    }
}

static void vma_insert_sorted(fut_mm_t *mm, fut_vma_t *vma) {
    if (!mm || !vma) {
        return;
    }

    /* Empty list - vma becomes the head */
    if (!mm->vma_list) {
        vma->next = NULL;
        mm->vma_list = vma;
        return;
    }

    /* Insert at head if vma starts before current head */
    if (vma->start < mm->vma_list->start) {
        vma->next = mm->vma_list;
        mm->vma_list = vma;
        vma_try_merge_neighbors(mm, vma);
        return;
    }

    /* Find insertion point in sorted list */
    fut_vma_t *prev = mm->vma_list;
    fut_vma_t *curr = prev->next;

    while (curr && curr->start < vma->start) {
        prev = curr;
        curr = curr->next;
    }

    /* Insert between prev and curr */
    vma->next = curr;
    prev->next = vma;

    /* Try to merge with neighbors */
    vma_try_merge_neighbors(mm, vma);
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
    fut_printf("[MM-CREATE] PML4 allocated successfully at %p\n", pml4_page);

    fut_printf("[MM-CREATE] About to memset PML4 page at %p\n", pml4_page);
    memset(pml4_page, 0, PAGE_SIZE);
    fut_printf("[MM-CREATE] Memset completed\n");

    pte_t *pml4 = (pte_t *)pml4_page;
    fut_printf("[MM-CREATE] About to copy kernel half, pml4=%p\n", pml4);
    copy_kernel_half(pml4);
    fut_printf("[MM-CREATE] Kernel half copied\n");

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
    extern void fut_printf(const char *, ...);
    extern uint64_t fut_read_cr3(void);

    mm = mm_fallback(mm);
    if (active_mm == mm) {
        return;
    }

    uint64_t old_cr3 = fut_read_cr3();
    uint64_t new_cr3 = mm->ctx.cr3_value;

    // fut_printf("[MM-SWITCH] CR3: 0x%016llx -> 0x%016llx (kernel=%s)\n",
    //            old_cr3, new_cr3, (mm == &kernel_mm) ? "yes" : "no");

    active_mm = mm;
    fut_write_cr3(new_cr3);

    // Verify CR3 was written
    uint64_t verify_cr3 = fut_read_cr3();
    if (verify_cr3 != new_cr3) {
        fut_printf("[MM-SWITCH] ERROR: CR3 verification failed! Expected 0x%016llx, got 0x%016llx\n",
                   new_cr3, verify_cr3);
    }
    (void)old_cr3;  // Suppress unused warning
}

static fut_mm_t *mm_from_current_thread(void) {
    fut_thread_t *thread = fut_thread_current();

    if (!thread) {
        return active_mm ? active_mm : &kernel_mm;
    }

    if (!thread->task) {
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
    if ((flags & 0x10) && hint) { /* MAP_FIXED - must use exact address */
        base = PAGE_ALIGN_DOWN(hint);
    } else if (hint) {
        /* Honor hint as a suggestion when provided */
        base = PAGE_ALIGN_DOWN(hint);
    } else {
        /* No hint provided - allocate from mmap_base */
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
    vma->vnode = NULL;  /* Anonymous mapping */
    vma->file_offset = 0;
    vma_insert_sorted(mm, vma);

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

    uintptr_t unmap_start = PAGE_ALIGN_DOWN(addr);
    uintptr_t aligned = PAGE_ALIGN_UP(len);
    uintptr_t unmap_end = unmap_start + aligned;
    if (unmap_end < unmap_start) {
        return -EINVAL;
    }

    fut_vma_t **link = &mm->vma_list;
    fut_vma_t *vma = mm->vma_list;

    while (vma) {
        fut_vma_t *next = vma->next;

        /* Check if this VMA overlaps with the unmap region */
        if (vma->end <= unmap_start || vma->start >= unmap_end) {
            /* No overlap, move to next */
            link = &vma->next;
            vma = next;
            continue;
        }

        /* VMA overlaps with unmap region */
        uintptr_t overlap_start = (vma->start > unmap_start) ? vma->start : unmap_start;
        uintptr_t overlap_end = (vma->end < unmap_end) ? vma->end : unmap_end;

        if (overlap_start <= vma->start && overlap_end >= vma->end) {
            /* Case 1: Entire VMA is unmapped - remove it */
            *link = vma->next;
            mm_unmap_and_free(mm, vma->start, vma->end);
            /* Release file backing if present */
            if (vma->vnode) {
                extern void fut_vnode_unref(struct fut_vnode *);
                fut_vnode_unref(vma->vnode);
            }
            fut_free(vma);
            vma = next;
            continue;
        }

        if (overlap_start == vma->start && overlap_end < vma->end) {
            /* Case 2: Unmap left part - shrink VMA from the left */
            mm_unmap_and_free(mm, vma->start, overlap_end);
            vma->start = overlap_end;
            link = &vma->next;
            vma = next;
            continue;
        }

        if (overlap_start > vma->start && overlap_end == vma->end) {
            /* Case 3: Unmap right part - shrink VMA from the right */
            mm_unmap_and_free(mm, overlap_start, vma->end);
            vma->end = overlap_start;
            link = &vma->next;
            vma = next;
            continue;
        }

        if (overlap_start > vma->start && overlap_end < vma->end) {
            /* Case 4: Unmap middle - split VMA into two */
            fut_vma_t *right_vma = fut_malloc(sizeof(*right_vma));
            if (!right_vma) {
                return -ENOMEM;
            }

            /* Create right portion */
            right_vma->start = overlap_end;
            right_vma->end = vma->end;
            right_vma->prot = vma->prot;
            right_vma->flags = vma->flags;
            right_vma->vnode = vma->vnode;  /* Share file backing */
            if (vma->vnode) {
                /* Adjust file offset for the right portion */
                uint64_t offset_delta = overlap_end - vma->start;
                right_vma->file_offset = vma->file_offset + offset_delta;
                /* TODO: Add vnode reference counting when implemented */
            } else {
                right_vma->file_offset = 0;
            }
            right_vma->next = vma->next;

            /* Shrink left portion */
            vma->end = overlap_start;
            vma->next = right_vma;

            /* Unmap the middle */
            mm_unmap_and_free(mm, overlap_start, overlap_end);

            link = &right_vma->next;
            vma = next;
            continue;
        }

        /* Move to next */
        link = &vma->next;
        vma = next;
    }

    /* Merge adjacent compatible VMAs after unmapping to reduce memory overhead */
    if (mm && mm->vma_list) {
        fut_vma_t *curr = mm->vma_list;
        while (curr && curr->next) {
            if (vma_can_merge(curr, curr->next)) {
                vma_merge(curr, curr->next);
                /* Don't advance curr - check if it can merge with new next */
            } else {
                curr = curr->next;
            }
        }
    }

    return 0;
}

/**
 * Map a file into memory with demand paging.
 * Creates a lazy mapping - pages are loaded on demand via page faults.
 */
void *fut_mm_map_file(fut_mm_t *mm, struct fut_vnode *vnode, uintptr_t hint,
                       size_t len, int prot, int flags, uint64_t file_offset) {
    extern void fut_printf(const char *, ...);
    extern void fut_vnode_ref(struct fut_vnode *);


    if (!mm || !vnode || len == 0) {
        return (void *)(intptr_t)(-EINVAL);
    }

    /* Align length to page boundary */
    size_t aligned = PAGE_ALIGN_UP(len);
    if (aligned == 0) {
        return (void *)(intptr_t)(-EINVAL);
    }

    /* Determine mapping address */
    uintptr_t base;
    if ((flags & 0x10) && hint) { /* MAP_FIXED - must use exact address */
        base = PAGE_ALIGN_DOWN(hint);
    } else if (hint) {
        /* Honor hint as a suggestion when provided */
        base = PAGE_ALIGN_DOWN(hint);
    } else {
        /* No hint provided - allocate from mmap_base */
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

    /* Create VMA to track this mapping without allocating physical pages yet */
    fut_vma_t *vma = fut_malloc(sizeof(*vma));
    if (!vma) {
        return (void *)(intptr_t)(-ENOMEM);
    }

    vma->start = base;
    vma->end = end;
    vma->prot = prot;
    vma->flags = flags;
    vma->vnode = vnode;
    vma->file_offset = file_offset;
    vma_insert_sorted(mm, vma);

    /* Add reference to vnode */
    fut_vnode_ref(vnode);

    mm->mmap_base = end;

    fut_printf("[MM-MAP-FILE] Created lazy mapping: vaddr=0x%llx-0x%llx size=%zu offset=%llu (demand paging enabled)\n",
               base, end, len, file_offset);
    return (void *)(uintptr_t)base;
}

#elif defined(__aarch64__)

/* ============================================================
 *   ARM64 Memory Management Implementation
 * ============================================================ */

#include "../../include/kernel/fut_mm.h"
#include "../../include/kernel/fut_memory.h"
#include "../../include/kernel/fut_task.h"
#include "../../include/kernel/fut_thread.h"

#include <arch/arm64/paging.h>
#include <kernel/errno.h>

#include <string.h>
#include <stdbool.h>
#include <stdint.h>

static fut_mm_t kernel_mm;
static fut_mm_t *active_mm = NULL;

#define USER_STACK_TOP      0x0000007FFFFF0000ULL
#define USER_VMA_MAX        (USER_STACK_TOP - (16ULL << 20))
#define USER_MMAP_BASE      0x0000400000000000ULL

static inline fut_mm_t *mm_fallback(fut_mm_t *mm) {
    return mm ? mm : &kernel_mm;
}

static uint64_t mm_pte_flags(int prot) {
    uint64_t flags = PTE_VALID | PTE_AF_BIT | PTE_ATTR_NORMAL | PTE_SH_INNER;
    if (prot & 0x2) {
        flags |= PTE_AP_RW_ALL;  /* Writable for user and kernel */
    } else {
        flags |= PTE_AP_RO_ALL;  /* Read-only for user and kernel */
    }
    if ((prot & 0x4) == 0) {
        flags |= PTE_PXN_BIT;  /* Privileged Execute Never */
        flags |= PTE_UXN_BIT;  /* User Execute Never */
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
            fut_pmm_free_page((void *)phys);
        }
    }
}

void fut_mm_system_init(void) {
    extern void fut_printf(const char *, ...);
    fut_printf("[MM] ARM64 memory management initialization\n");

    memset(&kernel_mm, 0, sizeof(kernel_mm));

    kernel_mm.ctx.pgd = fut_get_kernel_pgd();
    kernel_mm.ctx.ttbr0_el1 = (uint64_t)kernel_mm.ctx.pgd;
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

    fut_printf("[MM] ARM64 memory management initialized\n");
}

fut_mm_t *fut_mm_kernel(void) {
    return &kernel_mm;
}

static void copy_kernel_half(page_table_t *dst) {
    page_table_t *src = (page_table_t *)fut_get_kernel_pgd();
    /* Kernel occupies upper half entries (256-511) */
    for (size_t idx = 256; idx < 512; ++idx) {
        dst->entries[idx] = src->entries[idx];
    }
}

fut_mm_t *fut_mm_create(void) {
    extern void fut_printf(const char *, ...);

    fut_printf("[MM-CREATE] ARM64: Allocating MM structure...\n");
    fut_mm_t *mm = (fut_mm_t *)fut_malloc(sizeof(*mm));
    if (!mm) {
        fut_printf("[MM-CREATE] FAILED: malloc returned NULL\n");
        return NULL;
    }
    memset(mm, 0, sizeof(*mm));

    fut_printf("[MM-CREATE] ARM64: Allocating PGD page...\n");
    void *pgd_page = fut_pmm_alloc_page();
    if (!pgd_page) {
        fut_printf("[MM-CREATE] FAILED: pmm_alloc_page returned NULL (out of physical pages)\n");
        fut_free(mm);
        return NULL;
    }
    fut_printf("[MM-CREATE] ARM64: PGD allocated successfully at %p\n", pgd_page);

    memset(pgd_page, 0, PAGE_SIZE);
    page_table_t *pgd = (page_table_t *)pgd_page;
    copy_kernel_half(pgd);

    mm->ctx.pgd = pgd;
    mm->ctx.ttbr0_el1 = (uint64_t)pgd;
    mm->ctx.ref_count = 1;
    atomic_store_explicit(&mm->refcnt, 1, memory_order_relaxed);
    mm->flags = FUT_MM_USER;
    mm->brk_start = 0;
    mm->brk_current = 0;
    mm->heap_limit = USER_VMA_MAX;
    mm->heap_mapped_end = 0;
    mm->mmap_base = USER_MMAP_BASE;
    mm->vma_list = NULL;

    fut_printf("[MM-CREATE] ARM64: MM created successfully\n");
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

    if (mm->ctx.pgd) {
        fut_pmm_free_page(mm->ctx.pgd);
        mm->ctx.pgd = NULL;
    }

    fut_free(mm);
}

void fut_mm_switch(fut_mm_t *mm) {
    extern void fut_printf(const char *, ...);

    mm = mm_fallback(mm);
    if (active_mm == mm) {
        return;
    }

    active_mm = mm;
    fut_vmem_switch(&mm->ctx);
}

static fut_mm_t *mm_from_current_thread(void) {
    fut_thread_t *thread = fut_thread_current();

    if (!thread) {
        return active_mm ? active_mm : &kernel_mm;
    }

    if (!thread->task) {
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
    }

    mm->brk_start = base;
    mm->brk_current = base;
    mm->heap_limit = capped_limit;
    mm->heap_mapped_end = base;
}

uintptr_t fut_mm_brk_current(const fut_mm_t *mm) {
    if (!mm) {
        return 0;
    }
    return mm->brk_current;
}

uintptr_t fut_mm_brk_limit(const fut_mm_t *mm) {
    if (!mm) {
        return 0;
    }
    return mm->heap_limit;
}

void fut_mm_set_brk_current(fut_mm_t *mm, uintptr_t current) {
    if (!mm) {
        return;
    }
    mm->brk_current = current;
}


int fut_mm_unmap(fut_mm_t *mm, uintptr_t addr, size_t len) {
    if (!mm || len == 0) {
        return -EINVAL;
    }

    uintptr_t unmap_start = PAGE_ALIGN_DOWN(addr);
    uintptr_t aligned = PAGE_ALIGN_UP(len);
    uintptr_t unmap_end = unmap_start + aligned;
    if (unmap_end < unmap_start) {
        return -EINVAL;
    }

    fut_vma_t **link = &mm->vma_list;
    fut_vma_t *vma = mm->vma_list;

    while (vma) {
        fut_vma_t *next = vma->next;

        /* Check if this VMA overlaps with the unmap region */
        if (vma->end <= unmap_start || vma->start >= unmap_end) {
            /* No overlap, move to next */
            link = &vma->next;
            vma = next;
            continue;
        }

        /* VMA overlaps with unmap region */
        uintptr_t overlap_start = (vma->start > unmap_start) ? vma->start : unmap_start;
        uintptr_t overlap_end = (vma->end < unmap_end) ? vma->end : unmap_end;

        if (overlap_start <= vma->start && overlap_end >= vma->end) {
            /* Case 1: Entire VMA is unmapped - remove it */
            *link = vma->next;
            mm_unmap_and_free(mm, vma->start, vma->end);
            /* Release file backing if present */
            if (vma->vnode) {
                extern void fut_vnode_unref(struct fut_vnode *);
                fut_vnode_unref(vma->vnode);
            }
            fut_free(vma);
            vma = next;
            continue;
        }

        if (overlap_start == vma->start && overlap_end < vma->end) {
            /* Case 2: Unmap left part - shrink VMA from the left */
            mm_unmap_and_free(mm, vma->start, overlap_end);
            vma->start = overlap_end;
            link = &vma->next;
            vma = next;
            continue;
        }

        if (overlap_start > vma->start && overlap_end == vma->end) {
            /* Case 3: Unmap right part - shrink VMA from the right */
            mm_unmap_and_free(mm, overlap_start, vma->end);
            vma->end = overlap_start;
            link = &vma->next;
            vma = next;
            continue;
        }

        if (overlap_start > vma->start && overlap_end < vma->end) {
            /* Case 4: Unmap middle - split VMA into two */
            fut_vma_t *right_vma = fut_malloc(sizeof(*right_vma));
            if (!right_vma) {
                return -ENOMEM;
            }

            /* Create right portion */
            right_vma->start = overlap_end;
            right_vma->end = vma->end;
            right_vma->prot = vma->prot;
            right_vma->flags = vma->flags;
            right_vma->vnode = vma->vnode;  /* Share file backing */
            if (vma->vnode) {
                /* Adjust file offset for the right portion */
                uint64_t offset_delta = overlap_end - vma->start;
                right_vma->file_offset = vma->file_offset + offset_delta;
                /* TODO: Add vnode reference counting when implemented */
            } else {
                right_vma->file_offset = 0;
            }
            right_vma->next = vma->next;

            /* Shrink left portion */
            vma->end = overlap_start;
            vma->next = right_vma;

            /* Unmap the middle */
            mm_unmap_and_free(mm, overlap_start, overlap_end);

            link = &right_vma->next;
            vma = next;
            continue;
        }

        /* Move to next */
        link = &vma->next;
        vma = next;
    }

    return 0;
}

/**
 * Map a file into memory (ARM64 stub).
 * TODO: Implement proper ARM64 file-backed mmap.
 */
void *fut_mm_map_file(fut_mm_t *mm, struct fut_vnode *vnode, uintptr_t hint,
                       size_t len, int prot, int flags, uint64_t file_offset) {
    extern void fut_printf(const char *, ...);
    extern void fut_vnode_ref(struct fut_vnode *);

    if (!mm || !vnode || len == 0) {
        return (void *)(intptr_t)(-EINVAL);
    }

    /* Align length to page boundary */
    size_t aligned = PAGE_ALIGN_UP(len);
    if (aligned == 0) {
        return (void *)(intptr_t)(-EINVAL);
    }

    /* Determine mapping address */
    uintptr_t base;
    if ((flags & 0x10) && hint) { /* MAP_FIXED - must use exact address */
        base = PAGE_ALIGN_DOWN(hint);
    } else if (hint) {
        /* Honor hint as a suggestion when provided */
        base = PAGE_ALIGN_DOWN(hint);
    } else {
        /* No hint provided - allocate from mmap_base */
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

    /* Create VMA to track this mapping without allocating physical pages yet */
    fut_vma_t *vma = fut_malloc(sizeof(*vma));
    if (!vma) {
        return (void *)(intptr_t)(-ENOMEM);
    }

    vma->start = base;
    vma->end = end;
    vma->prot = prot;
    vma->flags = flags;
    vma->vnode = vnode;
    vma->file_offset = file_offset;
    vma_insert_sorted(mm, vma);

    /* Add reference to vnode */
    fut_vnode_ref(vnode);

    mm->mmap_base = end;

    fut_printf("[MM-MAP-FILE] Created lazy mapping: vaddr=0x%llx-0x%llx size=%zu offset=%llu (demand paging enabled)\n",
               base, end, len, file_offset);
    return (void *)(uintptr_t)base;
}

#else

#error "Unsupported architecture for memory management"

#endif  /* __x86_64__ / __aarch64__ */

/* ============================================================
 *   Platform-independent VMA management
 * ============================================================ */

/**
 * fut_mm_add_vma - Add a VMA to the mm's VMA list
 * @mm: Memory context
 * @start: Start address (page-aligned)
 * @end: End address (page-aligned, exclusive)
 * @prot: Protection flags (PROT_READ, PROT_WRITE, PROT_EXEC)
 * @flags: Mapping flags
 *
 * Returns 0 on success, -ENOMEM on failure.
 */
int fut_mm_add_vma(fut_mm_t *mm, uintptr_t start, uintptr_t end, int prot, int flags) {
    if (!mm || start >= end) {
        return -EINVAL;
    }

    /* Allocate new VMA */
    struct fut_vma *vma = (struct fut_vma *)fut_malloc(sizeof(struct fut_vma));
    if (!vma) {
        return -ENOMEM;
    }

    vma->start = start;
    vma->end = end;
    vma->prot = prot;
    vma->flags = flags;
    vma->vnode = NULL;  /* Set by caller if file-backed */
    vma->file_offset = 0;
    vma->next = NULL;

    /* Add to end of list (insertion order) */
    struct fut_vma **link = &mm->vma_list;
    while (*link) {
        link = &(*link)->next;
    }
    *link = vma;

    return 0;
}

/**
 * fut_mm_clone_vmas - Clone all VMAs from src_mm to dest_mm
 * @dest_mm: Destination memory context
 * @src_mm: Source memory context
 *
 * Copies the VMA list from src_mm to dest_mm. Does not copy actual page
 * contents - that's done separately by clone_mm() in sys_fork.c.
 *
 * Returns 0 on success, -ENOMEM on failure.
 */
int fut_mm_clone_vmas(fut_mm_t *dest_mm, fut_mm_t *src_mm) {
    if (!dest_mm || !src_mm) {
        return -EINVAL;
    }

    struct fut_vma *src_vma = src_mm->vma_list;
    while (src_vma) {
        int rc = fut_mm_add_vma(dest_mm, src_vma->start, src_vma->end,
                                src_vma->prot, src_vma->flags);
        if (rc < 0) {
            return rc;
        }
        src_vma = src_vma->next;
    }

    return 0;
}

/* ============================================================
 *   Page Reference Counting for Copy-On-Write
 * ============================================================ */

/*
 * Simple hash table for tracking page reference counts.
 * This allows multiple processes to share physical pages after fork().
 */

#define PAGE_REFCOUNT_BUCKETS 1024
#define PAGE_REFCOUNT_HASH(phys) (((phys) >> 12) % PAGE_REFCOUNT_BUCKETS)

struct page_refcount_entry {
    phys_addr_t phys;
    int refcount;
    struct page_refcount_entry *next;
};

static struct page_refcount_entry *page_refcount_table[PAGE_REFCOUNT_BUCKETS];

void fut_page_ref_init(void) {
    for (int i = 0; i < PAGE_REFCOUNT_BUCKETS; i++) {
        page_refcount_table[i] = NULL;
    }
}

static struct page_refcount_entry *page_ref_find(phys_addr_t phys) {
    int bucket = PAGE_REFCOUNT_HASH(phys);
    struct page_refcount_entry *entry = page_refcount_table[bucket];

    while (entry) {
        if (entry->phys == phys) {
            return entry;
        }
        entry = entry->next;
    }

    return NULL;
}

void fut_page_ref_inc(phys_addr_t phys) {
    int bucket = PAGE_REFCOUNT_HASH(phys);
    struct page_refcount_entry *entry = page_ref_find(phys);

    if (entry) {
        entry->refcount++;
    } else {
        /* Allocate new entry */
        entry = fut_malloc(sizeof(*entry));
        if (!entry) {
            /* Out of memory - this is bad, but we can't do much */
            return;
        }

        entry->phys = phys;
        entry->refcount = 2;  /* Parent + child */
        entry->next = page_refcount_table[bucket];
        page_refcount_table[bucket] = entry;
    }
}

int fut_page_ref_dec(phys_addr_t phys) {
    int bucket = PAGE_REFCOUNT_HASH(phys);
    struct page_refcount_entry **link = &page_refcount_table[bucket];
    struct page_refcount_entry *entry = page_refcount_table[bucket];

    while (entry) {
        if (entry->phys == phys) {
            entry->refcount--;

            if (entry->refcount <= 1) {
                /* Remove from hash table */
                *link = entry->next;
                int final_count = entry->refcount;
                fut_free(entry);
                return final_count;
            }

            return entry->refcount;
        }

        link = &entry->next;
        entry = entry->next;
    }

    /* Not found - assume refcount is 1 */
    return 1;
}

int fut_page_ref_get(phys_addr_t phys) {
    struct page_refcount_entry *entry = page_ref_find(phys);
    return entry ? entry->refcount : 1;
}
