// SPDX-License-Identifier: MPL-2.0
/*
 * page_fault.c - Page fault handling helpers
 */

#include "../../include/kernel/trap.h"

#include "../../include/kernel/uaccess.h"
#include "../../include/kernel/errno.h"
#include "../../include/kernel/fut_task.h"
#include "../../include/kernel/fut_mm.h"
#include "../../include/kernel/fut_memory.h"
#include "../../include/kernel/fut_vfs.h"
#include "../../include/kernel/signal.h"

#include <sys/types.h>

#ifdef __x86_64__
#include <arch/x86_64/regs.h>
#include <arch/x86_64/paging.h>
#include <arch/x86_64/pmap.h>
#endif

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

extern void fut_printf(const char *fmt, ...);

#ifdef __x86_64__

/**
 * Handle demand paging page fault.
 * Loads a page from file on demand for file-backed mmap.
 * Returns true if handled, false if not a demand paging fault.
 */
/**
 * Load a single demand-paged page and map it.
 * Helper used by demand paging handler and read-ahead.
 */
static bool load_demand_page(uint64_t page_addr, struct fut_vma *vma, fut_vmem_context_t *ctx) {
    extern void fut_printf(const char *, ...);

    if (!vma || !ctx) {
        return false;
    }

    /* Check if page is already present */
    uint64_t pte = 0;
    if (pmap_probe_pte(ctx, page_addr, &pte) == 0 && (pte & PTE_PRESENT)) {
        return false;  /* Already loaded */
    }

    /* Allocate a physical page */
    void *page = fut_pmm_alloc_page();
    if (!page) {
        return false;
    }

    /* Calculate file offset for this page */
    uint64_t page_offset = (page_addr - vma->start) + vma->file_offset;

    /* Zero-fill the page first */
    memset(page, 0, PAGE_SIZE);

    /* Read file contents into page */
    ssize_t bytes_read = 0;
    if (vma->vnode->ops && vma->vnode->ops->read) {
        bytes_read = vma->vnode->ops->read(vma->vnode, page, PAGE_SIZE, page_offset);
        if (bytes_read < 0) {
            fut_pmm_free_page(page);
            return false;
        }
        /* Partial reads are OK - rest of page remains zero */
    }

    /* Calculate PTE flags from VMA protection */
    uint64_t pte_flags = PTE_PRESENT | PTE_USER;
    if (vma->prot & 0x2) {
        pte_flags |= PTE_WRITABLE;
    }
    if ((vma->prot & 0x4) == 0) {
        pte_flags |= PTE_NX;
    }

    /* Map the page */
    phys_addr_t phys = pmap_virt_to_phys((uintptr_t)page);
    if (pmap_map_user(ctx, page_addr, phys, PAGE_SIZE, pte_flags) != 0) {
        fut_pmm_free_page(page);
        return false;
    }

    fut_printf("[DEMAND-PAGING] Loaded page: va=0x%llx phys=0x%llx file_offset=%llu bytes_read=%ld\n",
               page_addr, phys, page_offset, bytes_read);

    return true;
}

/**
 * Read-ahead prefetching: Load adjacent pages on demand page fault.
 * Detects sequential access patterns and preloads nearby pages.
 */
static void readahead_prefetch(uint64_t fault_addr, struct fut_vma *vma, fut_vmem_context_t *ctx) {
    extern void fut_printf(const char *, ...);

    if (!vma || !ctx) {
        return;
    }

    /* Prefetch up to 4 adjacent pages (16KB on 4K pages) */
    #define READAHEAD_COUNT 4

    uint64_t page_addr = PAGE_ALIGN_DOWN(fault_addr);

    /* Try to prefetch next pages (forward direction) */
    for (int i = 1; i <= READAHEAD_COUNT; i++) {
        uint64_t prefetch_addr = page_addr + (i * PAGE_SIZE);

        /* Stop if outside VMA */
        if (prefetch_addr >= vma->end) {
            break;
        }

        /* Try to load, but don't fail if it can't be loaded */
        if (!load_demand_page(prefetch_addr, vma, ctx)) {
            /* If we can't load a prefetch page, stop - might be at EOF */
            break;
        }
    }
}

static bool handle_demand_paging_fault(uint64_t fault_addr, fut_mm_t *mm) {
    extern void fut_printf(const char *, ...);
    extern void fut_vnode_ref(struct fut_vnode *);

    if (!mm) {
        return false;
    }

    /* Find VMA containing fault address */
    uint64_t page_addr = PAGE_ALIGN_DOWN(fault_addr);
    struct fut_vma *vma = mm->vma_list;
    while (vma) {
        if (page_addr >= vma->start && page_addr < vma->end) {
            break;
        }
        vma = vma->next;
    }

    /* Not in any VMA or not file-backed */
    if (!vma || !vma->vnode) {
        return false;
    }

    /* Get memory context for paging operations */
    fut_vmem_context_t *ctx = fut_mm_context(mm);
    if (!ctx) {
        return false;
    }

    /* Load the faulting page */
    if (!load_demand_page(page_addr, vma, ctx)) {
        return false;
    }

    /* Prefetch adjacent pages for sequential access optimization */
    readahead_prefetch(fault_addr, vma, ctx);

    return true;
}

/**
 * Handle copy-on-write page fault.
 * Returns true if handled, false if not a COW fault.
 *
 * Per-page COW tracking: Only process pages that are still mapped read-only.
 * Once a page is made writable (through copy or sole ownership), subsequent
 * faults won't trigger COW handling because the page is already writable.
 */
static bool handle_cow_fault(uint64_t fault_addr, uint64_t error_code) {
    /* Check if this is a write fault */
    if (!(error_code & 0x2)) {
        return false;  /* Not a write fault */
    }

    /* Check if page is present (COW pages are present but read-only) */
    if (!(error_code & 0x1)) {
        return false;  /* Page not present - not COW */
    }

    /* Get current task and MM */
    fut_task_t *task = fut_task_current();
    if (!task) {
        return false;
    }

    fut_mm_t *mm = fut_task_get_mm(task);
    if (!mm) {
        return false;
    }

    /* Find VMA containing fault address */
    uint64_t page_addr = PAGE_ALIGN_DOWN(fault_addr);
    struct fut_vma *vma = mm->vma_list;
    while (vma) {
        if (page_addr >= vma->start && page_addr < vma->end) {
            break;
        }
        vma = vma->next;
    }

    if (!vma || !(vma->flags & VMA_COW)) {
        return false;  /* Not a COW VMA */
    }

    /* Get the current physical page */
    fut_vmem_context_t *ctx = fut_mm_context(mm);
    uint64_t pte = 0;
    if (pmap_probe_pte(ctx, page_addr, &pte) != 0) {
        return false;
    }

    /* Per-page COW tracking: Check if page is actually read-only (still needs COW) */
    if ((pte & PTE_WRITABLE) != 0) {
        /* Page is already writable - COW already processed */
        fut_printf("[COW] Page already writable: va=0x%llx (COW already processed)\n",
                   page_addr);
        return false;  /* This shouldn't cause a fault - return false to handle normally */
    }

    phys_addr_t old_phys = pte & PTE_PHYS_ADDR_MASK;

    /* Check reference count */
    int refcount = fut_page_ref_get(old_phys);

    if (refcount > 1) {
        /* Multiple references - need to copy */
        void *new_page = fut_pmm_alloc_page();
        if (!new_page) {
            fut_printf("[COW] Failed to allocate page for COW\n");
            return false;
        }

        /* Copy old page to new page */
        void *old_page = (void *)pmap_phys_to_virt(old_phys);
        memcpy(new_page, old_page, PAGE_SIZE);

        /* Map new page with write permission */
        phys_addr_t new_phys = pmap_virt_to_phys((uintptr_t)new_page);
        uint64_t flags = (pte & (PTE_PRESENT | PTE_USER | PTE_NX)) | PTE_WRITABLE;

        fut_unmap_range(ctx, page_addr, PAGE_SIZE);
        if (pmap_map_user(ctx, page_addr, new_phys, PAGE_SIZE, flags) != 0) {
            fut_pmm_free_page(new_page);
            return false;
        }

        /* Decrement old page refcount */
        int new_refcount = fut_page_ref_dec(old_phys);
        if (new_refcount == 0) {
            /* Last reference gone - free the old page */
            fut_pmm_free_page(old_page);
        }

        fut_printf("[COW] Copied page: va=0x%llx old_phys=0x%llx new_phys=0x%llx refcount=%d->%d\n",
                   page_addr, old_phys, new_phys, refcount, new_refcount);
    } else {
        /* Only one reference - just make it writable (sole owner optimization) */
        uint64_t flags = (pte & (PTE_PRESENT | PTE_USER | PTE_NX)) | PTE_WRITABLE;

        fut_unmap_range(ctx, page_addr, PAGE_SIZE);
        if (pmap_map_user(ctx, page_addr, old_phys, PAGE_SIZE, flags) != 0) {
            return false;
        }

        /* Decrement refcount to remove from tracking (refcount was 1, now goes to 0) */
        fut_page_ref_dec(old_phys);

        fut_printf("[COW] Made page writable: va=0x%llx phys=0x%llx (sole owner, refcount 1->0)\n",
                   page_addr, old_phys);
    }

    /* Per-page COW tracking achieved through PTE flags:
     * - Writable pages won't trigger write faults, so no further COW processing
     * - Read-only pages will trigger faults and be processed
     * - Page reference counting tracks multi-process sharing
     * This provides fine-grained COW tracking per-page without additional metadata.
     */

    return true;
}

bool fut_trap_handle_page_fault(fut_interrupt_frame_t *frame) {
    const uint64_t fault_addr = fut_read_cr2();
    const struct fut_uaccess_window *window = fut_uaccess_window_current();

    if (window && window->resume && window->length != 0) {
        const uintptr_t start = (uintptr_t)window->user_ptr;
        const uintptr_t end = start + window->length;
        if (fault_addr >= start && fault_addr < end) {
            fut_uaccess_window_fault(-EFAULT);
            frame->rip = (uint64_t)window->resume;
            frame->rax = (uint64_t)(-EFAULT);
            return true;
        }
    }

    /* Try to handle as COW fault */
    if ((frame->cs & 0x3u) != 0) {  /* User mode fault */
        if (handle_cow_fault(fault_addr, frame->error_code)) {
            return true;  /* COW fault handled successfully */
        }
    }

    /* Try to handle as demand paging fault */
    if ((frame->cs & 0x3u) != 0) {  /* User mode fault */
        fut_mm_t *mm = fut_mm_current();
        if (handle_demand_paging_fault(fault_addr, mm)) {
            return true;  /* Demand paging fault handled successfully */
        }
    }

    if ((frame->cs & 0x3u) != 0) {
        fut_printf("[#PF] user fault addr=0x%016llx err=0x%llx rip=0x%016llx\n",
                   (unsigned long long)fault_addr,
                   (unsigned long long)frame->error_code,
                   (unsigned long long)frame->rip);
        fut_task_signal_exit(SIGSEGV);
    }

    return false;
}

#elif defined(__aarch64__)

/* ARM64 page fault handler stub - not yet implemented */
bool fut_trap_handle_page_fault(fut_interrupt_frame_t *frame) {
    (void)frame;
    return false;
}

#else
#error "Unsupported architecture for page fault handling"
#endif
