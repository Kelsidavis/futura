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

#ifdef __x86_64__
#include <platform/x86_64/regs.h>
#include <platform/x86_64/memory/paging.h>
#include <platform/x86_64/memory/pmap.h>
#endif

#ifdef __aarch64__
#include <platform/arm64/regs.h>
#include <platform/arm64/memory/paging.h>
#include <platform/arm64/memory/pmap.h>
#endif

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

extern void fut_printf(const char *fmt, ...);

/* ============================================================
 *   Architecture-Generic Demand Paging & COW Handling
 * ============================================================ */

/**
 * Load a single demand-paged page and map it.
 * Helper used by demand paging handler and read-ahead.
 */
/**
 * Load a page from file on demand (demand paging).
 *
 * Implements lazy page loading for file-backed memory mappings.
 * Called on page fault for unmapped file pages.
 *
 * Semantics:
 * - MAP_PRIVATE: Each process gets its own copy of the page after write.
 *   Modifications don't affect the file or other mappings.
 *   Implemented via COW (copy-on-write) in the page fault handler.
 *
 * - MAP_SHARED: All processes sharing the mapping see the same physical page.
 *   Writes to the page are visible to all mappers and persist to file.
 *   Dirty page tracking needed for write-back (Phase 4 enhancement).
 *
 * @param page_addr Virtual address to load (must be page-aligned)
 * @param vma Virtual memory area with file mapping info
 * @param ctx Page table context for mapping
 * @return true on success, false on error
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
        /* Partial reads are OK - rest of page remains zero (EOF handling) */
    }

    /* Calculate PTE flags from VMA protection */
    uint64_t pte_flags = PTE_PRESENT | PTE_USER;
    if (vma->prot & 0x2) {
        pte_flags |= PTE_WRITABLE;  /* PROT_WRITE requested */
    }
    if ((vma->prot & 0x4) == 0) {
        pte_flags |= PTE_NX;  /* Execute not allowed */
    }

    /* For MAP_PRIVATE with write permission, map as read-only initially.
     * Copy-on-write will handle the page when written to.
     * For MAP_SHARED, map with requested permissions.
     */
    if ((vma->prot & 0x2) && !(vma->flags & 0x01)) {  /* PROT_WRITE && !MAP_SHARED */
        /* MAP_PRIVATE + writable: Mark VMA as COW and map read-only */
        vma->flags |= VMA_COW;
        pte_flags &= ~PTE_WRITABLE;  /* Map read-only for COW */
    }

    /* Map the page */
    phys_addr_t phys = pmap_virt_to_phys((uintptr_t)page);
    if (pmap_map_user(ctx, page_addr, phys, PAGE_SIZE, pte_flags) != 0) {
        fut_pmm_free_page(page);
        return false;
    }

    /* Initialize page reference count for COW tracking.
     * When a page is first allocated and mapped, it has exactly one reference.
     * If the mapping is MAP_PRIVATE, COW handling will use this refcount to
     * determine if the page can be made writable in-place (refcount=1) or
     * requires copying (refcount>1 from shared mappings).
     */
    extern void fut_page_ref_inc(phys_addr_t phys);
    fut_page_ref_inc(phys);

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
 * Handle copy-on-write page fault (architecture-generic).
 * Returns true if handled, false if not a COW fault.
 *
 * Per-page COW tracking: Only process pages that are still mapped read-only.
 * Once a page is made writable (through copy or sole ownership), subsequent
 * faults won't trigger COW handling because the page is already writable.
 *
 * @param fault_addr Virtual address that faulted
 * @param is_write Whether the fault was a write (vs read)
 * @param is_present Whether the page is present (vs not mapped)
 */
static bool handle_cow_fault_generic(uint64_t fault_addr, bool is_write, bool is_present) {
    /* Check if this is a write fault */
    if (!is_write) {
        return false;  /* Not a write fault */
    }

    /* Check if page is present (COW pages are present but read-only) */
    if (!is_present) {
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

    /* Per-page COW tracking: Check if page is actually read-only (still needs COW)
     * Use architecture-specific helper to check writability */
    if (fut_pte_is_writable(pte)) {
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

        /* Initialize refcount for the new page (now owned by this process) */
        extern void fut_page_ref_inc(phys_addr_t phys);
        fut_page_ref_inc(new_phys);

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

/* ============================================================
 *   Architecture-Specific Page Fault Handlers
 * ============================================================ */

#ifdef __x86_64__

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
        bool is_write = (frame->error_code & 0x2) != 0;
        bool is_present = (frame->error_code & 0x1) != 0;
        if (handle_cow_fault_generic(fault_addr, is_write, is_present)) {
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
        /* Send SIGSEGV to terminate the faulting process */
        fut_task_signal_exit(SIGSEGV);
    }

    return false;
}

#elif defined(__aarch64__)

#include <platform/arm64/regs.h>
#include <platform/arm64/memory/paging.h>
#include <platform/arm64/memory/pmap.h>

/**
 * Handle ARM64 data/instruction abort (page fault).
 * Parses ESR (Exception Syndrome Register) to determine fault type.
 * Supports demand paging and copy-on-write.
 */
bool fut_trap_handle_page_fault(fut_interrupt_frame_t *frame) {
    extern void fut_printf(const char *fmt, ...);

    if (!frame) {
        return false;
    }

    /* Extract exception class from ESR */
    uint64_t esr = frame->esr;
    uint32_t ec = (esr >> 26) & 0x3F;  /* Exception Class [31:26] */

    /* Get fault address from FAR */
    uint64_t fault_addr = frame->far;

    /* Check if this is a data abort (page fault) */
    bool is_lower_el = (ec == 0x24);  /* ESR_EC_DABT_LOWER */
    bool is_current_el = (ec == 0x25); /* ESR_EC_DABT_CURRENT */

    if (!is_lower_el && !is_current_el) {
        return false;  /* Not a data abort */
    }

    /* Extract fault status code (FSC) from ESR bits [5:0] */
    uint32_t fsc = esr & 0x3F;

    /* FSC encoding for page faults:
     * 0x0C (Level 0 translation fault)
     * 0x0E (Level 1 translation fault)
     * 0x0F (Level 2 translation fault)
     * 0x10 (Level 3 translation fault)
     * 0x14 (Level 1 access fault)
     * 0x15 (Level 2 access fault)
     * 0x16 (Level 3 access fault)
     * 0x04-0x07 (Level 0-3 translation fault)
     */
    bool is_translation_fault = ((fsc & 0x3C) == 0x04) || ((fsc & 0x3C) == 0x0C) ||
                                ((fsc & 0x3F) == 0x0F) || ((fsc & 0x3F) == 0x10);
    bool is_access_fault = ((fsc & 0x3C) == 0x14) || ((fsc & 0x3F) == 0x16);

    if (!is_translation_fault && !is_access_fault) {
        return false;  /* Not a page fault we can handle */
    }

    /* Only handle user-space faults (lower EL = EL0 = user) */
    if (!is_lower_el) {
        return false;  /* Kernel page fault - not handled here */
    }

    /* Extract write flag from ESR bit 6 (WnR: Write not Read) */
    bool is_write = (esr >> 6) & 1;

    /* Get current process memory context */
    fut_mm_t *mm = fut_mm_current();
    if (!mm) {
        return false;
    }

    /* Determine if page is present (for access faults) */
    bool is_present = is_access_fault;

    /* Try to handle as COW fault if write */
    if (is_write && handle_cow_fault_generic(fault_addr, is_write, is_present)) {
        return true;  /* COW fault handled successfully */
    }

    /* Try to handle as demand paging fault */
    if (handle_demand_paging_fault(fault_addr, mm)) {
        return true;  /* Demand paging fault handled successfully */
    }

    fut_printf("[#PF-ARM64] user fault addr=0x%llx esr=0x%llx pc=0x%llx\n",
               (unsigned long long)fault_addr,
               (unsigned long long)esr,
               (unsigned long long)frame->pc);
    fut_printf("[#PF-ARM64] Registers: x0=0x%llx x1=0x%llx x2=0x%llx x3=0x%llx\n",
               (unsigned long long)frame->x[0], (unsigned long long)frame->x[1],
               (unsigned long long)frame->x[2], (unsigned long long)frame->x[3]);
    fut_printf("[#PF-ARM64] x4=0x%llx x5=0x%llx x6=0x%llx x7=0x%llx\n",
               (unsigned long long)frame->x[4], (unsigned long long)frame->x[5],
               (unsigned long long)frame->x[6], (unsigned long long)frame->x[7]);
    fut_printf("[#PF-ARM64] sp=0x%llx sp_el0=0x%llx\n",
               (unsigned long long)frame->sp, (unsigned long long)frame->sp_el0);

    return false;
}

#else
#error "Unsupported architecture for page fault handling"
#endif
