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
#include "../../include/kernel/signal.h"

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
 * Handle copy-on-write page fault.
 * Returns true if handled, false if not a COW fault.
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

        fut_printf("[COW] Copied page: va=0x%llx old_phys=0x%llx new_phys=0x%llx\n",
                   page_addr, old_phys, new_phys);
    } else {
        /* Only one reference - just make it writable */
        uint64_t flags = (pte & (PTE_PRESENT | PTE_USER | PTE_NX)) | PTE_WRITABLE;

        fut_unmap_range(ctx, page_addr, PAGE_SIZE);
        if (pmap_map_user(ctx, page_addr, old_phys, PAGE_SIZE, flags) != 0) {
            return false;
        }

        /* Decrement refcount (remove from tracking) */
        fut_page_ref_dec(old_phys);

        fut_printf("[COW] Made page writable: va=0x%llx phys=0x%llx (sole owner)\n",
                   page_addr, old_phys);
    }

    /* Clear COW flag if all pages in VMA have been copied */
    /* TODO: Track per-page COW status for finer granularity */

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
