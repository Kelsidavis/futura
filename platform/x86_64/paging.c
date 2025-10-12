/* paging.c - x86_64 Virtual Memory Management
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Dynamic page mapping implementation for Futura OS.
 * Provides on-demand mapping of physical memory into virtual address space.
 */

#include <arch/x86_64/paging.h>
#include <arch/x86_64/pmap.h>
#include <kernel/fut_memory.h>
#include <stddef.h>
#include <stdbool.h>

/* External boot page tables from boot.S */
extern page_table_t boot_pml4;
extern page_table_t boot_pdpt;
extern page_table_t boot_pd;

/* Kernel's PML4 (initialized to boot PML4) */
static pte_t *kernel_pml4 = NULL;

/**
 * Initialize paging subsystem.
 * Called during early kernel initialization.
 */
void fut_paging_init(void) {
    /* Use boot page tables as kernel page tables */
    kernel_pml4 = (pte_t *)&boot_pml4;

    /* Note: Boot already set up:
     * - PML4[0] and PML4[511] point to same PDPT (identity + higher-half)
     * - PDPT[0] and PDPT[510] point to same PD
     * - PD[0-3] map first 8MB with 2MB huge pages
     */
}

/**
 * Get kernel PML4 table.
 */
pte_t *fut_get_kernel_pml4(void) {
    return kernel_pml4;
}

/**
 * Allocate a page table (512 entries, 4KB).
 * Returns physical address of new page table.
 */
static page_table_t *alloc_page_table(void) {
    /* Allocate a 4KB page for the page table */
    void *page = fut_pmm_alloc_page();
    if (!page) {
        return NULL;
    }

    phys_addr_t phys = pmap_virt_to_phys((uintptr_t)page);
    page_table_t *table = (page_table_t *)pmap_kmap(phys);
    if (!table) {
        return NULL;
    }

    /* Zero-initialize all entries */
    for (int i = 0; i < 512; i++) {
        table->entries[i] = 0;
    }

    return table;
}

/**
 * Map a single 4KB page to virtual address.
 * Creates intermediate page tables as needed.
 *
 * @param vaddr Virtual address (must be page-aligned)
 * @param paddr Physical address (must be page-aligned)
 * @param flags Page flags (PTE_PRESENT | PTE_WRITABLE | etc.)
 * @return 0 on success, negative on error
 */
int fut_map_page(fut_vmem_context_t *ctx, uint64_t vaddr, uint64_t paddr, uint64_t flags) {
    /* Use kernel PML4 if no context provided */
    pte_t *pml4 = ctx ? ctx->pml4 : kernel_pml4;
    if (!pml4) {
#if defined(DEBUG)
        fut_printf("[VM] fut_map_page: no PML4 context\n");
#endif
        return -1;
    }

    /* Validate addresses are page-aligned */
    if ((vaddr & 0xFFF) || (paddr & 0xFFF)) {
#if defined(DEBUG)
        fut_printf("[VM] fut_map_page alignment error: vaddr=0x%llx paddr=0x%llx\n",
                   (unsigned long long)vaddr, (unsigned long long)paddr);
#endif
        return -1;
    }

    /* Extract page table indices from virtual address */
    uint64_t pml4_idx = PML4_INDEX(vaddr);
    uint64_t pdpt_idx = PDPT_INDEX(vaddr);
    uint64_t pd_idx = PD_INDEX(vaddr);
    uint64_t pt_idx = PT_INDEX(vaddr);

    /* Get or create PDPT */
    page_table_t *pdpt;
    if (!(pml4[pml4_idx] & PTE_PRESENT)) {
        /* Need to allocate new PDPT */
        pdpt = alloc_page_table();
        if (!pdpt) {
#if defined(DEBUG)
            fut_printf("[VM] Failed to allocate PDPT for vaddr=0x%llx\n",
                       (unsigned long long)vaddr);
#endif
            return -1;
        }
        phys_addr_t pdpt_phys = pmap_virt_to_phys((uintptr_t)pdpt);
        pml4[pml4_idx] = fut_make_pte(pdpt_phys, PTE_PRESENT | PTE_WRITABLE);
    } else {
        phys_addr_t pdpt_phys = fut_pte_to_phys(pml4[pml4_idx]);
        pdpt = (page_table_t *)pmap_kmap(pdpt_phys);
    }

    /* Get or create PD */
    page_table_t *pd;
    if (!(pdpt->entries[pdpt_idx] & PTE_PRESENT)) {
        /* Need to allocate new PD */
        pd = alloc_page_table();
        if (!pd) {
#if defined(DEBUG)
            fut_printf("[VM] Failed to allocate PD for vaddr=0x%llx\n",
                       (unsigned long long)vaddr);
#endif
            return -1;
        }
        phys_addr_t pd_phys = pmap_virt_to_phys((uintptr_t)pd);
        pdpt->entries[pdpt_idx] = fut_make_pte(pd_phys, PTE_PRESENT | PTE_WRITABLE);
    } else {
        phys_addr_t pd_phys = fut_pte_to_phys(pdpt->entries[pdpt_idx]);
        pd = (page_table_t *)pmap_kmap(pd_phys);
    }

    /* Get or create PT */
    page_table_t *pt;
    if (!(pd->entries[pd_idx] & PTE_PRESENT)) {
        /* Need to allocate new PT */
        pt = alloc_page_table();
        if (!pt) {
#if defined(DEBUG)
            fut_printf("[VM] Failed to allocate PT for vaddr=0x%llx\n",
                       (unsigned long long)vaddr);
#endif
            return -1;
        }
        phys_addr_t pt_phys = pmap_virt_to_phys((uintptr_t)pt);
        pd->entries[pd_idx] = fut_make_pte(pt_phys, PTE_PRESENT | PTE_WRITABLE);
    } else if (pd->entries[pd_idx] & PTE_LARGE_PAGE) {
#if defined(DEBUG)
        fut_printf("[VM] Splitting large page: vaddr=0x%llx paddr=0x%llx\n",
                   (unsigned long long)vaddr, (unsigned long long)paddr);
#endif
        /*
         * The region is currently mapped with a 2MB large page. To support
         * sub-page mappings (required for fut_map_range to extend the heap
         * beyond the initial boot window) we must split the large page into
         * a regular 4KB page table. Replicate the original mapping so the
         * address space remains intact before installing the requested page.
         */
        pte_t large_entry = pd->entries[pd_idx];
        uint64_t phys_base = fut_pte_to_phys(large_entry);
        uint64_t large_flags = fut_pte_flags(large_entry) & ~PTE_LARGE_PAGE;

        page_table_t *new_pt = alloc_page_table();
        if (!new_pt) {
#if defined(DEBUG)
            fut_printf("[VM] Failed to allocate replacement PT while splitting large page\n");
#endif
            return -1;
        }

        for (uint64_t i = 0; i < 512; ++i) {
            uint64_t page_phys = phys_base + (i * PAGE_SIZE);
            new_pt->entries[i] = fut_make_pte(page_phys, large_flags);
        }

        phys_addr_t new_pt_phys = pmap_virt_to_phys((uintptr_t)new_pt);
        pd->entries[pd_idx] = fut_make_pte(new_pt_phys, large_flags);
        pt = new_pt;

        /* Ensure processors observe the replacement page table */
        fut_flush_tlb_all();
    } else {
        phys_addr_t pt_phys = fut_pte_to_phys(pd->entries[pd_idx]);
        pt = (page_table_t *)pmap_kmap(pt_phys);
    }

    /* Map the page in PT */
    pt->entries[pt_idx] = fut_make_pte(paddr, flags | PTE_PRESENT);

    /* Flush TLB for this address */
    fut_flush_tlb_single(vaddr);

    return 0;
}

/**
 * Map contiguous range of physical memory.
 * Maps each 4KB page individually.
 *
 * @param vaddr Virtual base address
 * @param paddr Physical base address
 * @param size Size in bytes (will be rounded up to page size)
 * @param flags Page flags
 * @return 0 on success, negative on error
 */
int fut_map_range(fut_vmem_context_t *ctx, uint64_t vaddr, uint64_t paddr,
                  uint64_t size, uint64_t flags) {
    /* Align addresses and size to page boundaries */
    uint64_t start_vaddr = PAGE_ALIGN_DOWN(vaddr);
    uint64_t start_paddr = PAGE_ALIGN_DOWN(paddr);
    uint64_t end_vaddr = PAGE_ALIGN_UP(vaddr + size);

    /* Map each page in the range */
    for (uint64_t va = start_vaddr, pa = start_paddr;
         va < end_vaddr;
         va += PAGE_SIZE, pa += PAGE_SIZE) {

        int ret = fut_map_page(ctx, va, pa, flags);
        if (ret < 0) {
            /* Failed to map a page - should we unmap what we've done so far? */
            /* For now, just return error */
            return ret;
        }
    }

    return 0;
}

/**
 * Unmap a single page.
 */
int fut_unmap_page(fut_vmem_context_t *ctx, uint64_t vaddr) {
    pte_t *pml4 = ctx ? ctx->pml4 : kernel_pml4;
    if (!pml4) {
        return -1;
    }

    /* Extract indices */
    uint64_t pml4_idx = PML4_INDEX(vaddr);
    uint64_t pdpt_idx = PDPT_INDEX(vaddr);
    uint64_t pd_idx = PD_INDEX(vaddr);
    uint64_t pt_idx = PT_INDEX(vaddr);

    /* Walk page tables to find the mapping */
    if (!(pml4[pml4_idx] & PTE_PRESENT)) {
        return -1;  /* Not mapped */
    }

    page_table_t *pdpt = (page_table_t *)pmap_kmap(fut_pte_to_phys(pml4[pml4_idx]));
    if (!(pdpt->entries[pdpt_idx] & PTE_PRESENT)) {
        return -1;
    }

    page_table_t *pd = (page_table_t *)pmap_kmap(fut_pte_to_phys(pdpt->entries[pdpt_idx]));
    if (!(pd->entries[pd_idx] & PTE_PRESENT)) {
        return -1;
    }

    /* Check if large page */
    if (pd->entries[pd_idx] & PTE_LARGE_PAGE) {
        /* Unmapping 2MB page */
        pd->entries[pd_idx] = 0;
        fut_flush_tlb_single(vaddr);
        return 0;
    }

    page_table_t *pt = (page_table_t *)pmap_kmap(fut_pte_to_phys(pd->entries[pd_idx]));

    /* Unmap the page */
    pt->entries[pt_idx] = 0;
    fut_flush_tlb_single(vaddr);

    return 0;
}

/**
 * Unmap a range of pages.
 */
int fut_unmap_range(fut_vmem_context_t *ctx, uint64_t vaddr, uint64_t size) {
    uint64_t start = PAGE_ALIGN_DOWN(vaddr);
    uint64_t end = PAGE_ALIGN_UP(vaddr + size);

    for (uint64_t va = start; va < end; va += PAGE_SIZE) {
        fut_unmap_page(ctx, va);
    }

    return 0;
}

/**
 * Translate virtual address to physical address.
 */
int fut_virt_to_phys(fut_vmem_context_t *ctx, uint64_t vaddr, uint64_t *paddr) {
    pte_t *pml4 = ctx ? ctx->pml4 : kernel_pml4;
    if (!pml4 || !paddr) {
        return -1;
    }

    /* Extract indices */
    uint64_t pml4_idx = PML4_INDEX(vaddr);
    uint64_t pdpt_idx = PDPT_INDEX(vaddr);
    uint64_t pd_idx = PD_INDEX(vaddr);
    uint64_t pt_idx = PT_INDEX(vaddr);
    uint64_t offset = PAGE_OFFSET(vaddr);

    /* Walk page tables */
    if (!(pml4[pml4_idx] & PTE_PRESENT)) {
        return -1;
    }

    page_table_t *pdpt = (page_table_t *)pmap_kmap(fut_pte_to_phys(pml4[pml4_idx]));
    if (!(pdpt->entries[pdpt_idx] & PTE_PRESENT)) {
        return -1;
    }

    page_table_t *pd = (page_table_t *)pmap_kmap(fut_pte_to_phys(pdpt->entries[pdpt_idx]));
    if (!(pd->entries[pd_idx] & PTE_PRESENT)) {
        return -1;
    }

    /* Check if large page (2MB) */
    if (pd->entries[pd_idx] & PTE_LARGE_PAGE) {
        uint64_t base = fut_pte_to_phys(pd->entries[pd_idx]);
        *paddr = base + (vaddr & 0x1FFFFF);  /* 21-bit offset for 2MB page */
        return 0;
    }

    page_table_t *pt = (page_table_t *)pmap_kmap(fut_pte_to_phys(pd->entries[pd_idx]));
    if (!(pt->entries[pt_idx] & PTE_PRESENT)) {
        return -1;
    }

    *paddr = fut_pte_to_phys(pt->entries[pt_idx]) + offset;
    return 0;
}
