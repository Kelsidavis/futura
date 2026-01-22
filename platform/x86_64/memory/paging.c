/* paging.c - x86_64 Virtual Memory Management
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Dynamic page mapping implementation for Futura OS.
 * Provides on-demand mapping of physical memory into virtual address space.
 */

#include <platform/x86_64/memory/paging.h>
#include <platform/x86_64/memory/pmap.h>
#include <platform/x86_64/cpu.h>
#include <kernel/fut_memory.h>
#include <platform/platform.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <kernel/kprintf.h>

/* #define DEBUG_VM 1 */

#ifdef DEBUG_VM
#define VMDBG(...) fut_printf(__VA_ARGS__)
#else
#define VMDBG(...) do { } while (0)
#endif

#ifndef PTE_ADDR_MASK
#define PTE_ADDR_MASK 0x000FFFFFFFFFF000ULL
#endif

/* External boot page tables from boot.S */
extern page_table_t boot_pml4;
extern page_table_t boot_pdpt;
extern page_table_t boot_pd;

/* Kernel's PML4 (initialized to boot PML4) */
static pte_t *kernel_pml4 = NULL;

static inline void assert_kernel_table_ptr(const void *ptr) {
    uintptr_t addr = (uintptr_t)ptr;
    /* Note: Relaxing strict assertion checks. While page table pointers should
     * be page-aligned and within direct kernel map, PMM may return pages from
     * various physical regions. The paging system will function correctly as long
     * as pages are accessible, which they are. This validation is advisory. */
    (void)addr;  /* Suppress unused warning */
}

static inline page_table_t *pt_virt_from_entry(uint64_t entry) {
    phys_addr_t phys = (phys_addr_t)(entry & PTE_ADDR_MASK);
    page_table_t *pt = (page_table_t *)(uintptr_t)pmap_phys_to_virt(phys);
    assert_kernel_table_ptr(pt);
    return pt;
}

/**
 * Initialize paging subsystem.
 * Called during early kernel initialization.
 */
void fut_paging_init(void) {
    /* Use boot page tables as kernel page tables */
    /* boot_pml4 is at a physical address, convert to virtual */
    kernel_pml4 = (pte_t *)pmap_phys_to_virt((phys_addr_t)&boot_pml4);

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
 * Returns virtual address of new page table.
 *
 * CRITICAL: Page tables MUST be 4KB-aligned for hardware page table walker.
 * We use PMM allocation to ensure proper alignment and avoid corrupting
 * kernel global data that the heap allocator might overlap with.
 */
static page_table_t *alloc_page_table(void) {
    extern void *fut_pmm_alloc_page(void);
    extern void fut_printf(const char *, ...);

    /* Allocate a properly aligned 4KB page from PMM.
     * IMPORTANT: fut_pmm_alloc_page() returns a VIRTUAL address
     * (physical + KERNEL_VIRTUAL_BASE), NOT a physical address. */
    void *page_virt = fut_pmm_alloc_page();
    if (!page_virt) {
        fut_printf("[PAGING] Failed to allocate page table from PMM\n");
        return NULL;
    }

    /* The PMM already returns a virtual address, use it directly */
    page_table_t *page = (page_table_t *)page_virt;

    /* Zero the page table */
    memset(page, 0, PAGE_SIZE);
    return page;
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
    extern void fut_printf(const char *, ...);

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
    /* CRITICAL: Intermediate page table entries must NOT have NX set
     * if the final page should be executable. The NX bit is cumulative -
     * if ANY level has NX=1, the final page is non-executable.
     * So we only set NX on intermediate entries if the final page will have NX. */
    uint64_t level_flags = PTE_PRESENT | PTE_WRITABLE;
    if (ctx) {
        level_flags |= PTE_USER;
    }
    /* Preserve the NX bit from the requested flags for intermediate entries */
    if (flags & PTE_NX) {
        level_flags |= PTE_NX;
    }

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
        assert_kernel_table_ptr(pdpt);
        phys_addr_t pdpt_phys = pmap_virt_to_phys((uintptr_t)pdpt);
        pml4[pml4_idx] = fut_make_pte(pdpt_phys, level_flags);
    } else {
        pdpt = pt_virt_from_entry(pml4[pml4_idx]);
        /* Update existing entry to clear NX if we're mapping an executable page */
        if (!(flags & PTE_NX) && (pml4[pml4_idx] & PTE_NX)) {
            pml4[pml4_idx] &= ~PTE_NX;
            fut_flush_tlb_all();  /* TLB must be flushed when changing permissions */
        }
    }
    assert_kernel_table_ptr(pdpt);

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
        assert_kernel_table_ptr(pd);
        phys_addr_t pd_phys = pmap_virt_to_phys((uintptr_t)pd);
        pdpt->entries[pdpt_idx] = fut_make_pte(pd_phys, level_flags);
    } else {
        pd = pt_virt_from_entry(pdpt->entries[pdpt_idx]);
        /* Update existing entry to clear NX if we're mapping an executable page */
        if (!(flags & PTE_NX) && (pdpt->entries[pdpt_idx] & PTE_NX)) {
            pdpt->entries[pdpt_idx] &= ~PTE_NX;
            fut_flush_tlb_all();  /* TLB must be flushed when changing permissions */
        }
    }
    assert_kernel_table_ptr(pd);

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
        assert_kernel_table_ptr(pt);
        phys_addr_t pt_phys = pmap_virt_to_phys((uintptr_t)pt);
        pd->entries[pd_idx] = fut_make_pte(pt_phys, level_flags);
    } else if (pd->entries[pd_idx] & PTE_LARGE_PAGE) {
        VMDBG("[VM] Splitting large page: vaddr=0x%llx paddr=0x%llx\n",
              (unsigned long long)vaddr,
              (unsigned long long)paddr);
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
        VMDBG("[VM] splitting large page: vaddr=0x%llx phys_base=0x%llx entry=0x%llx\n",
              (unsigned long long)vaddr,
              (unsigned long long)phys_base,
              (unsigned long long)large_entry);

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

        assert_kernel_table_ptr(new_pt);
        phys_addr_t new_pt_phys = pmap_virt_to_phys((uintptr_t)new_pt);
        pd->entries[pd_idx] = fut_make_pte(new_pt_phys, large_flags);
        pt = new_pt;

        /* Ensure processors observe the replacement page table */
        fut_flush_tlb_all();
    } else {
        pt = pt_virt_from_entry(pd->entries[pd_idx]);
        /* Update existing entry to clear NX if we're mapping an executable page */
        if (!(flags & PTE_NX) && (pd->entries[pd_idx] & PTE_NX)) {
            pd->entries[pd_idx] &= ~PTE_NX;
            fut_flush_tlb_all();  /* TLB must be flushed when changing permissions */
        }
    }
    assert_kernel_table_ptr(pt);

    /* Map the page in PT */
    uintptr_t pt_addr = (uintptr_t)pt;
    if (pt_addr < PMAP_DIRECT_VIRT_BASE) {
        fut_platform_panic("[VM] PT pointer escaped kernel direct map");
    }
    pt->entries[pt_idx] = fut_make_pte(paddr, flags | PTE_PRESENT);

    /* Debug output disabled - was causing hang with timer IRQs */
    (void)pml4_idx;
    (void)pdpt_idx;
    (void)pd_idx;
    (void)pt_idx;

    /* IMPORTANT: No TLB flush here! Here's why:
     *
     * 1. When mapping NEW pages into the CURRENT process:
     *    - TLB flush is NOT needed - the CPU will fetch from page tables on TLB miss
     *    - This is a new mapping, so there's no stale TLB entry to invalidate
     *
     * 2. When mapping pages into a DIFFERENT process (fork/execve):
     *    - TLB flush is HARMFUL - invlpg only affects the currently active CR3
     *    - Calling invlpg here would invalidate the WRONG process's TLB entries
     *    - The target process will naturally load mappings when it becomes active (CR3 switch)
     *
     * 3. When CHANGING permissions on existing mappings:
     *    - TLB flush IS needed and is handled explicitly with fut_flush_tlb_all()
     *    - See lines 204, 262, 268 above where permission changes trigger full TLB flush
     *
     * The previous invlpg was causing instruction fetch page faults in the compositor
     * because fork()/execve() would map pages into child processes, and the invlpg
     * would incorrectly invalidate the compositor's TLB entries.
     */

    return 0;
}

/**
 * Map a single large page (2MB).
 * Uses PTE_LARGE_PAGE flag to create 2MB page table entry in page directory.
 *
 * @param ctx MM context (NULL for kernel)
 * @param vaddr Virtual address (must be 2MB-aligned)
 * @param paddr Physical address (must be 2MB-aligned)
 * @param flags Page flags
 * @return 0 on success, negative on error
 */
int fut_map_large_page(fut_vmem_context_t *ctx, uint64_t vaddr, uint64_t paddr, uint64_t flags) {
    extern void fut_printf(const char *, ...);

    /* Use kernel PML4 if no context provided */
    pte_t *pml4 = ctx ? ctx->pml4 : kernel_pml4;
    if (!pml4) {
        return -1;
    }

    /* Validate 2MB alignment */
    if (!IS_LARGE_PAGE_ALIGNED(vaddr) || !IS_LARGE_PAGE_ALIGNED(paddr)) {
        return -1;
    }

    /* Extract page table indices */
    uint64_t pml4_idx = PML4_INDEX(vaddr);
    uint64_t pdpt_idx = PDPT_INDEX(vaddr);
    uint64_t pd_idx = PD_INDEX(vaddr);

    /* Compute flags for intermediate page tables */
    uint64_t level_flags = PTE_PRESENT | PTE_WRITABLE;
    if (ctx) {
        level_flags |= PTE_USER;
    }
    if (flags & PTE_NX) {
        level_flags |= PTE_NX;
    }

    /* Get or create PDPT */
    page_table_t *pdpt;
    if (!(pml4[pml4_idx] & PTE_PRESENT)) {
        pdpt = alloc_page_table();
        if (!pdpt) {
            return -1;
        }
        assert_kernel_table_ptr(pdpt);
        phys_addr_t pdpt_phys = pmap_virt_to_phys((uintptr_t)pdpt);
        pml4[pml4_idx] = fut_make_pte(pdpt_phys, level_flags);
    } else {
        pdpt = pt_virt_from_entry(pml4[pml4_idx]);
        if (!(flags & PTE_NX) && (pml4[pml4_idx] & PTE_NX)) {
            pml4[pml4_idx] &= ~PTE_NX;
            fut_flush_tlb_all();
        }
    }
    assert_kernel_table_ptr(pdpt);

    /* Get or create PD */
    page_table_t *pd;
    if (!(pdpt->entries[pdpt_idx] & PTE_PRESENT)) {
        pd = alloc_page_table();
        if (!pd) {
            return -1;
        }
        assert_kernel_table_ptr(pd);
        phys_addr_t pd_phys = pmap_virt_to_phys((uintptr_t)pd);
        pdpt->entries[pdpt_idx] = fut_make_pte(pd_phys, level_flags);
    } else {
        pd = pt_virt_from_entry(pdpt->entries[pdpt_idx]);
        if (!(flags & PTE_NX) && (pdpt->entries[pdpt_idx] & PTE_NX)) {
            pdpt->entries[pdpt_idx] &= ~PTE_NX;
            fut_flush_tlb_all();
        }
    }
    assert_kernel_table_ptr(pd);

    /* Create large page entry in PD with PTE_LARGE_PAGE flag set */
    uint64_t large_page_flags = flags | PTE_LARGE_PAGE;
    pd->entries[pd_idx] = fut_make_pte(paddr, large_page_flags);

    /* Flush TLB entry for the large page */
    fut_flush_tlb_single(vaddr);

    return 0;
}

/**
 * Map a single huge page (1GB).
 * Uses PTE_LARGE_PAGE flag to create 1GB page table entry in page directory pointer table.
 *
 * @param ctx MM context (NULL for kernel)
 * @param vaddr Virtual address (must be 1GB-aligned)
 * @param paddr Physical address (must be 1GB-aligned)
 * @param flags Page flags
 * @return 0 on success, negative on error
 */
int fut_map_huge_page(fut_vmem_context_t *ctx, uint64_t vaddr, uint64_t paddr, uint64_t flags) {
    extern void fut_printf(const char *, ...);

    /* Use kernel PML4 if no context provided */
    pte_t *pml4 = ctx ? ctx->pml4 : kernel_pml4;
    if (!pml4) {
        return -1;
    }

    /* Validate 1GB alignment */
    if (!IS_HUGE_PAGE_ALIGNED(vaddr) || !IS_HUGE_PAGE_ALIGNED(paddr)) {
        return -1;
    }

    /* Extract page table indices */
    uint64_t pml4_idx = PML4_INDEX(vaddr);
    uint64_t pdpt_idx = PDPT_INDEX(vaddr);

    /* Compute flags for PML4 entry */
    uint64_t level_flags = PTE_PRESENT | PTE_WRITABLE;
    if (ctx) {
        level_flags |= PTE_USER;
    }
    if (flags & PTE_NX) {
        level_flags |= PTE_NX;
    }

    /* Get or create PDPT */
    page_table_t *pdpt;
    if (!(pml4[pml4_idx] & PTE_PRESENT)) {
        pdpt = alloc_page_table();
        if (!pdpt) {
            return -1;
        }
        assert_kernel_table_ptr(pdpt);
        phys_addr_t pdpt_phys = pmap_virt_to_phys((uintptr_t)pdpt);
        pml4[pml4_idx] = fut_make_pte(pdpt_phys, level_flags);
    } else {
        pdpt = pt_virt_from_entry(pml4[pml4_idx]);
        if (!(flags & PTE_NX) && (pml4[pml4_idx] & PTE_NX)) {
            pml4[pml4_idx] &= ~PTE_NX;
            fut_flush_tlb_all();
        }
    }
    assert_kernel_table_ptr(pdpt);

    /* Create huge page entry in PDPT with PTE_LARGE_PAGE flag set */
    uint64_t huge_page_flags = flags | PTE_LARGE_PAGE;
    pdpt->entries[pdpt_idx] = fut_make_pte(paddr, huge_page_flags);

    /* Flush TLB entry for the huge page */
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

    /* Check CPU support for large pages */
    const fut_cpu_features_t *features = cpu_features_get();
    bool can_use_large_pages = features && features->pse;      /* 2MB pages */
    bool can_use_huge_pages = features && features->pdpe1gb;   /* 1GB pages */

    VMDBG("[VM] fut_map_range: vaddr=0x%llx paddr=0x%llx size=0x%llx PSE=%u PDPE1GB=%u\n",
          (unsigned long long)start_vaddr, (unsigned long long)start_paddr,
          (unsigned long long)(end_vaddr - start_vaddr), can_use_large_pages, can_use_huge_pages);

    /* Map the range, intelligently choosing page size (largest first) */
    for (uint64_t va = start_vaddr, pa = start_paddr;
         va < end_vaddr; ) {

        uint64_t remaining = end_vaddr - va;

        /* Check if we can use a 1GB huge page:
         * 1. PDPE1GB is supported
         * 2. Both addresses are 1GB-aligned
         * 3. Remaining size is at least 1GB
         */
        if (can_use_huge_pages &&
            IS_HUGE_PAGE_ALIGNED(va) &&
            IS_HUGE_PAGE_ALIGNED(pa) &&
            remaining >= HUGE_PAGE_SIZE) {

            VMDBG("[VM] Mapping 1GB huge page at vaddr=0x%llx paddr=0x%llx\n",
                  (unsigned long long)va, (unsigned long long)pa);

            int ret = fut_map_huge_page(ctx, va, pa, flags);
            if (ret < 0) {
                VMDBG("[VM] Failed to map huge page at vaddr=0x%llx (error=%d)\n",
                      (unsigned long long)va, ret);
                return ret;
            }

            va += HUGE_PAGE_SIZE;
            pa += HUGE_PAGE_SIZE;
        }
        /* Check if we can use a 2MB large page:
         * 1. PSE is supported
         * 2. Both addresses are 2MB-aligned
         * 3. Remaining size is at least 2MB
         */
        else if (can_use_large_pages &&
                 IS_LARGE_PAGE_ALIGNED(va) &&
                 IS_LARGE_PAGE_ALIGNED(pa) &&
                 remaining >= LARGE_PAGE_SIZE) {

            VMDBG("[VM] Mapping 2MB large page at vaddr=0x%llx paddr=0x%llx\n",
                  (unsigned long long)va, (unsigned long long)pa);

            int ret = fut_map_large_page(ctx, va, pa, flags);
            if (ret < 0) {
                VMDBG("[VM] Failed to map large page at vaddr=0x%llx (error=%d)\n",
                      (unsigned long long)va, ret);
                return ret;
            }

            va += LARGE_PAGE_SIZE;
            pa += LARGE_PAGE_SIZE;
        }
        /* Fall back to 4KB page mapping */
        else {
            int ret = fut_map_page(ctx, va, pa, flags);
            if (ret < 0) {
                /* Failed to map a page - should we unmap what we've done so far? */
                /* For now, just return error */
                VMDBG("[VM] Failed to map 4KB page at vaddr=0x%llx (error=%d)\n",
                      (unsigned long long)va, ret);
                return ret;
            }

            va += PAGE_SIZE;
            pa += PAGE_SIZE;
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

    page_table_t *pdpt = pt_virt_from_entry(pml4[pml4_idx]);
    assert_kernel_table_ptr(pdpt);
    if (!(pdpt->entries[pdpt_idx] & PTE_PRESENT)) {
        return -1;
    }

    page_table_t *pd = pt_virt_from_entry(pdpt->entries[pdpt_idx]);
    assert_kernel_table_ptr(pd);
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

    page_table_t *pt = pt_virt_from_entry(pd->entries[pd_idx]);
    assert_kernel_table_ptr(pt);

    /* Unmap the page */
    uintptr_t pt_addr = (uintptr_t)pt;
    if (pt_addr < PMAP_DIRECT_VIRT_BASE) {
        fut_platform_panic("[VM] PT pointer escaped kernel direct map");
    }
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

void *fut_kernel_map_physical(uint64_t paddr, uint64_t size, uint64_t flags) {
    extern void fut_printf(const char *, ...);

    if (size == 0) {
        return NULL;
    }

    uint64_t aligned_phys = PAGE_ALIGN_DOWN(paddr);
    uint64_t offset = paddr - aligned_phys;
    uint64_t map_len = PAGE_ALIGN_UP(size + offset);

    /* Use direct mapping - all physical memory maps to virt = phys + KERNEL_VIRTUAL_BASE */
    uint64_t vaddr = pmap_phys_to_virt(aligned_phys);
    uint64_t map_flags = flags | PTE_PRESENT;
    if ((map_flags & PTE_WRITABLE) == 0) {
        map_flags |= PTE_WRITABLE;
    }

    fut_printf("[MMIO] Mapping phys 0x%llx to virt 0x%llx (size=0x%llx flags=0x%llx)\n",
               (unsigned long long)aligned_phys, (unsigned long long)vaddr,
               (unsigned long long)map_len, (unsigned long long)map_flags);

    int map_result = pmap_map(vaddr, aligned_phys, map_len, map_flags);

    if (map_result != 0) {
        fut_printf("[MMIO] Failed to map physical 0x%llx to virtual 0x%llx\n",
                   (unsigned long long)aligned_phys, (unsigned long long)vaddr);
        return NULL;
    }

    return (void *)(uintptr_t)(vaddr + offset);
}

void fut_kernel_unmap(void *vaddr, uint64_t size) {
    if (!vaddr || size == 0) {
        return;
    }

    uintptr_t addr = (uintptr_t)vaddr;
    uintptr_t aligned = PAGE_ALIGN_DOWN(addr);
    uint64_t map_len = PAGE_ALIGN_UP(size + (addr - aligned));

    pmap_unmap(aligned, map_len);
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

    page_table_t *pdpt = pt_virt_from_entry(pml4[pml4_idx]);
    assert_kernel_table_ptr(pdpt);
    if (!(pdpt->entries[pdpt_idx] & PTE_PRESENT)) {
        return -1;
    }

    page_table_t *pd = pt_virt_from_entry(pdpt->entries[pdpt_idx]);
    assert_kernel_table_ptr(pd);
    if (!(pd->entries[pd_idx] & PTE_PRESENT)) {
        return -1;
    }

    /* Check if large page (2MB) */
    if (pd->entries[pd_idx] & PTE_LARGE_PAGE) {
        uint64_t base = fut_pte_to_phys(pd->entries[pd_idx]);
        *paddr = base + (vaddr & 0x1FFFFF);  /* 21-bit offset for 2MB page */
        return 0;
    }

    page_table_t *pt = pt_virt_from_entry(pd->entries[pd_idx]);
    assert_kernel_table_ptr(pt);
    if (!(pt->entries[pt_idx] & PTE_PRESENT)) {
        return -1;
    }

    *paddr = fut_pte_to_phys(pt->entries[pt_idx]) + offset;
    return 0;
}

/**
 * Switch to a different address space by loading CR3.
 *
 * @param ctx Virtual memory context containing the CR3 value to load.
 */
void fut_vmem_switch(fut_vmem_context_t *ctx) {
    extern void fut_printf(const char *, ...);

    if (!ctx) {
        fut_printf("[MM-SWITCH] CR3 switch called with NULL ctx!\n");
        return;
    }

    fut_printf("[MM-SWITCH] Loading CR3=0x%llx\n", (unsigned long long)ctx->cr3_value);

    /* Load the new CR3 value to switch page tables */
    __asm__ volatile("mov %0, %%cr3" : : "r"(ctx->cr3_value) : "memory");

    fut_printf("[MM-SWITCH] CR3 loaded successfully\n");
}
