/* pmap.c - ARM64 Physical Memory Mapping
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * ARM64 physical memory mapping and page table walking implementation.
 */

#include <arch/arm64/pmap.h>
#include <kernel/errno.h>
#include <kernel/fut_memory.h>

extern void fut_printf(const char *fmt, ...);

/* Get the PGD from context, using kernel PGD if context is NULL or invalid */
static inline page_table_t *pmap_context_pgd(fut_vmem_context_t *ctx) {
    if (!ctx || !ctx->pgd) {
        return fut_get_kernel_pgd();
    }

    uintptr_t raw = (uintptr_t)ctx->pgd;
    if (raw >= PMAP_DIRECT_VIRT_BASE) {
        return (page_table_t *)raw;
    }

    return (page_table_t *)pmap_kmap((phys_addr_t)raw);
}

/* Get virtual address for a page table from its physical address */
static inline page_table_t *pmap_table_from_phys(phys_addr_t phys) {
    return (page_table_t *)pmap_kmap(phys);
}

/* ============================================================
 *   Kernel Mapping Helpers
 * ============================================================ */

void *pmap_kmap(phys_addr_t phys) {
    return (void *)(uintptr_t)pmap_phys_to_virt(phys);
}

void pmap_kunmap(void *virt) {
    (void)virt;
}

int pmap_map(uint64_t vaddr, phys_addr_t paddr, size_t len, uint64_t prot) {
    return fut_map_range(NULL, vaddr, paddr, len, prot);
}

int pmap_unmap(uint64_t vaddr, size_t len) {
    return fut_unmap_range(NULL, vaddr, len);
}

int pmap_protect(uint64_t vaddr, size_t len, uint64_t prot) {
    const uint64_t start = PAGE_ALIGN_DOWN(vaddr);
    const uint64_t end = PAGE_ALIGN_UP(vaddr + len);

    for (uint64_t addr = start; addr < end; addr += PAGE_SIZE) {
        uint64_t phys = 0;
        int rc = fut_virt_to_phys(NULL, addr, &phys);
        if (rc != 0) {
            return rc;
        }
        rc = fut_map_page(NULL, addr, phys, prot);
        if (rc != 0) {
            return rc;
        }
    }
    return 0;
}

void pmap_dump(uint64_t vaddr, size_t len) {
    const uint64_t start = PAGE_ALIGN_DOWN(vaddr);
    const uint64_t end = PAGE_ALIGN_UP(vaddr + len);

    for (uint64_t addr = start; addr < end; addr += PAGE_SIZE) {
        uint64_t phys = 0;
        const int rc = fut_virt_to_phys(NULL, addr, &phys);

        if (rc != 0) {
            fut_printf("[pmap] 0x%016llx -> unmapped (err=%d)\n",
                       (unsigned long long)addr, rc);
            continue;
        }

        fut_printf("[pmap] 0x%016llx -> 0x%016llx\n",
                   (unsigned long long)addr,
                   (unsigned long long)phys);
    }
}

/* ============================================================
 *   ARM64 Page Table Walking (4-Level Hierarchy)
 * ============================================================
 *
 * ARM64 page table hierarchy (for 48-bit VA, 4KB granule):
 * L0 (PGD): Indexed by bits 39-47
 * L1 (PMD): Indexed by bits 30-38
 * L2 (PTE): Indexed by bits 21-29 (block pages at this level)
 * L3 (PAGE): Indexed by bits 12-20 (leaf page entries)
 */

int pmap_probe_pte(fut_vmem_context_t *ctx, uint64_t vaddr, uint64_t *pte_out) {
    if (!pte_out) {
        return -EINVAL;
    }

    /* Get the PGD (Level 0 page table) from context */
    page_table_t *pgd = pmap_context_pgd(ctx);
    if (!pgd) {
        return -EFAULT;
    }

    /* Compute indices for each level of the page table hierarchy */
    uint64_t pgd_idx = PGD_INDEX(vaddr);
    uint64_t pmd_idx = PMD_INDEX(vaddr);
    uint64_t pte_idx = PTE_INDEX(vaddr);
    uint64_t page_idx = PAGE_INDEX(vaddr);

    /* Level 0: PGD walk */
    pte_t pgde = pgd->entries[pgd_idx];
    if (!fut_pte_is_present(pgde)) {
        return -EFAULT;
    }

    /* Level 1: PMD walk */
    page_table_t *pmd = pmap_table_from_phys(fut_pte_to_phys(pgde));
    pte_t pmde = pmd->entries[pmd_idx];
    if (!fut_pte_is_present(pmde)) {
        return -EFAULT;
    }

    /* Level 2: PTE walk */
    page_table_t *pte = pmap_table_from_phys(fut_pte_to_phys(pmde));
    pte_t pte_entry = pte->entries[pte_idx];
    if (!fut_pte_is_present(pte_entry)) {
        return -EFAULT;
    }

    /* Check if this is a block descriptor (2MB page at L2) */
    if (fut_pte_is_block(pte_entry)) {
        *pte_out = pte_entry;
        return 0;
    }

    /* Level 3: PAGE walk (final level) */
    page_table_t *page_tbl = pmap_table_from_phys(fut_pte_to_phys(pte_entry));
    pte_t page_entry = page_tbl->entries[page_idx];
    if (!fut_pte_is_present(page_entry)) {
        return -EFAULT;
    }

    *pte_out = page_entry;
    return 0;
}

/* ============================================================
 *   User Space Mapping
 * ============================================================ */

int pmap_map_user(fut_vmem_context_t *ctx, uint64_t uaddr, phys_addr_t paddr,
                  size_t len, uint64_t prot) {
    if (!ctx) {
        return -EINVAL;
    }
    return fut_map_range(ctx, uaddr, paddr, len, prot);
}

/* ============================================================
 *   Copy-on-Write Support
 * ============================================================ */

/**
 * Mark a page as read-only (for copy-on-write).
 * Clears the writable AP bits from the page table entry.
 */
int pmap_set_page_ro(fut_vmem_context_t *ctx, uint64_t vaddr) {
    if (!ctx) {
        return -EINVAL;
    }

    page_table_t *pgd = pmap_context_pgd(ctx);
    if (!pgd) {
        return -EINVAL;
    }

    /* Compute indices */
    uint64_t pgd_idx = PGD_INDEX(vaddr);
    uint64_t pmd_idx = PMD_INDEX(vaddr);
    uint64_t pte_idx = PTE_INDEX(vaddr);
    uint64_t page_idx = PAGE_INDEX(vaddr);

    /* Level 0: PGD walk */
    pte_t pgde = pgd->entries[pgd_idx];
    if (!fut_pte_is_present(pgde)) {
        return -EFAULT;
    }

    /* Level 1: PMD walk */
    page_table_t *pmd = pmap_table_from_phys(fut_pte_to_phys(pgde));
    pte_t pmde = pmd->entries[pmd_idx];
    if (!fut_pte_is_present(pmde)) {
        return -EFAULT;
    }

    /* Level 2: PTE walk */
    page_table_t *pte = pmap_table_from_phys(fut_pte_to_phys(pmde));
    pte_t pte_entry = pte->entries[pte_idx];
    if (!fut_pte_is_present(pte_entry)) {
        return -EFAULT;
    }

    /* Check if this is a block descriptor (2MB page at L2) */
    if (fut_pte_is_block(pte_entry)) {
        /* Block page (2MB) - clear AP bits to make read-only
         * Change AP from RW to RO by setting AP[1] = 1 (and keeping AP[0] as-is) */
        uint64_t ap = (pte_entry & PTE_AP_MASK) >> PTE_AP_SHIFT;
        if (ap == 0 || ap == 1) {  /* Currently writable */
            /* Set to read-only: change AP[1:0] from 0x to 2x */
            pte->entries[pte_idx] = (pte_entry & ~PTE_AP_MASK) | (((ap | 2) & 3) << PTE_AP_SHIFT);
        }
        return 0;
    }

    /* Level 3: PAGE walk (final level) */
    page_table_t *page_tbl = pmap_table_from_phys(fut_pte_to_phys(pte_entry));
    pte_t page_entry = page_tbl->entries[page_idx];
    if (!fut_pte_is_present(page_entry)) {
        return -EFAULT;
    }

    /* Clear writable bit on 4KB page - change AP bits to read-only */
    uint64_t ap = (page_entry & PTE_AP_MASK) >> PTE_AP_SHIFT;
    if (ap == 0 || ap == 1) {  /* Currently writable */
        /* Set to read-only: change AP[1:0] from 0x to 2x */
        page_tbl->entries[page_idx] = (page_entry & ~PTE_AP_MASK) | (((ap | 2) & 3) << PTE_AP_SHIFT);
    }

    /* Flush TLB entry for this page */
    fut_flush_tlb_single(vaddr);

    return 0;
}
