/* pmap.c - ARM64 Physical Memory Mapping
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * ARM64 physical memory mapping and page table walking implementation.
 */

#include <platform/arm64/memory/pmap.h>
#include <kernel/errno.h>
#include <kernel/fut_memory.h>

extern void fut_printf(const char *fmt, ...);

/* Get the PGD from context, using kernel PGD if context is NULL or invalid */
static inline page_table_t *pmap_context_pgd(fut_vmem_context_t *ctx) {
    if (!ctx || !ctx->pgd) {
        return fut_get_kernel_pgd();
    }

    /* ARM64: Identity mapping - pgd pointer is already a virtual address */
    return (page_table_t *)ctx->pgd;
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
    extern void fut_printf(const char *, ...);
    if (!pte_out) {
        return -EINVAL;
    }

    /* Get the PGD (Level 0 page table) from context */
    page_table_t *pgd = pmap_context_pgd(ctx);
    if (!pgd) {
        fut_printf("[PROBE] No PGD\n");
        return -EFAULT;
    }

    /* Compute indices for each level of the page table hierarchy */
    uint64_t pgd_idx = PGD_INDEX(vaddr);
    uint64_t pmd_idx = PMD_INDEX(vaddr);
    uint64_t pte_idx = PTE_INDEX(vaddr);
    uint64_t page_idx = PAGE_INDEX(vaddr);

    /* fut_printf("[PROBE] vaddr=0x%llx pgd=0x%llx idx[%llu,%llu,%llu,%llu]\n",
               (unsigned long long)vaddr, (unsigned long long)(uintptr_t)pgd, pgd_idx, pmd_idx, pte_idx, page_idx); */

    /* Level 0: PGD walk */
    pte_t pgde = pgd->entries[pgd_idx];
    if (!fut_pte_is_present(pgde)) {
        fut_printf("[PROBE] PGD[%llu] not present\n", pgd_idx);
        return -EFAULT;
    }

    /* Level 1: PMD walk */
    uint64_t pmd_phys = fut_pte_to_phys(pgde);
    page_table_t *pmd = pmap_table_from_phys(pmd_phys);
    /* fut_printf("[PROBE] PMD: entry=0x%llx phys=0x%llx ptr=0x%llx\n",
               (unsigned long long)pgde, (unsigned long long)pmd_phys, (unsigned long long)(uintptr_t)pmd); */
    pte_t pmde = pmd->entries[pmd_idx];
    if (!fut_pte_is_present(pmde)) {
        fut_printf("[PROBE] PMD[%llu] not present\n", pmd_idx);
        return -EFAULT;
    }

    /* Level 2: PTE walk */
    uint64_t pte_phys = fut_pte_to_phys(pmde);
    page_table_t *pte = pmap_table_from_phys(pte_phys);
    /* fut_printf("[PROBE] PTE: entry=0x%llx phys=0x%llx ptr=0x%llx\n",
               (unsigned long long)pmde, (unsigned long long)pte_phys, (unsigned long long)(uintptr_t)pte); */
    pte_t pte_entry = pte->entries[pte_idx];
    if (!fut_pte_is_present(pte_entry)) {
        fut_printf("[PROBE] PTE[%llu] not present\n", pte_idx);
        return -EFAULT;
    }

    /* Check if this is a block descriptor (2MB page at L2) */
    if (fut_pte_is_block(pte_entry)) {
        *pte_out = pte_entry;
        return 0;
    }

    /* Level 3: PAGE walk (final level) */
    uint64_t pt_phys = fut_pte_to_phys(pte_entry);
    page_table_t *page_tbl = pmap_table_from_phys(pt_phys);
    /* fut_printf("[PROBE] PT: entry=0x%llx phys=0x%llx ptr=0x%llx\n",
               (unsigned long long)pte_entry, (unsigned long long)pt_phys, (unsigned long long)(uintptr_t)page_tbl); */
    pte_t page_entry = page_tbl->entries[page_idx];
    if (!fut_pte_is_present(page_entry)) {
        fut_printf("[PROBE] PT[%llu] not present\n", page_idx);
        return -EFAULT;
    }

    /* fut_printf("[PROBE] Success: final_pte=0x%llx\n", (unsigned long long)page_entry); */
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
 *   Page Table Destruction (Recursive)
 * ============================================================
 *
 * Recursively walks page table hierarchy and frees all allocated tables.
 * Stops at user space boundary and doesn't free kernel page tables.
 */

/**
 * Recursively free page tables starting from a given level.
 * @param table Current level page table
 * @param level Current level (0=PGD, 1=PMD, 2=PTE, 3=PAGE)
 */
static void pmap_free_table_recursive(page_table_t *table, int level) {
    if (!table || level >= 3) {
        return;  /* Can't recurse beyond level 3 (leaf pages) */
    }

    /* Walk all entries in this table */
    for (int i = 0; i < 512; i++) {
        pte_t entry = table->entries[i];

        /* Skip invalid entries */
        if (!fut_pte_is_present(entry)) {
            continue;
        }

        /* At level 2 (PTE), check if it's a block descriptor (2MB page) */
        if (level == 2 && fut_pte_is_block(entry)) {
            /* Block pages don't have sub-tables, just mark for unmapping */
            continue;
        }

        /* For non-block entries, get the next-level table and recurse */
        if (!fut_pte_is_block(entry) || level < 2) {
            phys_addr_t phys = fut_pte_to_phys(entry);
            page_table_t *next_table = pmap_table_from_phys(phys);
            pmap_free_table_recursive(next_table, level + 1);
        }
    }

    /* Free this table itself (ARM64: all tables in user context should be freed) */
    fut_pmm_free_page((void *)table);
}

/**
 * Recursively free all page tables in a user address space.
 * Called when destroying a process's virtual memory context.
 * Does not free kernel page tables.
 */
void pmap_free_tables(fut_vmem_context_t *ctx) {
    if (!ctx) {
        return;
    }

    page_table_t *pgd = pmap_context_pgd(ctx);
    if (!pgd) {
        return;
    }

    /* Start recursive freeing from PGD (level 0) */
    pmap_free_table_recursive(pgd, 0);

    /* Clear the context */
    fut_vmem_set_root(ctx, NULL);
    fut_vmem_set_reload_value(ctx, 0);
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
