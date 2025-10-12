// SPDX-License-Identifier: MPL-2.0
/*
 * pmap.c - Minimal physical mapping helpers for x86_64
 *
 * Phase 0 goal: ensure that higher layers only ever store raw physical frame
 * numbers inside page tables while still providing a convenient way to touch
 * those frames from the kernel. The helpers below intentionally stay tiny;
 * later phases will grow this module once user copy and devfs plumbing land.
 */

#include <arch/x86_64/pmap.h>

#include <kernel/errno.h>
#include <kernel/fut_memory.h>

extern void fut_printf(const char *fmt, ...);

static inline pte_t *pmap_context_pml4(fut_vmem_context_t *ctx) {
    if (!ctx || !ctx->pml4) {
        return fut_get_kernel_pml4();
    }

    uintptr_t raw = (uintptr_t)ctx->pml4;
    if (raw >= PMAP_DIRECT_VIRT_BASE) {
        return (pte_t *)raw;
    }

    return (pte_t *)pmap_kmap((phys_addr_t)raw);
}

static inline page_table_t *pmap_table_from_phys(phys_addr_t phys) {
    return (page_table_t *)pmap_kmap(phys);
}

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

int pmap_probe_pte(fut_vmem_context_t *ctx, uint64_t vaddr, uint64_t *pte_out) {
    if (!pte_out) {
        return -EINVAL;
    }

    pte_t *pml4 = pmap_context_pml4(ctx);
    if (!pml4) {
        return -EFAULT;
    }

    uint64_t pml4_idx = PML4_INDEX(vaddr);
    uint64_t pdpt_idx = PDPT_INDEX(vaddr);
    uint64_t pd_idx = PD_INDEX(vaddr);
    uint64_t pt_idx = PT_INDEX(vaddr);

    pte_t pml4e = pml4[pml4_idx];
    if (!fut_pte_is_present(pml4e)) {
        return -EFAULT;
    }

    page_table_t *pdpt = pmap_table_from_phys(fut_pte_to_phys(pml4e));
    pte_t pdpte = pdpt->entries[pdpt_idx];
    if (!fut_pte_is_present(pdpte)) {
        return -EFAULT;
    }

    page_table_t *pd = pmap_table_from_phys(fut_pte_to_phys(pdpte));
    pte_t pde = pd->entries[pd_idx];
    if (!fut_pte_is_present(pde)) {
        return -EFAULT;
    }

    if (fut_pte_is_large(pde)) {
        *pte_out = pde;
        return 0;
    }

    page_table_t *pt = pmap_table_from_phys(fut_pte_to_phys(pde));
    pte_t pte = pt->entries[pt_idx];
    if (!fut_pte_is_present(pte)) {
        return -EFAULT;
    }

    *pte_out = pte;
    return 0;
}

int pmap_map_user(fut_vmem_context_t *ctx, uint64_t uaddr, phys_addr_t paddr,
                  size_t len, uint64_t prot) {
    (void)ctx;
    return pmap_map(uaddr, paddr, len, prot);
}
