/* arm64_paging.c - ARM64 Virtual Memory Management Implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * ARM64 (AArch64) page table setup, memory mapping, and TLB management.
 */

#include <platform/arm64/memory/paging.h>
#include <platform/arm64/memory/pmap.h>
#include <platform/arm64/regs.h>
#include <kernel/fut_mm.h>
#include <kernel/fut_memory.h>
#include <kernel/errno.h>
#include <string.h>
#include <stdatomic.h>

/* ============================================================
 *   Debug Output Control
 * ============================================================ */

/* Uncomment to enable verbose ARM64 paging debug output */
#define DEBUG_ARM64_PAGING

#ifdef DEBUG_ARM64_PAGING
#define PAGING_DEBUG(...) fut_printf(__VA_ARGS__)
#else
#define PAGING_DEBUG(...) do {} while(0)
#endif

/* ============================================================
 *   Kernel Page Table (Static)
 * ============================================================ */

static page_table_t kernel_pgd __attribute__((aligned(PAGE_SIZE)));
static fut_vmem_context_t kernel_vmem_context;
static _Atomic(fut_vmem_context_t*) current_vmem_context = NULL;

/* ============================================================
 *   ARM64 Control Register Helpers
 * ============================================================ */

/**
 * Read TTBR0_EL1 (User space page table)
 */
static inline uint64_t read_ttbr0_el1(void) {
    uint64_t ttbr0;
    __asm__ volatile("mrs %0, ttbr0_el1" : "=r"(ttbr0));
    return ttbr0;
}

/**
 * Write TTBR0_EL1 (User space page table)
 */
static inline void write_ttbr0_el1(uint64_t ttbr0) {
    __asm__ volatile("msr ttbr0_el1, %0" :: "r"(ttbr0));
    __asm__ volatile("isb" ::: "memory");
}

/**
 * Read TTBR1_EL1 (Kernel space page table)
 */
static inline uint64_t read_ttbr1_el1(void) {
    uint64_t ttbr1;
    __asm__ volatile("mrs %0, ttbr1_el1" : "=r"(ttbr1));
    return ttbr1;
}

/**
 * Write TTBR1_EL1 (Kernel space page table)
 */
static inline void write_ttbr1_el1(uint64_t ttbr1) {
    __asm__ volatile("msr ttbr1_el1, %0" :: "r"(ttbr1));
    __asm__ volatile("isb" ::: "memory");
}

/**
 * Read TCR_EL1 (Translation Control Register)
 */
static inline uint64_t read_tcr_el1(void) {
    uint64_t tcr;
    __asm__ volatile("mrs %0, tcr_el1" : "=r"(tcr));
    return tcr;
}

/**
 * Write TCR_EL1 (Translation Control Register)
 */
static inline void write_tcr_el1(uint64_t tcr) {
    __asm__ volatile("msr tcr_el1, %0" :: "r"(tcr));
    __asm__ volatile("isb" ::: "memory");
}

/**
 * Read MAIR_EL1 (Memory Attribute Indirection Register)
 */
static inline uint64_t read_mair_el1(void) {
    uint64_t mair;
    __asm__ volatile("mrs %0, mair_el1" : "=r"(mair));
    return mair;
}

/**
 * Write MAIR_EL1 (Memory Attribute Indirection Register)
 */
static inline void write_mair_el1(uint64_t mair) {
    __asm__ volatile("msr mair_el1, %0" :: "r"(mair));
    __asm__ volatile("isb" ::: "memory");
}

/**
 * Read SCTLR_EL1 (System Control Register)
 */
static inline uint64_t read_sctlr_el1(void) {
    uint64_t sctlr;
    __asm__ volatile("mrs %0, sctlr_el1" : "=r"(sctlr));
    return sctlr;
}

/**
 * Write SCTLR_EL1 (System Control Register)
 */
static inline void write_sctlr_el1(uint64_t sctlr) {
    __asm__ volatile("msr sctlr_el1, %0" :: "r"(sctlr));
    __asm__ volatile("isb" ::: "memory");
}

/* ============================================================
 *   Page Table Allocation
 * ============================================================ */

/**
 * Allocate a single page table.
 * @return Physical address of allocated page table, or NULL on failure
 */
static page_table_t *alloc_page_table(void) {
    /* Allocate page table from physical memory manager */
    page_table_t *pt = (page_table_t *)fut_pmm_alloc_page();
    if (!pt) {
        return NULL;
    }
    memset(pt, 0, PAGE_SIZE);
    return pt;
}

/**
 * Free a page table.
 * @param pt Page table to free
 */
static void free_page_table(page_table_t *pt) {
    /* Return page table to physical memory manager */
    fut_pmm_free_page(pt);
}

/* ============================================================
 *   Page Table Walking
 * ============================================================ */

/**
 * Get or create page table at a specific level.
 * @param parent_table Parent page table
 * @param index Index in parent table
 * @param allocate Whether to allocate if missing
 * @return Page table at child level, or NULL
 */
static page_table_t *get_or_create_table(page_table_t *parent_table, int index, bool allocate) {
    extern void fut_printf(const char *, ...);

    /* Temporarily switch to kernel page table for page table operations
     * to ensure we can access all physical memory. Save/restore user TTBR0.
     */
    extern page_table_t boot_l1_table;
    uint64_t user_ttbr0;
    __asm__ volatile("mrs %0, ttbr0_el1" : "=r"(user_ttbr0));
    __asm__ volatile("msr ttbr0_el1, %0; isb" :: "r"(pmap_virt_to_phys(&boot_l1_table)));

    pte_t entry = parent_table->entries[index];

    if (!fut_pte_is_present(entry)) {
        if (!allocate) {
            /* Restore user page table before returning */
            __asm__ volatile("msr ttbr0_el1, %0; isb" :: "r"(user_ttbr0));
            return NULL;
        }

        page_table_t *new_table = alloc_page_table();
        if (!new_table) {
            /* Restore user page table before returning */
            __asm__ volatile("msr ttbr0_el1, %0; isb" :: "r"(user_ttbr0));
            return NULL;
        }

        /* Create table descriptor pointing to new table
         * CRITICAL: PTEs must contain physical addresses, not virtual */
        uint64_t phys_addr = pmap_virt_to_phys(new_table);
        pte_t table_desc = fut_make_pte(phys_addr, PTE_VALID | PTE_TABLE);
        parent_table->entries[index] = table_desc;

        /* Clean the table descriptor to PoC so MMU walker can see it */
        __asm__ volatile("dc cvac, %0" :: "r"(&parent_table->entries[index]) : "memory");
        __asm__ volatile("dsb ish" ::: "memory");

        PAGING_DEBUG("[PT] Created table: parent=%p idx=%d new=%p desc=0x%llx\n",
                   parent_table, index, new_table, (unsigned long long)table_desc);

        /* Restore user page table before returning */
        __asm__ volatile("msr ttbr0_el1, %0; isb" :: "r"(user_ttbr0));
        return new_table;
    }

    if (fut_pte_is_table(entry)) {
        /* Extract physical address and convert to virtual */
        uint64_t phys = fut_pte_to_phys(entry);
        PAGING_DEBUG("[PT] Reusing table: idx=%d entry=0x%llx phys=0x%llx\n",
                   index, (unsigned long long)entry, (unsigned long long)phys);

        page_table_t *result = (page_table_t *)pmap_phys_to_virt(phys);

        /* Restore user page table before returning */
        __asm__ volatile("msr ttbr0_el1, %0; isb" :: "r"(user_ttbr0));
        return result;
    }

    /* Block descriptor found - split it into L3 page table for finer-grained mapping.
     * This is needed when user processes need 4KB pages with different permissions
     * (e.g., user-accessible thread stacks) within a 2MB kernel-only DRAM block. */
    if (fut_pte_is_block(entry)) {
        if (!allocate) {
            /* Restore user page table before returning */
            __asm__ volatile("msr ttbr0_el1, %0; isb" :: "r"(user_ttbr0));
            return NULL;  /* Can't split without allocation */
        }

        /* Allocate new L3 page table */
        page_table_t *new_l3_table = alloc_page_table();
        if (!new_l3_table) {
            /* Restore user page table before returning */
            __asm__ volatile("msr ttbr0_el1, %0; isb" :: "r"(user_ttbr0));
            return NULL;
        }

        /* Extract block's base physical address (2MB-aligned) */
        uint64_t block_base_phys = fut_pte_to_phys(entry) & ~(0x1FFFFFULL);  /* Mask to 2MB boundary */

        /* Extract attribute bits from original block descriptor.
         * Preserve: AP bits, memory attributes, shareability, access flag, etc.
         * Clear: physical address and descriptor type bits. */
        uint64_t block_attrs = entry & 0xFFF0000000000FFCULL;

        /* Fill L3 table with 512 x 4KB page descriptors covering the 2MB block */
        for (int i = 0; i < 512; i++) {
            uint64_t page_phys = block_base_phys + (i * 0x1000);  /* 4KB pages */
            /* L3 descriptors need PTE_VALID | PTE_TABLE (bits[1:0]=0b11) for page descriptor */
            pte_t page_desc = fut_make_pte(page_phys, block_attrs | PTE_VALID | PTE_TABLE);
            new_l3_table->entries[i] = page_desc;
        }

        /* Replace L2 block descriptor with table descriptor pointing to new L3 table */
        uint64_t l3_table_phys = pmap_virt_to_phys(new_l3_table);
        pte_t table_desc = fut_make_pte(l3_table_phys, PTE_VALID | PTE_TABLE);
        parent_table->entries[index] = table_desc;

        /* Clean entries to Point of Coherency so MMU can see them */
        __asm__ volatile("dc cvac, %0" :: "r"(&parent_table->entries[index]) : "memory");
        __asm__ volatile("dsb ish" ::: "memory");

        /* Flush entire TLB to ensure block mapping is replaced by page mappings */
        extern void fut_flush_tlb_all(void);
        fut_flush_tlb_all();

        /* Restore user page table before returning */
        __asm__ volatile("msr ttbr0_el1, %0; isb" :: "r"(user_ttbr0));
        return new_l3_table;
    }

    PAGING_DEBUG("[PT] ERROR: Unknown entry type at idx=%d entry=0x%llx\n",
               index, (unsigned long long)entry);
    /* Restore user page table before returning */
    __asm__ volatile("msr ttbr0_el1, %0; isb" :: "r"(user_ttbr0));
    return NULL;
}

/* ============================================================
 *   Flag Translation for Architecture-Generic Code
 * ============================================================
 *
 * Translates generic x86_64-style PTE flags (used by architecture-generic
 * demand paging code) to ARM64-specific AP bit flags.
 */

/**
 * Translate generic PTE flags (x86_64-style) or PROT flags to ARM64 PTE flags.
 * Used by architecture-generic code (demand paging, COW) and ELF loader.
 * @param generic_flags Flags using either PTE_* or PROT_* constants
 * @return ARM64 PTE flags with proper AP bits and attributes
 */
static uint64_t arm64_translate_flags(uint64_t generic_flags) {
    extern void fut_printf(const char *, ...);

    uint64_t arm64_flags = 0;
    bool is_user = true;  /* Default to user pages */
    bool is_writable = false;
    bool is_executable = true;  /* Default to executable */

    /* Detect if these are PROT_* flags (low bits only) or PTE_* flags (may have high bits) */
    /* PROT_* values: PROT_READ=1, PROT_WRITE=2, PROT_EXEC=4 (all < 8) */
    /* PTE_* values include PTE_NX at bit 63, PTE_USER at higher bits */
    if ((generic_flags & ~0x7ULL) == 0) {
        /* These look like PROT_* flags */
        is_writable = (generic_flags & 0x2) != 0;  /* PROT_WRITE */
        is_executable = (generic_flags & 0x4) != 0;  /* PROT_EXEC */
        /* PROT_* flags always mean user pages for ELF loading */
        arm64_flags |= PTE_VALID;
        PAGING_DEBUG("[TRANSLATE-FLAGS] PROT_* input: 0x%llx -> is_user=%d is_writable=%d is_exec=%d\n",
                   (unsigned long long)generic_flags, is_user, is_writable, is_executable);
    } else {
        /* These are PTE_* flags */
        if (generic_flags & PTE_PRESENT) {
            arm64_flags |= PTE_VALID;
        }
        is_user = (generic_flags & PTE_USER) != 0;
        is_writable = (generic_flags & PTE_WRITABLE) != 0;
        is_executable = (generic_flags & PTE_NX) == 0;  /* NX=0 means executable */
        PAGING_DEBUG("[TRANSLATE-FLAGS] PTE_* input: 0x%llx -> is_user=%d is_writable=%d is_exec=%d\n",
                   (unsigned long long)generic_flags, is_user, is_writable, is_executable);
    }

    /* Determine AP bits based on user/writable flags */
    if (is_user) {
        /* User-accessible page */
        if (is_writable) {
            arm64_flags |= PTE_AP_RW_ALL;      /* User read/write */
            PAGING_DEBUG("[TRANSLATE-FLAGS] Setting PTE_AP_RW_ALL (0x%llx)\n",
                       (unsigned long long)PTE_AP_RW_ALL);
        } else {
            arm64_flags |= PTE_AP_RO_ALL;      /* User read-only */
            PAGING_DEBUG("[TRANSLATE-FLAGS] Setting PTE_AP_RO_ALL (0x%llx)\n",
                       (unsigned long long)PTE_AP_RO_ALL);
        }
    } else {
        /* Kernel-only page */
        if (is_writable) {
            arm64_flags |= PTE_AP_RW_EL1;      /* Kernel read/write only */
            PAGING_DEBUG("[TRANSLATE-FLAGS] Setting PTE_AP_RW_EL1 (0x%llx)\n",
                       (unsigned long long)PTE_AP_RW_EL1);
        } else {
            arm64_flags |= PTE_AP_RO_EL1;      /* Kernel read-only */
            PAGING_DEBUG("[TRANSLATE-FLAGS] Setting PTE_AP_RO_EL1 (0x%llx)\n",
                       (unsigned long long)PTE_AP_RO_EL1);
        }
    }

    /* Set memory attributes (normal, cacheable) */
    arm64_flags |= PTE_ATTR_NORMAL;

    /* Set sharability */
    arm64_flags |= PTE_SH_INNER;

    /* Set access flag (required for page to be mappable) */
    arm64_flags |= PTE_AF_BIT;

    /* Handle execute permission - set UXN if not executable */
    if (!is_executable) {
        arm64_flags |= PTE_UXN_BIT;
    }

    /* For user pages, always set PXN (prevent kernel execution in user pages) */
    if (is_user) {
        arm64_flags |= PTE_PXN_BIT;
    }

    PAGING_DEBUG("[TRANSLATE-FLAGS] Final ARM64 flags: 0x%llx (AP bits [7:6]=0x%llx)\n",
               (unsigned long long)arm64_flags,
               (unsigned long long)((arm64_flags >> 6) & 0x3));

    return arm64_flags;
}

/* ============================================================
 *   Page Table Operations
 * ============================================================ */

/**
 * Map a single page in a virtual memory context.
 * @param ctx Virtual memory context (NULL for kernel)
 * @param vaddr Virtual address (must be page-aligned)
 * @param paddr Physical address (must be page-aligned)
 * @param flags Page table entry flags
 * @return 0 on success, negative on error
 */
int fut_map_page(fut_vmem_context_t *ctx, uint64_t vaddr, uint64_t paddr, uint64_t flags) {
    if (!IS_PAGE_ALIGNED(vaddr) || !IS_PAGE_ALIGNED(paddr)) {
        return -EINVAL;  /* Invalid alignment */
    }

    if (!fut_is_canonical(vaddr)) {
        return -EFAULT;  /* Invalid address */
    }

    if (!ctx) {
        ctx = &kernel_vmem_context;
    }

    page_table_t *pgd = ctx->pgd;
    if (!pgd) {
        return -EINVAL;  /* No page table */
    }

    /* Translate generic flags to ARM64 flags if needed */
    uint64_t arm64_flags = arm64_translate_flags(flags);

    /* Walk page table hierarchy and create intermediate tables as needed
     * ARM64 with 39-bit VA (T0SZ=25) uses 3-level page tables:
     * L1 (PGD): bits [38:30] -> L2 table
     * L2 (PMD): bits [29:21] -> L3 table
     * L3 (PTE): bits [20:12] -> physical page
     */
    int pgd_idx = PGD_INDEX(vaddr);
    PAGING_DEBUG("[MAP-PAGE] VA=0x%llx: PGD[%d] lookup at %p\n",
               (unsigned long long)vaddr, pgd_idx, pgd);

    page_table_t *pmd = get_or_create_table(pgd, pgd_idx, true);
    if (!pmd) {
        return -ENOMEM;  /* Failed to allocate L2 (PMD) */
    }
    PAGING_DEBUG("[MAP-PAGE] Got PMD table at %p\n", pmd);

    int pmd_idx = PMD_INDEX(vaddr);
    PAGING_DEBUG("[MAP-PAGE] PMD[%d] lookup\n", pmd_idx);

    page_table_t *pte_table = get_or_create_table(pmd, pmd_idx, true);
    if (!pte_table) {
        return -ENOMEM;  /* Failed to allocate L3 (PTE table) */
    }
    PAGING_DEBUG("[MAP-PAGE] Got PTE table at %p\n", pte_table);

    /* L3 is the final level - write page descriptor here */
    int pte_idx = PTE_INDEX(vaddr);
    PAGING_DEBUG("[MAP-PAGE] PTE[%d] will be written\n", pte_idx);
    /* For level 3 page descriptors, bits [1:0] must be 0b11 (PTE_TYPE_PAGE)
     * This means we need PTE_VALID (bit 0) | PTE_TABLE (bit 1) = 0b11 */
    pte_t pte = fut_make_pte(paddr, arm64_flags | PTE_TABLE);

    extern void fut_printf(const char *, ...);
    PAGING_DEBUG("[MAP-PAGE] VA=0x%llx PA=0x%llx flags_in=0x%llx arm64_flags=0x%llx PTE=0x%llx (AP[7:6]=0x%llx)\n",
               (unsigned long long)vaddr, (unsigned long long)paddr,
               (unsigned long long)flags, (unsigned long long)arm64_flags,
               (unsigned long long)pte, (unsigned long long)((pte >> 6) & 0x3));

    pte_table->entries[pte_idx] = pte;

    /* Clean the PTE to Point of Coherency so MMU page table walker can see it */
    __asm__ volatile("dc cvac, %0" :: "r"(&pte_table->entries[pte_idx]) : "memory");
    __asm__ volatile("dsb ish" ::: "memory");

    /* Read back to verify write */
    pte_t readback = pte_table->entries[pte_idx];
    if (readback != pte) {
        PAGING_DEBUG("[MAP-PAGE] ERROR: PTE readback mismatch! wrote=0x%llx read=0x%llx\n",
                   (unsigned long long)pte, (unsigned long long)readback);
    } else {
        PAGING_DEBUG("[MAP-PAGE] ✓ PTE verified: table=%p idx=%d\n", pte_table, pte_idx);
    }

    /* Invalidate TLB entry for this address */
    fut_flush_tlb_single(vaddr);

    return 0;
}

/**
 * Map a contiguous region of physical memory.
 * @param ctx Virtual memory context (NULL for kernel)
 * @param vaddr Virtual base address
 * @param paddr Physical base address
 * @param size Size in bytes (will be rounded up to page size)
 * @param flags Page flags
 * @return 0 on success, negative on error
 */
int fut_map_range(fut_vmem_context_t *ctx, uint64_t vaddr, uint64_t paddr,
                  uint64_t size, uint64_t flags) {
    uint64_t aligned_size = PAGE_ALIGN_UP(size);
    uint64_t pages = aligned_size / PAGE_SIZE;

    for (uint64_t i = 0; i < pages; i++) {
        uint64_t va = vaddr + (i * PAGE_SIZE);
        uint64_t pa = paddr + (i * PAGE_SIZE);
        int ret = fut_map_page(ctx, va, pa, flags);
        if (ret < 0) {
            return ret;
        }
    }

    return 0;
}

/**
 * Unmap a single page.
 * @param ctx Virtual memory context (NULL for kernel)
 * @param vaddr Virtual address to unmap
 * @return 0 on success, negative on error
 */
int fut_unmap_page(fut_vmem_context_t *ctx, uint64_t vaddr) {
    if (!IS_PAGE_ALIGNED(vaddr)) {
        return -EINVAL;  /* Invalid alignment */
    }

    if (!ctx) {
        ctx = &kernel_vmem_context;
    }

    page_table_t *pgd = ctx->pgd;
    if (!pgd) {
        return -EINVAL;  /* No page table */
    }

    /* Walk to page table entry */
    int pgd_idx = PGD_INDEX(vaddr);
    pte_t pgd_entry = pgd->entries[pgd_idx];
    if (!fut_pte_is_present(pgd_entry)) {
        return -ENOENT;  /* Already unmapped - PGD not present */
    }

    page_table_t *pmd = (page_table_t *)fut_pte_to_phys(pgd_entry);
    int pmd_idx = PMD_INDEX(vaddr);
    pte_t pmd_entry = pmd->entries[pmd_idx];
    if (!fut_pte_is_present(pmd_entry)) {
        return -ENOENT;  /* Already unmapped - PMD not present */
    }

    page_table_t *pte_table = (page_table_t *)fut_pte_to_phys(pmd_entry);
    int pte_idx = PTE_INDEX(vaddr);
    pte_t pte_entry = pte_table->entries[pte_idx];
    if (!fut_pte_is_present(pte_entry)) {
        return -ENOENT;  /* Already unmapped - PTE not present */
    }

    page_table_t *page_table = (page_table_t *)fut_pte_to_phys(pte_entry);
    int page_idx = PAGE_INDEX(vaddr);

    /* Clear the entry */
    page_table->entries[page_idx] = 0;

    /* Invalidate TLB */
    fut_flush_tlb_single(vaddr);

    return 0;
}

/**
 * Unmap a contiguous region.
 * @param ctx Virtual memory context (NULL for kernel)
 * @param vaddr Virtual base address
 * @param size Size in bytes
 * @return 0 on success, negative on error
 */
int fut_unmap_range(fut_vmem_context_t *ctx, uint64_t vaddr, uint64_t size) {
    uint64_t aligned_size = PAGE_ALIGN_UP(size);
    uint64_t pages = aligned_size / PAGE_SIZE;

    for (uint64_t i = 0; i < pages; i++) {
        uint64_t va = vaddr + (i * PAGE_SIZE);
        int ret = fut_unmap_page(ctx, va);
        if (ret < 0) {
            return ret;
        }
    }

    return 0;
}

/**
 * Translate virtual address to physical address.
 * @param ctx Virtual memory context (NULL for current)
 * @param vaddr Virtual address
 * @param paddr Pointer to store physical address
 * @return 0 on success, negative if not mapped
 */
int fut_virt_to_phys(fut_vmem_context_t *ctx, uint64_t vaddr, uint64_t *paddr) {
    if (!ctx) {
        ctx = &kernel_vmem_context;
    }

    page_table_t *pgd = ctx->pgd;
    if (!pgd) {
        return -EINVAL;  /* No page table */
    }

    /* Walk page tables */
    int pgd_idx = PGD_INDEX(vaddr);
    pte_t pgd_entry = pgd->entries[pgd_idx];
    if (!fut_pte_is_present(pgd_entry)) {
        return -EFAULT;  /* PGD entry not present */
    }

    page_table_t *pmd = (page_table_t *)fut_pte_to_phys(pgd_entry);
    int pmd_idx = PMD_INDEX(vaddr);
    pte_t pmd_entry = pmd->entries[pmd_idx];
    if (!fut_pte_is_present(pmd_entry)) {
        return -EFAULT;  /* PMD entry not present */
    }

    page_table_t *pte_table = (page_table_t *)fut_pte_to_phys(pmd_entry);
    int pte_idx = PTE_INDEX(vaddr);
    pte_t pte_entry = pte_table->entries[pte_idx];
    if (!fut_pte_is_present(pte_entry)) {
        return -EFAULT;  /* PTE entry not present */
    }

    page_table_t *page_table = (page_table_t *)fut_pte_to_phys(pte_entry);
    int page_idx = PAGE_INDEX(vaddr);
    pte_t page_entry = page_table->entries[page_idx];
    if (!fut_pte_is_present(page_entry)) {
        return -EFAULT;  /* Page entry not present */
    }

    /* Extract physical address */
    uint64_t phys = fut_pte_to_phys(page_entry);
    uint64_t offset = PAGE_OFFSET(vaddr);
    *paddr = phys + offset;

    return 0;
}

/**
 * Update page flags without changing physical mapping.
 * @param ctx Virtual memory context (NULL for kernel)
 * @param vaddr Virtual address
 * @param flags New page flags
 * @return 0 on success, negative on error
 */
int fut_update_page_flags(fut_vmem_context_t *ctx, uint64_t vaddr, uint64_t flags) {
    uint64_t paddr;
    int ret = fut_virt_to_phys(ctx, vaddr, &paddr);
    if (ret < 0) {
        return ret;
    }

    /* Unmap and remap with new flags */
    ret = fut_unmap_page(ctx, vaddr);
    if (ret < 0) {
        return ret;
    }

    return fut_map_page(ctx, vaddr, PAGE_ALIGN_DOWN(paddr), flags);
}

/**
 * Identity map physical memory region (vaddr = paddr).
 * @param ctx Virtual memory context (NULL for kernel)
 * @param paddr Physical address (also used as virtual address)
 * @param size Size in bytes
 * @param flags Page flags
 * @return 0 on success, negative on error
 */
int fut_identity_map(fut_vmem_context_t *ctx, uint64_t paddr, uint64_t size, uint64_t flags) {
    return fut_map_range(ctx, paddr, paddr, size, flags);
}

/* ============================================================
 *   Virtual Memory Context Management
 * ============================================================ */

/**
 * Create new virtual memory context.
 * @return New VM context with identity-mapped address space, or NULL on failure
 */
fut_vmem_context_t *fut_vmem_create(void) {
    extern page_table_t boot_l1_table;  /* Boot page table with identity mappings */

    fut_vmem_context_t *ctx = (fut_vmem_context_t *)fut_malloc(sizeof(fut_vmem_context_t));
    if (!ctx) {
        return NULL;
    }

    ctx->pgd = alloc_page_table();
    if (!ctx->pgd) {
        fut_free(ctx);
        return NULL;
    }

    /* Copy entire page table from boot_l1_table to get identity mappings.
     * This includes:
     *   - L1[0]: Peripherals (0x00000000-0x3FFFFFFF)
     *   - L1[1]: DRAM (0x40000000-0x7FFFFFFF) - where user code lives
     *   - L1[256]: PCIe ECAM (0x4000000000+)
     *
     * TODO: Once higher-half kernel is implemented, only copy lower half (0-255)
     * and map kernel to upper half (256-511) separately.
     */
    memcpy(ctx->pgd->entries, boot_l1_table.entries, 512 * sizeof(pte_t));

    /* Debug: Verify critical entries were copied */
    extern void fut_printf(const char *, ...);
    fut_printf("[VMEM-CREATE] boot_l1_table @ %p, new pgd @ %p\n",
               (void*)&boot_l1_table, (void*)ctx->pgd);
    fut_printf("[VMEM-CREATE] boot L1[0] = 0x%llx (peripherals)\n",
               (unsigned long long)boot_l1_table.entries[0]);
    fut_printf("[VMEM-CREATE] boot L1[1] = 0x%llx (DRAM - kernel/user code)\n",
               (unsigned long long)boot_l1_table.entries[1]);
    fut_printf("[VMEM-CREATE] boot L1[256] = 0x%llx (PCIe)\n",
               (unsigned long long)boot_l1_table.entries[256]);
    fut_printf("[VMEM-CREATE] new L1[0] = 0x%llx\n",
               (unsigned long long)ctx->pgd->entries[0]);
    fut_printf("[VMEM-CREATE] new L1[1] = 0x%llx\n",
               (unsigned long long)ctx->pgd->entries[1]);
    fut_printf("[VMEM-CREATE] new L1[256] = 0x%llx\n",
               (unsigned long long)ctx->pgd->entries[256]);

    /* CRITICAL: TTBR0_EL1 must contain physical address, not virtual
     * ctx->pgd is a kernel VA (0xFFFFFF80...), convert to PA */
    ctx->ttbr0_el1 = pmap_virt_to_phys(ctx->pgd);
    ctx->ref_count = 1;

    fut_printf("[VMEM-CREATE] PGD VA=0x%llx PA=0x%llx, TTBR0=0x%llx\n",
               (unsigned long long)ctx->pgd,
               (unsigned long long)ctx->ttbr0_el1,
               (unsigned long long)ctx->ttbr0_el1);

    return ctx;
}

/**
 * Recursively free page tables starting from a given level.
 * Walks the table hierarchy and frees intermediate tables,
 * but does not free individual memory pages (they're tracked separately).
 *
 * @param table Page table to recursively free
 * @param level Current table level (0=PGD, 1=PMD, 2=PTE, 3=pages)
 */
static void free_page_tables_recursive(page_table_t *table, int level) {
    if (!table) {
        return;
    }

    /* At level 3, entries point to actual pages (not tables), so just free the table */
    if (level >= 2) {
        free_page_table(table);
        return;
    }

    /* For levels 0-2, recursively free child tables */
    for (int i = 0; i < 512; i++) {
        pte_t pte = table->entries[i];

        /* Check if entry is valid and points to a table (not a block descriptor) */
        if ((pte & PTE_VALID) && (pte & PTE_TABLE)) {
            /* Extract physical address of next level table and convert to VA */
            phys_addr_t phys = pte & PTE_PHYS_ADDR_MASK;
            page_table_t *child = (page_table_t *)pmap_phys_to_virt(phys);

            /* Recursively free child table */
            free_page_tables_recursive(child, level + 1);
        }
    }

    /* Free the current level table */
    free_page_table(table);
}

/**
 * Destroy virtual memory context and free page tables.
 * @param ctx VM context to destroy
 */
void fut_vmem_destroy(fut_vmem_context_t *ctx) {
    if (!ctx) {
        return;
    }

    /* Recursively free all page tables in user space portion */
    if (ctx->pgd) {
        free_page_tables_recursive(ctx->pgd, 0);
    }

    fut_free(ctx);
}

/**
 * Switch to virtual memory context.
 * Loads PGD into TTBR0_EL1 register.
 * @param ctx VM context to switch to
 */
void fut_vmem_switch(fut_vmem_context_t *ctx) {
    if (!ctx) {
        ctx = &kernel_vmem_context;
    }

    write_ttbr0_el1(ctx->ttbr0_el1);
    atomic_store(&current_vmem_context, ctx);
}

/**
 * Get current virtual memory context.
 * @return Current VM context
 */
fut_vmem_context_t *fut_vmem_current(void) {
    fut_vmem_context_t *ctx = atomic_load(&current_vmem_context);
    if (!ctx) {
        return &kernel_vmem_context;
    }
    return ctx;
}

/* ============================================================
 *   Kernel Space Mapping
 * ============================================================ */

/**
 * Get kernel PGD table.
 * @return Physical address of kernel PGD
 */
page_table_t *fut_get_kernel_pgd(void) {
    return &kernel_pgd;
}

/**
 * Map physical memory into kernel space.
 * Uses a simple linear kernel virtual space allocator.
 *
 * @param paddr Physical address
 * @param size Size in bytes
 * @param flags Page flags
 * @return Virtual address of mapping, or NULL on failure
 */
void *fut_kernel_map_physical(uint64_t paddr, uint64_t size, uint64_t flags) {
    /* Use identity mapping when physical address is already in kernel space */
    if (paddr >= KERNEL_VIRTUAL_BASE) {
        return (void *)paddr;
    }

    /* Map to kernel heap region */
    static uint64_t kernel_map_ptr = KERNEL_HEAP_BASE;
    uint64_t vaddr = kernel_map_ptr;
    kernel_map_ptr += PAGE_ALIGN_UP(size);

    if (kernel_map_ptr > KERNEL_STACK_BASE) {
        return NULL;  /* Out of kernel virtual space */
    }

    int ret = fut_map_range(NULL, vaddr, paddr, size, flags);
    if (ret < 0) {
        return NULL;
    }

    return (void *)vaddr;
}

/**
 * Unmap kernel virtual address.
 * @param vaddr Virtual address to unmap
 * @param size Size of region to unmap
 */
void fut_kernel_unmap(void *vaddr, uint64_t size) {
    fut_unmap_range(NULL, (uint64_t)vaddr, size);
}

/* ============================================================
 *   Paging Initialization
 * ============================================================ */

/**
 * Initialize ARM64 paging subsystem.
 * Sets up kernel page tables and enables MMU.
 */
void fut_paging_init(void) {
    /* Initialize kernel VMem context
     * CRITICAL: TTBR0_EL1 must contain physical address */
    kernel_vmem_context.pgd = &kernel_pgd;
    kernel_vmem_context.ttbr0_el1 = pmap_virt_to_phys(&kernel_pgd);
    kernel_vmem_context.ref_count = 1;

    /* Set up memory attributes */
    uint64_t mair = 0;
    mair |= (0x00 << 0);   /* Attribute 0: Device nGnRnE */
    mair |= (0x04 << 8);   /* Attribute 1: Normal, non-cacheable */
    mair |= (0xFF << 16);  /* Attribute 2: Normal, cacheable */
    mair |= (0x04 << 24);  /* Attribute 3: Device nGnRE */
    write_mair_el1(mair);

    /* Set up translation control register - MUST MATCH boot.S settings! */
    uint64_t tcr = 0;
    /* T0SZ = 25 (39-bit user VA) - matches boot.S */
    tcr |= (25 << 0);
    /* T1SZ = 25 (39-bit kernel VA) - matches boot.S */
    tcr |= (25 << 16);
    /* TG0 = 00 (4KB granule for TTBR0) - bits [15:14] remain 0 */
    /* TG1 = 10 (4KB granule for TTBR1) - bits [31:30] */
    tcr |= (2 << 30);
    /* SH0 = 3 (inner shareable) */
    tcr |= (3 << 12);
    /* SH1 = 3 (inner shareable) */
    tcr |= (3 << 28);
    /* ORGN0 = 1 (normal, write-back write-allocate) */
    tcr |= (1 << 10);
    /* ORGN1 = 1 */
    tcr |= (1 << 26);
    /* IRGN0 = 1 (normal, write-back write-allocate) */
    tcr |= (1 << 8);
    /* IRGN1 = 1 */
    tcr |= (1 << 24);

    /* Debug: Print TCR value before writing */
    extern void fut_printf(const char *, ...);
    fut_printf("[PAGING-INIT] Setting TCR_EL1 = 0x%llx, T0SZ=%llu, TG0=%llu\n",
               (unsigned long long)tcr,
               (unsigned long long)(tcr & 0x3F),
               (unsigned long long)((tcr >> 14) & 0x3));

    write_tcr_el1(tcr);

    /* Load kernel TTBR1_EL1
     * CRITICAL: TTBR1_EL1 must contain physical address */
    write_ttbr1_el1(pmap_virt_to_phys(&kernel_pgd));

    /* Enable MMU by setting SCTLR_EL1.M bit */
    uint64_t sctlr = read_sctlr_el1();
    sctlr |= SCTLR_M_BIT;      /* Enable MMU */
    sctlr |= SCTLR_C_BIT;      /* Enable data cache */
    sctlr |= SCTLR_I_BIT;      /* Enable instruction cache */
    write_sctlr_el1(sctlr);

    atomic_store(&current_vmem_context, &kernel_vmem_context);
}

/* ============================================================
 *   Debug Functions
 * ============================================================ */

/**
 * Dump page table entries for a virtual address.
 * Walks the 4-level page table hierarchy and prints entries.
 */
void fut_dump_page_tables(fut_vmem_context_t *ctx, uint64_t vaddr) {
    extern void fut_printf(const char *fmt, ...);

    if (!ctx || !ctx->pgd) {
        fut_printf("[PT-DUMP] Invalid context\n");
        return;
    }

    fut_printf("[PT-DUMP] Walking page tables for vaddr=0x%llx\n", vaddr);

    /* Level 0: PGD */
    int pgd_idx = PGD_INDEX(vaddr);
    pte_t pgd_entry = ctx->pgd->entries[pgd_idx];
    fut_printf("[PT-DUMP] PGD[%d] = 0x%llx %s\n", pgd_idx, pgd_entry,
               (pgd_entry & PTE_VALID) ? "(valid)" : "(invalid)");

    if (!(pgd_entry & PTE_VALID)) {
        return;
    }

    /* Level 1: PMD - convert PA to VA for kernel access */
    phys_addr_t pmd_phys = pgd_entry & PTE_PHYS_ADDR_MASK;
    page_table_t *pmd = (page_table_t *)pmap_phys_to_virt(pmd_phys);
    int pmd_idx = PMD_INDEX(vaddr);
    pte_t pmd_entry = pmd->entries[pmd_idx];
    fut_printf("[PT-DUMP]  PMD[%d] = 0x%llx %s\n", pmd_idx, pmd_entry,
               (pmd_entry & PTE_VALID) ? "(valid)" : "(invalid)");

    if (!(pmd_entry & PTE_VALID)) {
        return;
    }

    /* Level 2: PTE - convert PA to VA for kernel access */
    phys_addr_t pte_phys = pmd_entry & PTE_PHYS_ADDR_MASK;
    page_table_t *pte_table = (page_table_t *)pmap_phys_to_virt(pte_phys);
    int pte_idx = PTE_INDEX(vaddr);
    pte_t pte_entry = pte_table->entries[pte_idx];
    fut_printf("[PT-DUMP]   PTE[%d] = 0x%llx %s\n", pte_idx, pte_entry,
               (pte_entry & PTE_VALID) ? "(valid)" : "(invalid)");

    if (!(pte_entry & PTE_VALID)) {
        return;
    }

    /* Level 3: Page - convert PA to VA for kernel access */
    phys_addr_t page_phys = pte_entry & PTE_PHYS_ADDR_MASK;
    page_table_t *page_table = (page_table_t *)pmap_phys_to_virt(page_phys);
    int page_idx = PAGE_INDEX(vaddr);
    pte_t page_entry = page_table->entries[page_idx];
    fut_printf("[PT-DUMP]    Page[%d] = 0x%llx %s\n", page_idx, page_entry,
               (page_entry & PTE_VALID) ? "(valid)" : "(invalid)");

    if (page_entry & PTE_VALID) {
        phys_addr_t final_phys = page_entry & PTE_PHYS_ADDR_MASK;
        uint64_t page_offset = vaddr & 0xFFF;
        phys_addr_t final_addr = final_phys + page_offset;
        fut_printf("[PT-DUMP]    Physical address: 0x%llx\n", final_addr);
    }
}

/**
 * Print virtual memory context statistics.
 * Shows PGD address and reference count.
 */
void fut_vmem_print_stats(fut_vmem_context_t *ctx) {
    extern void fut_printf(const char *fmt, ...);

    if (!ctx) {
        fut_printf("[VMEM-STATS] Invalid context\n");
        return;
    }

    fut_printf("[VMEM-STATS] Context: %p\n", (void *)ctx);
    fut_printf("[VMEM-STATS]   PGD: 0x%llx\n", (uint64_t)ctx->pgd);
    fut_printf("[VMEM-STATS]   TTBR0_EL1: 0x%llx\n", ctx->ttbr0_el1);
    fut_printf("[VMEM-STATS]   Reference count: %llu\n", ctx->ref_count);
}

/**
 * Verify virtual memory context consistency.
 * Checks that PGD is valid and aligned.
 */
bool fut_vmem_verify(fut_vmem_context_t *ctx) {
    extern void fut_printf(const char *fmt, ...);

    if (!ctx) {
        fut_printf("[VMEM-VERIFY] NULL context\n");
        return false;
    }

    if (!ctx->pgd) {
        fut_printf("[VMEM-VERIFY] NULL PGD\n");
        return false;
    }

    /* Check PGD alignment */
    if (!IS_PAGE_ALIGNED((uintptr_t)ctx->pgd)) {
        fut_printf("[VMEM-VERIFY] PGD not page-aligned: 0x%llx\n",
                   (uint64_t)ctx->pgd);
        return false;
    }

    /* Check TTBR0_EL1 alignment */
    if (!IS_PAGE_ALIGNED(ctx->ttbr0_el1)) {
        fut_printf("[VMEM-VERIFY] TTBR0_EL1 not page-aligned: 0x%llx\n",
                   ctx->ttbr0_el1);
        return false;
    }

    fut_printf("[VMEM-VERIFY] Context OK: PGD=0x%llx TTBR0_EL1=0x%llx\n",
               (uint64_t)ctx->pgd, ctx->ttbr0_el1);
    return true;
}
