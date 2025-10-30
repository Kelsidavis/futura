/* arm64_paging.c - ARM64 Virtual Memory Management Implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * ARM64 (AArch64) page table setup, memory mapping, and TLB management.
 */

#include <platform/arm64/memory/paging.h>
#include <platform/arm64/regs.h>
#include <kernel/fut_mm.h>
#include <kernel/fut_memory.h>
#include <string.h>
#include <stdatomic.h>

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
    /* For now, use simple allocator from physical memory manager */
    /* TODO: Integrate with buddy allocator or slab allocator */
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
    /* TODO: Integrate with physical memory manager */
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
    pte_t entry = parent_table->entries[index];

    if (!fut_pte_is_present(entry)) {
        if (!allocate) {
            return NULL;
        }

        page_table_t *new_table = alloc_page_table();
        if (!new_table) {
            return NULL;
        }

        /* Create table descriptor pointing to new table */
        uint64_t phys_addr = (uint64_t)new_table;
        pte_t table_desc = fut_make_pte(phys_addr, PTE_VALID | PTE_TABLE);
        parent_table->entries[index] = table_desc;

        return new_table;
    }

    if (fut_pte_is_table(entry)) {
        /* Extract physical address and convert to virtual */
        uint64_t phys = fut_pte_to_phys(entry);
        return (page_table_t *)phys;  /* Assuming identity mapping for now */
    }

    return NULL;  /* Block descriptor found where table expected */
}

/* ============================================================
 *   Flag Translation for Architecture-Generic Code
 * ============================================================
 *
 * Translates generic x86_64-style PTE flags (used by architecture-generic
 * demand paging code) to ARM64-specific AP bit flags.
 */

/**
 * Translate generic PTE flags (x86_64-style) to ARM64 PTE flags.
 * Used by architecture-generic code (demand paging, COW) that
 * uses x86_64 flag constants.
 * @param generic_flags Flags using x86_64-style constants (PTE_PRESENT, PTE_USER, PTE_WRITABLE, PTE_NX)
 * @return ARM64 PTE flags with proper AP bits and attributes
 */
static uint64_t arm64_translate_flags(uint64_t generic_flags) {
    uint64_t arm64_flags = 0;

    /* Always set VALID if PTE_PRESENT is set */
    if (generic_flags & PTE_PRESENT) {
        arm64_flags |= PTE_VALID;
    }

    /* Determine if this is a user-accessible page by checking for PTE_USER (mapped to PTE_AF_BIT) */
    bool is_user = (generic_flags & PTE_USER) != 0;

    /* Check bit 62 which is set to indicate "writable request" on ARM64.
     * Note: On x86_64, PTE_WRITABLE is a real bit that gets into PTEs.
     * On ARM64, we use bit 62 as a signal during translation (it won't end up in final PTE).
     */
    bool is_writable = (generic_flags & PTE_WRITABLE) != 0;

    /* Determine AP bits based on user/writable flags */
    if (is_user) {
        /* User-accessible page */
        if (is_writable) {
            arm64_flags |= PTE_AP_RW_ALL;      /* User read/write */
        } else {
            arm64_flags |= PTE_AP_RO_ALL;      /* User read-only */
        }
    } else {
        /* Kernel-only page */
        if (is_writable) {
            arm64_flags |= PTE_AP_RW_EL1;      /* Kernel read/write only */
        } else {
            arm64_flags |= PTE_AP_RO_EL1;      /* Kernel read-only */
        }
    }

    /* Set memory attributes (normal, cacheable) */
    arm64_flags |= PTE_ATTR_NORMAL;

    /* Set sharability */
    arm64_flags |= PTE_SH_INNER;

    /* Set access flag (required for page to be mappable) */
    arm64_flags |= PTE_AF_BIT;

    /* Handle NX (no-execute) bit - set UXN if PTE_NX is set */
    if (generic_flags & PTE_NX) {
        arm64_flags |= PTE_UXN_BIT;
    }

    /* For user pages, always set PXN (prevent kernel execution in user pages) */
    if (is_user) {
        arm64_flags |= PTE_PXN_BIT;
    }

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
        return -1;  /* Invalid alignment */
    }

    if (!fut_is_canonical(vaddr)) {
        return -2;  /* Invalid address */
    }

    if (!ctx) {
        ctx = &kernel_vmem_context;
    }

    page_table_t *pgd = ctx->pgd;
    if (!pgd) {
        return -3;  /* No page table */
    }

    /* Translate generic flags to ARM64 flags if needed */
    uint64_t arm64_flags = arm64_translate_flags(flags);

    /* Walk page table hierarchy and create intermediate tables as needed */
    int pgd_idx = PGD_INDEX(vaddr);
    page_table_t *pmd = get_or_create_table(pgd, pgd_idx, true);
    if (!pmd) {
        return -4;  /* Failed to allocate PMD */
    }

    int pmd_idx = PMD_INDEX(vaddr);
    page_table_t *pte_table = get_or_create_table(pmd, pmd_idx, true);
    if (!pte_table) {
        return -5;  /* Failed to allocate PTE table */
    }

    int pte_idx = PTE_INDEX(vaddr);
    page_table_t *page_table = get_or_create_table(pte_table, pte_idx, true);
    if (!page_table) {
        return -6;  /* Failed to allocate page table */
    }

    int page_idx = PAGE_INDEX(vaddr);
    pte_t pte = fut_make_pte(paddr, arm64_flags);
    page_table->entries[page_idx] = pte;

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
        return -1;
    }

    if (!ctx) {
        ctx = &kernel_vmem_context;
    }

    page_table_t *pgd = ctx->pgd;
    if (!pgd) {
        return -2;
    }

    /* Walk to page table entry */
    int pgd_idx = PGD_INDEX(vaddr);
    pte_t pgd_entry = pgd->entries[pgd_idx];
    if (!fut_pte_is_present(pgd_entry)) {
        return -3;  /* Already unmapped */
    }

    page_table_t *pmd = (page_table_t *)fut_pte_to_phys(pgd_entry);
    int pmd_idx = PMD_INDEX(vaddr);
    pte_t pmd_entry = pmd->entries[pmd_idx];
    if (!fut_pte_is_present(pmd_entry)) {
        return -4;
    }

    page_table_t *pte_table = (page_table_t *)fut_pte_to_phys(pmd_entry);
    int pte_idx = PTE_INDEX(vaddr);
    pte_t pte_entry = pte_table->entries[pte_idx];
    if (!fut_pte_is_present(pte_entry)) {
        return -5;
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
        return -1;
    }

    /* Walk page tables */
    int pgd_idx = PGD_INDEX(vaddr);
    pte_t pgd_entry = pgd->entries[pgd_idx];
    if (!fut_pte_is_present(pgd_entry)) {
        return -2;
    }

    page_table_t *pmd = (page_table_t *)fut_pte_to_phys(pgd_entry);
    int pmd_idx = PMD_INDEX(vaddr);
    pte_t pmd_entry = pmd->entries[pmd_idx];
    if (!fut_pte_is_present(pmd_entry)) {
        return -3;
    }

    page_table_t *pte_table = (page_table_t *)fut_pte_to_phys(pmd_entry);
    int pte_idx = PTE_INDEX(vaddr);
    pte_t pte_entry = pte_table->entries[pte_idx];
    if (!fut_pte_is_present(pte_entry)) {
        return -4;
    }

    page_table_t *page_table = (page_table_t *)fut_pte_to_phys(pte_entry);
    int page_idx = PAGE_INDEX(vaddr);
    pte_t page_entry = page_table->entries[page_idx];
    if (!fut_pte_is_present(page_entry)) {
        return -5;
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
 * @return New VM context with empty user space, or NULL on failure
 */
fut_vmem_context_t *fut_vmem_create(void) {
    fut_vmem_context_t *ctx = (fut_vmem_context_t *)fut_malloc(sizeof(fut_vmem_context_t));
    if (!ctx) {
        return NULL;
    }

    ctx->pgd = alloc_page_table();
    if (!ctx->pgd) {
        fut_free(ctx);
        return NULL;
    }

    /* Copy kernel portion (upper half) from kernel PGD */
    memcpy(&ctx->pgd->entries[256], &kernel_pgd.entries[256], 256 * sizeof(pte_t));

    ctx->ttbr0_el1 = (uint64_t)ctx->pgd;
    ctx->ref_count = 1;

    return ctx;
}

/**
 * Destroy virtual memory context and free page tables.
 * @param ctx VM context to destroy
 */
void fut_vmem_destroy(fut_vmem_context_t *ctx) {
    if (!ctx) {
        return;
    }

    /* TODO: Recursively free all page tables in user space portion */
    if (ctx->pgd) {
        free_page_table(ctx->pgd);
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
 * @param paddr Physical address
 * @param size Size in bytes
 * @param flags Page flags
 * @return Virtual address of mapping, or NULL on failure
 */
void *fut_kernel_map_physical(uint64_t paddr, uint64_t size, uint64_t flags) {
    /* TODO: Implement kernel virtual space allocator */
    /* For now, use identity mapping in kernel space */
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
    /* Initialize kernel VMem context */
    kernel_vmem_context.pgd = &kernel_pgd;
    kernel_vmem_context.ttbr0_el1 = (uint64_t)&kernel_pgd;
    kernel_vmem_context.ref_count = 1;

    /* Set up memory attributes */
    uint64_t mair = 0;
    mair |= (0x00 << 0);   /* Attribute 0: Device nGnRnE */
    mair |= (0x04 << 8);   /* Attribute 1: Normal, non-cacheable */
    mair |= (0xFF << 16);  /* Attribute 2: Normal, cacheable */
    mair |= (0x04 << 24);  /* Attribute 3: Device nGnRE */
    write_mair_el1(mair);

    /* Set up translation control register */
    uint64_t tcr = 0;
    /* T0SZ = 16 (48-bit user VA) */
    tcr |= (16 << 0);
    /* T1SZ = 16 (48-bit kernel VA) */
    tcr |= (16 << 16);
    /* TG0 = 0 (4KB granule) */
    /* TG1 = 0 (4KB granule) */
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
    write_tcr_el1(tcr);

    /* Load kernel TTBR1_EL1 */
    write_ttbr1_el1((uint64_t)&kernel_pgd);

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

void fut_dump_page_tables(fut_vmem_context_t *ctx, uint64_t vaddr) {
    (void)ctx;
    (void)vaddr;
    /* TODO: Implement page table dumping for debugging */
}

void fut_vmem_print_stats(fut_vmem_context_t *ctx) {
    (void)ctx;
    /* TODO: Implement statistics printing */
}

bool fut_vmem_verify(fut_vmem_context_t *ctx) {
    (void)ctx;
    /* TODO: Implement consistency checking */
    return true;
}
