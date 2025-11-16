/* paging.h - Futura OS ARM64 Paging and Virtual Memory
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * ARM64 (AArch64) page table structures and virtual memory management.
 * Supports 48-bit virtual addressing with 4-level page table hierarchy.
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>

/* ============================================================
 *   Virtual Address Space Layout (ARMv8.0 with 48-bit VA)
 * ============================================================ */

/* ARM64 supports configurable VA space via TCR_EL1.T0SZ and TCR_EL1.T1SZ
 * With 48-bit VA space and 4KB page size:
 * User space:   0x0000000000000000 - 0x0000FFFFFFFFFFFF (256TB)
 * Kernel space: 0xFFFF000000000000 - 0xFFFFFFFFFFFFFFFF (256TB)
 * Non-canonical: 0x000100000000000 - 0xFFFEFFFFFFFFFFFF (invalid)
 */

#define KERNEL_VIRTUAL_BASE     0xFFFF800000000000ULL   /* Kernel start (kernel half) */
#define KERNEL_HEAP_BASE        0xFFFFC00000000000ULL   /* Kernel heap */
#define KERNEL_STACK_BASE       0xFFFFE00000000000ULL   /* Kernel stacks */
#define USER_SPACE_END          0x0000FFFFFFFFFFFFULL   /* 256TB user space limit */

/* ============================================================
 *   Page Sizes and Alignment
 * ============================================================ */

#define PAGE_SIZE               4096                    /* 4KB pages */
#define PAGE_SHIFT              12
#define PAGE_MASK               (~(PAGE_SIZE - 1))

#define LARGE_PAGE_SIZE         (2 * 1024 * 1024)       /* 2MB pages (L2 block) */
#define LARGE_PAGE_SHIFT        21
#define HUGE_PAGE_SIZE          (1024 * 1024 * 1024)    /* 1GB pages (L1 block) */
#define HUGE_PAGE_SHIFT         30

/* Alignment macros */
#define PAGE_ALIGN_DOWN(addr)   ((addr) & PAGE_MASK)
#define PAGE_ALIGN_UP(addr)     (((addr) + PAGE_SIZE - 1) & PAGE_MASK)
#define IS_PAGE_ALIGNED(addr)   (((addr) & ~PAGE_MASK) == 0)

/* ============================================================
 *   Page Table Entry Flags (ARM64 descriptor format)
 * ============================================================ */

/* Descriptor type bits (bits 0-1) */
#define PTE_TYPE_MASK           0x3ULL
#define PTE_TYPE_INVALID        0x0ULL
#define PTE_TYPE_BLOCK          0x1ULL                  /* Block descriptor */
#define PTE_TYPE_TABLE          0x3ULL                  /* Table descriptor */
#define PTE_TYPE_PAGE           0x3ULL                  /* Page descriptor (at L3) */

/* Access flags */
#define PTE_VALID               (1ULL << 0)             /* Valid/present bit */
#define PTE_TABLE               (1ULL << 1)             /* Table descriptor bit */

/* Memory attributes (bits 2-4) */
#define PTE_ATTR_SHIFT          2
#define PTE_ATTR_MASK           (0x7ULL << PTE_ATTR_SHIFT)
#define PTE_ATTR_DEVICE_nGnRnE  (0x0ULL << PTE_ATTR_SHIFT)  /* Device, no gather, no reorder, no early ack */
#define PTE_ATTR_DEVICE_nGnRE   (0x1ULL << PTE_ATTR_SHIFT)  /* Device, no gather, reorder ok */
#define PTE_ATTR_DEVICE_GRE     (0x2ULL << PTE_ATTR_SHIFT)  /* Device, gather/reorder ok */
#define PTE_ATTR_NORMAL         (0x4ULL << PTE_ATTR_SHIFT)  /* Normal (cacheable) memory */

/* Access control bits */
#define PTE_SH_SHIFT            8
#define PTE_SH_MASK             (0x3ULL << PTE_SH_SHIFT)
#define PTE_SH_NONE             (0x0ULL << PTE_SH_SHIFT)     /* Non-shareable */
#define PTE_SH_OUTER            (0x2ULL << PTE_SH_SHIFT)     /* Outer shareable */
#define PTE_SH_INNER            (0x3ULL << PTE_SH_SHIFT)     /* Inner shareable */

#define PTE_AP_SHIFT            6
#define PTE_AP_MASK             (0x3ULL << PTE_AP_SHIFT)
#define PTE_AP_RW_EL1           (0x0ULL << PTE_AP_SHIFT)     /* EL1 read/write, EL0 none */
#define PTE_AP_RW_ALL           (0x1ULL << PTE_AP_SHIFT)     /* EL1/EL0 read/write */
#define PTE_AP_RO_EL1           (0x2ULL << PTE_AP_SHIFT)     /* EL1 read-only, EL0 none */
#define PTE_AP_RO_ALL           (0x3ULL << PTE_AP_SHIFT)     /* EL1/EL0 read-only */

#define PTE_NS_BIT              (1ULL << 5)             /* Non-secure bit */
#define PTE_AF_BIT              (1ULL << 10)            /* Access flag */
#define PTE_DBM_BIT             (1ULL << 51)            /* Dirty bit management (ARMv8.1) */
#define PTE_CONT_BIT            (1ULL << 52)            /* Contiguous hint */
#define PTE_PXN_BIT             (1ULL << 53)            /* Privilege execute never */
#define PTE_UXN_BIT             (1ULL << 54)            /* User execute never */

/* Common page flag combinations */
#define PTE_KERNEL_RO           (PTE_VALID | PTE_ATTR_NORMAL | PTE_AP_RO_EL1 | PTE_AF_BIT | PTE_SH_INNER | PTE_UXN_BIT | PTE_PXN_BIT)
#define PTE_KERNEL_RW           (PTE_VALID | PTE_ATTR_NORMAL | PTE_AP_RW_EL1 | PTE_AF_BIT | PTE_SH_INNER | PTE_UXN_BIT | PTE_PXN_BIT)
#define PTE_KERNEL_RX           (PTE_VALID | PTE_ATTR_NORMAL | PTE_AP_RO_EL1 | PTE_AF_BIT | PTE_SH_INNER | PTE_UXN_BIT)
#define PTE_USER_RO             (PTE_VALID | PTE_ATTR_NORMAL | PTE_AP_RO_ALL | PTE_AF_BIT | PTE_SH_INNER | PTE_PXN_BIT)
#define PTE_USER_RW             (PTE_VALID | PTE_ATTR_NORMAL | PTE_AP_RW_ALL | PTE_AF_BIT | PTE_SH_INNER | PTE_PXN_BIT)
#define PTE_USER_RX             (PTE_VALID | PTE_ATTR_NORMAL | PTE_AP_RO_ALL | PTE_AF_BIT | PTE_SH_INNER)
#define PTE_DEVICE              (PTE_VALID | PTE_ATTR_DEVICE_nGnRnE | PTE_AP_RW_EL1 | PTE_AF_BIT | PTE_SH_OUTER | PTE_UXN_BIT | PTE_PXN_BIT)

/* Physical address mask (bits 12-47 for 48-bit VA, bits 12-51 with 52-bit PA support) */
#define PTE_PHYS_ADDR_MASK      0x0000FFFFFFFFF000ULL
/* Flags mask: all bits except physical address and bit 62 (ARM64 internal signal bit) */
#define PTE_FLAGS_MASK          ((~PTE_PHYS_ADDR_MASK) & ~(1ULL << 62))

/* ============================================================
 *   Page Table Structure (4-Level Hierarchy)
 * ============================================================ */

/**
 * Page table entry (64-bit).
 * Used for all levels: L0 (PGD), L1 (PMD), L2 (PTE), L3 (PTE)
 */
typedef uint64_t pte_t;

/**
 * Page table (512 entries per table for 4KB granule).
 */
typedef struct page_table {
    pte_t entries[512];
} __attribute__((aligned(PAGE_SIZE))) page_table_t;

_Static_assert(sizeof(page_table_t) == PAGE_SIZE, "Page table must be 4KB");

/* Page table indices from virtual address
 * ARM64 with T0SZ=25 (39-bit VA) uses 3-level page tables:
 * L1 (PGD): bits [38:30] -> 512 entries × 1GB = 512GB range
 * L2 (PMD): bits [29:21] -> 512 entries × 2MB = 1GB range
 * L3 (PTE): bits [20:12] -> 512 entries × 4KB = 2MB range (FINAL LEVEL)
 */
#define PGD_INDEX(vaddr)        (((vaddr) >> 30) & 0x1FF)   /* L1: bits [38:30] */
#define PMD_INDEX(vaddr)        (((vaddr) >> 21) & 0x1FF)   /* L2: bits [29:21] */
#define PTE_INDEX(vaddr)        (((vaddr) >> 12) & 0x1FF)   /* L3: bits [20:12] (FINAL) */
#define PAGE_INDEX(vaddr)       (((vaddr) >> 12) & 0x1FF)   /* Same as PTE for 3-level */
#define PAGE_OFFSET(vaddr)      ((vaddr) & 0xFFF)           /* Page offset */

/* ============================================================
 *   Virtual Memory Context
 * ============================================================ */

/**
 * Virtual memory address space (per-process).
 */
typedef struct fut_vmem_context {
    page_table_t *pgd;          /* Physical address of PGD (L0 table) */
    uint64_t ttbr0_el1;         /* Value to load into TTBR0_EL1 */
    uint64_t ref_count;         /* Reference count for sharing */
} fut_vmem_context_t;

/* ============================================================
 *   Address Validation
 * ============================================================ */

/**
 * Check if virtual address is canonical (valid for 48-bit VA).
 * @param vaddr Virtual address to check
 * @return true if canonical, false otherwise
 */
static inline bool fut_is_canonical(uint64_t vaddr) {
    /* For 48-bit VA: bits 48-63 must all be same as bit 47 */
    uint64_t upper = vaddr >> 48;
    return (upper == 0) || (upper == 0xFFFF);
}

/**
 * Check if address is in kernel space.
 */
static inline bool fut_is_kernel_address(uint64_t vaddr) {
    return vaddr >= 0xFFFF000000000000ULL;
}

/**
 * Check if address is in user space.
 */
static inline bool fut_is_user_address(uint64_t vaddr) {
    return vaddr <= USER_SPACE_END;
}

/* ============================================================
 *   Page Table Entry Manipulation
 * ============================================================ */

/**
 * Create page table entry from physical address and flags.
 */
static inline pte_t fut_make_pte(uint64_t phys_addr, uint64_t flags) {
    return (phys_addr & PTE_PHYS_ADDR_MASK) | (flags & PTE_FLAGS_MASK);
}

/**
 * Extract physical address from page table entry.
 */
static inline uint64_t fut_pte_to_phys(pte_t entry) {
    return entry & PTE_PHYS_ADDR_MASK;
}

/**
 * Extract flags from page table entry.
 */
static inline uint64_t fut_pte_flags(pte_t entry) {
    return entry & PTE_FLAGS_MASK;
}

/**
 * Check if page table entry is valid/present.
 */
static inline bool fut_pte_is_present(pte_t entry) {
    return (entry & PTE_VALID) != 0;
}

/**
 * Check if page table entry is a block descriptor (large page).
 */
static inline bool fut_pte_is_block(pte_t entry) {
    return (entry & PTE_TYPE_MASK) == PTE_TYPE_BLOCK;
}

/**
 * Check if page table entry is a table descriptor.
 */
static inline bool fut_pte_is_table(pte_t entry) {
    return (entry & PTE_TYPE_MASK) == PTE_TYPE_TABLE;
}

/**
 * Check if page table entry allows write access.
 */
static inline bool fut_pte_is_writable(pte_t entry) {
    uint64_t ap = (entry & PTE_AP_MASK) >> PTE_AP_SHIFT;
    return (ap == 0) || (ap == 1);  /* AP[1] = 0 means writable */
}

/**
 * Check if page table entry is user-accessible.
 */
static inline bool fut_pte_is_user(pte_t entry) {
    uint64_t ap = (entry & PTE_AP_MASK) >> PTE_AP_SHIFT;
    return (ap & 1);  /* AP[0] = 1 means user accessible */
}

/* ============================================================
 *   Virtual Memory Management Functions
 * ============================================================ */

/**
 * Initialize paging subsystem.
 * Sets up kernel page tables and enables MMU.
 */
void fut_paging_init(void);

/**
 * Create new virtual memory context.
 * @return New VM context with empty user space
 */
fut_vmem_context_t *fut_vmem_create(void);

/**
 * Destroy virtual memory context and free page tables.
 * @param ctx VM context to destroy
 */
void fut_vmem_destroy(fut_vmem_context_t *ctx);

/**
 * Switch to virtual memory context.
 * Loads PGD into TTBR0_EL1 register.
 * @param ctx VM context to switch to
 */
void fut_vmem_switch(fut_vmem_context_t *ctx);

/**
 * Get current virtual memory context.
 * @return Current VM context
 */
fut_vmem_context_t *fut_vmem_current(void);

/**
 * Map physical page to virtual address.
 * @param ctx VM context (NULL for current)
 * @param vaddr Virtual address (must be page-aligned)
 * @param paddr Physical address (must be page-aligned)
 * @param flags Page flags (PTE_VALID | PTE_ATTR_NORMAL | etc.)
 * @return 0 on success, negative on error
 */
int fut_map_page(fut_vmem_context_t *ctx, uint64_t vaddr, uint64_t paddr, uint64_t flags);

/**
 * Map large page (2MB) to virtual address.
 * @param ctx VM context (NULL for current)
 * @param vaddr Virtual address (must be 2MB-aligned)
 * @param paddr Physical address (must be 2MB-aligned)
 * @param flags Page flags
 * @return 0 on success, negative on error
 */
int fut_map_large_page(fut_vmem_context_t *ctx, uint64_t vaddr, uint64_t paddr, uint64_t flags);

/**
 * Unmap page from virtual address.
 * @param ctx VM context (NULL for current)
 * @param vaddr Virtual address to unmap
 * @return 0 on success, negative on error
 */
int fut_unmap_page(fut_vmem_context_t *ctx, uint64_t vaddr);

/**
 * Translate virtual address to physical address.
 * @param ctx VM context (NULL for current)
 * @param vaddr Virtual address
 * @param paddr Pointer to store physical address
 * @return 0 on success, negative if not mapped
 */
int fut_virt_to_phys(fut_vmem_context_t *ctx, uint64_t vaddr, uint64_t *paddr);

/**
 * Update page flags without changing physical mapping.
 * @param ctx VM context (NULL for current)
 * @param vaddr Virtual address
 * @param flags New page flags
 * @return 0 on success, negative on error
 */
int fut_update_page_flags(fut_vmem_context_t *ctx, uint64_t vaddr, uint64_t flags);

/**
 * Map contiguous physical memory region.
 * @param ctx VM context (NULL for current)
 * @param vaddr Virtual base address
 * @param paddr Physical base address
 * @param size Size in bytes (will be rounded up to page size)
 * @param flags Page flags
 * @return 0 on success, negative on error
 */
int fut_map_range(fut_vmem_context_t *ctx, uint64_t vaddr, uint64_t paddr,
                  uint64_t size, uint64_t flags);

/**
 * Unmap contiguous virtual memory region.
 * @param ctx VM context (NULL for current)
 * @param vaddr Virtual base address
 * @param size Size in bytes
 * @return 0 on success, negative on error
 */
int fut_unmap_range(fut_vmem_context_t *ctx, uint64_t vaddr, uint64_t size);

/**
 * Identity map physical memory region (vaddr = paddr).
 * @param ctx VM context (NULL for current)
 * @param paddr Physical address (also used as virtual address)
 * @param size Size in bytes
 * @param flags Page flags
 * @return 0 on success, negative on error
 */
int fut_identity_map(fut_vmem_context_t *ctx, uint64_t paddr, uint64_t size, uint64_t flags);

/**
 * Flush TLB entry for specific virtual address.
 * @param vaddr Virtual address to flush
 */
static inline void fut_flush_tlb_single(uint64_t vaddr) {
    /* ARM64: TLBI VALE1 - TLB invalidate by VA at EL1 */
    __asm__ volatile("tlbi vale1, %0" :: "r"(vaddr >> 12) : "memory");
    __asm__ volatile("dsb sy" ::: "memory");
    __asm__ volatile("isb" ::: "memory");
}

/**
 * Flush entire TLB (all entries).
 */
static inline void fut_flush_tlb_all(void) {
    /* ARM64: TLBI VMALLE1 - invalidate all EL1 TLB entries */
    __asm__ volatile("tlbi vmalle1" ::: "memory");
    __asm__ volatile("dsb sy" ::: "memory");
}

/* ============================================================
 *   Kernel Page Table Management
 * ============================================================ */

/**
 * Get kernel PGD table.
 * @return Physical address of kernel PGD
 */
page_table_t *fut_get_kernel_pgd(void);

/**
 * Map physical memory into kernel space.
 * Used for MMIO, framebuffer, etc.
 * @param paddr Physical address
 * @param size Size in bytes
 * @param flags Page flags
 * @return Virtual address of mapping, or NULL on failure
 */
void *fut_kernel_map_physical(uint64_t paddr, uint64_t size, uint64_t flags);

/**
 * Unmap kernel virtual address.
 * @param vaddr Virtual address to unmap
 * @param size  Size of region to unmap
 */
void fut_kernel_unmap(void *vaddr, uint64_t size);

/* ============================================================
 *   Page Fault Handler
 * ============================================================ */

/**
 * Handle page fault exception.
 * Called from data/instruction abort handlers.
 * @param frame Interrupt frame
 * @param esr Exception syndrome register value
 * @param far Fault address register value (FAR_EL1)
 */
void fut_page_fault_handler(void *frame, uint64_t esr, uint64_t far);

/* ============================================================
 *   Architecture-Neutral Accessors for VMM Context
 * ============================================================ */

/**
 * Get page table root from virtual memory context.
 * On ARM64, this returns the PGD (Level 0 page table).
 */
static inline void *fut_vmem_get_root(fut_vmem_context_t *ctx) {
    return (void *)ctx->pgd;
}

/**
 * Set page table root in virtual memory context.
 * On ARM64, sets the PGD (Level 0 page table).
 */
static inline void fut_vmem_set_root(fut_vmem_context_t *ctx, void *root) {
    ctx->pgd = (page_table_t *)root;
}

/**
 * Get page table reload value from virtual memory context.
 * On ARM64, this returns the value to load into TTBR0_EL1.
 */
static inline uint64_t fut_vmem_get_reload_value(fut_vmem_context_t *ctx) {
    return ctx->ttbr0_el1;
}

/**
 * Set page table reload value in virtual memory context.
 * On ARM64, sets the value to load into TTBR0_EL1.
 */
static inline void fut_vmem_set_reload_value(fut_vmem_context_t *ctx, uint64_t value) {
    ctx->ttbr0_el1 = value;
}

/**
 * Convert root page table pointer to physical address.
 * Assumes the PGD pointer is a virtual kernel address.
 */
static inline uint64_t fut_vmem_root_to_phys(void *root) {
    /* ARM64: strip the high bits to get physical address */
    uintptr_t virt = (uintptr_t)root;
    if (virt >= KERNEL_VIRTUAL_BASE) {
        return (uint64_t)(virt & ~KERNEL_VIRTUAL_BASE);
    }
    return (uint64_t)virt;
}

/**
 * Convert physical address to root page table pointer.
 * Returns a kernel virtual address from a physical address.
 */
static inline void *fut_vmem_phys_to_root(uint64_t phys) {
    /* ARM64 kernel space mapping: physical + KERNEL_VIRTUAL_BASE */
    return (void *)(KERNEL_VIRTUAL_BASE | phys);
}

/* ============================================================
 *   Debug and Statistics
 * ============================================================ */

/**
 * Dump page table hierarchy for debugging.
 * @param ctx VM context (NULL for current)
 * @param vaddr Virtual address to dump
 */
void fut_dump_page_tables(fut_vmem_context_t *ctx, uint64_t vaddr);

/**
 * Print virtual memory statistics.
 * @param ctx VM context (NULL for current)
 */
void fut_vmem_print_stats(fut_vmem_context_t *ctx);

/**
 * Verify page table consistency.
 * @param ctx VM context (NULL for current)
 * @return true if valid, false if corrupted
 */
bool fut_vmem_verify(fut_vmem_context_t *ctx);

/* ============================================================
 *   x86_64 Compatibility Constants (for architecture-generic code)
 * ============================================================
 * Maps x86_64 PTE flag names to ARM64 equivalents for code
 * that needs to work across both architectures.
 *
 * Note: On ARM64, writability is determined by AP bits set during
 * mapping, not by a single PTE_WRITABLE flag. To preserve
 * architecture-generic code logic, we use bit 62 (unused by ARM64 user PTEs)
 * as a signal bit that's interpreted during flag translation.
 */

#define PTE_PRESENT             PTE_VALID       /* Page is present/valid */
#define PTE_WRITABLE            (1ULL << 62)    /* Internal flag: bit 62 indicates "writable request" for ARM64 translation */
#define PTE_USER                PTE_AF_BIT      /* User accessible (use AF_BIT as marker, set during translation) */
#define PTE_NX                  PTE_UXN_BIT     /* No-execute */
#define PTE_PHYS_ADDR_MASK      0x0000FFFFFFFFF000ULL  /* Physical address bits [47:12] */

/**
 * Extract compatibility flags from ARM64 hardware PTE.
 * Converts AP bits [7:6] back to PTE_WRITABLE for architecture-generic code.
 * Used by sys_fork.c and other generic memory management code.
 *
 * @param pte Hardware PTE entry
 * @return Compatibility flags (PTE_PRESENT | PTE_WRITABLE | PTE_USER | PTE_NX)
 */
static inline uint64_t pte_extract_flags(uint64_t pte) {
    uint64_t flags = 0;

    /* Check if page is present/valid */
    if (pte & PTE_VALID) {
        flags |= PTE_PRESENT;
    }

    /* Extract AP bits [7:6] to determine writability
     * AP[1:0] encoding:
     *   0b00 (0): EL1 read/write, EL0 none (kernel-only writable)
     *   0b01 (1): EL1/EL0 read/write (user writable)
     *   0b10 (2): EL1 read-only, EL0 none (kernel-only read-only)
     *   0b11 (3): EL1/EL0 read-only (user read-only)
     *
     * If AP[1] is clear (bit 7), page is writable; if set, read-only
     */
    uint64_t ap = (pte >> PTE_AP_SHIFT) & 0x3;
    if ((ap & 0x2) == 0) {  /* AP[1] == 0 means writable (RW) */
        flags |= PTE_WRITABLE;
    }

    /* User-accessible if AP[0] is set (bit 6) */
    if (ap & 0x1) {  /* AP[0] == 1 means user-accessible */
        flags |= PTE_USER;
    }

    /* No-execute if UXN bit is set */
    if (pte & PTE_UXN_BIT) {
        flags |= PTE_NX;
    }

    return flags;
}
