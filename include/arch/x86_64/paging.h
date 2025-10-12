/* paging.h - Futura OS x86_64 Paging and Virtual Memory
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * 4-level page table structures and virtual memory management for x86_64.
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>

/* ============================================================
 *   Virtual Address Space Layout
 * ============================================================ */

/* Canonical addressing in x86_64:
 * User space:   0x0000000000000000 - 0x00007FFFFFFFFFFF (lower half)
 * Kernel space: 0xFFFF800000000000 - 0xFFFFFFFFFFFFFFFF (upper half)
 * Non-canonical addresses (invalid): 0x0000800000000000 - 0xFFFF7FFFFFFFFFFF
 */

#define KERNEL_VIRTUAL_BASE     0xFFFFFFFF80000000ULL   /* -2GB */
#define KERNEL_HEAP_BASE        0xFFFFFFFFC0000000ULL   /* -1GB */
#define KERNEL_STACK_BASE       0xFFFFFFFFE0000000ULL   /* -512MB */
#define USER_SPACE_END          0x00007FFFFFFFFFFFULL   /* 128TB user space */

/* ============================================================
 *   Page Sizes and Alignment
 * ============================================================ */

#define PAGE_SIZE               4096                    /* 4KB pages */
#define PAGE_SHIFT              12
#define PAGE_MASK               (~(PAGE_SIZE - 1))

#define LARGE_PAGE_SIZE         (2 * 1024 * 1024)       /* 2MB pages */
#define LARGE_PAGE_SHIFT        21
#define HUGE_PAGE_SIZE          (1024 * 1024 * 1024)    /* 1GB pages */
#define HUGE_PAGE_SHIFT         30

/* Alignment macros */
#define PAGE_ALIGN_DOWN(addr)   ((addr) & PAGE_MASK)
#define PAGE_ALIGN_UP(addr)     (((addr) + PAGE_SIZE - 1) & PAGE_MASK)
#define IS_PAGE_ALIGNED(addr)   (((addr) & ~PAGE_MASK) == 0)

/* ============================================================
 *   Page Table Entry Flags (Common to all levels)
 * ============================================================ */

#define PTE_PRESENT             (1ULL << 0)     /* Page is present in memory */
#define PTE_WRITABLE            (1ULL << 1)     /* Page is writable */
#define PTE_USER                (1ULL << 2)     /* User mode access allowed */
#define PTE_WRITE_THROUGH       (1ULL << 3)     /* Write-through caching */
#define PTE_CACHE_DISABLE       (1ULL << 4)     /* Disable caching */
#define PTE_ACCESSED            (1ULL << 5)     /* Page has been accessed */
#define PTE_DIRTY               (1ULL << 6)     /* Page has been written to */
#define PTE_LARGE_PAGE          (1ULL << 7)     /* 2MB/1GB page (PD/PDPT only) */
#define PTE_PAT                 (1ULL << 7)     /* PAT selector (PT level) */
#define PTE_GLOBAL              (1ULL << 8)     /* Global page (not flushed on CR3 reload) */

/* Available for OS use (bits 9-11, 52-62) */
#define PTE_OS_1                (1ULL << 9)
#define PTE_OS_2                (1ULL << 10)
#define PTE_OS_3                (1ULL << 11)

#define PTE_NX                  (1ULL << 63)    /* No-Execute (requires EFER.NXE) */

/* Common flag combinations */
#define PTE_KERNEL_RO           (PTE_PRESENT)
#define PTE_KERNEL_RW           (PTE_PRESENT | PTE_WRITABLE)
#define PTE_KERNEL_RX           (PTE_PRESENT)
#define PTE_USER_RO             (PTE_PRESENT | PTE_USER)
#define PTE_USER_RW             (PTE_PRESENT | PTE_USER | PTE_WRITABLE)
#define PTE_USER_RX             (PTE_PRESENT | PTE_USER)

/* Physical address mask (bits 12-51, supports 52-bit physical addressing) */
#define PTE_PHYS_ADDR_MASK      0x000FFFFFFFFFF000ULL
#define PTE_FLAGS_MASK          (~PTE_PHYS_ADDR_MASK)

/* ============================================================
 *   Page Table Structure (4-Level Hierarchy)
 * ============================================================ */

/**
 * Page table entry (64-bit).
 * Used for PML4, PDPT, PD, and PT entries.
 */
typedef uint64_t pte_t;

/**
 * Page table (512 entries per table).
 */
typedef struct page_table {
    pte_t entries[512];
} __attribute__((aligned(PAGE_SIZE))) page_table_t;

static_assert(sizeof(page_table_t) == PAGE_SIZE, "Page table must be 4KB");

/* Page table indices from virtual address */
#define PML4_INDEX(vaddr)       (((vaddr) >> 39) & 0x1FF)
#define PDPT_INDEX(vaddr)       (((vaddr) >> 30) & 0x1FF)
#define PD_INDEX(vaddr)         (((vaddr) >> 21) & 0x1FF)
#define PT_INDEX(vaddr)         (((vaddr) >> 12) & 0x1FF)
#define PAGE_OFFSET(vaddr)      ((vaddr) & 0xFFF)

/* ============================================================
 *   Virtual Memory Context
 * ============================================================ */

/**
 * Virtual memory address space (per-process).
 */
typedef struct fut_vmem_context {
    pte_t *pml4;                /* Physical address of PML4 table */
    uint64_t cr3_value;         /* Value to load into CR3 */
    uint64_t ref_count;         /* Reference count for sharing */
} fut_vmem_context_t;

/* ============================================================
 *   Canonical Address Validation
 * ============================================================ */

/**
 * Check if virtual address is canonical.
 * @param vaddr Virtual address to check
 * @return true if canonical, false otherwise
 */
static inline bool fut_is_canonical(uint64_t vaddr) {
    /* Sign-extend bit 47 to bits 48-63 */
    int64_t sign_extended = (int64_t)vaddr;
    sign_extended <<= 16;
    sign_extended >>= 16;
    return (uint64_t)sign_extended == vaddr;
}

/**
 * Check if address is in kernel space.
 */
static inline bool fut_is_kernel_address(uint64_t vaddr) {
    return vaddr >= 0xFFFF800000000000ULL;
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
 * Check if page table entry is present.
 */
static inline bool fut_pte_is_present(pte_t entry) {
    return (entry & PTE_PRESENT) != 0;
}

/**
 * Check if page table entry is a large page.
 */
static inline bool fut_pte_is_large(pte_t entry) {
    return (entry & PTE_LARGE_PAGE) != 0;
}

/**
 * Check if page table entry is writable.
 */
static inline bool fut_pte_is_writable(pte_t entry) {
    return (entry & PTE_WRITABLE) != 0;
}

/**
 * Check if page table entry is user-accessible.
 */
static inline bool fut_pte_is_user(pte_t entry) {
    return (entry & PTE_USER) != 0;
}

/* ============================================================
 *   Virtual Memory Management Functions
 * ============================================================ */

/**
 * Initialize paging subsystem.
 * Sets up kernel page tables and enables paging features.
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
 * Loads PML4 into CR3 register.
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
 * @param flags Page flags (PTE_PRESENT | PTE_WRITABLE | etc.)
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
    __asm__ volatile("invlpg (%0)" :: "r"(vaddr) : "memory");
}

/**
 * Flush entire TLB (reload CR3).
 */
static inline void fut_flush_tlb_all(void) {
    uint64_t cr3;
    __asm__ volatile("mov %%cr3, %0" : "=r"(cr3));
    __asm__ volatile("mov %0, %%cr3" :: "r"(cr3) : "memory");
}

/* ============================================================
 *   Kernel Page Table Management
 * ============================================================ */

/**
 * Get kernel PML4 table.
 * @return Physical address of kernel PML4
 */
pte_t *fut_get_kernel_pml4(void);

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
 */
void fut_kernel_unmap(void *vaddr);

/* ============================================================
 *   Page Fault Handler
 * ============================================================ */

/**
 * Handle page fault exception.
 * Called from ISR 14 (INT_PAGE_FAULT).
 * @param frame Interrupt frame
 * @param error_code Page fault error code
 * @param faulting_addr CR2 value (faulting address)
 */
void fut_page_fault_handler(void *frame, uint64_t error_code, uint64_t faulting_addr);

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
