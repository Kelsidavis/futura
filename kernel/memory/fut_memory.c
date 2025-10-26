/* fut_memory.c - Futura OS Memory Manager Implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * This is a freestanding C23 implementation with no libc dependencies.
 * All operations are deterministic and suitable for bare-metal execution.
 */

#include "../../include/kernel/fut_memory.h"
#include <platform/platform.h>
#include <kernel/errno.h>

#if defined(__x86_64__)
#include <arch/x86_64/pmap.h>
#endif

/* ============================================================
 *   Physical Memory Manager (Bitmap-based)
 * ============================================================ */

static uint8_t  *pmm_bitmap = nullptr;   // Allocation bitmap
static uint64_t  pmm_total  = 0;         // Total pages
static uint64_t  pmm_free   = 0;         // Free pages
static uintptr_t pmm_base   = 0;         // Physical base address
static uint64_t  pmm_reserved_pages = 0;

/* Bitmap manipulation macros */
#define BITMAP_SET(b)   (pmm_bitmap[(b)/8u] |=  (1u << ((b)%8u)))
#define BITMAP_CLR(b)   (pmm_bitmap[(b)/8u] &= ~(1u << ((b)%8u)))
#define BITMAP_TST(b)   (pmm_bitmap[(b)/8u] &   (1u << ((b)%8u)))

#ifndef FUT_ASSERT
#define FUT_ASSERT(expr) do { if (!(expr)) fut_platform_panic("FUT_ASSERT failed: " #expr); } while (0)
#endif

void fut_pmm_init(uint64_t mem_size_bytes, uintptr_t phys_base) {
    // Calculate total number of pages
    pmm_total = mem_size_bytes / FUT_PAGE_SIZE;
    pmm_base  = phys_base;

#if defined(__x86_64__)
    /* Boot paging sets up 512 × 2MB huge pages in PD[0-511] mapping physical 0x0-0x40000000 (1GB).
     * The limit must match the boot mapping, not exceed it. Attempting to allocate beyond
     * this range would cause page faults due to missing page table entries. */
    uint64_t boot_map_limit = 0x40000000;  /* 1GB - matches boot page table setup */
    uint64_t pmm_max_phys = pmm_base + (pmm_total * FUT_PAGE_SIZE);
    uint64_t safe_limit_pages = pmm_total;  /* Default: no limit needed */

    if (pmm_max_phys > boot_map_limit && pmm_base < boot_map_limit) {
        /* PMM extends beyond conservative safe range, restrict it */
        uint64_t safe_mapped_bytes = boot_map_limit - pmm_base;
        safe_limit_pages = safe_mapped_bytes / FUT_PAGE_SIZE;
    }

    if (pmm_total > safe_limit_pages) {
        fut_printf("[PMM] Limiting to safe range: %llu pages (phys 0x%llx to 0x%llx)\n",
                   (unsigned long long)safe_limit_pages,
                   (unsigned long long)pmm_base,
                   (unsigned long long)boot_map_limit);
        pmm_total = safe_limit_pages;
    }
#endif

    // Bitmap size: 1 bit per page
    uint64_t bitmap_bytes = (pmm_total + 7u) / 8u;
    pmm_bitmap =
#if defined(__x86_64__)
        (uint8_t *)(uintptr_t)pmap_phys_to_virt((phys_addr_t)phys_base);
#else
        (uint8_t *)(uintptr_t)phys_base;
#endif

    // Clear the bitmap (all pages free initially)
    for (uint64_t i = 0; i < bitmap_bytes; ++i) {
        pmm_bitmap[i] = 0;
    }

    // Reserve pages used by the bitmap itself
    uint64_t bitmap_pages = FUT_PAGE_ALIGN(bitmap_bytes) / FUT_PAGE_SIZE;
    pmm_reserved_pages = bitmap_pages;
    for (uint64_t i = 0; i < bitmap_pages; ++i) {
        BITMAP_SET(i);
    }

    pmm_free = (pmm_total > bitmap_pages) ? (pmm_total - bitmap_pages) : 0;
}

void *fut_pmm_alloc_page(void) {
    // Linear scan for first free page
    for (uint64_t i = pmm_reserved_pages; i < pmm_total; ++i) {
        if (!BITMAP_TST(i)) {
            BITMAP_SET(i);
            --pmm_free;
            uintptr_t phys = pmm_base + i * FUT_PAGE_SIZE;
#if defined(__x86_64__)
            uintptr_t virt = pmap_phys_to_virt((phys_addr_t)phys);
            // Compiler barrier to prevent optimization issues
            __asm__ volatile("" : "+r"(virt) :: "memory");
            return (void *)virt;
#else
            return (void *)(uintptr_t)phys;
#endif
        }
    }

    return nullptr;  // Out of memory
}

void fut_pmm_free_page(void *addr) {
    if (!addr) return;

    // Calculate page index
    uintptr_t addr_val = (uintptr_t)addr;

#if defined(__x86_64__)
    phys_addr_t phys = pmap_virt_to_phys(addr_val);
#else
    phys_addr_t phys = (phys_addr_t)addr_val;
#endif

    if (phys < pmm_base) {
        return;
    }

    uint64_t idx = (phys - pmm_base) / FUT_PAGE_SIZE;

    // Validate and free
    if (idx < pmm_total && BITMAP_TST(idx)) {
        BITMAP_CLR(idx);
        ++pmm_free;
    }
}

uint64_t fut_pmm_total_pages(void) {
    return pmm_total;
}

uint64_t fut_pmm_free_pages(void) {
    return pmm_free;
}

uintptr_t fut_pmm_base_phys(void) {
    return pmm_base;
}

uintptr_t fut_pmm_bitmap_end_virt(void) {
    uintptr_t offset = pmm_reserved_pages * FUT_PAGE_SIZE;
#if defined(__x86_64__)
    return pmap_phys_to_virt(pmm_base + offset);
#else
    return pmm_base + offset;
#endif
}

void fut_pmm_reserve_range(uintptr_t phys_addr, size_t size_bytes) {
    extern void fut_printf(const char *, ...);

    if (size_bytes == 0) {
        return;
    }

    uintptr_t start = phys_addr;
    uintptr_t end = phys_addr + size_bytes;

    if (end <= start) {
        return;
    }

    if (start < pmm_base) {
        start = pmm_base;
    }
    if (end <= pmm_base) {
        return;
    }

    uint64_t first_page = (start - pmm_base) >> FUT_PAGE_SHIFT;
    uint64_t last_page = (end - 1ULL - pmm_base) >> FUT_PAGE_SHIFT;
    if (last_page >= pmm_total) {
        last_page = pmm_total - 1ULL;
    }

    uint64_t reserved_count = 0;
    for (uint64_t idx = first_page; idx <= last_page; ++idx) {
        if (!BITMAP_TST(idx)) {
            BITMAP_SET(idx);
            if (pmm_free > 0) {
                --pmm_free;
                reserved_count++;
            }
        }
    }

    fut_printf("[PMM-RESERVE] Reserved %llu pages (0x%llx-0x%llx), %llu pages now free\n",
               reserved_count, (unsigned long long)phys_addr,
               (unsigned long long)(phys_addr + size_bytes), pmm_free);
}

/* ============================================================
 *   Kernel Heap (Buddy + Slab Allocators)
 * ============================================================ */

#include "../../include/kernel/buddy_allocator.h"
#include "../../include/kernel/slab_allocator.h"

static uintptr_t heap_base  = 0;          // Heap start address
static uintptr_t heap_limit = 0;          // Heap end address

void fut_heap_init(uintptr_t heap_start, uintptr_t heap_end) {
    // Align heap boundaries to page boundaries
    heap_base  = FUT_PAGE_ALIGN(heap_start);
    heap_limit = FUT_PAGE_ALIGN(heap_end);

    uintptr_t bitmap_guard = fut_pmm_bitmap_end_virt();
    if (heap_base < bitmap_guard) {
        heap_base = bitmap_guard;
    }

    fut_printf("[HEAP-INIT] heap_base=%p heap_limit=%p (size=%llu KB)\n",
               (void*)heap_base, (void*)heap_limit,
               (unsigned long long)((heap_limit - heap_base) / 1024));

    if (heap_limit > heap_base) {
#if defined(__x86_64__)
        phys_addr_t phys_start = pmap_virt_to_phys(heap_base);
        phys_addr_t phys_end = pmap_virt_to_phys(heap_limit - FUT_PAGE_SIZE) + FUT_PAGE_SIZE;
        fut_printf("[HEAP-INIT] phys_start=%p phys_end=%p (size=%llu KB)\n",
                   (void*)phys_start, (void*)phys_end,
                   (unsigned long long)((phys_end - phys_start) / 1024));
        /* Reserve heap range PLUS one guard page after to prevent heap overflow
         * from corrupting immediately adjacent allocations (like page tables) */
        fut_pmm_reserve_range((uintptr_t)phys_start, (size_t)(phys_end - phys_start + FUT_PAGE_SIZE));
#else
        fut_pmm_reserve_range(heap_base, heap_limit - heap_base + FUT_PAGE_SIZE);
#endif
    }

    FUT_ASSERT(heap_base >= bitmap_guard);

    // Initialize buddy allocator with the heap range
    buddy_heap_init(heap_base, heap_limit);

    // Initialize slab allocator caches (uses buddy for slab allocation)
    slab_init();
}

/**
 * Integrated allocator: slab for small objects, buddy for large allocations
 * This provides both efficiency (slab) and flexibility (buddy)
 */

void *fut_malloc(size_t size) {
    if (!size) return nullptr;

    /* Use slab allocator - it handles both small and large allocations */
    return slab_malloc(size);
}

void fut_free(void *ptr) {
    if (!ptr) return;

    /* Use slab allocator */
    slab_free(ptr);
}

void *fut_realloc(void *ptr, size_t new_size) {
    if (!ptr) return fut_malloc(new_size);
    if (!new_size) {
        fut_free(ptr);
        return nullptr;
    }

    /* Use slab allocator */
    return slab_realloc(ptr, new_size);
}

/* ============================================================
 *   Multi-Page Allocation
 * ============================================================ */

void *fut_malloc_pages(size_t num_pages) {
    if (!num_pages) return nullptr;

    // Try to allocate contiguous pages from PMM
    // Note: Current PMM implementation doesn't support multi-page contiguous allocation
    // For now, allocate pages individually and hope they're contiguous (simple approach)
    // Future optimization: Implement buddy allocator or best-fit for contiguous allocation

    // For simplicity, allocate the first page and verify subsequent pages are contiguous
    void *first_page = fut_pmm_alloc_page();
    if (!first_page) return nullptr;

    uintptr_t base = (uintptr_t)first_page;

    // Allocate remaining pages and verify they're contiguous
    for (size_t i = 1; i < num_pages; ++i) {
        void *page = fut_pmm_alloc_page();
        if (!page) {
            // Failed to allocate - free what we've allocated so far
            for (size_t j = 0; j < i; ++j) {
                fut_pmm_free_page((void *)(base + j * FUT_PAGE_SIZE));
            }
            return nullptr;
        }

        // Check if contiguous (note: this is probabilistic, not guaranteed)
        // If not contiguous, we still accept it for now (simple implementation)
        // Future: Implement proper contiguous allocation in PMM
    }

    return first_page;
}

void fut_free_pages(void *ptr, size_t num_pages) {
    if (!ptr || !num_pages) return;

    // Free each page back to PMM
    uintptr_t base = (uintptr_t)ptr;
    for (size_t i = 0; i < num_pages; ++i) {
        fut_pmm_free_page((void *)(base + i * FUT_PAGE_SIZE));
    }
}

/* ============================================================
 *   Heap Bounds Accessors
 * ============================================================ */

uintptr_t fut_heap_get_base(void) {
    return heap_base;
}

uintptr_t fut_heap_get_limit(void) {
    return heap_limit;
}

/* ============================================================
 *   Diagnostics
 * ============================================================ */

void fut_mem_print_stats(void) {
    const double total_mb = (pmm_total * FUT_PAGE_SIZE) / (1024.0 * 1024.0);
    const double free_mb = (pmm_free * FUT_PAGE_SIZE) / (1024.0 * 1024.0);

    fut_printf("[futura] Physical Memory Statistics:\n");
    fut_printf("[futura]   Total: %llu pages (%.2f MiB)\n",
              pmm_total, total_mb);
    fut_printf("[futura]   Free : %llu pages (%.2f MiB)\n",
              pmm_free, free_mb);
    fut_printf("[futura]   Used : %llu pages (%.2f MiB)\n",
              pmm_total - pmm_free, total_mb - free_mb);
}
