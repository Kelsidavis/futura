/* fut_memory.c - Futura OS Memory Manager Implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * This is a freestanding C23 implementation with no libc dependencies.
 * All operations are deterministic and suitable for bare-metal execution.
 */

#include "../../include/kernel/fut_memory.h"

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

void fut_pmm_init(uint64_t mem_size_bytes, uintptr_t phys_base) {
    // Calculate total number of pages
    pmm_total = mem_size_bytes / FUT_PAGE_SIZE;
    pmm_base  = phys_base;

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
            return (void *)(uintptr_t)pmap_phys_to_virt((phys_addr_t)phys);
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

/* ============================================================
 *   Kernel Heap (Simple First-Fit Allocator)
 * ============================================================ */

typedef struct block_hdr {
    size_t size;              // Size of usable space (excluding header)
    struct block_hdr *next;   // Next free block
} block_hdr_t;

static block_hdr_t *free_list = nullptr;  // Head of free list
static uintptr_t heap_base  = 0;          // Heap start address
static uintptr_t heap_limit = 0;          // Heap end address

void fut_heap_init(uintptr_t heap_start, uintptr_t heap_end) {
    // Align heap boundaries to page boundaries
    heap_base  = FUT_PAGE_ALIGN(heap_start);
    heap_limit = FUT_PAGE_ALIGN(heap_end);

    // Create initial free block spanning entire heap
    free_list = (block_hdr_t *)heap_base;
    free_list->size = heap_limit - heap_base - sizeof(block_hdr_t);
    free_list->next = nullptr;

}

/**
 * Split a free block if it's significantly larger than needed.
 * This reduces fragmentation by returning excess space to the free list.
 */
static void split_block(block_hdr_t *block, size_t size) {
    /* Only split when there is enough space for a new header and payload. */
    if (block->size <= size + sizeof(block_hdr_t)) {
        return;
    }

    const size_t remain = block->size - size - sizeof(block_hdr_t);

    // Only split if remainder is large enough to be useful
    if (remain > sizeof(block_hdr_t)) {
        block_hdr_t *newb = (block_hdr_t *)((uintptr_t)block + sizeof(block_hdr_t) + size);
        newb->size = remain;
        newb->next = block->next;

        block->size = size;
        block->next = newb;
    }
}

/**
 * Helper: Check if pointer is within heap range.
 */
static inline bool is_heap_ptr(const void *ptr) {
    uintptr_t addr = (uintptr_t)ptr;
    return addr >= heap_base && addr < heap_limit;
}

void *fut_malloc(size_t size) {
    if (!size) return nullptr;

    // Round up to page alignment for simplicity and performance
    size = FUT_PAGE_ALIGN(size);


    // For very large allocations (>=4MB), use PMM directly
    // Note: PMM allocations are not automatically mapped, so this is disabled
    // until proper virtual memory mapping is implemented.
    // const size_t LARGE_ALLOC_THRESHOLD = 4 * 1024 * 1024;  // 4MB
    // if (size >= LARGE_ALLOC_THRESHOLD) {
    //     size_t num_pages = size / FUT_PAGE_SIZE;
    //     return fut_malloc_pages(num_pages);
    // }
    // For now, all allocations go through the heap (which is pre-mapped).

    // Search free list for suitable block (first-fit)
    for (block_hdr_t *prev = nullptr, *cur = free_list; cur; prev = cur, cur = cur->next) {
        if (cur->size >= size) {
            // Found suitable block - split if oversized
            split_block(cur, size);

            // Remove from free list
            if (prev) {
                prev->next = cur->next;
            } else {
                free_list = cur->next;
            }

            // Return pointer to usable space (after header)
            return (uint8_t *)cur + sizeof(block_hdr_t);
        }
    }

    return nullptr;  // Out of memory (heap exhausted)
}

/**
 * Helper: Coalesce adjacent free blocks to reduce fragmentation.
 * Repeatedly scans the free list and merges contiguous blocks until no more merges are possible.
 */
static void coalesce_free_blocks(void) {
    // Keep merging until no more adjacent blocks are found
    bool merged;
    do {
        merged = false;

        // For each block in the free list
        for (block_hdr_t *cur = free_list; cur && !merged; cur = cur->next) {
            // Calculate where the next contiguous block would be in physical memory
            uintptr_t cur_end = (uintptr_t)cur + sizeof(block_hdr_t) + cur->size;

            // Search for a block that starts immediately after this one
            block_hdr_t *prev = nullptr;
            for (block_hdr_t *search = free_list; search; prev = search, search = search->next) {
                // Skip if it's the same block
                if (search == cur) {
                    continue;
                }

                // Check if this block is physically adjacent
                if ((uintptr_t)search == cur_end) {
                    // Found adjacent block - merge it into cur
                    cur->size += sizeof(block_hdr_t) + search->size;

                    // Remove the merged block from free list
                    if (prev) {
                        prev->next = search->next;
                    } else {
                        free_list = search->next;
                    }

                    // Mark that we merged something and restart the outer loop
                    merged = true;
                    break;
                }
            }
        }
    } while (merged);  // Repeat until no more merges happen
}

void fut_free(void *ptr) {
    if (!ptr) return;

    // Check if this is a heap or PMM allocation
    if (!is_heap_ptr(ptr)) {
        // PMM allocation - cannot free without knowing size
        // This should only happen for fut_malloc_pages allocations which use fut_free_pages
        // Ignoring for now (user must use fut_free_pages for PMM allocations)
        return;
    }

    // Heap allocation - get block header
    block_hdr_t *blk = (block_hdr_t *)((uintptr_t)ptr - sizeof(block_hdr_t));

    // Insert at head of free list (LIFO for cache locality)
    blk->next = free_list;
    free_list = blk;

    // Coalesce adjacent free blocks to reduce fragmentation
    coalesce_free_blocks();
}

void *fut_realloc(void *ptr, size_t new_size) {
    if (!ptr) return fut_malloc(new_size);
    if (!new_size) {
        fut_free(ptr);
        return nullptr;
    }

    // Get current block header
    block_hdr_t *blk = (block_hdr_t *)((uintptr_t)ptr - sizeof(block_hdr_t));

    // If current block is large enough, just return it
    if (blk->size >= new_size) {
        return ptr;
    }

    // Allocate new block
    void *newp = fut_malloc(new_size);
    if (!newp) return nullptr;

    // Copy data from old to new (minimum of old and new sizes)
    const size_t copy = blk->size < new_size ? blk->size : new_size;
    for (size_t i = 0; i < copy; ++i) {
        ((uint8_t *)newp)[i] = ((uint8_t *)ptr)[i];
    }

    // Free old block
    fut_free(ptr);

    return newp;
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
