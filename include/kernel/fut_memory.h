/* fut_memory.h - Futura OS Memory Manager (C23)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * A modern 64-bit physical memory manager and kernel heap for the
 * Futura nanokernel. Designed for bare-metal operation on x86-64, ARM64,
 * and Apple Silicon with no dependencies on libc or operating system services.
 *
 * Features:
 * - Bitmap-based physical memory manager for 4KB pages
 * - Simple kernel heap with first-fit allocation
 * - Power-of-two alignment for optimal performance
 * - Supports memory sizes from 8MB to multiple terabytes
 * - Fully freestanding (no undefined behavior, no libc)
 */

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* ============================================================
 *   Constants
 * ============================================================ */

#define FUT_PAGE_SIZE   4096ULL
#define FUT_PAGE_SHIFT  12ULL
#define FUT_PAGE_ALIGN(x) (((x) + FUT_PAGE_SIZE - 1ULL) & ~(FUT_PAGE_SIZE - 1ULL))

/* ============================================================
 *   Physical Memory Manager (PMM)
 * ============================================================ */

/**
 * Initialize the physical memory manager.
 *
 * @param mem_size_bytes Total physical memory available in bytes
 * @param phys_base      Physical address where usable memory starts
 *
 * The PMM will use the beginning of the memory region to store its
 * bitmap, which tracks allocated/free pages. Those pages are marked
 * as allocated to prevent reuse.
 */
void fut_pmm_init(uint64_t mem_size_bytes, uintptr_t phys_base);

/**
 * Allocate a single 4KB page of physical memory.
 *
 * @return Physical address of allocated page, or nullptr if no memory available
 */
void *fut_pmm_alloc_page(void);

/**
 * Free a previously allocated page.
 *
 * @param addr Physical address returned by fut_pmm_alloc_page()
 */
void fut_pmm_free_page(void *addr);

/**
 * Get total number of pages managed by PMM.
 *
 * @return Total page count
 */
uint64_t fut_pmm_total_pages(void);

/**
 * Get number of free pages available for allocation.
 *
 * @return Free page count
 */
uint64_t fut_pmm_free_pages(void);

/* ============================================================
 *   Kernel Heap
 * ============================================================ */

/**
 * Initialize the kernel heap allocator.
 *
 * @param heap_start Virtual/physical address where heap begins
 * @param heap_end   Virtual/physical address where heap ends
 *
 * The heap region is managed as a linked list of free blocks.
 * All allocations are page-aligned for simplicity and performance.
 */
void fut_heap_init(uintptr_t heap_start, uintptr_t heap_end);

/**
 * Allocate memory from kernel heap.
 *
 * @param size Number of bytes to allocate
 * @return Pointer to allocated memory, or nullptr on failure
 *
 * All allocations are page-aligned. Requests are rounded up to
 * the nearest page boundary.
 */
void *fut_malloc(size_t size);

/**
 * Free memory previously allocated by fut_malloc.
 *
 * @param ptr Pointer returned by fut_malloc(), or nullptr (no-op)
 */
void fut_free(void *ptr);

/**
 * Resize a previously allocated memory block.
 *
 * @param ptr      Existing allocation, or nullptr (acts like fut_malloc)
 * @param new_size New size in bytes, or 0 (acts like fut_free)
 * @return Pointer to resized block, or nullptr on failure
 *
 * Data from the old block is preserved up to min(old_size, new_size).
 * If reallocation fails, the original block remains unchanged.
 */
void *fut_realloc(void *ptr, size_t new_size);

/**
 * Allocate multiple contiguous pages directly from PMM.
 *
 * @param num_pages Number of contiguous 4KB pages to allocate
 * @return Pointer to first page, or nullptr on failure
 *
 * This is optimized for large allocations and bypasses the heap entirely.
 * Use fut_free_pages() to free allocations made with this function.
 */
void *fut_malloc_pages(size_t num_pages);

/**
 * Free pages allocated by fut_malloc_pages().
 *
 * @param ptr       Pointer returned by fut_malloc_pages()
 * @param num_pages Number of pages originally allocated
 */
void fut_free_pages(void *ptr, size_t num_pages);

/* ============================================================
 *   Diagnostics
 * ============================================================ */

/**
 * Print memory statistics to kernel console.
 *
 * Requires fut_printf() to be available. Displays:
 * - Total and free page counts
 * - Memory usage in MiB
 */
void fut_mem_print_stats(void);

/* ============================================================
 *   Kernel Printf (must be provided externally)
 * ============================================================ */

/**
 * Kernel printf function - must be implemented elsewhere.
 *
 * Expected signature: void fut_printf(const char *fmt, ...);
 */
extern void fut_printf(const char *fmt, ...);
