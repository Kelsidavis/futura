// SPDX-License-Identifier: MPL-2.0
/*
 * buddy_allocator.h - Buddy Allocator Public Interface
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Power-of-two buddy allocator for kernel heap management. The buddy
 * algorithm provides O(log n) allocation and deallocation with low
 * external fragmentation through block splitting and coalescing.
 *
 * How it works:
 *   - Memory is divided into blocks of power-of-two sizes
 *   - When allocating, find smallest block >= requested size
 *   - If no exact block, split larger block in half ("buddies")
 *   - When freeing, check if "buddy" block is also free
 *   - If buddy is free, coalesce back into larger block
 *
 * This allocator is used for the kernel heap (fut_malloc/fut_free)
 * and provides memory for kernel data structures, buffers, and
 * internal allocations.
 */

#ifndef _KERNEL_BUDDY_ALLOCATOR_H_
#define _KERNEL_BUDDY_ALLOCATOR_H_

#include <stddef.h>
#include <stdint.h>

/**
 * Initialize the buddy allocator with a memory region.
 *
 * Must be called once during early boot before any allocations.
 * The region [start, end) will be managed by the allocator.
 *
 * @param start  Physical/virtual address of heap start (page-aligned)
 * @param end    Physical/virtual address of heap end (page-aligned)
 */
void buddy_heap_init(uintptr_t start, uintptr_t end);

/**
 * Allocate a memory block.
 *
 * Returns a pointer to at least 'size' bytes of memory. The actual
 * allocation may be larger (rounded up to power of two). Memory is
 * not zeroed.
 *
 * @param size  Minimum number of bytes to allocate
 * @return Pointer to allocated memory, or NULL if out of memory
 */
void *buddy_malloc(size_t size);

/**
 * Free a previously allocated memory block.
 *
 * The pointer must have been returned by buddy_malloc() or
 * buddy_realloc(). Passing NULL is a no-op. Double-free is
 * undefined behavior.
 *
 * @param ptr  Pointer to free (may be NULL)
 */
void buddy_free(void *ptr);

/**
 * Resize an allocated memory block.
 *
 * Changes the size of the allocation at ptr to size bytes. Contents
 * are preserved up to the minimum of old and new sizes. May move the
 * block to a new location.
 *
 * Special cases:
 *   - ptr == NULL: equivalent to buddy_malloc(size)
 *   - size == 0: equivalent to buddy_free(ptr), returns NULL
 *
 * @param ptr   Pointer to reallocate (may be NULL)
 * @param size  New size in bytes
 * @return Pointer to resized block, or NULL on failure
 */
void *buddy_realloc(void *ptr, size_t size);

/**
 * Get total bytes currently allocated.
 *
 * @return Sum of all active allocation sizes
 */
size_t buddy_get_total_allocated(void);

/**
 * Get total heap size.
 *
 * @return Total size of heap region in bytes
 */
size_t buddy_get_heap_size(void);

#endif /* _KERNEL_BUDDY_ALLOCATOR_H_ */
