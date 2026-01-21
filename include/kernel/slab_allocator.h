// SPDX-License-Identifier: MPL-2.0
/*
 * slab_allocator.h - Slab Allocator Public Interface
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Slab allocator for efficient allocation of small, frequently-used
 * objects. Maintains per-size caches to reduce fragmentation and
 * improve allocation speed for common kernel object sizes.
 *
 * Architecture:
 *   - Small allocations (<= max slab size): served from size-specific caches
 *   - Large allocations (> max slab size): passed to buddy allocator
 *   - Each slab cache contains pre-allocated slots for objects of one size
 *   - Free slots are tracked via a freelist within each slab
 *
 * Benefits over pure buddy allocation:
 *   - O(1) allocation/free for cached sizes
 *   - Reduced internal fragmentation for small objects
 *   - Better cache locality for frequently allocated objects
 *
 * Typical cache sizes: 16, 32, 64, 128, 256, 512, 1024, 2048 bytes
 */

#ifndef _KERNEL_SLAB_ALLOCATOR_H_
#define _KERNEL_SLAB_ALLOCATOR_H_

#include <stddef.h>

/**
 * Initialize the slab allocator.
 *
 * Creates size-specific caches for common allocation sizes.
 * Must be called after buddy_heap_init() and before any slab allocations.
 */
void slab_init(void);

/**
 * Allocate memory from slab caches or buddy allocator.
 *
 * For small sizes, uses an appropriate slab cache for O(1) allocation.
 * For large sizes, falls back to the buddy allocator.
 *
 * @param size  Number of bytes to allocate
 * @return Pointer to allocated memory, or NULL if out of memory
 */
void *slab_malloc(size_t size);

/**
 * Free memory back to slab cache or buddy allocator.
 *
 * Automatically determines whether the allocation came from a slab
 * cache or the buddy allocator and frees appropriately.
 *
 * @param ptr  Pointer to free (may be NULL)
 */
void slab_free(void *ptr);

/**
 * Resize an allocated memory block.
 *
 * May move the block to a new location. Contents are preserved
 * up to the minimum of old and new sizes.
 *
 * @param ptr   Pointer to reallocate (may be NULL)
 * @param size  New size in bytes
 * @return Pointer to resized block, or NULL on failure
 */
void *slab_realloc(void *ptr, size_t size);

/**
 * Print slab allocator statistics.
 *
 * Outputs per-cache statistics including total allocations,
 * current usage, and fragmentation metrics.
 */
void slab_print_stats(void);

/**
 * Validate all slab caches for corruption.
 *
 * Checks freelist integrity, magic numbers, and other internal
 * consistency markers. Reports any corruption found with context.
 *
 * @param context  Description of when validation is occurring (for logs)
 */
void slab_debug_validate_all(const char *context);

#endif /* _KERNEL_SLAB_ALLOCATOR_H_ */
