/* buddy_allocator.h - Buddy Allocator Public Interface
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#ifndef _KERNEL_BUDDY_ALLOCATOR_H_
#define _KERNEL_BUDDY_ALLOCATOR_H_

#include <stddef.h>
#include <stdint.h>

/* Initialize buddy allocator with heap bounds */
void buddy_heap_init(uintptr_t start, uintptr_t end);

/* Allocate memory block */
void *buddy_malloc(size_t size);

/* Free memory block */
void buddy_free(void *ptr);

/* Reallocate memory block */
void *buddy_realloc(void *ptr, size_t size);

/* Get statistics */
size_t buddy_get_total_allocated(void);
size_t buddy_get_heap_size(void);

#endif /* _KERNEL_BUDDY_ALLOCATOR_H_ */
