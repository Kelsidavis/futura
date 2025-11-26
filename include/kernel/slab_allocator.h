/* slab_allocator.h - Slab Allocator Public Interface
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#ifndef _KERNEL_SLAB_ALLOCATOR_H_
#define _KERNEL_SLAB_ALLOCATOR_H_

#include <stddef.h>

/* Initialize slab allocator caches */
void slab_init(void);

/* Allocate memory (uses slab for small objects, buddy for large) */
void *slab_malloc(size_t size);

/* Free memory */
void slab_free(void *ptr);

/* Reallocate memory */
void *slab_realloc(void *ptr, size_t size);

/* Print statistics */
void slab_print_stats(void);

/* Debug helper to validate all slabs and report corruption sources */
void slab_debug_validate_all(const char *context);

#endif /* _KERNEL_SLAB_ALLOCATOR_H_ */
