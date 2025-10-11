/* malloc.c - Memory Allocator for Futura OS Userland
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Simple bump allocator for userland processes.
 * Phase 3: Upgrade to proper malloc/free with free lists.
 */

#include <stddef.h>
#include <stdint.h>

/* Heap boundaries (set by linker or at runtime) */
extern char _heap_start;
extern char _heap_end;

/* Current heap pointer (bump allocator) */
static char *heap_ptr = &_heap_start;
static char *heap_limit = &_heap_end;

/**
 * Initialize heap (called from CRT0 or early startup).
 */
void heap_init(void *start, size_t size) {
    heap_ptr = (char *)start;
    heap_limit = (char *)start + size;
}

/**
 * Allocate memory (bump allocator).
 * Phase 3: Replace with proper malloc/free implementation.
 */
void *malloc(size_t size) {
    /* Align to 16 bytes */
    size = (size + 15) & ~15;

    /* Check if we have enough space */
    if (heap_ptr + size > heap_limit) {
        /* Out of memory - Phase 3: Request more memory from kernel */
        return NULL;
    }

    void *ptr = heap_ptr;
    heap_ptr += size;

    return ptr;
}

/**
 * Allocate and zero memory.
 */
void *calloc(size_t nmemb, size_t size) {
    size_t total = nmemb * size;
    void *ptr = malloc(total);

    if (ptr) {
        /* Zero the memory */
        unsigned char *p = (unsigned char *)ptr;
        for (size_t i = 0; i < total; i++) {
            p[i] = 0;
        }
    }

    return ptr;
}

/**
 * Reallocate memory.
 * Phase 3: Implement properly with copy and free.
 */
void *realloc(void *ptr, size_t size) {
    /* Phase 3: Proper implementation would:
     * 1. Allocate new block
     * 2. Copy old data
     * 3. Free old block
     */

    if (!ptr) {
        return malloc(size);
    }

    /* For now, always allocate new */
    void *new_ptr = malloc(size);
    if (!new_ptr) {
        return NULL;
    }

    /* Copy data (assume we don't know old size - this is a limitation) */
    /* Phase 3: Store allocation metadata to track sizes */
    unsigned char *src = (unsigned char *)ptr;
    unsigned char *dst = (unsigned char *)new_ptr;
    for (size_t i = 0; i < size; i++) {
        dst[i] = src[i];
    }

    return new_ptr;
}

/**
 * Free memory.
 * Phase 3: Implement with free lists.
 */
void free(void *ptr) {
    /* Bump allocator doesn't support free */
    /* Phase 3: Implement proper free list management */
    (void)ptr;
}

/**
 * Get heap statistics (for debugging).
 */
void heap_stats(size_t *used, size_t *total) {
    if (used) {
        *used = heap_ptr - &_heap_start;
    }
    if (total) {
        *total = heap_limit - &_heap_start;
    }
}
