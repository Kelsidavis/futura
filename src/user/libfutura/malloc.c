// SPDX-License-Identifier: MPL-2.0
// Free-list allocator with brk-based backing store
//
// Freed blocks are returned to a free list for reuse. New allocations
// check the free list first, falling back to brk expansion. No block
// splitting or coalescing — keeps the implementation simple.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <user/sys.h>

/* Thread-safe spinlock for malloc */
static volatile int malloc_lock = 0;

static inline void malloc_lock_acquire(void) {
    while (__atomic_test_and_set(&malloc_lock, __ATOMIC_ACQUIRE)) {
        /* Spin */
    }
}

static inline void malloc_lock_release(void) {
    __atomic_clear(&malloc_lock, __ATOMIC_RELEASE);
}

/* Block header — sits immediately before the user-visible pointer.
 * On free, the user area is repurposed as a free_next pointer. */
typedef struct {
    size_t size;  /* Aligned user-area size (not including header) */
} alloc_header_t;

#define HEADER_SIZE sizeof(alloc_header_t)

/* Minimum user-area size must fit a pointer (for the free list link) */
#define MIN_ALLOC_SIZE 16u

static size_t align_size(size_t size) {
    size = (size + 15u) & ~15u;
    return size < MIN_ALLOC_SIZE ? MIN_ALLOC_SIZE : size;
}

/* Free list — singly-linked list through the user area of freed blocks */
typedef struct free_node {
    struct free_node *next;
} free_node_t;

static free_node_t *free_list = NULL;

void *malloc(size_t size) {
    if (size == 0) {
        return NULL;
    }

    size_t aligned = align_size(size);
    size_t total = HEADER_SIZE + aligned;

    malloc_lock_acquire();

    /* First-fit search of the free list */
    free_node_t **prev = &free_list;
    free_node_t *node = free_list;
    while (node) {
        alloc_header_t *hdr = (alloc_header_t *)((uint8_t *)node - HEADER_SIZE);
        if (hdr->size >= aligned) {
            /* Remove from free list and return this block */
            *prev = node->next;
            malloc_lock_release();
            return (void *)node;
        }
        prev = &node->next;
        node = node->next;
    }

    /* Nothing suitable on the free list — expand the heap via brk */
    long current = sys_brk_call(NULL);
    if (current < 0 || (uintptr_t)current < 0x10000) {
        malloc_lock_release();
        return NULL;
    }

    long requested = current + (long)total;
    long rc = sys_brk_call((void *)(uintptr_t)requested);
    if (rc < 0 || rc < requested) {
        malloc_lock_release();
        return NULL;
    }

    malloc_lock_release();

    /* Set up header */
    alloc_header_t *header = (alloc_header_t *)(uintptr_t)current;
    header->size = aligned;

    return (void *)((uint8_t *)header + HEADER_SIZE);
}

void free(void *ptr) {
    if (!ptr) {
        return;
    }

    /* Sanity: reject obviously-bad pointers */
    if ((uintptr_t)ptr < 0x10000) {
        return;
    }

    malloc_lock_acquire();

    /* Push onto the free list — the user area becomes a free_node_t */
    free_node_t *node = (free_node_t *)ptr;
    node->next = free_list;
    free_list = node;

    malloc_lock_release();
}

void *calloc(size_t nmemb, size_t size) {
    /* Check for multiplication overflow */
    if (nmemb != 0 && size > __SIZE_MAX__ / nmemb) {
        return NULL;
    }
    size_t total_size = nmemb * size;
    void *ptr = malloc(total_size);
    if (ptr) {
        memset(ptr, 0, total_size);
    }
    return ptr;
}

void *realloc(void *ptr, size_t size) {
    if (!ptr) {
        return malloc(size);
    }
    if (size == 0) {
        free(ptr);
        return NULL;
    }

    /* Get old size from header */
    alloc_header_t *header = (alloc_header_t *)((uint8_t *)ptr - HEADER_SIZE);
    size_t old_size = header->size;

    if (old_size >= size) {
        return ptr;  /* Already big enough */
    }

    void *new_ptr = malloc(size);
    if (!new_ptr) {
        return NULL;
    }

    size_t copy = old_size < size ? old_size : size;
    memcpy(new_ptr, ptr, copy);
    free(ptr);
    return new_ptr;
}

void heap_stats(size_t *used, size_t *total) {
    (void)used;
    (void)total;
}
