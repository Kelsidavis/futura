/* buddy_allocator.c - Buddy Heap Allocator for Futura OS
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * A power-of-2 buddy allocator that prevents fragmentation through automatic coalescing.
 * Suitable for kernel heap management with support for arbitrary allocation sizes.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

/* ============================================================
 *   Buddy Allocator Constants and Data Structures
 * ============================================================ */

/* Minimum allocation size: 64 bytes (covers typical structures + header) */
#define MIN_ORDER 6                                    /* 2^6 = 64 bytes */
#define MIN_BLOCK_SIZE (1UL << MIN_ORDER)

/* Maximum allocation size: 512 MB (covers 512MB heap) */
#define MAX_ORDER 29                                   /* 2^29 = 512 MB */
#define MAX_BLOCK_SIZE (1UL << MAX_ORDER)

/* Number of free lists, one per order */
#define NUM_ORDERS (MAX_ORDER - MIN_ORDER + 1)

/* Block header: packed metadata (8 bytes) */
typedef struct block_hdr {
    uint32_t order : 5;         /* Order (0-29) - 5 bits */
    uint32_t is_allocated : 1;  /* Allocation flag - 1 bit */
    uint32_t reserved : 26;     /* Reserved - 26 bits */
    uint32_t magic;             /* Magic number for validation */
} block_hdr_t;

#define BLOCK_MAGIC 0xDEADBEEF

/* Free block list node */
typedef struct free_block {
    struct free_block *next;
    struct free_block *prev;
} free_block_t;

/* ============================================================
 *   Buddy Allocator State
 * ============================================================ */

static free_block_t *free_lists[NUM_ORDERS];  /* Free list for each order */
static uintptr_t heap_start = 0;              /* Heap base address */
static uintptr_t heap_end = 0;                /* Heap end address */
static size_t total_allocated = 0;            /* Total bytes allocated */

/* ============================================================
 *   Helper Macros and Functions
 * ============================================================ */

/* Get block order from size (rounds up to next power of 2) */
static inline int size_to_order(size_t size) {
    if (size <= MIN_BLOCK_SIZE) return MIN_ORDER;

    int order = MIN_ORDER;
    size_t block_size = MIN_BLOCK_SIZE;

    while (order < MAX_ORDER && block_size < size) {
        order++;
        block_size <<= 1;
    }

    return order;
}

/* Get block size from order */
static inline size_t order_to_size(int order) {
    return 1UL << order;
}

/* Get block header from data pointer */
static inline block_hdr_t *get_block_hdr(const void *ptr) {
    return (block_hdr_t *)ptr - 1;
}

/* Get data pointer from block header */
static inline void *get_data_ptr(block_hdr_t *hdr) {
    return (void *)(hdr + 1);
}

/* Get buddy block address (XOR with block size) */
static inline uintptr_t get_buddy_addr(uintptr_t addr, size_t block_size) {
    return addr ^ block_size;
}

/* Check if pointer is within heap */
static inline bool is_in_heap(uintptr_t addr) {
    return addr >= heap_start && addr < heap_end;
}

/* ============================================================
 *   Buddy Allocator Core Operations
 * ============================================================ */

void buddy_heap_init(uintptr_t start, uintptr_t end) {
    heap_start = start;
    heap_end = end;
    total_allocated = 0;

    /* Initialize all free lists */
    for (int i = 0; i < NUM_ORDERS; i++) {
        free_lists[i] = NULL;
    }

    /* Create initial free block spanning entire heap */
    size_t heap_size = end - start;
    int initial_order = size_to_order(heap_size);

    if (initial_order > MAX_ORDER) {
        initial_order = MAX_ORDER;
    }

    /* Add initial block to appropriate free list */
    block_hdr_t *initial = (block_hdr_t *)start;
    initial->order = initial_order;
    initial->is_allocated = 0;
    initial->magic = BLOCK_MAGIC;

    free_block_t *freeblk = (free_block_t *)get_data_ptr(initial);
    freeblk->next = NULL;
    freeblk->prev = NULL;

    free_lists[initial_order - MIN_ORDER] = freeblk;
}

void *buddy_malloc(size_t size) {
    if (size == 0) return NULL;

    /* Account for block header */
    size_t needed = size + sizeof(block_hdr_t);
    int order = size_to_order(needed);

    if (order > MAX_ORDER) {
        return NULL;  /* Too large */
    }

    /* Search free lists starting from requested order */
    int search_order = order;
    while (search_order <= MAX_ORDER) {
        free_block_t *candidate = free_lists[search_order - MIN_ORDER];

        if (candidate != NULL) {
            /* Found a free block - remove from free list */
            if (candidate->next) {
                candidate->next->prev = candidate->prev;
            }
            if (candidate->prev) {
                candidate->prev->next = candidate->next;
            } else {
                free_lists[search_order - MIN_ORDER] = candidate->next;
            }

            /* Split block recursively if it's larger than needed */
            block_hdr_t *hdr = (block_hdr_t *)candidate - 1;
            while (hdr->order > order) {
                hdr->order--;

                /* Create buddy block */
                uintptr_t addr = (uintptr_t)hdr;
                uintptr_t buddy_addr = get_buddy_addr(addr, order_to_size(hdr->order));
                block_hdr_t *buddy_hdr = (block_hdr_t *)buddy_addr;

                buddy_hdr->order = hdr->order;
                buddy_hdr->is_allocated = 0;
                buddy_hdr->magic = BLOCK_MAGIC;

                /* Add buddy to free list */
                free_block_t *buddy_free = (free_block_t *)get_data_ptr(buddy_hdr);
                buddy_free->next = free_lists[hdr->order - MIN_ORDER];
                buddy_free->prev = NULL;
                if (free_lists[hdr->order - MIN_ORDER]) {
                    free_lists[hdr->order - MIN_ORDER]->prev = buddy_free;
                }
                free_lists[hdr->order - MIN_ORDER] = buddy_free;
            }

            /* Mark as allocated */
            hdr->is_allocated = 1;
            total_allocated += order_to_size(hdr->order);

            return get_data_ptr(hdr);
        }

        search_order++;
    }

    return NULL;  /* Out of memory */
}

void buddy_free(void *ptr) {
    if (ptr == NULL) return;

    block_hdr_t *hdr = get_block_hdr(ptr);

    /* Validate block */
    if (hdr->magic != BLOCK_MAGIC || !hdr->is_allocated) {
        return;  /* Invalid or double-free */
    }

    total_allocated -= order_to_size(hdr->order);
    hdr->is_allocated = 0;

    /* Add to free list and coalesce with buddy if possible */
    int order = hdr->order;
    uintptr_t addr = (uintptr_t)hdr;

    while (order < MAX_ORDER) {
        uintptr_t buddy_addr = get_buddy_addr(addr, order_to_size(order));

        /* Check if buddy is free and in heap */
        if (!is_in_heap(buddy_addr)) {
            break;  /* Buddy out of range, can't coalesce */
        }

        block_hdr_t *buddy_hdr = (block_hdr_t *)buddy_addr;

        /* Validate buddy and check if free */
        if (buddy_hdr->magic != BLOCK_MAGIC || buddy_hdr->order != order ||
            buddy_hdr->is_allocated) {
            break;  /* Buddy not free or invalid */
        }

        /* Coalesce: remove buddy from free list */
        free_block_t *buddy_free = (free_block_t *)get_data_ptr(buddy_hdr);
        if (buddy_free->next) {
            buddy_free->next->prev = buddy_free->prev;
        }
        if (buddy_free->prev) {
            buddy_free->prev->next = buddy_free->next;
        } else {
            free_lists[order - MIN_ORDER] = buddy_free->next;
        }

        /* Merge blocks: use lower address as combined block */
        if (addr > buddy_addr) {
            addr = buddy_addr;
            hdr = (block_hdr_t *)addr;
        }

        hdr->order++;
        order++;
    }

    /* Add coalesced block to free list */
    free_block_t *free_hdr = (free_block_t *)get_data_ptr(hdr);
    free_hdr->next = free_lists[order - MIN_ORDER];
    free_hdr->prev = NULL;
    if (free_lists[order - MIN_ORDER]) {
        free_lists[order - MIN_ORDER]->prev = free_hdr;
    }
    free_lists[order - MIN_ORDER] = free_hdr;
}

void *buddy_realloc(void *ptr, size_t size) {
    if (ptr == NULL) return buddy_malloc(size);
    if (size == 0) {
        buddy_free(ptr);
        return NULL;
    }

    block_hdr_t *hdr = get_block_hdr(ptr);
    if (hdr->magic != BLOCK_MAGIC) {
        return NULL;  /* Invalid pointer */
    }

    size_t current_size = order_to_size(hdr->order) - sizeof(block_hdr_t);

    if (size <= current_size) {
        /* Requested size fits in current block */
        return ptr;
    }

    /* Need larger block */
    void *new_ptr = buddy_malloc(size);
    if (new_ptr == NULL) {
        return NULL;  /* Allocation failed */
    }

    /* Copy data */
    memcpy(new_ptr, ptr, current_size);

    /* Free old block */
    buddy_free(ptr);

    return new_ptr;
}

size_t buddy_get_total_allocated(void) {
    return total_allocated;
}

size_t buddy_get_heap_size(void) {
    return heap_end - heap_start;
}
