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

    extern void fut_printf(const char *, ...);
    fut_printf("[BUDDY-INIT] Initializing buddy allocator: start=%p end=%p (size=%llu KB)\n",
               (void*)start, (void*)end, (unsigned long long)((end - start) / 1024));

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

    extern void fut_printf(const char *, ...);

    if (order > MAX_ORDER) {
        fut_printf("[BUDDY-MALLOC] FAILED: size=%llu needed=%llu order=%d MAX=%d\n",
                   (unsigned long long)size, (unsigned long long)needed, order, MAX_ORDER);
        return NULL;  /* Too large */
    }

    fut_printf("[BUDDY-MALLOC] Requesting %llu bytes (order=%d, heap=%p-%p)\n",
               (unsigned long long)size, order, (void*)heap_start, (void*)heap_end);

    /* Search free lists starting from requested order */
    int search_order = order;
    while (search_order <= MAX_ORDER) {
        free_block_t *candidate = free_lists[search_order - MIN_ORDER];

        /* Debug: list all blocks in this free list */
        int block_count = 0;
        free_block_t *tmp = candidate;
        while (tmp) {
            /* Safety: Validate pointer before dereferencing */
            if ((uintptr_t)tmp < heap_start || (uintptr_t)tmp >= heap_end) {
                fut_printf("[BUDDY-MALLOC] ERROR: Corrupted free list pointer %p (outside heap bounds)\n", (void*)tmp);
                fut_printf("[BUDDY-MALLOC]   Heap bounds: %p - %p\n", (void*)heap_start, (void*)heap_end);
                return NULL;  /* Abort allocation due to heap corruption */
            }
            block_count++;
            tmp = tmp->next;
        }
        if (block_count > 0) {
            fut_printf("[BUDDY-MALLOC] Order %d has %d free blocks\n", search_order, block_count);
        }

        if (candidate != NULL) {
            fut_printf("[BUDDY-MALLOC] Found free block at order %d (size %llu) candidate=%p\n",
                       search_order, (unsigned long long)order_to_size(search_order), (void*)candidate);

            /* Get the block header */
            block_hdr_t *hdr = (block_hdr_t *)candidate - 1;
            fut_printf("[BUDDY-MALLOC] Block header at %p\n", (void*)hdr);

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
            while (hdr->order > order) {
                hdr->order--;

                /* Create buddy block */
                uintptr_t addr = (uintptr_t)hdr;
                uintptr_t buddy_addr = get_buddy_addr(addr, order_to_size(hdr->order));
                block_hdr_t *buddy_hdr = (block_hdr_t *)buddy_addr;

                buddy_hdr->order = hdr->order;
                buddy_hdr->is_allocated = 0;
                buddy_hdr->magic = BLOCK_MAGIC;

                /* Only add buddy to free list if it's within heap bounds */
                size_t buddy_size = order_to_size(hdr->order);
                if (buddy_addr >= heap_start && (buddy_addr + buddy_size) <= heap_end) {
                    /* Add buddy to free list */
                    free_block_t *buddy_free = (free_block_t *)get_data_ptr(buddy_hdr);
                    buddy_free->next = free_lists[hdr->order - MIN_ORDER];
                    buddy_free->prev = NULL;
                    if (free_lists[hdr->order - MIN_ORDER]) {
                        free_lists[hdr->order - MIN_ORDER]->prev = buddy_free;
                    }
                    free_lists[hdr->order - MIN_ORDER] = buddy_free;
                } else {
                    fut_printf("[BUDDY-MALLOC] WARNING: Buddy block outside heap bounds, skipping\n");
                    fut_printf("[BUDDY-MALLOC]   Buddy: %p-%p (size=%llu)\n",
                               (void*)buddy_addr, (void*)(buddy_addr + buddy_size),
                               (unsigned long long)buddy_size);
                }
            }

            /* Validate block is within heap bounds */
            uintptr_t block_addr = (uintptr_t)hdr;
            size_t block_size = order_to_size(hdr->order);
            if (block_addr < heap_start || (block_addr + block_size) > heap_end) {
                fut_printf("[BUDDY-MALLOC] ERROR: Block OUTSIDE heap bounds!\n");
                fut_printf("[BUDDY-MALLOC]   Block: %p-%p (size=%llu)\n",
                           (void*)block_addr, (void*)(block_addr + block_size),
                           (unsigned long long)block_size);
                fut_printf("[BUDDY-MALLOC]   Heap:  %p-%p\n",
                           (void*)heap_start, (void*)heap_end);
                return NULL;  /* Refuse to allocate outside heap */
            }

            /* Mark as allocated */
            hdr->is_allocated = 1;
            total_allocated += order_to_size(hdr->order);

            void *result = get_data_ptr(hdr);

            /* NOTE: Memory clearing has been removed due to issues with RAMFS file buffers
             * being cleared after successful writes. The VFS layer (ramfs) uses guard values
             * (magic_guard_before/after) to detect corruption instead.
             * CRITICAL: Callers MUST initialize their data appropriately.
             */

            fut_printf("[BUDDY-MALLOC] Allocated at %p (hdr=%p size=%llu)\n",
                       result, (void*)hdr, (unsigned long long)order_to_size(hdr->order));
            return result;
        }

        search_order++;
    }

    /* Out of memory - print detailed fragmentation info */
    fut_printf("[BUDDY-MALLOC] OUT OF MEMORY: size=%llu (needed=%llu, requested order=%d)\n",
               (unsigned long long)size, (unsigned long long)needed, order);

    /* Print free block count at each order to understand fragmentation */
    fut_printf("[BUDDY-MALLOC] Heap fragmentation status:\n");
    size_t total_free_size = 0;
    for (int i = 0; i < NUM_ORDERS; i++) {
        int order_val = i + MIN_ORDER;
        free_block_t *candidate = free_lists[i];
        int count = 0;
        while (candidate) {
            /* Safety: Validate pointer before dereferencing */
            if ((uintptr_t)candidate < heap_start || (uintptr_t)candidate >= heap_end) {
                fut_printf("[BUDDY-MALLOC] WARNING: Corrupted free list at order %d, pointer %p outside heap\n",
                          order_val, (void*)candidate);
                break;
            }
            count++;
            total_free_size += order_to_size(order_val);
            candidate = candidate->next;
        }
        if (count > 0) {
            fut_printf("[BUDDY-MALLOC]   Order %2d (2^%2d = %8llu bytes): %d blocks (total %llu bytes)\n",
                       order_val, order_val, (unsigned long long)order_to_size(order_val), count,
                       (unsigned long long)(count * order_to_size(order_val)));
        }
    }
    fut_printf("[BUDDY-MALLOC] Total free size: %llu bytes, Total allocated: %llu bytes\n",
               (unsigned long long)total_free_size, (unsigned long long)total_allocated);

    return NULL;  /* Out of memory */
}

void buddy_free(void *ptr) {
    if (ptr == NULL) return;

    extern void fut_printf(const char *, ...);

    fut_printf("[BUDDY-FREE-START] Freeing ptr=%p\n", ptr);

    /* CRITICAL: Validate that ptr and header location are within heap bounds BEFORE reading header */
    uintptr_t ptr_addr = (uintptr_t)ptr;
    if (ptr_addr < heap_start || ptr_addr >= heap_end) {
        fut_printf("[BUDDY-FREE] ERROR: Pointer %p is outside heap bounds [%p-%p]\n",
                   ptr, (void*)heap_start, (void*)heap_end);
        return;
    }

    /* Check that the header location would be within bounds */
    uintptr_t hdr_addr = ptr_addr - sizeof(block_hdr_t);
    if (hdr_addr < heap_start || hdr_addr >= heap_end) {
        fut_printf("[BUDDY-FREE] ERROR: Header location %p would be outside heap bounds\n", (void*)hdr_addr);
        return;
    }

    block_hdr_t *hdr = get_block_hdr(ptr);
    fut_printf("[BUDDY-FREE-START] Block header at %p, magic=0x%x, allocated=%d, order=%d\n",
               (void*)hdr, hdr->magic, hdr->is_allocated, hdr->order);

    /* Validate block */
    if (hdr->magic != BLOCK_MAGIC || !hdr->is_allocated) {
        fut_printf("[BUDDY-FREE-START] Invalid block or double-free, returning\n");
        return;  /* Invalid or double-free */
    }

    fut_printf("[BUDDY-FREE-START] About to update total_allocated and mark as free\n");
    total_allocated -= order_to_size(hdr->order);
    hdr->is_allocated = 0;
    fut_printf("[BUDDY-FREE-START] Marked as free, starting coalesce\n");

    /* Add to free list and coalesce with buddy if possible */
    int order = hdr->order;
    uintptr_t addr = (uintptr_t)hdr;
    int coalesce_count = 0;

    while (order < MAX_ORDER) {
        uintptr_t buddy_addr = get_buddy_addr(addr, order_to_size(order));

        /* Check if buddy is free and in heap */
        if (!is_in_heap(buddy_addr)) {
            /* Cannot coalesce - buddy is outside heap bounds */
            fut_printf("[BUDDY-FREE] Coalesce stop at order %d: buddy %p outside heap bounds [%p-%p]\n",
                       order, (void*)buddy_addr, (void*)heap_start, (void*)heap_end);
            break;
        }

        /* CRITICAL: Validate entire buddy block header is within bounds */
        size_t buddy_block_size = order_to_size(order);
        if (buddy_addr + buddy_block_size > heap_end) {
            fut_printf("[BUDDY-FREE] Coalesce stop at order %d: buddy block extends beyond heap end\n", order);
            fut_printf("[BUDDY-FREE]   Block: %p-%p, Heap end: %p\n",
                       (void*)buddy_addr, (void*)(buddy_addr + buddy_block_size), (void*)heap_end);
            break;
        }

        block_hdr_t *buddy_hdr = (block_hdr_t *)buddy_addr;

        /* Validate buddy and check if free */
        if (buddy_hdr->magic != BLOCK_MAGIC) {
            /* Buddy has invalid magic - corruption or never allocated */
            fut_printf("[BUDDY-FREE] Coalesce stop at order %d: buddy %p has invalid magic 0x%x\n",
                       order, (void*)buddy_addr, buddy_hdr->magic);
            break;
        }

        if (buddy_hdr->order != order) {
            /* Buddy has different order - can't merge */
            fut_printf("[BUDDY-FREE] Coalesce stop at order %d: buddy order mismatch (buddy=%d, expected=%d)\n",
                       order, buddy_hdr->order, order);
            break;
        }

        if (buddy_hdr->is_allocated) {
            /* Buddy is still allocated - can't merge */
            fut_printf("[BUDDY-FREE] Coalesce stop at order %d: buddy is allocated\n", order);
            break;
        }

        /* Coalesce: remove buddy from free list */
        free_block_t *buddy_free = (free_block_t *)get_data_ptr(buddy_hdr);

        /* CRITICAL: Validate buddy_free pointer before dereferencing */
        if ((uintptr_t)buddy_free < heap_start || (uintptr_t)buddy_free >= heap_end) {
            fut_printf("[BUDDY-FREE] Coalesce stop at order %d: buddy_free data pointer %p outside heap bounds\n",
                       order, (void*)buddy_free);
            break;
        }

        /* Validate that buddy's next pointer won't corrupt free list */
        if (buddy_free->next != NULL && ((uintptr_t)buddy_free->next < heap_start || (uintptr_t)buddy_free->next >= heap_end)) {
            fut_printf("[BUDDY-FREE] Coalesce stop at order %d: buddy->next pointer %p is corrupted (outside heap)\n",
                       order, (void*)buddy_free->next);
            break;
        }

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

            /* CRITICAL: Revalidate the new hdr after reassignment */
            if ((uintptr_t)hdr < heap_start || (uintptr_t)hdr >= heap_end) {
                fut_printf("[BUDDY-FREE] ERROR: Coalesced header %p is outside heap bounds after merging\n", (void*)hdr);
                break;
            }
        }

        hdr->order++;
        order++;
        coalesce_count++;
    }

    if (coalesce_count > 0) {
        fut_printf("[BUDDY-FREE] Coalesced %d times (block %p, final order %d)\n",
                   coalesce_count, (void*)addr, order);
    }

    /* CRITICAL: Validate final coalesced block before adding to free list */
    if ((uintptr_t)hdr < heap_start || (uintptr_t)hdr >= heap_end) {
        fut_printf("[BUDDY-FREE] ERROR: Final coalesced header %p outside heap bounds!\n", (void*)hdr);
        return;
    }

    size_t final_block_size = order_to_size(order);
    if ((uintptr_t)hdr + final_block_size > heap_end) {
        fut_printf("[BUDDY-FREE] ERROR: Final coalesced block extends beyond heap end!\n");
        fut_printf("[BUDDY-FREE]   Block: %p-%p, Heap end: %p\n",
                   (void*)hdr, (void*)((uintptr_t)hdr + final_block_size), (void*)heap_end);
        return;
    }

    /* Add coalesced block to free list */
    fut_printf("[BUDDY-FREE] About to add to free list: hdr=%p order=%d order-MIN_ORDER=%d\n",
               (void*)hdr, order, order - MIN_ORDER);
    free_block_t *free_hdr = (free_block_t *)get_data_ptr(hdr);
    fut_printf("[BUDDY-FREE] free_hdr=%p current list head=%p\n",
               (void*)free_hdr, (void*)free_lists[order - MIN_ORDER]);

    /* Validate free_hdr is within heap bounds before using it */
    if ((uintptr_t)free_hdr < heap_start || (uintptr_t)free_hdr >= heap_end) {
        fut_printf("[BUDDY-FREE] ERROR: free_hdr data pointer %p outside heap bounds!\n", (void*)free_hdr);
        return;
    }

    free_hdr->next = free_lists[order - MIN_ORDER];
    fut_printf("[BUDDY-FREE] Set free_hdr->next=%p\n", (void*)free_hdr->next);

    /* Validate the current list head isn't corrupted before updating it */
    if (free_lists[order - MIN_ORDER] != NULL) {
        if ((uintptr_t)free_lists[order - MIN_ORDER] < heap_start ||
            (uintptr_t)free_lists[order - MIN_ORDER] >= heap_end) {
            fut_printf("[BUDDY-FREE] ERROR: Current list head %p is corrupted (outside heap)!\n",
                       (void*)free_lists[order - MIN_ORDER]);
            return;
        }
    }

    free_hdr->prev = NULL;
    if (free_lists[order - MIN_ORDER]) {
        fut_printf("[BUDDY-FREE] Setting prev pointer on old head\n");
        free_lists[order - MIN_ORDER]->prev = free_hdr;
    }
    fut_printf("[BUDDY-FREE] Updating list head to %p\n", (void*)free_hdr);
    free_lists[order - MIN_ORDER] = free_hdr;
    fut_printf("[BUDDY-FREE] Free complete\n");
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
