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
#include <kernel/kprintf.h>

/* ============================================================
 *   Buddy Allocator Constants and Data Structures
 * ============================================================ */

/* Debug verbosity control - disabled by default for performance */
#ifdef BUDDY_VERBOSE_DEBUG
#define BUDDY_DEBUG_PRINTF(...) fut_printf(__VA_ARGS__)
#else
#define BUDDY_DEBUG_PRINTF(...) do {} while(0)
#endif

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

    BUDDY_DEBUG_PRINTF("[BUDDY-INIT] Initializing buddy allocator: start=%p end=%p (size=%llu KB)\n",
               (void*)start, (void*)end, (unsigned long long)((end - start) / 1024));

    /* Initialize all free lists */
    for (int i = 0; i < NUM_ORDERS; i++) {
        free_lists[i] = NULL;
    }

    /* CRITICAL FIX: Calculate the maximum order that heap start is actually aligned to.
     * The buddy allocator's XOR-based buddy address calculation assumes power-of-2 alignment
     * at the order size. If heap start is misaligned, buddy calculations produce wrong addresses,
     * corrupting the free lists and causing heap chaos.
     *
     * Instead of using the full heap size for the initial block order, we use the largest
     * power-of-2 that divides the heap start address. This ensures all blocks are properly aligned
     * for correct buddy address calculations throughout the heap's lifetime. */

    int max_alignment_order = MIN_ORDER;  /* At least page-sized (MIN_ORDER = 6, 64 bytes) */

    /* Find the highest bit set in the heap start address
     * This tells us the maximum power-of-2 alignment */
    if (start != 0) {
        /* Count trailing zeros in the address (= log2 of alignment) */
        uintptr_t alignment = start & -start;  /* Isolate lowest set bit */
        int alignment_shift = 0;
        uintptr_t temp = alignment;
        while (temp > 1) {
            temp >>= 1;
            alignment_shift++;
        }

        if (alignment_shift >= MIN_ORDER) {
            max_alignment_order = alignment_shift;
        }

        BUDDY_DEBUG_PRINTF("[BUDDY-INIT] Heap start %p is aligned to 2^%d bytes\n",
                   (void*)start, alignment_shift);
    }

    /* Create initial free block based on heap size, but don't exceed the alignment constraint */
    size_t heap_size = end - start;
    int initial_order = size_to_order(heap_size);

    /* Limit initial order to what the heap start is actually aligned to */
    if (initial_order > max_alignment_order) {
        BUDDY_DEBUG_PRINTF("[BUDDY-INIT] LIMITING initial order from %d to %d due to address alignment\n",
                   initial_order, max_alignment_order);
        initial_order = max_alignment_order;
    }

    if (initial_order > MAX_ORDER) {
        initial_order = MAX_ORDER;
    }

    BUDDY_DEBUG_PRINTF("[BUDDY-INIT] Creating initial free block with order %d (size=%llu bytes)\n",
               initial_order, (unsigned long long)(1UL << initial_order));

    /* Add blocks to fill the entire heap, starting with properly-aligned blocks.
     * If the heap start is misaligned, we create smaller blocks until we reach
     * an address where we can create larger aligned blocks. */

    uintptr_t current_addr = start;
    size_t remaining_size = heap_size;

    int iteration = 0;
    while (remaining_size > 0 && current_addr < end) {
        /* Find the largest order that fits in remaining space AND is properly aligned at current_addr */
        int block_order = MIN_ORDER;

        /* Determine the maximum order based on address alignment */
        int alignment_shift = MIN_ORDER;
        if (current_addr != 0) {
            uintptr_t alignment = current_addr & -current_addr;
            alignment_shift = 0;
            uintptr_t temp = alignment;
            while (temp > 1) {
                temp >>= 1;
                alignment_shift++;
            }
            if (alignment_shift < MIN_ORDER) {
                alignment_shift = MIN_ORDER;
            } else if (alignment_shift > MAX_ORDER) {
                alignment_shift = MAX_ORDER;
            }
            BUDDY_DEBUG_PRINTF("[BUDDY-INIT][%d] addr=%p alignment=0x%llx align_shift=%d\n",
                       iteration, (void*)current_addr, (unsigned long long)alignment,
                       alignment_shift);
        }

        block_order = alignment_shift;

        /* Constrain by remaining space: largest order whose block fits */
        int size_order = MAX_ORDER;
        while (size_order > MIN_ORDER && (1UL << size_order) > remaining_size) {
            size_order--;
        }
        if (size_order < MIN_ORDER) {
            size_order = MIN_ORDER;
        }

        if (block_order > size_order) {
            block_order = size_order;
        }
        BUDDY_DEBUG_PRINTF("[BUDDY-INIT][%d] after size constraint block_order=%d remaining=%llu\n",
                   iteration, block_order, (unsigned long long)remaining_size);

        /* Ensure block_order is at least MIN_ORDER */
        if (block_order < MIN_ORDER) {
            block_order = MIN_ORDER;
        }

        size_t block_size = 1UL << block_order;
        if (block_size > remaining_size) {
            break;  /* No more room for blocks */
        }

        /* Create block header at current address */
        block_hdr_t *blk = (block_hdr_t *)current_addr;
        blk->order = block_order;
        blk->is_allocated = 0;
        blk->magic = BLOCK_MAGIC;
        BUDDY_DEBUG_PRINTF("[BUDDY-INIT][%d] Header set: blk=%p order=%d is_allocated=%d magic=0x%x\n",
                   iteration, (void*)blk, blk->order, blk->is_allocated, blk->magic);
        BUDDY_DEBUG_PRINTF("[BUDDY-INIT][%d] Header raw: %02x %02x %02x %02x %02x %02x %02x %02x\n",
                   iteration,
                   ((uint8_t*)blk)[0], ((uint8_t*)blk)[1], ((uint8_t*)blk)[2], ((uint8_t*)blk)[3],
                   ((uint8_t*)blk)[4], ((uint8_t*)blk)[5], ((uint8_t*)blk)[6], ((uint8_t*)blk)[7]);

        /* Add to free list */
        free_block_t *freeblk = (free_block_t *)get_data_ptr(blk);
        BUDDY_DEBUG_PRINTF("[BUDDY-INIT][%d] data_ptr=%p (header=%p + sizeof(header)=%llu)\n",
                   iteration, (void*)freeblk, (void*)blk, (unsigned long long)sizeof(block_hdr_t));
        BUDDY_DEBUG_PRINTF("[BUDDY-INIT][%d] Adding to free_lists[%d] (order %d)\n",
                   iteration, block_order - MIN_ORDER, block_order);
        BUDDY_DEBUG_PRINTF("[BUDDY-INIT][%d] Current free_lists[%d] head=%p\n",
                   iteration, block_order - MIN_ORDER, (void*)free_lists[block_order - MIN_ORDER]);
        freeblk->next = free_lists[block_order - MIN_ORDER];
        freeblk->prev = NULL;
        if (free_lists[block_order - MIN_ORDER]) {
            free_lists[block_order - MIN_ORDER]->prev = freeblk;
        }
        free_lists[block_order - MIN_ORDER] = freeblk;
        BUDDY_DEBUG_PRINTF("[BUDDY-INIT][%d] New free_lists[%d] head=%p\n",
                   iteration, block_order - MIN_ORDER, (void*)free_lists[block_order - MIN_ORDER]);

        /* Move to next block position */
        current_addr += block_size;
        remaining_size -= block_size;
        BUDDY_DEBUG_PRINTF("[BUDDY-INIT][%d] Created block order=%d size=%llu, next_addr=%p remaining=%llu\n",
                   iteration, block_order, (unsigned long long)block_size,
                   (void*)current_addr, (unsigned long long)remaining_size);
        iteration++;

        if (iteration > 100) {
            BUDDY_DEBUG_PRINTF("[BUDDY-INIT] ERROR: Too many iterations, breaking\n");
            break;
        }
    }

    BUDDY_DEBUG_PRINTF("[BUDDY-INIT] Heap initialization complete\n");
}

void *buddy_malloc(size_t size) {
    if (size == 0) return NULL;

    /* Account for block header */
    size_t needed = size + sizeof(block_hdr_t);
    int order = size_to_order(needed);


    if (order > MAX_ORDER) {
        BUDDY_DEBUG_PRINTF("[BUDDY-MALLOC] FAILED: size=%llu needed=%llu order=%d MAX=%d\n",
                   (unsigned long long)size, (unsigned long long)needed, order, MAX_ORDER);
        return NULL;  /* Too large */
    }

    BUDDY_DEBUG_PRINTF("[BUDDY-MALLOC] Requesting %llu bytes (order=%d, heap=%p-%p)\n",
               (unsigned long long)size, order, (void*)heap_start, (void*)heap_end);

    /* Search free lists starting from requested order */
    int search_order = order;
    while (search_order <= MAX_ORDER) {
        free_block_t *candidate = free_lists[search_order - MIN_ORDER];

        /* CRITICAL: Validate free list head before dereferencing */
        if (candidate && ((uintptr_t)candidate < heap_start || (uintptr_t)candidate >= heap_end)) {
            BUDDY_DEBUG_PRINTF("[BUDDY-MALLOC] WARNING: Corrupted free list head %p at order %d, marking list as empty\n",
                       (void*)candidate, search_order);
            /* Mark free list as corrupted/empty - don't try to dereference it */
            free_lists[search_order - MIN_ORDER] = NULL;
            candidate = NULL;
        }

        /* Debug: list all blocks in this free list */
        int block_count = 0;
        free_block_t *tmp = candidate;
        while (tmp) {
            /* Safety: Validate pointer before dereferencing */
            if ((uintptr_t)tmp < heap_start || (uintptr_t)tmp >= heap_end) {
                BUDDY_DEBUG_PRINTF("[BUDDY-MALLOC] WARNING: Corrupted pointer %p in free list at order %d, breaking traversal\n",
                           (void*)tmp, search_order);
                break;  /* Stop traversal but don't fail allocation */
            }
            block_count++;
            tmp = tmp->next;
        }
        if (block_count > 0) {
            BUDDY_DEBUG_PRINTF("[BUDDY-MALLOC] Order %d has %d free blocks\n", search_order, block_count);
        }

        if (candidate != NULL) {
            BUDDY_DEBUG_PRINTF("[BUDDY-MALLOC] Found free block at order %d (size %llu) candidate=%p\n",
                       search_order, (unsigned long long)order_to_size(search_order), (void*)candidate);

            /* Get the block header */
            block_hdr_t *hdr = (block_hdr_t *)candidate - 1;
            BUDDY_DEBUG_PRINTF("[BUDDY-MALLOC] Block header at %p\n", (void*)hdr);
            BUDDY_DEBUG_PRINTF("[BUDDY-MALLOC] Header contents: order=%d is_allocated=%d magic=0x%x\n",
                       hdr->order, hdr->is_allocated, hdr->magic);
            BUDDY_DEBUG_PRINTF("[BUDDY-MALLOC] Header raw bytes: %02x %02x %02x %02x %02x %02x %02x %02x\n",
                       ((uint8_t*)hdr)[0], ((uint8_t*)hdr)[1], ((uint8_t*)hdr)[2], ((uint8_t*)hdr)[3],
                       ((uint8_t*)hdr)[4], ((uint8_t*)hdr)[5], ((uint8_t*)hdr)[6], ((uint8_t*)hdr)[7]);

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
                size_t buddy_size = order_to_size(hdr->order);

                /* CRITICAL: Only write to buddy header if it's within heap bounds
                 * Writing to an invalid address corrupts memory outside the heap */
                if (buddy_addr >= heap_start && (buddy_addr + buddy_size) <= heap_end) {
                    /* Safe to write - buddy is within heap */
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
                } else {
                    BUDDY_DEBUG_PRINTF("[BUDDY-MALLOC] WARNING: Buddy block outside heap bounds, skipping\n");
                    BUDDY_DEBUG_PRINTF("[BUDDY-MALLOC]   Buddy: %p-%p (size=%llu)\n",
                               (void*)buddy_addr, (void*)(buddy_addr + buddy_size),
                               (unsigned long long)buddy_size);
                }
            }

            /* Validate block is within heap bounds */
            uintptr_t block_addr = (uintptr_t)hdr;
            size_t block_size = order_to_size(hdr->order);
            if (block_addr < heap_start || (block_addr + block_size) > heap_end) {
                BUDDY_DEBUG_PRINTF("[BUDDY-MALLOC] ERROR: Block OUTSIDE heap bounds!\n");
                BUDDY_DEBUG_PRINTF("[BUDDY-MALLOC]   Block: %p-%p (size=%llu)\n",
                           (void*)block_addr, (void*)(block_addr + block_size),
                           (unsigned long long)block_size);
                BUDDY_DEBUG_PRINTF("[BUDDY-MALLOC]   Heap:  %p-%p\n",
                           (void*)heap_start, (void*)heap_end);
                return NULL;  /* Refuse to allocate outside heap */
            }

            /* Mark as allocated */
            hdr->is_allocated = 1;
            total_allocated += order_to_size(hdr->order);

            void *result = get_data_ptr(hdr);
            size_t alloc_size __attribute__((unused)) = order_to_size(hdr->order);

            /* CRITICAL: Clear allocated memory ONLY for small blocks to prevent data leakage
             * For slab allocations (order 16-19, ~64KB-512KB), clear ONLY the requested size
             * NOT the full allocated size (which is rounded up to power of 2)
             * This prevents overwriting adjacent allocations
             * For large allocations (order 20+, >1MB), DON'T clear to preserve file performance
             * Callers of large allocations MUST initialize their data appropriately */
            BUDDY_DEBUG_PRINTF("[BUDDY-MALLOC-CLEAR] order=%d alloc_size=%llu requested_size=%llu data=%p\n",
                       hdr->order, (unsigned long long)alloc_size, (unsigned long long)size, result);
            if (hdr->order <= 19) {  /* Only clear small blocks (up to 512KB) */
                /* FIX: Clear only the REQUESTED size, not the full allocated size
                 * This prevents overwriting adjacent allocations when buddy allocator
                 * rounds up (e.g., 64KB request gets 128KB allocation) */
                size_t data_size = size;  /* Use requested size, not alloc_size */
                extern void *memset(void *, int, size_t);
                BUDDY_DEBUG_PRINTF("[BUDDY-MALLOC-CLEAR] Clearing %llu bytes (requested) starting at %p\n",
                           (unsigned long long)data_size, result);
                memset(result, 0, data_size);
                BUDDY_DEBUG_PRINTF("[BUDDY-MALLOC-CLEAR] Clear complete, first 8 bytes now: %02x %02x %02x %02x %02x %02x %02x %02x\n",
                           ((uint8_t*)result)[0], ((uint8_t*)result)[1], ((uint8_t*)result)[2], ((uint8_t*)result)[3],
                           ((uint8_t*)result)[4], ((uint8_t*)result)[5], ((uint8_t*)result)[6], ((uint8_t*)result)[7]);
            } else {
                BUDDY_DEBUG_PRINTF("[BUDDY-MALLOC-CLEAR] SKIPPING: order %d > 19\n", hdr->order);
            }

            BUDDY_DEBUG_PRINTF("[BUDDY-MALLOC] Allocated at %p (hdr=%p size=%llu)\n",
                       result, (void*)hdr, (unsigned long long)alloc_size);
            return result;
        }

        search_order++;
    }

    /* Out of memory - print detailed fragmentation info */
    BUDDY_DEBUG_PRINTF("[BUDDY-MALLOC] OUT OF MEMORY: size=%llu (needed=%llu, requested order=%d)\n",
               (unsigned long long)size, (unsigned long long)needed, order);

    /* Print free block count at each order to understand fragmentation */
    BUDDY_DEBUG_PRINTF("[BUDDY-MALLOC] Heap fragmentation status:\n");
    size_t total_free_size = 0;
    for (int i = 0; i < NUM_ORDERS; i++) {
        int order_val = i + MIN_ORDER;
        free_block_t *candidate = free_lists[i];
        int count = 0;
        while (candidate) {
            /* Safety: Validate pointer before dereferencing */
            if ((uintptr_t)candidate < heap_start || (uintptr_t)candidate >= heap_end) {
                BUDDY_DEBUG_PRINTF("[BUDDY-MALLOC] WARNING: Corrupted free list at order %d, pointer %p outside heap\n",
                          order_val, (void*)candidate);
                break;
            }
            count++;
            total_free_size += order_to_size(order_val);
            candidate = candidate->next;
        }
        if (count > 0) {
            BUDDY_DEBUG_PRINTF("[BUDDY-MALLOC]   Order %2d (2^%2d = %8llu bytes): %d blocks (total %llu bytes)\n",
                       order_val, order_val, (unsigned long long)order_to_size(order_val), count,
                       (unsigned long long)(count * order_to_size(order_val)));
        }
    }
    BUDDY_DEBUG_PRINTF("[BUDDY-MALLOC] Total free size: %llu bytes, Total allocated: %llu bytes\n",
               (unsigned long long)total_free_size, (unsigned long long)total_allocated);

    return NULL;  /* Out of memory */
}

void buddy_free(void *ptr) {
    if (ptr == NULL) return;


    BUDDY_DEBUG_PRINTF("[BUDDY-FREE-START] Freeing ptr=%p\n", ptr);

    /* CRITICAL: Validate that ptr and header location are within heap bounds BEFORE reading header */
    uintptr_t ptr_addr = (uintptr_t)ptr;
    if (ptr_addr < heap_start || ptr_addr >= heap_end) {
        BUDDY_DEBUG_PRINTF("[BUDDY-FREE] ERROR: Pointer %p is outside heap bounds [%p-%p]\n",
                   ptr, (void*)heap_start, (void*)heap_end);
        return;
    }

    /* Check that the header location would be within bounds */
    uintptr_t hdr_addr = ptr_addr - sizeof(block_hdr_t);
    if (hdr_addr < heap_start || hdr_addr >= heap_end) {
        BUDDY_DEBUG_PRINTF("[BUDDY-FREE] ERROR: Header location %p would be outside heap bounds\n", (void*)hdr_addr);
        return;
    }

    /* CRITICAL: Ensure header address is properly aligned
     * Buddy allocator assumes header is immediately before data pointer
     * If not properly aligned, header calculations will be wrong */
    if ((hdr_addr & 0x7) != 0) {
        BUDDY_DEBUG_PRINTF("[BUDDY-FREE] ERROR: Header address %p is not 8-byte aligned (misaligned data pointer)\n", (void*)hdr_addr);
        return;
    }

    block_hdr_t *hdr = get_block_hdr(ptr);
    BUDDY_DEBUG_PRINTF("[BUDDY-FREE-START] Block header at %p, magic=0x%x, allocated=%d, order=%d\n",
               (void*)hdr, hdr->magic, hdr->is_allocated, hdr->order);

    /* Validate block */
    if (hdr->magic != BLOCK_MAGIC || !hdr->is_allocated) {
        BUDDY_DEBUG_PRINTF("[BUDDY-FREE-START] Invalid block or double-free, returning\n");
        return;  /* Invalid or double-free */
    }

    BUDDY_DEBUG_PRINTF("[BUDDY-FREE-START] About to update total_allocated and mark as free\n");
    total_allocated -= order_to_size(hdr->order);
    hdr->is_allocated = 0;
    BUDDY_DEBUG_PRINTF("[BUDDY-FREE-START] Marked as free, starting coalesce\n");

    /* Add to free list and coalesce with buddy if possible */
    int order = hdr->order;
    uintptr_t addr = (uintptr_t)hdr;
    int coalesce_count = 0;

    while (order < MAX_ORDER) {
        uintptr_t buddy_addr = get_buddy_addr(addr, order_to_size(order));

        /* Check if buddy is free and in heap */
        if (!is_in_heap(buddy_addr)) {
            /* Cannot coalesce - buddy is outside heap bounds */
            BUDDY_DEBUG_PRINTF("[BUDDY-FREE] Coalesce stop at order %d: buddy %p outside heap bounds [%p-%p]\n",
                       order, (void*)buddy_addr, (void*)heap_start, (void*)heap_end);
            break;
        }

        /* CRITICAL: Validate entire buddy block header is within bounds */
        size_t buddy_block_size = order_to_size(order);
        if (buddy_addr + buddy_block_size > heap_end) {
            BUDDY_DEBUG_PRINTF("[BUDDY-FREE] Coalesce stop at order %d: buddy block extends beyond heap end\n", order);
            BUDDY_DEBUG_PRINTF("[BUDDY-FREE]   Block: %p-%p, Heap end: %p\n",
                       (void*)buddy_addr, (void*)(buddy_addr + buddy_block_size), (void*)heap_end);
            break;
        }

        block_hdr_t *buddy_hdr = (block_hdr_t *)buddy_addr;

        /* CRITICAL: Ensure buddy header address itself is valid before reading
         * Prevent reading from uninitialized or misaligned memory */
        if ((buddy_addr & 0x7) != 0) {
            BUDDY_DEBUG_PRINTF("[BUDDY-FREE] ERROR: Buddy address %p is not 8-byte aligned!\n", (void*)buddy_addr);
            break;
        }

        /* Validate buddy and check if free */
        if (buddy_hdr->magic != BLOCK_MAGIC) {
            /* Buddy has invalid magic - corruption or never allocated */
            BUDDY_DEBUG_PRINTF("[BUDDY-FREE] Coalesce stop at order %d: buddy %p has invalid magic 0x%x\n",
                       order, (void*)buddy_addr, buddy_hdr->magic);
            break;
        }

        if (buddy_hdr->order != order) {
            /* Buddy has different order - can't merge */
            BUDDY_DEBUG_PRINTF("[BUDDY-FREE] Coalesce stop at order %d: buddy order mismatch (buddy=%d, expected=%d)\n",
                       order, buddy_hdr->order, order);
            break;
        }

        if (buddy_hdr->is_allocated) {
            /* Buddy is still allocated - can't merge */
            BUDDY_DEBUG_PRINTF("[BUDDY-FREE] Coalesce stop at order %d: buddy is allocated\n", order);
            break;
        }

        /* Coalesce: remove buddy from free list */
        free_block_t *buddy_free = (free_block_t *)get_data_ptr(buddy_hdr);

        /* CRITICAL: Validate buddy_free pointer before dereferencing */
        if ((uintptr_t)buddy_free < heap_start || (uintptr_t)buddy_free >= heap_end) {
            BUDDY_DEBUG_PRINTF("[BUDDY-FREE] Coalesce stop at order %d: buddy_free data pointer %p outside heap bounds\n",
                       order, (void*)buddy_free);
            break;
        }

        /* Validate that buddy's next pointer won't corrupt free list */
        if (buddy_free->next != NULL && ((uintptr_t)buddy_free->next < heap_start || (uintptr_t)buddy_free->next >= heap_end)) {
            BUDDY_DEBUG_PRINTF("[BUDDY-FREE] Coalesce stop at order %d: buddy->next pointer %p is corrupted (outside heap)\n",
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
                BUDDY_DEBUG_PRINTF("[BUDDY-FREE] ERROR: Coalesced header %p is outside heap bounds after merging\n", (void*)hdr);
                break;
            }
        }

        hdr->order++;
        order++;
        coalesce_count++;
    }

    if (coalesce_count > 0) {
        BUDDY_DEBUG_PRINTF("[BUDDY-FREE] Coalesced %d times (block %p, final order %d)\n",
                   coalesce_count, (void*)addr, order);
    }

    /* CRITICAL: Validate final coalesced block before adding to free list */
    if ((uintptr_t)hdr < heap_start || (uintptr_t)hdr >= heap_end) {
        BUDDY_DEBUG_PRINTF("[BUDDY-FREE] ERROR: Final coalesced header %p outside heap bounds!\n", (void*)hdr);
        return;
    }

    size_t final_block_size = order_to_size(order);
    if ((uintptr_t)hdr + final_block_size > heap_end) {
        BUDDY_DEBUG_PRINTF("[BUDDY-FREE] ERROR: Final coalesced block extends beyond heap end!\n");
        BUDDY_DEBUG_PRINTF("[BUDDY-FREE]   Block: %p-%p, Heap end: %p\n",
                   (void*)hdr, (void*)((uintptr_t)hdr + final_block_size), (void*)heap_end);
        return;
    }

    /* Add coalesced block to free list */
    BUDDY_DEBUG_PRINTF("[BUDDY-FREE] About to add to free list: hdr=%p order=%d order-MIN_ORDER=%d\n",
               (void*)hdr, order, order - MIN_ORDER);
    free_block_t *free_hdr = (free_block_t *)get_data_ptr(hdr);
    BUDDY_DEBUG_PRINTF("[BUDDY-FREE] free_hdr=%p current list head=%p\n",
               (void*)free_hdr, (void*)free_lists[order - MIN_ORDER]);

    /* Validate free_hdr is within heap bounds before using it */
    if ((uintptr_t)free_hdr < heap_start || (uintptr_t)free_hdr >= heap_end) {
        BUDDY_DEBUG_PRINTF("[BUDDY-FREE] ERROR: free_hdr data pointer %p outside heap bounds!\n", (void*)free_hdr);
        return;
    }

    free_hdr->next = free_lists[order - MIN_ORDER];
    BUDDY_DEBUG_PRINTF("[BUDDY-FREE] Set free_hdr->next=%p\n", (void*)free_hdr->next);

    /* Validate the current list head isn't corrupted before updating it */
    if (free_lists[order - MIN_ORDER] != NULL) {
        if ((uintptr_t)free_lists[order - MIN_ORDER] < heap_start ||
            (uintptr_t)free_lists[order - MIN_ORDER] >= heap_end) {
            BUDDY_DEBUG_PRINTF("[BUDDY-FREE] ERROR: Current list head %p is corrupted (outside heap)!\n",
                       (void*)free_lists[order - MIN_ORDER]);
            return;
        }
    }

    free_hdr->prev = NULL;
    if (free_lists[order - MIN_ORDER]) {
        BUDDY_DEBUG_PRINTF("[BUDDY-FREE] Setting prev pointer on old head\n");
        free_lists[order - MIN_ORDER]->prev = free_hdr;
    }
    BUDDY_DEBUG_PRINTF("[BUDDY-FREE] Updating list head to %p\n", (void*)free_hdr);
    free_lists[order - MIN_ORDER] = free_hdr;
    BUDDY_DEBUG_PRINTF("[BUDDY-FREE] Free complete\n");
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
