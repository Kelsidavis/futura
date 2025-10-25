/* slab_allocator.c - Slab Allocator for Small Object Allocation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * A slab allocator built on top of the buddy allocator for efficient
 * allocation of small, fixed-size objects. Uses pre-allocated slabs
 * to minimize fragmentation and improve cache locality.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "../../include/kernel/buddy_allocator.h"

/* ============================================================
 *   Slab Allocator Constants
 * ============================================================ */

/* Standard object sizes supported by slab allocator */
static const size_t SLAB_SIZES[] = {
    32,    /* slab[0]:  32 bytes */
    64,    /* slab[1]:  64 bytes */
    128,   /* slab[2]:  128 bytes */
    256,   /* slab[3]:  256 bytes */
    512,   /* slab[4]:  512 bytes */
    1024,  /* slab[5]:  1 KB */
    2048,  /* slab[6]:  2 KB */
    4096,  /* slab[7]:  4 KB (page size) */
    8192,  /* slab[8]:  8 KB */
    16384, /* slab[9]:  16 KB */
};

#define NUM_SLAB_SIZES (sizeof(SLAB_SIZES) / sizeof(SLAB_SIZES[0]))

/* Slab size: should be multiple of page size for efficiency */
#define SLAB_PAGE_SIZE 4096
#define SLAB_SIZE (16 * SLAB_PAGE_SIZE)  /* 64 KB slab */

/* ============================================================
 *   Slab Data Structures
 * ============================================================ */

/* Individual object header within a slab */
typedef struct slab_obj {
    struct slab_obj *next;  /* Next free object in slab */
    uint8_t is_allocated;   /* Allocation flag */
    uint8_t reserved[7];    /* Padding to 16 bytes */
} slab_obj_t;

#define SLAB_OBJ_HDR_SIZE sizeof(slab_obj_t)

/* A slab contains multiple objects of the same size */
typedef struct slab {
    uint64_t magic;              /* Magic number for integrity checking */
    struct slab *next;           /* Next slab in list */
    struct slab *prev;           /* Previous slab in list */
    size_t obj_size;             /* Size of each object (including header) */
    size_t obj_count;            /* Total objects in slab */
    size_t free_count;           /* Number of free objects */
    slab_obj_t *free_list;       /* Head of free object list */
    uint8_t *data;               /* Raw slab data */
} slab_t;

/* Cache for a specific object size */
typedef struct slab_cache {
    size_t obj_size;             /* Size of objects in this cache */
    slab_t *slabs;               /* List of slabs */
    size_t num_slabs;            /* Number of slabs */
    size_t total_allocated;      /* Total objects allocated */
    size_t total_freed;          /* Total objects freed */
} slab_cache_t;

/* ============================================================
 *   Global Slab Allocator State
 * ============================================================ */

static slab_cache_t slab_caches[NUM_SLAB_SIZES];

/* ============================================================
 *   Helper Functions
 * ============================================================ */

/* Find appropriate slab cache for size */
static int find_slab_index(size_t size) {
    for (size_t i = 0; i < NUM_SLAB_SIZES; i++) {
        if (size <= SLAB_SIZES[i]) {
            return (int)i;
        }
    }
    return -1;  /* Size too large for slab allocator */
}

/* Calculate how many objects fit in a slab */
static size_t calc_objects_per_slab(size_t obj_size) {
    /* Allocate slab from buddy allocator */
    size_t usable_size = SLAB_SIZE - sizeof(slab_t);
    return usable_size / (obj_size + SLAB_OBJ_HDR_SIZE);
}

/* ============================================================
 *   Slab Allocator Core Operations
 * ============================================================ */

void slab_init(void) {
    /* Initialize all slab caches */
    for (size_t i = 0; i < NUM_SLAB_SIZES; i++) {
        slab_caches[i].obj_size = SLAB_SIZES[i];
        slab_caches[i].slabs = NULL;
        slab_caches[i].num_slabs = 0;
        slab_caches[i].total_allocated = 0;
        slab_caches[i].total_freed = 0;
    }
}

/* SLAB MAGIC for integrity checking */
#define SLAB_MAGIC 0xDEADC0DEDEADBEEFULL

/* Allocate a new slab and add it to cache */
static slab_t *slab_create(slab_cache_t *cache) {
    extern void fut_printf(const char *, ...);

    /* Allocate slab metadata + data from buddy allocator */
    uint8_t *slab_mem = (uint8_t *)buddy_malloc(SLAB_SIZE);
    if (!slab_mem) {
        return NULL;
    }

    /* Slab structure at beginning of allocation */
    slab_t *slab = (slab_t *)slab_mem;
    slab->magic = SLAB_MAGIC;
    slab->next = NULL;
    slab->prev = NULL;
    slab->obj_size = cache->obj_size + SLAB_OBJ_HDR_SIZE;
    slab->obj_count = calc_objects_per_slab(cache->obj_size);
    slab->free_count = slab->obj_count;
    slab->data = slab_mem + sizeof(slab_t);

    /* Initialize free list - with explicit initialization to prevent corruption */
    slab->free_list = NULL;

    /* First, explicitly clear the entire slab data area to prevent uninitialized memory */
    size_t slab_data_size = slab->obj_count * slab->obj_size;
    extern void *memset(void *, int, size_t);
    memset(slab->data, 0, slab_data_size);

    for (size_t i = 0; i < slab->obj_count; i++) {
        slab_obj_t *obj = (slab_obj_t *)(slab->data + i * slab->obj_size);
        /* Validate object pointer is within slab bounds */
        uint8_t *obj_as_bytes = (uint8_t *)obj;
        if (obj_as_bytes < slab->data || obj_as_bytes >= (slab->data + slab_data_size)) {
            fut_printf("[SLAB-CREATE] WARNING: Object pointer %p is out of bounds for slab %p!\n",
                       (void*)obj, (void*)slab);
            continue;  /* Skip this object */
        }
        obj->is_allocated = 0;
        obj->next = slab->free_list;
        slab->free_list = obj;
    }

    /* Add to cache's slab list */
    slab->next = cache->slabs;
    if (cache->slabs) {
        cache->slabs->prev = slab;
    }
    cache->slabs = slab;
    cache->num_slabs++;

    fut_printf("[SLAB-CREATE] Created slab at %p for size %llu (obj_size=%llu, count=%llu)\n",
               (void*)slab, (unsigned long long)cache->obj_size,
               (unsigned long long)slab->obj_size, (unsigned long long)slab->obj_count);

    return slab;
}

/* Validate slab integrity before using it */
static int slab_is_valid(slab_t *slab) {
    extern void fut_printf(const char *, ...);

    if (!slab) return 0;

    /* Check magic number */
    if (slab->magic != SLAB_MAGIC) {
        fut_printf("[SLAB-VALIDATE] ERROR: Slab %p has corrupted magic 0x%llx (expected 0x%llx)\n",
                   (void*)slab, (unsigned long long)slab->magic, (unsigned long long)SLAB_MAGIC);
        return 0;
    }

    /* Check object size is reasonable */
    if (slab->obj_size == 0 || slab->obj_size > SLAB_SIZE) {
        fut_printf("[SLAB-VALIDATE] ERROR: Slab %p has invalid obj_size %llu\n",
                   (void*)slab, (unsigned long long)slab->obj_size);
        return 0;
    }

    /* Check object count is reasonable */
    if (slab->obj_count == 0 || slab->obj_count > (SLAB_SIZE / 16)) {
        fut_printf("[SLAB-VALIDATE] ERROR: Slab %p has invalid obj_count %llu\n",
                   (void*)slab, (unsigned long long)slab->obj_count);
        return 0;
    }

    return 1;
}

void *slab_malloc(size_t size) {
    if (size == 0) return NULL;

    extern void fut_printf(const char *, ...);
    extern uintptr_t fut_heap_get_base(void);
    extern uintptr_t fut_heap_get_limit(void);

    uintptr_t heap_base = fut_heap_get_base();
    uintptr_t heap_limit = fut_heap_get_limit();

    int idx = find_slab_index(size);
    if (idx < 0) {
        /* Size too large for slab allocator, use buddy directly */
        return buddy_malloc(size);
    }

    slab_cache_t *cache = &slab_caches[idx];

    /* Try to find free object in existing slabs */
    for (slab_t *slab = cache->slabs; slab; slab = slab->next) {
        /* CRITICAL: Validate slab integrity before accessing it */
        if (!slab_is_valid(slab)) {
            fut_printf("[SLAB-MALLOC] WARNING: Skipping corrupted slab %p\n", (void*)slab);
            /* Mark as empty to prevent further use */
            slab->free_list = NULL;
            slab->free_count = 0;
            continue;
        }

        if (slab->free_list) {
            /* Found free object */
            slab_obj_t *obj = slab->free_list;

            /* CRITICAL: Validate object pointer before using it */
            if ((uintptr_t)obj < heap_base || (uintptr_t)obj >= heap_limit) {
                fut_printf("[SLAB-MALLOC] ERROR: Corrupted slab free list! Pointer %p is outside heap [%p-%p]\n",
                           (void*)obj, (void*)heap_base, (void*)heap_limit);
                /* Mark this slab's free list as empty to skip it */
                slab->free_list = NULL;
                slab->free_count = 0;
                /* Continue to next slab */
                continue;
            }

            /* CRITICAL: Validate that object is within slab bounds */
            uint8_t *obj_byte_ptr = (uint8_t *)obj;
            uint8_t *slab_end = slab->data + (slab->obj_count * slab->obj_size);
            if (obj_byte_ptr < slab->data || obj_byte_ptr >= slab_end) {
                fut_printf("[SLAB-MALLOC] ERROR: Object %p not in slab range [%p-%p]\n",
                           (void*)obj, (void*)slab->data, (void*)slab_end);
                /* Mark this slab's free list as corrupted */
                slab->free_list = NULL;
                slab->free_count = 0;
                continue;
            }

            slab->free_list = obj->next;
            obj->is_allocated = 1;
            slab->free_count--;
            cache->total_allocated++;

            /* Return data pointer (after header) */
            void *result = (void *)(obj + 1);

            /* Debug: Trace allocations from the problematic slab */
            static int alloc_count = 0;
            if ((uintptr_t)slab == 0xffffffff88149008ULL && alloc_count < 20) {
                fut_printf("[SLAB-ALLOC-DEBUG] #%d: Allocated %p from slab %p (size=%zu)\n",
                           alloc_count++, result, (void*)slab, size);
            }

            /* Validate result pointer before returning */
            if ((uintptr_t)result < heap_base || (uintptr_t)result >= heap_limit) {
                fut_printf("[SLAB-MALLOC] ERROR: Result pointer %p is outside heap [%p-%p]!\n",
                           result, (void*)heap_base, (void*)heap_limit);
                return NULL;
            }

            return result;
        }
    }

    /* No free objects in existing slabs, create new slab */
    slab_t *new_slab = slab_create(cache);
    if (!new_slab) {
        return NULL;
    }

    /* Allocate from new slab */
    slab_obj_t *obj = new_slab->free_list;
    if (!obj) {
        fut_printf("[SLAB-MALLOC] ERROR: New slab created but has no free objects!\n");
        return NULL;
    }

    /* CRITICAL: Validate object pointer */
    if ((uintptr_t)obj < heap_base || (uintptr_t)obj >= heap_limit) {
        fut_printf("[SLAB-MALLOC] ERROR: New slab object pointer %p is outside heap [%p-%p]!\n",
                   (void*)obj, (void*)heap_base, (void*)heap_limit);
        return NULL;
    }

    /* CRITICAL: Validate that object is within slab bounds */
    uint8_t *obj_byte_ptr = (uint8_t *)obj;
    uint8_t *new_slab_end = new_slab->data + (new_slab->obj_count * new_slab->obj_size);
    if (obj_byte_ptr < new_slab->data || obj_byte_ptr >= new_slab_end) {
        fut_printf("[SLAB-MALLOC] ERROR: New slab object %p not in slab range [%p-%p]!\n",
                   (void*)obj, (void*)new_slab->data, (void*)new_slab_end);
        return NULL;
    }

    new_slab->free_list = obj->next;
    obj->is_allocated = 1;
    new_slab->free_count--;
    cache->total_allocated++;

    void *result = (void *)(obj + 1);

    /* Validate result pointer before returning */
    if ((uintptr_t)result < heap_base || (uintptr_t)result >= heap_limit) {
        fut_printf("[SLAB-MALLOC] ERROR: New slab result pointer %p is outside heap [%p-%p]!\n",
                   result, (void*)heap_base, (void*)heap_limit);
        return NULL;
    }

    return result;
}

void slab_free(void *ptr) {
    if (!ptr) return;

    extern void fut_printf(const char *, ...);
    extern uintptr_t fut_heap_get_base(void);
    extern uintptr_t fut_heap_get_limit(void);

    uintptr_t heap_base = fut_heap_get_base();
    uintptr_t heap_limit = fut_heap_get_limit();

    /* Find which slab and cache this object belongs to FIRST,
     * before trying to access the header */
    slab_obj_t *obj = (slab_obj_t *)ptr - 1;

    for (size_t i = 0; i < NUM_SLAB_SIZES; i++) {
        slab_cache_t *cache = &slab_caches[i];

        /* Safely iterate through slabs with bounds checking */
        for (slab_t *slab = cache->slabs; slab; slab = slab->next) {
            /* CRITICAL: Validate slab pointer before dereferencing using actual heap bounds */
            if ((uintptr_t)slab < heap_base || (uintptr_t)slab >= heap_limit) {
                fut_printf("[SLAB-FREE] WARNING: Corrupted slab pointer %p (outside heap [%p-%p]), skipping\n",
                           (void*)slab, (void*)heap_base, (void*)heap_limit);
                goto check_buddy;
            }

            /* CRITICAL: Validate slab integrity */
            if (!slab_is_valid(slab)) {
                fut_printf("[SLAB-FREE] WARNING: Slab %p (cache_size=%zu) failed integrity check (ptr=%p obj=%p), skipping\n",
                           (void*)slab, SLAB_SIZES[i], ptr, (void*)obj);
                continue;
            }

            /* Validate slab->data pointer before dereferencing */
            if (!slab->data || (uintptr_t)slab->data < 0xffffffff80000000ULL || (uintptr_t)slab->data >= 0xffffffffa0389000ULL) {
                fut_printf("[SLAB-FREE] WARNING: Invalid slab->data pointer %p, skipping slab\n", (void*)slab->data);
                continue;
            }

            /* Check if obj is within this slab's data range */
            uint8_t *slab_start = slab->data;
            uint8_t *slab_end = slab->data + (slab->obj_count * slab->obj_size);

            if ((uint8_t *)obj >= slab_start && (uint8_t *)obj < slab_end) {
                /* Found the slab - NOW it's safe to access the header */
                /* Validate object */
                if (!obj->is_allocated) {
                    return;  /* Double free */
                }

                obj->is_allocated = 0;

                /* Add object back to free list */
                obj->next = slab->free_list;
                slab->free_list = obj;
                slab->free_count++;
                cache->total_freed++;
                return;
            }
        }
    }

check_buddy:
    /* If not found in any slab cache, it was allocated by buddy allocator directly */
    buddy_free(ptr);
}

void *slab_realloc(void *ptr, size_t new_size) {
    if (!ptr) return slab_malloc(new_size);
    if (new_size == 0) {
        slab_free(ptr);
        return NULL;
    }

    /* Check if pointer is in any slab cache */
    slab_obj_t *obj = (slab_obj_t *)ptr - 1;

    for (size_t i = 0; i < NUM_SLAB_SIZES; i++) {
        slab_cache_t *cache = &slab_caches[i];
        for (slab_t *slab = cache->slabs; slab; slab = slab->next) {
            uint8_t *slab_start = slab->data;
            uint8_t *slab_end = slab->data + (slab->obj_count * slab->obj_size);
            if ((uint8_t *)obj >= slab_start && (uint8_t *)obj < slab_end) {
                /* Found in slab cache - use normal realloc */
                size_t current_size = slab->obj_size - SLAB_OBJ_HDR_SIZE;

                void *new_ptr = slab_malloc(new_size);
                if (!new_ptr) {
                    return NULL;
                }

                size_t copy_size = (current_size < new_size) ? current_size : new_size;
                memcpy(new_ptr, ptr, copy_size);

                slab_free(ptr);
                return new_ptr;
            }
        }
    }

    /* Not found in any slab - it must be from buddy allocator
     * Use buddy_realloc directly instead of guessing size */
    return buddy_realloc(ptr, new_size);
}

/* ============================================================
 *   Diagnostics
 * ============================================================ */

void slab_print_stats(void) {
    uint64_t total_allocated = 0;
    uint64_t total_freed = 0;
    uint64_t total_slabs = 0;

    for (size_t i = 0; i < NUM_SLAB_SIZES; i++) {
        slab_cache_t *cache = &slab_caches[i];

        if (cache->num_slabs > 0) {
            total_allocated += cache->total_allocated;
            total_freed += cache->total_freed;
            total_slabs += cache->num_slabs;
        }
    }

    /* Future: Add logging/debug output */
    (void)total_allocated;  /* Suppress unused warning */
    (void)total_freed;
    (void)total_slabs;
}
