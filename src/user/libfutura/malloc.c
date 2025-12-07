// SPDX-License-Identifier: MPL-2.0
// Simple bump allocator - no free list, no splitting
// This wastes memory but is simple and correct

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

/* Simple header to track allocation size (needed for realloc) */
typedef struct {
    size_t size;
} alloc_header_t;

#define HEADER_SIZE sizeof(alloc_header_t)

static size_t align_size(size_t size) {
    return (size + 15u) & ~15u;
}

/* Debug print - only for large allocations to avoid spam */
static void malloc_debug(const char *msg, size_t val1, size_t val2) {
    /* Simple syscall-based debug - use write to stderr */
    char buf[128];
    int len = 0;
    const char *p = msg;
    while (*p && len < 80) buf[len++] = *p++;
    buf[len++] = ' ';
    /* Print val1 as hex */
    buf[len++] = '0'; buf[len++] = 'x';
    for (int i = 60; i >= 0; i -= 4) {
        int d = (val1 >> i) & 0xf;
        if (d || i == 0 || len > 4) buf[len++] = d < 10 ? '0' + d : 'a' + d - 10;
    }
    buf[len++] = ' ';
    /* Print val2 as hex */
    buf[len++] = '0'; buf[len++] = 'x';
    for (int i = 60; i >= 0; i -= 4) {
        int d = (val2 >> i) & 0xf;
        if (d || i == 0 || len > 4) buf[len++] = d < 10 ? '0' + d : 'a' + d - 10;
    }
    buf[len++] = '\n';
    sys_write(2, buf, len);
}

void *malloc(size_t size) {
    if (size == 0) {
        return NULL;
    }

    size_t aligned = align_size(size);
    size_t total = HEADER_SIZE + aligned;

    /* Debug large allocations */
    if (size > 100000) {
        malloc_debug("[MALLOC] large alloc size=", size, total);
    }

    malloc_lock_acquire();

    /* Get current break */
    long current = sys_brk_call(NULL);
    if (current < 0) {
        malloc_lock_release();
        if (size > 100000) malloc_debug("[MALLOC] brk(NULL) failed rc=", (size_t)current, 0);
        return NULL;
    }

    /* Expand break */
    long requested = current + (long)total;
    if (size > 100000) {
        malloc_debug("[MALLOC] current brk=", (size_t)current, (size_t)requested);
    }
    long rc = sys_brk_call((void *)(uintptr_t)requested);
    if (rc < 0 || rc < requested) {
        malloc_lock_release();
        if (size > 100000) malloc_debug("[MALLOC] brk expand failed rc=", (size_t)rc, (size_t)requested);
        return NULL;
    }

    malloc_lock_release();

    /* Set up header */
    alloc_header_t *header = (alloc_header_t *)(uintptr_t)current;
    header->size = aligned;

    void *result = (void *)((uint8_t *)header + HEADER_SIZE);
    if (size > 100000) {
        malloc_debug("[MALLOC] success ptr=", (size_t)result, size);
    }
    return result;
}

void free(void *ptr) {
    /* Bump allocator doesn't actually free - memory is leaked */
    (void)ptr;
}

void *calloc(size_t nmemb, size_t size) {
    size_t total = nmemb * size;
    void *ptr = malloc(total);
    if (ptr) {
        memset(ptr, 0, total);
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
        return ptr;
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
