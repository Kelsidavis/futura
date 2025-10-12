// SPDX-License-Identifier: MPL-2.0

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <user/sys.h>

typedef struct block_header {
    size_t size;
    bool free;
    struct block_header *next;
} block_header_t;

static block_header_t *free_list = NULL;

static size_t align_size(size_t size) {
    return (size + 15u) & ~15u;
}

static block_header_t *block_from_ptr(void *ptr) {
    if (!ptr) {
        return NULL;
    }
    return (block_header_t *)((uint8_t *)ptr - sizeof(block_header_t));
}

static void remove_from_free_list(block_header_t *block, block_header_t *prev) {
    if (prev) {
        prev->next = block->next;
    } else {
        free_list = block->next;
    }
    block->next = NULL;
    block->free = false;
}

static block_header_t *split_block(block_header_t *block, size_t size) {
    const size_t remaining = block->size - size;
    if (remaining <= sizeof(block_header_t)) {
        return NULL;
    }

    uint8_t *payload = (uint8_t *)block + sizeof(block_header_t);
    block_header_t *split = (block_header_t *)(payload + size);
    split->size = remaining - sizeof(block_header_t);
    split->free = true;
    split->next = block->next;

    block->size = size;
    block->next = split;
    return split;
}

static void coalesce_list(void) {
    block_header_t *curr = free_list;
    while (curr && curr->next) {
        uintptr_t curr_end = (uintptr_t)curr + sizeof(block_header_t) + curr->size;
        if (curr_end == (uintptr_t)curr->next) {
            curr->size += sizeof(block_header_t) + curr->next->size;
            curr->next = curr->next->next;
        } else {
            curr = curr->next;
        }
    }
}

static void insert_free_block(block_header_t *block) {
    block->free = true;

    if (!free_list || block < free_list) {
        block->next = free_list;
        free_list = block;
    } else {
        block_header_t *curr = free_list;
        while (curr->next && curr->next < block) {
            curr = curr->next;
        }
        block->next = curr->next;
        curr->next = block;
    }

    coalesce_list();
}

static block_header_t *find_suitable_block(size_t size, block_header_t **out_prev) {
    block_header_t *prev = NULL;
    for (block_header_t *curr = free_list; curr; prev = curr, curr = curr->next) {
        if (curr->free && curr->size >= size) {
            if (out_prev) {
                *out_prev = prev;
            }
            return curr;
        }
    }
    return NULL;
}

static block_header_t *request_from_kernel(size_t size) {
    size_t total = sizeof(block_header_t) + size;
    total = align_size(total);

    long current = sys_brk_call(NULL);
    if (current < 0) {
        return NULL;
    }

    long requested = current + (long)total;
    long rc = sys_brk_call((void *)(uintptr_t)requested);
    if (rc < 0 || rc < requested) {
        return NULL;
    }

    block_header_t *block = (block_header_t *)(uintptr_t)current;
    block->size = total - sizeof(block_header_t);
    block->free = false;
    block->next = NULL;
    return block;
}

void *malloc(size_t size) {
    if (size == 0) {
        return NULL;
    }

    size = align_size(size);

    block_header_t *prev = NULL;
    block_header_t *block = find_suitable_block(size, &prev);
    if (block) {
        split_block(block, size);
        remove_from_free_list(block, prev);
        return (uint8_t *)block + sizeof(block_header_t);
    }

    block = request_from_kernel(size);
    if (!block) {
        return NULL;
    }

    block_header_t *split = split_block(block, size);
    if (split) {
        insert_free_block(split);
        block->next = NULL;
    }
    return (uint8_t *)block + sizeof(block_header_t);
}

void free(void *ptr) {
    if (!ptr) {
        return;
    }

    block_header_t *block = block_from_ptr(ptr);
    insert_free_block(block);
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

    block_header_t *block = block_from_ptr(ptr);
    if (block->size >= size) {
        return ptr;
    }

    void *new_ptr = malloc(size);
    if (!new_ptr) {
        return NULL;
    }

    size_t copy = block->size < size ? block->size : size;
    memcpy(new_ptr, ptr, copy);
    free(ptr);
    return new_ptr;
}

void heap_stats(size_t *used, size_t *total) {
    (void)used;
    (void)total;
}
