// SPDX-License-Identifier: MPL-2.0
/*
 * fut_mm.h - Per-task virtual memory contexts
 *
 * Provides a minimal abstraction around fut_vmem_context_t so higher layers
 * can manage process address spaces without touching raw paging structures.
 * Phase 4 introduces dedicated mm objects, reference counting, and helpers
 * for switching CR3 as threads migrate between tasks.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>

#include <arch/x86_64/paging.h>

typedef struct fut_mm {
    fut_vmem_context_t ctx;
    atomic_uint_fast64_t refcnt;
    uint32_t flags;
    uintptr_t brk_start;
    uintptr_t brk_current;
    uintptr_t heap_limit;
    uintptr_t heap_mapped_end;
    uintptr_t mmap_base;
    struct fut_vma *vma_list;
} fut_mm_t;

enum {
    FUT_MM_KERNEL = 0x0001,
    FUT_MM_USER   = 0x0002,
};

void fut_mm_system_init(void);

fut_mm_t *fut_mm_kernel(void);
fut_mm_t *fut_mm_create(void);
void fut_mm_retain(fut_mm_t *mm);
void fut_mm_release(fut_mm_t *mm);

void fut_mm_switch(fut_mm_t *mm);
fut_mm_t *fut_mm_current(void);
fut_vmem_context_t *fut_mm_context(fut_mm_t *mm);

void fut_mm_set_heap_base(fut_mm_t *mm, uintptr_t base, uintptr_t limit);
uintptr_t fut_mm_brk_current(const fut_mm_t *mm);
uintptr_t fut_mm_brk_limit(const fut_mm_t *mm);
void fut_mm_set_brk_current(fut_mm_t *mm, uintptr_t current);
void *fut_mm_map_anonymous(fut_mm_t *mm, uintptr_t hint, size_t len, int prot, int flags);
int fut_mm_unmap(fut_mm_t *mm, uintptr_t addr, size_t len);
