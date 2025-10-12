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
