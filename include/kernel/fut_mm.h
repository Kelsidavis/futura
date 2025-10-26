// SPDX-License-Identifier: MPL-2.0
/*
 * fut_mm.h - Per-task virtual memory contexts
 *
 * Provides a minimal abstraction around fut_vmem_context_t so higher layers
 * can manage process address spaces without touching raw paging structures.
 * Phase 4 introduces dedicated mm objects, reference counting, and helpers
 * for switching TTBR0_EL1 (ARM64) or CR3 (x86_64) as threads migrate between tasks.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>

/* Include architecture-specific paging header */
#if defined(__aarch64__)
#include <arch/arm64/paging.h>
typedef uint64_t phys_addr_t;
#elif defined(__x86_64__)
#include <arch/x86_64/paging.h>
#include <arch/x86_64/pmap.h>  /* For phys_addr_t */
#else
#error "Unsupported architecture for memory management"
#endif

/* Forward declaration for file backing */
struct fut_vnode;

/* VMA flags */
#define VMA_COW       0x1000  /* Copy-on-write pages */
#define VMA_SHARED    0x2000  /* Shared mapping (not private) */

/* Virtual Memory Area - represents a contiguous mapped region */
struct fut_vma {
    uintptr_t start;    /* Start address (page-aligned) */
    uintptr_t end;      /* End address (page-aligned, exclusive) */
    int prot;           /* Protection flags (PROT_READ, PROT_WRITE, PROT_EXEC) */
    int flags;          /* Mapping flags (includes VMA_COW, VMA_SHARED) */

    /* File backing (NULL for anonymous mappings) */
    struct fut_vnode *vnode;  /* Backing file vnode (holds reference) */
    uint64_t file_offset;      /* Offset into backing file */

    struct fut_vma *next;  /* Next VMA in list */
};

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
void *fut_mm_map_file(fut_mm_t *mm, struct fut_vnode *vnode, uintptr_t hint,
                       size_t len, int prot, int flags, uint64_t file_offset);
int fut_mm_unmap(fut_mm_t *mm, uintptr_t addr, size_t len);

/* VMA management for fork() */
int fut_mm_add_vma(fut_mm_t *mm, uintptr_t start, uintptr_t end, int prot, int flags);
int fut_mm_clone_vmas(fut_mm_t *dest_mm, fut_mm_t *src_mm);

/* Page reference counting for COW */
void fut_page_ref_init(void);
void fut_page_ref_inc(phys_addr_t phys);
int fut_page_ref_dec(phys_addr_t phys);  /* Returns new refcount */
int fut_page_ref_get(phys_addr_t phys);  /* Returns current refcount */
