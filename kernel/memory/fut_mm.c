// SPDX-License-Identifier: MPL-2.0
/*
 * fut_mm.c - Per-task memory context management
 *
 * Establishes a minimal MM container around fut_vmem_context_t so the kernel
 * can track process address spaces, switch CR3 during scheduling, and expose
 * the active page tables to uaccess helpers.
 */

#include "../../include/kernel/fut_mm.h"

#include "../../include/kernel/fut_memory.h"
#include "../../include/kernel/fut_task.h"
#include "../../include/kernel/fut_thread.h"

#include <arch/x86_64/paging.h>
#include <arch/x86_64/pmap.h>
#include <arch/x86_64/regs.h>

#include <kernel/errno.h>

#include <string.h>

static fut_mm_t kernel_mm;
static fut_mm_t *active_mm = NULL;

static inline fut_mm_t *mm_fallback(fut_mm_t *mm) {
    return mm ? mm : &kernel_mm;
}

void fut_mm_system_init(void) {
    memset(&kernel_mm, 0, sizeof(kernel_mm));

    kernel_mm.ctx.pml4 = fut_get_kernel_pml4();
    kernel_mm.ctx.cr3_value = pmap_virt_to_phys((uintptr_t)kernel_mm.ctx.pml4);
    kernel_mm.ctx.ref_count = 1;
    atomic_store_explicit(&kernel_mm.refcnt, 1, memory_order_relaxed);
    kernel_mm.flags = FUT_MM_KERNEL;

    active_mm = &kernel_mm;
}

fut_mm_t *fut_mm_kernel(void) {
    return &kernel_mm;
}

static void copy_kernel_half(pte_t *dst) {
    pte_t *src = fut_get_kernel_pml4();
    /* Kernel occupies upper half entries (256-511). */
    for (size_t idx = 256; idx < 512; ++idx) {
        dst[idx] = src[idx];
    }
}

fut_mm_t *fut_mm_create(void) {
    fut_mm_t *mm = (fut_mm_t *)fut_malloc(sizeof(*mm));
    if (!mm) {
        return NULL;
    }
    memset(mm, 0, sizeof(*mm));

    void *pml4_page = fut_pmm_alloc_page();
    if (!pml4_page) {
        fut_free(mm);
        return NULL;
    }

    memset(pml4_page, 0, PAGE_SIZE);
    pte_t *pml4 = (pte_t *)pml4_page;
    copy_kernel_half(pml4);

    mm->ctx.pml4 = pml4;
    mm->ctx.cr3_value = pmap_virt_to_phys((uintptr_t)pml4);
    mm->ctx.ref_count = 1;
    atomic_store_explicit(&mm->refcnt, 1, memory_order_relaxed);
    mm->flags = FUT_MM_USER;

    return mm;
}

void fut_mm_retain(fut_mm_t *mm) {
    if (!mm) {
        return;
    }
    atomic_fetch_add_explicit(&mm->refcnt, 1, memory_order_acq_rel);
}

void fut_mm_release(fut_mm_t *mm) {
    if (!mm || mm == &kernel_mm) {
        return;
    }
    if (atomic_fetch_sub_explicit(&mm->refcnt, 1, memory_order_acq_rel) != 1) {
        return;
    }

    if (mm->ctx.pml4) {
        fut_pmm_free_page(mm->ctx.pml4);
        mm->ctx.pml4 = NULL;
    }

    fut_free(mm);
}

void fut_mm_switch(fut_mm_t *mm) {
    mm = mm_fallback(mm);
    if (active_mm == mm) {
        return;
    }

    active_mm = mm;
    fut_write_cr3(mm->ctx.cr3_value);
}

static fut_mm_t *mm_from_current_thread(void) {
    fut_thread_t *thread = fut_thread_current();
    if (!thread || !thread->task) {
        return active_mm ? active_mm : &kernel_mm;
    }

    fut_mm_t *task_mm = fut_task_get_mm(thread->task);
    if (task_mm) {
        return task_mm;
    }
    return &kernel_mm;
}

fut_mm_t *fut_mm_current(void) {
    return mm_from_current_thread();
}

fut_vmem_context_t *fut_mm_context(fut_mm_t *mm) {
    mm = mm_fallback(mm);
    return &mm->ctx;
}
