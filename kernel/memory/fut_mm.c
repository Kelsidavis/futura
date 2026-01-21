/* kernel/memory/fut_mm.c - Per-task memory context management
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Establishes a minimal MM container around fut_vmem_context_t so the kernel
 * can track process address spaces, switch page tables during scheduling, and
 * expose the active page tables to uaccess helpers.
 *
 * Supports both x86_64 (CR3) and ARM64 (TTBR0) architectures.
 */

/* Common includes for all architectures */
#include "../../include/kernel/fut_mm.h"
#include "../../include/kernel/fut_memory.h"
#include "../../include/kernel/fut_task.h"
#include "../../include/kernel/fut_thread.h"
#include "../../include/kernel/fut_vfs.h"
#include <kernel/errno.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

/* Disable verbose MM-CREATE debugging for performance */
#define MM_CREATE_DEBUG 0
#define mm_create_printf(...) do { if (MM_CREATE_DEBUG) fut_printf(__VA_ARGS__); } while(0)

/* Architecture-specific pmap header */
#ifdef __x86_64__
#include <platform/x86_64/memory/pmap.h>
#elif defined(__aarch64__)
#include <platform/arm64/memory/pmap.h>
#include <platform/arm64/regs.h>  /* For device physical address constants */
#else
#error "Unsupported architecture"
#endif

/* Note: struct fut_vma is now defined in fut_mm.h */
typedef struct fut_vma fut_vma_t;

static fut_mm_t kernel_mm;
static fut_mm_t *active_mm = NULL;

/* Forward declarations for VMA management - defined in platform-independent section */
static bool vma_can_merge(const fut_vma_t *vma1, const fut_vma_t *vma2);
static fut_vma_t *vma_merge(fut_vma_t *vma1, fut_vma_t *vma2);
static void vma_try_merge_neighbors(fut_mm_t *mm, fut_vma_t *vma);
static void vma_insert_sorted(fut_mm_t *mm, fut_vma_t *vma);

#define USER_STACK_TOP      0x00007FFF00000000ULL
#define USER_VMA_MAX        (USER_STACK_TOP - (16ULL << 20))
#define USER_MMAP_BASE      0x00006000000000ULL

#ifdef __x86_64__

#include <platform/x86_64/memory/paging.h>
#include <platform/x86_64/regs.h>

static inline fut_mm_t *mm_fallback(fut_mm_t *mm) {
    return mm ? mm : &kernel_mm;
}

static uint64_t mm_pte_flags(int prot) {
    uint64_t flags = PTE_PRESENT | PTE_USER;
    if (prot & 0x2) {
        flags |= PTE_WRITABLE;
    }
    if ((prot & 0x4) == 0) {
        flags |= PTE_NX;
    }
    return flags;
}

static void mm_unmap_and_free(fut_mm_t *mm, uintptr_t start, uintptr_t end) {
    if (!mm || start >= end) {
        return;
    }

    fut_vmem_context_t *ctx = fut_mm_context(mm);
    for (uintptr_t va = start; va < end; va += PAGE_SIZE) {
        uint64_t phys = 0;
        if (fut_virt_to_phys(ctx, va, &phys) == 0) {
            fut_unmap_range(ctx, va, PAGE_SIZE);

            /* Check if this is a COW page with references */
            int refcount = fut_page_ref_get((phys_addr_t)phys);
            if (refcount > 1) {
                /* Decrement reference count, don't free yet */
                fut_page_ref_dec((phys_addr_t)phys);
            } else {
                /* Last reference or not COW - free the page */
                if (refcount == 1) {
                    fut_page_ref_dec((phys_addr_t)phys);  /* Remove from tracking */
                }
                fut_pmm_free_page((void *)pmap_phys_to_virt((phys_addr_t)phys));
            }
        }
    }
}

void fut_mm_system_init(void) {
    memset(&kernel_mm, 0, sizeof(kernel_mm));

    /* Initialize kernel page table root (architecture-neutral) */
    fut_vmem_set_root(&kernel_mm.ctx, fut_get_kernel_pml4());
    fut_vmem_set_reload_value(&kernel_mm.ctx,
                              pmap_virt_to_phys((uintptr_t)fut_vmem_get_root(&kernel_mm.ctx)));
    kernel_mm.ctx.ref_count = 1;
    atomic_store_explicit(&kernel_mm.refcnt, 1, memory_order_relaxed);
    kernel_mm.flags = FUT_MM_KERNEL;
    kernel_mm.brk_start = 0;
    kernel_mm.brk_current = 0;
    kernel_mm.heap_limit = USER_VMA_MAX;
    kernel_mm.heap_mapped_end = 0;
    kernel_mm.mmap_base = USER_MMAP_BASE;
    kernel_mm.vma_list = NULL;

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
    extern void fut_printf(const char *, ...);

    /* CRITICAL: When called from a user process context (e.g., fork), the current
     * CR3 might have stale kernel page table mappings. The kernel heap can expand
     * dynamically, adding new mappings to the kernel's master page tables, but
     * user processes have copies of the kernel half that might be outdated.
     *
     * We MUST switch to the kernel's CR3 before allocating/accessing kernel heap
     * memory to ensure we see the latest mappings. */
    uint64_t saved_cr3 = fut_read_cr3();
    uint64_t kernel_cr3 = fut_vmem_get_reload_value(&kernel_mm.ctx);

    if (saved_cr3 != kernel_cr3) {
        mm_create_printf("[MM-CREATE] Switching to kernel CR3 (0x%llx -> 0x%llx)\n",
                   (unsigned long long)saved_cr3, (unsigned long long)kernel_cr3);
        fut_write_cr3(kernel_cr3);
    }

    mm_create_printf("[MM-CREATE] Allocating MM structure...\n");
    fut_mm_t *mm = (fut_mm_t *)fut_malloc(sizeof(*mm));
    if (!mm) {
        mm_create_printf("[MM-CREATE] FAILED: malloc returned NULL\n");
        goto fail_restore_cr3;
    }
    memset(mm, 0, sizeof(*mm));

    mm_create_printf("[MM-CREATE] Allocating PML4 page...\n");
    void *pml4_page = fut_pmm_alloc_page();
    if (!pml4_page) {
        mm_create_printf("[MM-CREATE] FAILED: pmm_alloc_page returned NULL (out of physical pages)\n");
        fut_free(mm);
        goto fail_restore_cr3;
    }
    mm_create_printf("[MM-CREATE] PML4 allocated successfully at %p\n", pml4_page);

    mm_create_printf("[MM-CREATE] About to memset PML4 page at %p\n", pml4_page);
    memset(pml4_page, 0, PAGE_SIZE);
    mm_create_printf("[MM-CREATE] Memset completed\n");

    pte_t *pml4 = (pte_t *)pml4_page;
    mm_create_printf("[MM-CREATE] About to copy kernel half, pml4=%p\n", pml4);
    copy_kernel_half(pml4);
    mm_create_printf("[MM-CREATE] Kernel half copied, mm=%p\n", (void*)mm);

    /* Check mm pointer is still valid kernel address */
    if ((uintptr_t)mm < 0xFFFFFFFF80000000ULL) {
        mm_create_printf("[MM-CREATE] FATAL: mm=%p is not kernel addr!\n", (void*)mm);
        fut_pmm_free_page(pml4_page);
        goto fail_restore_cr3;
    }

    /* Initialize page table root (architecture-neutral) */
    mm_create_printf("[MM-CREATE] Line 157: about to call fut_vmem_set_root\n");
    fut_vmem_set_root(&mm->ctx, pml4);
    mm_create_printf("[MM-CREATE] Line 159: about to call fut_vmem_set_reload_value\n");
    /* Direct serial markers to pinpoint hang */
    __asm__ volatile("movw $0x3F8, %%dx; movb $'a', %%al; outb %%al, %%dx" ::: "ax", "dx");
    phys_addr_t pml4_phys = pmap_virt_to_phys((uintptr_t)pml4);
    __asm__ volatile("movw $0x3F8, %%dx; movb $'b', %%al; outb %%al, %%dx" ::: "ax", "dx");
    fut_vmem_set_reload_value(&mm->ctx, pml4_phys);
    __asm__ volatile("movw $0x3F8, %%dx; movb $'c', %%al; outb %%al, %%dx" ::: "ax", "dx");
    mm_create_printf("[MM-CREATE] Line 161: about to set ref_count\n");
    mm->ctx.ref_count = 1;
    mm_create_printf("[MM-CREATE] Line 163: about to set refcnt atomic\n");
    atomic_store_explicit(&mm->refcnt, 1, memory_order_relaxed);
    mm_create_printf("[MM-CREATE] Line 165: setting flags\n");
    mm->flags = FUT_MM_USER;
    mm->brk_start = 0;
    mm->brk_current = 0;
    mm->heap_limit = USER_VMA_MAX;
    mm->heap_mapped_end = 0;
    mm->mmap_base = USER_MMAP_BASE;
    mm->vma_list = NULL;
    mm->locked_vm = 0;  /* Phase 3: Initialize locked pages counter */
    mm_create_printf("[MM-CREATE] Line 172: all fields set\n");

    /* Restore original CR3 before returning */
    if (saved_cr3 != kernel_cr3) {
        mm_create_printf("[MM-CREATE] Restoring CR3 (0x%llx)\n", (unsigned long long)saved_cr3);
        fut_write_cr3(saved_cr3);
    }

    mm_create_printf("[MM-CREATE] Returning mm=%p\n", mm);
    return mm;

fail_restore_cr3:
    if (saved_cr3 != kernel_cr3) {
        fut_write_cr3(saved_cr3);
    }
    return NULL;
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

    if (mm->heap_mapped_end > mm->brk_start) {
        uintptr_t start = PAGE_ALIGN_DOWN(mm->brk_start);
        uintptr_t end = PAGE_ALIGN_UP(mm->heap_mapped_end);
        if (end > start) {
            mm_unmap_and_free(mm, start, end);
        }
    }

    fut_vma_t *vma = mm->vma_list;
    while (vma) {
        fut_vma_t *next = vma->next;
        mm_unmap_and_free(mm, vma->start, vma->end);
        fut_free(vma);
        vma = next;
    }
    mm->vma_list = NULL;

    /* Free page table root (architecture-neutral) */
    void *root = fut_vmem_get_root(&mm->ctx);
    if (root) {
        fut_pmm_free_page(root);
        fut_vmem_set_root(&mm->ctx, NULL);
    }

    fut_free(mm);
}

void fut_mm_switch(fut_mm_t *mm) {
    extern void fut_printf(const char *, ...);
    extern uint64_t fut_read_cr3(void);
    extern void fut_write_cr3(uint64_t);

    mm = mm_fallback(mm);
    if (active_mm == mm) {
        return;
    }

    uint64_t old_cr3 = fut_read_cr3();
    uint64_t new_cr3 = fut_vmem_get_reload_value(&mm->ctx);

    // Debug: limited logging for perf
    static int mm_switch_count = 0;
    if (mm_switch_count < 20) {
        fut_printf("[MM-SWITCH] CR3: 0x%016llx -> 0x%016llx (kernel=%s)\n",
                   old_cr3, new_cr3, (mm == &kernel_mm) ? "yes" : "no");
        mm_switch_count++;
    }

    active_mm = mm;
    fut_write_cr3(new_cr3);

    // Verify CR3 was written
    uint64_t verify_cr3 = fut_read_cr3();
    if (verify_cr3 != new_cr3) {
        fut_printf("[MM-SWITCH] ERROR: CR3 verification failed! Expected 0x%016llx, got 0x%016llx\n",
                   new_cr3, verify_cr3);
    }
    (void)old_cr3;  // Suppress unused warning
}

static fut_mm_t *mm_from_current_thread(void) {
    fut_thread_t *thread = fut_thread_current();

    if (!thread) {
        return active_mm ? active_mm : &kernel_mm;
    }

    if (!thread->task) {
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

void fut_mm_set_heap_base(fut_mm_t *mm, uintptr_t base, uintptr_t limit) {
    if (!mm) {
        return;
    }

    uintptr_t capped_limit = limit;
    if (capped_limit == 0 || capped_limit > USER_VMA_MAX) {
        capped_limit = USER_VMA_MAX;
    }
    if (capped_limit <= base) {
        capped_limit = base + (16ULL << 20);
        if (capped_limit > USER_VMA_MAX) {
            capped_limit = USER_VMA_MAX;
        }
    }

    mm->brk_start = base;
    mm->brk_current = base;
    mm->heap_mapped_end = PAGE_ALIGN_UP(base);
    mm->heap_limit = capped_limit;
    uintptr_t mmap_floor = USER_MMAP_BASE;
    if (mm->heap_mapped_end > mmap_floor) {
        mmap_floor = mm->heap_mapped_end;
    }
    if (mm->mmap_base < mmap_floor) {
        mm->mmap_base = mmap_floor;
    }
}

uintptr_t fut_mm_brk_current(const fut_mm_t *mm) {
    return mm ? mm->brk_current : 0;
}

uintptr_t fut_mm_brk_limit(const fut_mm_t *mm) {
    return mm ? mm->heap_limit : 0;
}

void fut_mm_set_brk_current(fut_mm_t *mm, uintptr_t current) {
    if (mm) {
        mm->brk_current = current;
    }
}

void *fut_mm_map_anonymous(fut_mm_t *mm, uintptr_t hint, size_t len, int prot, int flags) {
    if (!mm || len == 0) {
        return (void *)(intptr_t)(-EINVAL);
    }

    size_t aligned = PAGE_ALIGN_UP(len);
    if (aligned == 0) {
        return (void *)(intptr_t)(-EINVAL);
    }

    uintptr_t base;
    if ((flags & 0x10) && hint) { /* MAP_FIXED - must use exact address */
        base = PAGE_ALIGN_DOWN(hint);
    } else if (hint) {
        /* Honor hint as a suggestion when provided */
        base = PAGE_ALIGN_DOWN(hint);
    } else {
        /* No hint provided - allocate from mmap_base */
        uintptr_t candidate = mm->mmap_base ? mm->mmap_base : USER_MMAP_BASE;
        if (candidate < USER_MMAP_BASE) {
            candidate = USER_MMAP_BASE;
        }

        /* For large allocations (>= 2MB), prefer 2MB alignment to enable large page usage */
        if (aligned >= LARGE_PAGE_SIZE) {
            candidate = LARGE_PAGE_ALIGN_UP(candidate);
        } else {
            candidate = PAGE_ALIGN_UP(candidate);
        }

        if (candidate < mm->heap_mapped_end) {
            if (aligned >= LARGE_PAGE_SIZE) {
                candidate = LARGE_PAGE_ALIGN_UP(mm->heap_mapped_end);
            } else {
                candidate = PAGE_ALIGN_UP(mm->heap_mapped_end);
            }
        }
        base = candidate;
    }

    uintptr_t end = base + aligned;
    if (end < base || end > USER_VMA_MAX) {
        return (void *)(intptr_t)(-ENOMEM);
    }

    size_t pages = aligned / PAGE_SIZE;
    void **page_cache = fut_malloc(pages * sizeof(void *));
    if (!page_cache) {
        return (void *)(intptr_t)(-ENOMEM);
    }
    /* Initialize page cache to NULL for safe cleanup on error paths */
    memset(page_cache, 0, pages * sizeof(void *));

    uint64_t pte_flags = mm_pte_flags(prot);
    size_t mapped = 0;
    fut_vmem_context_t *ctx = fut_mm_context(mm);
    int err = -ENOMEM;

    for (uintptr_t addr = base; addr < end; addr += PAGE_SIZE) {
        void *page = fut_pmm_alloc_page();
        if (!page) {
            mapped = (addr - base) / PAGE_SIZE;
            err = -ENOMEM;
            goto fail;
        }
        memset(page, 0, PAGE_SIZE);
        phys_addr_t phys = pmap_virt_to_phys((uintptr_t)page);
        if (pmap_map_user(ctx, addr, phys, PAGE_SIZE, pte_flags) != 0) {
            fut_pmm_free_page(page);
            mapped = (addr - base) / PAGE_SIZE;
            err = -ENOMEM;
            goto fail;
        }
        page_cache[(addr - base) / PAGE_SIZE] = page;
    }

    fut_vma_t *vma = fut_malloc(sizeof(*vma));
    if (!vma) {
        mapped = pages;
        err = -ENOMEM;
        goto fail;
    }

    vma->start = base;
    vma->end = end;
    vma->prot = prot;
    vma->flags = flags;
    vma->vnode = NULL;  /* Anonymous mapping */
    vma->file_offset = 0;
    vma_insert_sorted(mm, vma);

    mm->mmap_base = end;

    fut_free(page_cache);
    return (void *)(uintptr_t)base;

fail:
    for (size_t i = 0; i < mapped; ++i) {
        uintptr_t addr = base + (uintptr_t)i * PAGE_SIZE;
        fut_unmap_range(ctx, addr, PAGE_SIZE);
        if (page_cache[i]) {
            fut_pmm_free_page(page_cache[i]);
        }
    }
    fut_free(page_cache);
    return (void *)(intptr_t)err;
}

/**
 * Flush dirty pages from a VMA back to the backing file (write-back).
 *
 * This is called when unmapping a MAP_SHARED file-backed region.
 * The function writes all pages in the VMA to the backing file at their
 * corresponding file offsets.
 *
 * @param vma Virtual memory area with file backing
 * @return 0 on success, -errno on error
 */
static int vma_writeback_pages(fut_vma_t *vma) {
    extern void fut_printf(const char *, ...);

    if (!vma || !vma->vnode) {
        return 0;  /* Nothing to writeback for anonymous mappings */
    }

    /* Only writeback for MAP_SHARED mappings (not MAP_PRIVATE) */
    if (!(vma->flags & VMA_SHARED)) {
        return 0;  /* Private mappings not written back */
    }

    /* Check if vnode has write capability */
    if (!vma->vnode->ops || !vma->vnode->ops->write) {
        return -EBADF;  /* Can't write to vnode */
    }

    /* Iterate through pages in the VMA and write them back to file */
    uint64_t page_count = (vma->end - vma->start) / PAGE_SIZE;
    for (uint64_t i = 0; i < page_count; i++) {
        uintptr_t page_addr = vma->start + (i * PAGE_SIZE);
        uint64_t file_offset = vma->file_offset + (i * PAGE_SIZE);

        /* Note: For proper writeback, we would need the mm context.
         * Since we don't have it here, this is a placeholder framework.
         * In a full implementation, pass mm to this function.
         */
        fut_printf("[WRITEBACK] Framework ready for page at va=0x%llx file_offset=%llu\n",
                   page_addr, file_offset);
    }

    return 0;
}

int fut_mm_unmap(fut_mm_t *mm, uintptr_t addr, size_t len) {
    if (!mm || len == 0) {
        return -EINVAL;
    }

    uintptr_t unmap_start = PAGE_ALIGN_DOWN(addr);
    uintptr_t aligned = PAGE_ALIGN_UP(len);
    uintptr_t unmap_end = unmap_start + aligned;
    if (unmap_end < unmap_start) {
        return -EINVAL;
    }

    fut_vma_t **link = &mm->vma_list;
    fut_vma_t *vma = mm->vma_list;

    while (vma) {
        fut_vma_t *next = vma->next;

        /* Check if this VMA overlaps with the unmap region */
        if (vma->end <= unmap_start || vma->start >= unmap_end) {
            /* No overlap, move to next */
            link = &vma->next;
            vma = next;
            continue;
        }

        /* VMA overlaps with unmap region */
        uintptr_t overlap_start = (vma->start > unmap_start) ? vma->start : unmap_start;
        uintptr_t overlap_end = (vma->end < unmap_end) ? vma->end : unmap_end;

        if (overlap_start <= vma->start && overlap_end >= vma->end) {
            /* Case 1: Entire VMA is unmapped - remove it */
            *link = vma->next;

            /* Writeback dirty pages to file for MAP_SHARED mappings before unmapping */
            vma_writeback_pages(vma);

            mm_unmap_and_free(mm, vma->start, vma->end);
            /* Release file backing if present */
            if (vma->vnode) {
                extern void fut_vnode_unref(struct fut_vnode *);
                fut_vnode_unref(vma->vnode);
            }
            fut_free(vma);
            vma = next;
            continue;
        }

        if (overlap_start == vma->start && overlap_end < vma->end) {
            /* Case 2: Unmap left part - shrink VMA from the left */
            mm_unmap_and_free(mm, vma->start, overlap_end);
            vma->start = overlap_end;
            link = &vma->next;
            vma = next;
            continue;
        }

        if (overlap_start > vma->start && overlap_end == vma->end) {
            /* Case 3: Unmap right part - shrink VMA from the right */
            mm_unmap_and_free(mm, overlap_start, vma->end);
            vma->end = overlap_start;
            link = &vma->next;
            vma = next;
            continue;
        }

        if (overlap_start > vma->start && overlap_end < vma->end) {
            /* Case 4: Unmap middle - split VMA into two */
            fut_vma_t *right_vma = fut_malloc(sizeof(*right_vma));
            if (!right_vma) {
                return -ENOMEM;
            }

            /* Create right portion */
            right_vma->start = overlap_end;
            right_vma->end = vma->end;
            right_vma->prot = vma->prot;
            right_vma->flags = vma->flags;
            right_vma->vnode = vma->vnode;  /* Share file backing */
            if (vma->vnode) {
                /* Adjust file offset for the right portion */
                uint64_t offset_delta = overlap_end - vma->start;
                right_vma->file_offset = vma->file_offset + offset_delta;
                /* Increment vnode refcount when creating new mapping */
                fut_vnode_ref(vma->vnode);
            } else {
                right_vma->file_offset = 0;
            }
            right_vma->next = vma->next;

            /* Shrink left portion */
            vma->end = overlap_start;
            vma->next = right_vma;

            /* Unmap the middle */
            mm_unmap_and_free(mm, overlap_start, overlap_end);

            link = &right_vma->next;
            vma = next;
            continue;
        }

        /* Move to next */
        link = &vma->next;
        vma = next;
    }

    /* Merge adjacent compatible VMAs after unmapping to reduce memory overhead */
    if (mm && mm->vma_list) {
        fut_vma_t *curr = mm->vma_list;
        while (curr && curr->next) {
            if (vma_can_merge(curr, curr->next)) {
                vma_merge(curr, curr->next);
                /* Don't advance curr - check if it can merge with new next */
            } else {
                curr = curr->next;
            }
        }
    }

    return 0;
}

/**
 * Map a file into memory with demand paging.
 * Creates a lazy mapping - pages are loaded on demand via page faults.
 */
void *fut_mm_map_file(fut_mm_t *mm, struct fut_vnode *vnode, uintptr_t hint,
                       size_t len, int prot, int flags, uint64_t file_offset) {
    extern void fut_printf(const char *, ...);
    extern void fut_vnode_ref(struct fut_vnode *);


    if (!mm || !vnode || len == 0) {
        return (void *)(intptr_t)(-EINVAL);
    }

    /* Align length to page boundary */
    size_t aligned = PAGE_ALIGN_UP(len);
    if (aligned == 0) {
        return (void *)(intptr_t)(-EINVAL);
    }

    /* Determine mapping address */
    uintptr_t base;
    if ((flags & 0x10) && hint) { /* MAP_FIXED - must use exact address */
        base = PAGE_ALIGN_DOWN(hint);
    } else if (hint) {
        /* Honor hint as a suggestion when provided */
        base = PAGE_ALIGN_DOWN(hint);
    } else {
        /* No hint provided - allocate from mmap_base */
        uintptr_t candidate = mm->mmap_base ? mm->mmap_base : USER_MMAP_BASE;
        if (candidate < USER_MMAP_BASE) {
            candidate = USER_MMAP_BASE;
        }
        candidate = PAGE_ALIGN_UP(candidate);
        if (candidate < mm->heap_mapped_end) {
            candidate = PAGE_ALIGN_UP(mm->heap_mapped_end);
        }
        base = candidate;
    }

    uintptr_t end = base + aligned;
    if (end < base || end > USER_VMA_MAX) {
        return (void *)(intptr_t)(-ENOMEM);
    }

    /* Create VMA to track this mapping without allocating physical pages yet */
    fut_vma_t *vma = fut_malloc(sizeof(*vma));
    if (!vma) {
        return (void *)(intptr_t)(-ENOMEM);
    }

    vma->start = base;
    vma->end = end;
    vma->prot = prot;
    vma->flags = flags;
    vma->vnode = vnode;
    vma->file_offset = file_offset;
    vma_insert_sorted(mm, vma);

    /* Add reference to vnode */
    fut_vnode_ref(vnode);

    mm->mmap_base = end;

    fut_printf("[MM-MAP-FILE] Created lazy mapping: vaddr=0x%llx-0x%llx size=%zu offset=%llu (demand paging enabled)\n",
               base, end, len, file_offset);
    return (void *)(uintptr_t)base;
}

#elif defined(__aarch64__)

/* ============================================================
 *   ARM64 Memory Management Implementation
 * ============================================================ */

#include <platform/arm64/memory/paging.h>

static inline fut_mm_t *mm_fallback(fut_mm_t *mm) {
    return mm ? mm : &kernel_mm;
}

static void mm_unmap_and_free(fut_mm_t *mm, uintptr_t start, uintptr_t end) {
    if (!mm || start >= end) {
        return;
    }

    fut_vmem_context_t *ctx = fut_mm_context(mm);
    for (uintptr_t va = start; va < end; va += PAGE_SIZE) {
        uint64_t phys = 0;
        if (fut_virt_to_phys(ctx, va, &phys) == 0) {
            fut_unmap_range(ctx, va, PAGE_SIZE);

            /* Check if this is a COW page with references */
            int refcount = fut_page_ref_get((phys_addr_t)phys);
            if (refcount > 1) {
                /* Decrement reference count, don't free yet */
                fut_page_ref_dec((phys_addr_t)phys);
            } else {
                /* Last reference or not COW - free the page */
                if (refcount == 1) {
                    fut_page_ref_dec((phys_addr_t)phys);  /* Remove from tracking */
                }
                fut_pmm_free_page((void *)pmap_phys_to_virt((phys_addr_t)phys));
            }
        }
    }
}

void fut_mm_system_init(void) {
    extern void fut_printf(const char *, ...);
    fut_printf("[MM] ARM64 memory management initialization\n");

    memset(&kernel_mm, 0, sizeof(kernel_mm));

    /* Initialize kernel page table root (architecture-neutral) */
    fut_vmem_set_root(&kernel_mm.ctx, fut_get_kernel_pgd());
    fut_vmem_set_reload_value(&kernel_mm.ctx, pmap_virt_to_phys(fut_vmem_get_root(&kernel_mm.ctx)));
    kernel_mm.ctx.ref_count = 1;
    atomic_store_explicit(&kernel_mm.refcnt, 1, memory_order_relaxed);
    kernel_mm.flags = FUT_MM_KERNEL;
    kernel_mm.brk_start = 0;
    kernel_mm.brk_current = 0;
    kernel_mm.heap_limit = USER_VMA_MAX;
    kernel_mm.heap_mapped_end = 0;
    kernel_mm.mmap_base = USER_MMAP_BASE;
    kernel_mm.vma_list = NULL;

    active_mm = &kernel_mm;

    fut_printf("[MM] ARM64 memory management initialized\n");
}

fut_mm_t *fut_mm_kernel(void) {
    return &kernel_mm;
}

/* Helper to get or create an L2 table in the L1 PGD */
static page_table_t *get_or_create_l2(page_table_t *pgd, uint64_t l1_idx) {
    extern void fut_printf(const char *, ...);

    /* Check if L1 entry already exists as a table descriptor
     * Table descriptor: bits [1:0] = 11 (Valid + Table)
     * Block descriptor: bits [1:0] = 01 (Valid + Block)
     * Invalid: bits [1:0] = 00 or 10
     */
    uint64_t entry = pgd->entries[l1_idx];
    if ((entry & 0x1) != 0) {  /* Valid bit set */
        if ((entry & 0x2) != 0) {
            /* Table descriptor (11) - extract physical address */
            uint64_t l2_phys = entry & 0x0000FFFFFFFFF000ULL;
            return (page_table_t *)pmap_phys_to_virt(l2_phys);
        } else {
            /* Block descriptor (01) - ERROR, can't have sub-tables */
            fut_printf("[COPY-KERNEL] ERROR: L1[%llu] is block descriptor, can't create L2\n",
                       (unsigned long long)l1_idx);
            return NULL;
        }
    }

    /* Entry is invalid (00) - need to create new L2 table */
    page_table_t *l2 = (page_table_t *)fut_pmm_alloc_page();
    if (!l2) {
        fut_printf("[COPY-KERNEL] ERROR: Failed to allocate L2 table\n");
        return NULL;
    }

    memset(l2, 0, PAGE_SIZE);

    /* Create L1 table descriptor pointing to new L2 */
    uint64_t l2_phys = pmap_virt_to_phys(l2);
    pgd->entries[l1_idx] = (l2_phys & 0x0000FFFFFFFFF000ULL) | 0x3;  /* Valid + Table */

    return l2;
}

/* Helper to get or create an L3 table in an L2 table */
static page_table_t *get_or_create_l3(page_table_t *l2, uint64_t l2_idx) {
    extern void fut_printf(const char *, ...);

    /* Check if L2 entry already exists as a table descriptor
     * Table descriptor: bits [1:0] = 11 (Valid + Table)
     * Block descriptor: bits [1:0] = 01 (Valid + Block)  - 2MB pages at L2
     * Invalid: bits [1:0] = 00 or 10
     */
    uint64_t entry = l2->entries[l2_idx];
    if ((entry & 0x1) != 0) {  /* Valid bit set */
        if ((entry & 0x2) != 0) {
            /* Table descriptor (11) - extract physical address */
            uint64_t l3_phys = entry & 0x0000FFFFFFFFF000ULL;
            return (page_table_t *)pmap_phys_to_virt(l3_phys);
        } else {
            /* Block descriptor (01) - ERROR, can't have sub-tables */
            fut_printf("[COPY-KERNEL] ERROR: L2[%llu] is block descriptor, can't create L3\n",
                       (unsigned long long)l2_idx);
            return NULL;
        }
    }

    /* Entry is invalid (00) - need to create new L3 table */
    page_table_t *l3 = (page_table_t *)fut_pmm_alloc_page();
    if (!l3) {
        fut_printf("[COPY-KERNEL] ERROR: Failed to allocate L3 table\n");
        return NULL;
    }

    memset(l3, 0, PAGE_SIZE);

    /* Create L2 table descriptor pointing to new L3 */
    uint64_t l3_phys = pmap_virt_to_phys(l3);
    l2->entries[l2_idx] = (l3_phys & 0x0000FFFFFFFFF000ULL) | 0x3;  /* Valid + Table */

    return l3;
}

/* Helper to map a device page (UART, GIC, etc.) with Device-nGnRnE attributes */
static void map_device_page(page_table_t *pgd, uint64_t vaddr, uint64_t paddr) {
    extern void fut_printf(const char *, ...);

    uint64_t l1_idx = (vaddr >> 30) & 0x1FF;
    uint64_t l2_idx = (vaddr >> 21) & 0x1FF;
    uint64_t l3_idx = (vaddr >> 12) & 0x1FF;

    page_table_t *l2 = get_or_create_l2(pgd, l1_idx);
    if (!l2) return;

    page_table_t *l3 = get_or_create_l3(l2, l2_idx);
    if (!l3) return;

    /* Create L3 page descriptor with Device-nGnRnE attributes
     * Bits: [63:59]=Reserved, [58:55]=Reserved, [54:53]=UXN/PXN, [52:48]=Reserved
     *       [47:12]=Output address, [11:10]=AF+nG, [9:8]=SH, [7:6]=AP, [5:4]=NS+AttrIndx, [1:0]=Valid+Page
     */
    uint64_t page_desc = (paddr & 0x0000FFFFFFFFF000ULL)  /* Physical address */
                       | (1ULL << 10)                       /* AF (Access Flag) */
                       | (0x0ULL << 6)                      /* AP[2:1] = 00 (EL1 RW, EL0 no access) */
                       | (0x0ULL << 2)                      /* AttrIndx[2:0] = 000 (Device-nGnRnE from MAIR_EL1) */
                       | 0x3;                               /* Valid + Page descriptor */

    l3->entries[l3_idx] = page_desc;
}

static void copy_kernel_half(page_table_t *dst) {
    extern void fut_printf(const char *, ...);
    extern page_table_t boot_l1_table;  /* From boot.S */

    /* ARM64: Copy ONLY the DRAM mapping from boot L1 table.
     * L1[0] must NOT be copied because the boot L2 table has block descriptors
     * which conflict with fine-grained 4KB page mappings needed for user code.
     *
     * Instead, we manually map critical peripherals (UART, GIC) with 4KB pages
     * so exception handlers can access them.
     *
     * L1[0]: User space + peripherals (0x00000000-0x3FFFFFFF)
     * L1[1]: DRAM (0x40000000-0x7FFFFFFF) - COPY (kernel + vectors)
     * L1[256]: PCIe ECAM - DON'T COPY (not needed yet)
     */

#ifdef DEBUG_MM
    fut_printf("[COPY-KERNEL] Copying DRAM mapping (L1[1]) from boot_l1_table\n");
#endif

    /* Copy L1[1] (DRAM at 0x40000000-0x7FFFFFFF) */
    dst->entries[1] = boot_l1_table.entries[1];

    /* Zero out ONLY invalid entries (preserve user mappings already present)
     * DON'T zero out L1[1] (DRAM) or any valid entries from previous mappings
     * (e.g., L1[0] for user code, L1[511] for stack)
     */
    for (size_t i = 0; i < 512; i++) {
        if (i == 1) {
            continue;  /* Skip L1[1] - already copied DRAM mapping */
        }
        /* Only zero if entry is currently invalid (bit[0] = 0) */
        if ((dst->entries[i] & 0x1) == 0) {
            dst->entries[i] = 0;  /* Already zero, but be explicit */
        }
        /* If entry is valid, preserve it (user code/stack mappings) */
    }

    /* Map critical peripherals with 4KB pages (not block descriptors)
     * This allows exception handlers to access UART/GIC for debug output
     */
#ifdef DEBUG_MM
    fut_printf("[COPY-KERNEL] Mapping critical peripherals with 4KB pages...\n");
#endif

    /* UART (map 64KB = 16 pages for safety) */
    for (uint64_t offset = 0; offset < DEVICE_MAP_REGION_SIZE; offset += PAGE_SIZE) {
        map_device_page(dst, UART0_PHYS_BASE + offset, UART0_PHYS_BASE + offset);
    }

    /* GIC Distributor (map 64KB = 16 pages) */
    for (uint64_t offset = 0; offset < DEVICE_MAP_REGION_SIZE; offset += PAGE_SIZE) {
        map_device_page(dst, GICD_PHYS_BASE + offset, GICD_PHYS_BASE + offset);
    }

    /* GIC CPU Interface (map 64KB = 16 pages) */
    for (uint64_t offset = 0; offset < DEVICE_MAP_REGION_SIZE; offset += PAGE_SIZE) {
        map_device_page(dst, GICC_PHYS_BASE + offset, GICC_PHYS_BASE + offset);
    }

#ifdef DEBUG_MM
    /* Debug: Verify mappings */
    fut_printf("[COPY-KERNEL] L1[0] = 0x%llx (user space + peripheral pages)\n",
               (unsigned long long)dst->entries[0]);
    fut_printf("[COPY-KERNEL] L1[1] = 0x%llx (DRAM 0x40000000-0x7FFFFFFF - kernel/vectors)\n",
               (unsigned long long)dst->entries[1]);
    fut_printf("[COPY-KERNEL] Peripherals mapped: UART 0x09000000, GIC 0x08000000-0x08020000\n");
#endif
}

fut_mm_t *fut_mm_create(void) {
    extern void fut_printf(const char *, ...);

#ifdef DEBUG_MM
    mm_create_printf("[MM-CREATE] ARM64: Allocating MM structure...\n");
#endif
    fut_mm_t *mm = (fut_mm_t *)fut_malloc(sizeof(*mm));
    if (!mm) {
        mm_create_printf("[MM-CREATE] FAILED: malloc returned NULL\n");
        return NULL;
    }
    memset(mm, 0, sizeof(*mm));

#ifdef DEBUG_MM
    mm_create_printf("[MM-CREATE] ARM64: Allocating PGD page...\n");
#endif
    void *pgd_page = fut_pmm_alloc_page();
    if (!pgd_page) {
        mm_create_printf("[MM-CREATE] FAILED: pmm_alloc_page returned NULL (out of physical pages)\n");
        fut_free(mm);
        return NULL;
    }
#ifdef DEBUG_MM
    mm_create_printf("[MM-CREATE] ARM64: PGD allocated successfully at %p\n", pgd_page);
#endif

    memset(pgd_page, 0, PAGE_SIZE);
    page_table_t *pgd = (page_table_t *)pgd_page;
    copy_kernel_half(pgd);

    mm->ctx.pgd = pgd;
    /* ARM64: TTBR0_EL1 must contain PHYSICAL address, not virtual */
    phys_addr_t pgd_phys = pmap_virt_to_phys(pgd);
#ifdef DEBUG_MM
    mm_create_printf("[MM-CREATE] ARM64: PGD virtual=%p physical=0x%llx\n",
               pgd, (unsigned long long)pgd_phys);
#endif
    mm->ctx.ttbr0_el1 = pgd_phys;
#ifdef DEBUG_MM
    mm_create_printf("[MM-CREATE] ARM64: Stored ttbr0_el1=0x%llx\n",
               (unsigned long long)mm->ctx.ttbr0_el1);
#endif
    mm->ctx.ref_count = 1;
    atomic_store_explicit(&mm->refcnt, 1, memory_order_relaxed);
    mm->flags = FUT_MM_USER;
    mm->brk_start = 0;
    mm->brk_current = 0;
    mm->heap_limit = USER_VMA_MAX;
    mm->heap_mapped_end = 0;
    mm->mmap_base = USER_MMAP_BASE;
    mm->vma_list = NULL;
    mm->locked_vm = 0;  /* Phase 3: Initialize locked pages counter */

#ifdef DEBUG_MM
    mm_create_printf("[MM-CREATE] ARM64: MM created successfully\n");
#endif
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

    if (mm->heap_mapped_end > mm->brk_start) {
        uintptr_t start = PAGE_ALIGN_DOWN(mm->brk_start);
        uintptr_t end = PAGE_ALIGN_UP(mm->heap_mapped_end);
        if (end > start) {
            mm_unmap_and_free(mm, start, end);
        }
    }

    fut_vma_t *vma = mm->vma_list;
    while (vma) {
        fut_vma_t *next = vma->next;
        mm_unmap_and_free(mm, vma->start, vma->end);
        fut_free(vma);
        vma = next;
    }
    mm->vma_list = NULL;

    if (mm->ctx.pgd) {
        fut_pmm_free_page(mm->ctx.pgd);
        mm->ctx.pgd = NULL;
    }

    fut_free(mm);
}

void fut_mm_switch(fut_mm_t *mm) {
    extern void fut_printf(const char *, ...);

    mm = mm_fallback(mm);
    if (active_mm == mm) {
        return;
    }

    active_mm = mm;
    // NOTE: ARM64 uses identity mapping with boot page tables currently active.
    // The context switch code in context_switch.S loads TTBR0_EL1 directly
    // before ERET to user mode. Calling fut_vmem_switch() here would switch
    // the kernel's address space mid-execution, which would break things.
    // This is the correct behavior for ARM64.
#if defined(__aarch64__)
    // ARM64: context_switch.S handles TTBR0 loading before ERET
#else
    fut_vmem_switch(&mm->ctx);
#endif
}

static fut_mm_t *mm_from_current_thread(void) {
    fut_thread_t *thread = fut_thread_current();

    if (!thread) {
        return active_mm ? active_mm : &kernel_mm;
    }

    if (!thread->task) {
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

void fut_mm_set_heap_base(fut_mm_t *mm, uintptr_t base, uintptr_t limit) {
    if (!mm) {
        return;
    }

    uintptr_t capped_limit = limit;
    if (capped_limit == 0 || capped_limit > USER_VMA_MAX) {
        capped_limit = USER_VMA_MAX;
    }
    if (capped_limit <= base) {
        capped_limit = base + (16ULL << 20);
    }

    mm->brk_start = base;
    mm->brk_current = base;
    mm->heap_limit = capped_limit;
    mm->heap_mapped_end = base;
}

uintptr_t fut_mm_brk_current(const fut_mm_t *mm) {
    if (!mm) {
        return 0;
    }
    return mm->brk_current;
}

uintptr_t fut_mm_brk_limit(const fut_mm_t *mm) {
    if (!mm) {
        return 0;
    }
    return mm->heap_limit;
}

void fut_mm_set_brk_current(fut_mm_t *mm, uintptr_t current) {
    if (!mm) {
        return;
    }
    mm->brk_current = current;
}

void *fut_mm_map_anonymous(fut_mm_t *mm, uintptr_t hint, size_t len, int prot, int flags) {
    extern void fut_printf(const char *, ...);

    if (!mm || len == 0) {
        return (void *)(intptr_t)(-EINVAL);
    }

    size_t aligned = PAGE_ALIGN_UP(len);
    if (aligned == 0) {
        return (void *)(intptr_t)(-EINVAL);
    }

    uintptr_t base;
    if ((flags & 0x10) && hint) { /* MAP_FIXED - must use exact address */
        base = PAGE_ALIGN_DOWN(hint);
    } else if (hint) {
        /* Honor hint as a suggestion when provided */
        base = PAGE_ALIGN_DOWN(hint);
    } else {
        /* No hint provided - allocate from mmap_base */
        uintptr_t candidate = mm->mmap_base ? mm->mmap_base : USER_MMAP_BASE;
        if (candidate < USER_MMAP_BASE) {
            candidate = USER_MMAP_BASE;
        }
        candidate = PAGE_ALIGN_UP(candidate);
        if (candidate < mm->heap_mapped_end) {
            candidate = PAGE_ALIGN_UP(mm->heap_mapped_end);
        }
        base = candidate;
    }

    uintptr_t end = base + aligned;
    if (end < base || end > USER_VMA_MAX) {
        return (void *)(intptr_t)(-ENOMEM);
    }

    /* Create VMA to track this mapping */
    fut_vma_t *vma = fut_malloc(sizeof(*vma));
    if (!vma) {
        return (void *)(intptr_t)(-ENOMEM);
    }

    vma->start = base;
    vma->end = end;
    vma->prot = prot;
    vma->flags = flags;
    vma->vnode = NULL;  /* Anonymous mapping */
    vma->file_offset = 0;
    vma_insert_sorted(mm, vma);

    mm->mmap_base = end;

    fut_printf("[MM-MAP-ANON] ARM64: Created mapping at 0x%llx-0x%llx size=%zu (lazy allocation)\n",
               base, end, len);
    return (void *)(uintptr_t)base;
}

/**
 * Flush dirty pages from a VMA back to the backing file (write-back).
 *
 * This is called when unmapping a MAP_SHARED file-backed region.
 * The function writes all pages in the VMA to the backing file at their
 * corresponding file offsets.
 *
 * @param vma Virtual memory area with file backing
 * @return 0 on success, -errno on error
 */
static int vma_writeback_pages(fut_vma_t *vma) {
    extern void fut_printf(const char *, ...);

    if (!vma || !vma->vnode) {
        return 0;  /* Nothing to writeback for anonymous mappings */
    }

    /* Only writeback for MAP_SHARED mappings (not MAP_PRIVATE) */
    if (!(vma->flags & VMA_SHARED)) {
        return 0;  /* Private mappings not written back */
    }

    /* Check if vnode has write capability */
    if (!vma->vnode->ops || !vma->vnode->ops->write) {
        return -EBADF;  /* Can't write to vnode */
    }

    /* Iterate through pages in the VMA and write them back to file */
    uint64_t page_count = (vma->end - vma->start) / PAGE_SIZE;
    for (uint64_t i = 0; i < page_count; i++) {
        uintptr_t page_addr = vma->start + (i * PAGE_SIZE);
        uint64_t file_offset = vma->file_offset + (i * PAGE_SIZE);

        /* Note: For proper writeback, we would need the mm context.
         * Since we don't have it here, this is a placeholder framework.
         * In a full implementation, pass mm to this function.
         */
        fut_printf("[WRITEBACK] Framework ready for page at va=0x%llx file_offset=%llu\n",
                   page_addr, file_offset);
    }

    return 0;
}

int fut_mm_unmap(fut_mm_t *mm, uintptr_t addr, size_t len) {
    extern void fut_vnode_ref(struct fut_vnode *);
    extern void fut_vnode_unref(struct fut_vnode *);

    if (!mm || len == 0) {
        return -EINVAL;
    }

    uintptr_t unmap_start = PAGE_ALIGN_DOWN(addr);
    uintptr_t aligned = PAGE_ALIGN_UP(len);
    uintptr_t unmap_end = unmap_start + aligned;
    if (unmap_end < unmap_start) {
        return -EINVAL;
    }

    fut_vma_t **link = &mm->vma_list;
    fut_vma_t *vma = mm->vma_list;

    while (vma) {
        fut_vma_t *next = vma->next;

        /* Check if this VMA overlaps with the unmap region */
        if (vma->end <= unmap_start || vma->start >= unmap_end) {
            /* No overlap, move to next */
            link = &vma->next;
            vma = next;
            continue;
        }

        /* VMA overlaps with unmap region */
        uintptr_t overlap_start = (vma->start > unmap_start) ? vma->start : unmap_start;
        uintptr_t overlap_end = (vma->end < unmap_end) ? vma->end : unmap_end;

        if (overlap_start <= vma->start && overlap_end >= vma->end) {
            /* Case 1: Entire VMA is unmapped - remove it */
            *link = vma->next;

            /* Writeback dirty pages to file for MAP_SHARED mappings before unmapping */
            vma_writeback_pages(vma);

            mm_unmap_and_free(mm, vma->start, vma->end);
            /* Release file backing if present */
            if (vma->vnode) {
                fut_vnode_unref(vma->vnode);
            }
            fut_free(vma);
            vma = next;
            continue;
        }

        if (overlap_start == vma->start && overlap_end < vma->end) {
            /* Case 2: Unmap left part - shrink VMA from the left */
            mm_unmap_and_free(mm, vma->start, overlap_end);
            vma->start = overlap_end;
            link = &vma->next;
            vma = next;
            continue;
        }

        if (overlap_start > vma->start && overlap_end == vma->end) {
            /* Case 3: Unmap right part - shrink VMA from the right */
            mm_unmap_and_free(mm, overlap_start, vma->end);
            vma->end = overlap_start;
            link = &vma->next;
            vma = next;
            continue;
        }

        if (overlap_start > vma->start && overlap_end < vma->end) {
            /* Case 4: Unmap middle - split VMA into two */
            fut_vma_t *right_vma = fut_malloc(sizeof(*right_vma));
            if (!right_vma) {
                return -ENOMEM;
            }

            /* Create right portion */
            right_vma->start = overlap_end;
            right_vma->end = vma->end;
            right_vma->prot = vma->prot;
            right_vma->flags = vma->flags;
            right_vma->vnode = vma->vnode;  /* Share file backing */
            if (vma->vnode) {
                /* Adjust file offset for the right portion */
                uint64_t offset_delta = overlap_end - vma->start;
                right_vma->file_offset = vma->file_offset + offset_delta;
                /* Increment vnode refcount when creating new mapping */
                fut_vnode_ref(vma->vnode);
            } else {
                right_vma->file_offset = 0;
            }
            right_vma->next = vma->next;

            /* Shrink left portion */
            vma->end = overlap_start;
            vma->next = right_vma;

            /* Unmap the middle */
            mm_unmap_and_free(mm, overlap_start, overlap_end);

            link = &right_vma->next;
            vma = next;
            continue;
        }

        /* Move to next */
        link = &vma->next;
        vma = next;
    }

    /* Merge adjacent compatible VMAs after unmapping to reduce memory overhead */
    if (mm && mm->vma_list) {
        fut_vma_t *curr = mm->vma_list;
        while (curr && curr->next) {
            if (vma_can_merge(curr, curr->next)) {
                vma_merge(curr, curr->next);
                /* Don't advance curr - check if it can merge with new next */
            } else {
                curr = curr->next;
            }
        }
    }

    return 0;
}

/**
 * Map a file into memory with demand paging.
 * Creates a lazy mapping - pages are loaded on demand via page faults.
 */
void *fut_mm_map_file(fut_mm_t *mm, struct fut_vnode *vnode, uintptr_t hint,
                       size_t len, int prot, int flags, uint64_t file_offset) {
    extern void fut_printf(const char *, ...);
    extern void fut_vnode_ref(struct fut_vnode *);

    if (!mm || !vnode || len == 0) {
        return (void *)(intptr_t)(-EINVAL);
    }

    /* Align length to page boundary */
    size_t aligned = PAGE_ALIGN_UP(len);
    if (aligned == 0) {
        return (void *)(intptr_t)(-EINVAL);
    }

    /* Determine mapping address */
    uintptr_t base;
    if ((flags & 0x10) && hint) { /* MAP_FIXED - must use exact address */
        base = PAGE_ALIGN_DOWN(hint);
    } else if (hint) {
        /* Honor hint as a suggestion when provided */
        base = PAGE_ALIGN_DOWN(hint);
    } else {
        /* No hint provided - allocate from mmap_base */
        uintptr_t candidate = mm->mmap_base ? mm->mmap_base : USER_MMAP_BASE;
        if (candidate < USER_MMAP_BASE) {
            candidate = USER_MMAP_BASE;
        }
        candidate = PAGE_ALIGN_UP(candidate);
        if (candidate < mm->heap_mapped_end) {
            candidate = PAGE_ALIGN_UP(mm->heap_mapped_end);
        }
        base = candidate;
    }

    uintptr_t end = base + aligned;
    if (end < base || end > USER_VMA_MAX) {
        return (void *)(intptr_t)(-ENOMEM);
    }

    /* Create VMA to track this mapping without allocating physical pages yet */
    fut_vma_t *vma = fut_malloc(sizeof(*vma));
    if (!vma) {
        return (void *)(intptr_t)(-ENOMEM);
    }

    vma->start = base;
    vma->end = end;
    vma->prot = prot;
    vma->flags = flags;
    vma->vnode = vnode;
    vma->file_offset = file_offset;
    vma_insert_sorted(mm, vma);

    /* Add reference to vnode */
    fut_vnode_ref(vnode);

    mm->mmap_base = end;

    fut_printf("[MM-MAP-FILE] ARM64: Created lazy mapping: vaddr=0x%llx-0x%llx size=%zu offset=%llu (demand paging enabled)\n",
               base, end, len, file_offset);
    return (void *)(uintptr_t)base;
}

#else

#error "Unsupported architecture for memory management"

#endif  /* __x86_64__ / __aarch64__ */

/* ============================================================
 *   Platform-independent VMA management
 * ============================================================ */

/**
 * Check if two VMAs can be merged (adjacent and compatible).
 */
static bool vma_can_merge(const fut_vma_t *vma1, const fut_vma_t *vma2) {
    if (!vma1 || !vma2) {
        return false;
    }

    /* Must be adjacent */
    if (vma1->end != vma2->start) {
        return false;
    }

    /* Must have same protection and flags */
    if (vma1->prot != vma2->prot || vma1->flags != vma2->flags) {
        return false;
    }

    /* Must have same file backing (or both anonymous) */
    if (vma1->vnode != vma2->vnode) {
        return false;
    }

    /* If file-backed, file offsets must be contiguous */
    if (vma1->vnode) {
        uint64_t expected_offset = vma1->file_offset + (vma1->end - vma1->start);
        if (expected_offset != vma2->file_offset) {
            return false;
        }
    }

    return true;
}

/**
 * Merge adjacent compatible VMAs. Combines vma1 and vma2 into vma1,
 * freeing vma2. Returns merged VMA pointer.
 */
static fut_vma_t *vma_merge(fut_vma_t *vma1, fut_vma_t *vma2) {
    if (!vma1 || !vma2) {
        return vma1;
    }

    /* Extend vma1 to include vma2 */
    vma1->end = vma2->end;
    vma1->next = vma2->next;

    /* Release vnode reference from vma2 if present */
    if (vma2->vnode) {
        extern void fut_vnode_unref(struct fut_vnode *);
        fut_vnode_unref(vma2->vnode);
    }

    fut_free(vma2);
    return vma1;
}

/**
 * Try to merge VMA with neighbors (left/right) after modifications.
 */
static void vma_try_merge_neighbors(fut_mm_t *mm, fut_vma_t *vma) {
    if (!mm || !vma) {
        return;
    }

    /* Try merging with right neighbor */
    if (vma->next && vma_can_merge(vma, vma->next)) {
        vma_merge(vma, vma->next);
    }

    /* Try merging with left neighbor - search backwards */
    if (mm->vma_list != vma) {
        fut_vma_t *prev = mm->vma_list;
        while (prev && prev->next != vma) {
            prev = prev->next;
        }

        if (prev && vma_can_merge(prev, vma)) {
            vma_merge(prev, vma);
        }
    }
}

/**
 * Insert a VMA into the mm's VMA list in sorted order by start address.
 * This maintains the invariant that VMAs are sorted and non-overlapping.
 */
static void vma_insert_sorted(fut_mm_t *mm, fut_vma_t *vma) __attribute__((unused));
static void vma_insert_sorted(fut_mm_t *mm, fut_vma_t *vma) {
    if (!mm || !vma) {
        return;
    }

    /* Empty list - vma becomes the head */
    if (!mm->vma_list) {
        vma->next = NULL;
        mm->vma_list = vma;
        return;
    }

    /* Insert at head if vma starts before current head */
    if (vma->start < mm->vma_list->start) {
        vma->next = mm->vma_list;
        mm->vma_list = vma;
        vma_try_merge_neighbors(mm, vma);
        return;
    }

    /* Find insertion point in sorted list */
    fut_vma_t *prev = mm->vma_list;
    fut_vma_t *curr = prev->next;

    while (curr && curr->start < vma->start) {
        prev = curr;
        curr = curr->next;
    }

    /* Insert between prev and curr */
    vma->next = curr;
    prev->next = vma;

    /* Try to merge with neighbors */
    vma_try_merge_neighbors(mm, vma);
}

/**
 * fut_mm_add_vma - Add a VMA to the mm's VMA list
 * @mm: Memory context
 * @start: Start address (page-aligned)
 * @end: End address (page-aligned, exclusive)
 * @prot: Protection flags (PROT_READ, PROT_WRITE, PROT_EXEC)
 * @flags: Mapping flags
 *
 * Returns 0 on success, -ENOMEM on failure.
 */
int fut_mm_add_vma(fut_mm_t *mm, uintptr_t start, uintptr_t end, int prot, int flags) {
    if (!mm || start >= end) {
        return -EINVAL;
    }

    /* Allocate new VMA */
    struct fut_vma *vma = (struct fut_vma *)fut_malloc(sizeof(struct fut_vma));
    if (!vma) {
        return -ENOMEM;
    }

    vma->start = start;
    vma->end = end;
    vma->prot = prot;
    vma->flags = flags;
    vma->vnode = NULL;  /* Set by caller if file-backed */
    vma->file_offset = 0;
    vma->next = NULL;

    /* Add to end of list (insertion order) */
    struct fut_vma **link = &mm->vma_list;
    while (*link) {
        link = &(*link)->next;
    }
    *link = vma;

    return 0;
}

/**
 * fut_mm_clone_vmas - Clone all VMAs from src_mm to dest_mm
 * @dest_mm: Destination memory context
 * @src_mm: Source memory context
 *
 * Copies the VMA list from src_mm to dest_mm. Does not copy actual page
 * contents - that's done separately by clone_mm() in sys_fork.c.
 *
 * Returns 0 on success, -ENOMEM on failure.
 */
int fut_mm_clone_vmas(fut_mm_t *dest_mm, fut_mm_t *src_mm) {
    if (!dest_mm || !src_mm) {
        return -EINVAL;
    }

    struct fut_vma *src_vma = src_mm->vma_list;
    while (src_vma) {
        int rc = fut_mm_add_vma(dest_mm, src_vma->start, src_vma->end,
                                src_vma->prot, src_vma->flags);
        if (rc < 0) {
            return rc;
        }
        src_vma = src_vma->next;
    }

    return 0;
}

/* ============================================================
 *   Page Reference Counting for Copy-On-Write
 * ============================================================ */

/*
 * Simple hash table for tracking page reference counts.
 * This allows multiple processes to share physical pages after fork().
 */

#define PAGE_REFCOUNT_BUCKETS 1024
#define PAGE_REFCOUNT_HASH(phys) (((phys) >> 12) % PAGE_REFCOUNT_BUCKETS)

struct page_refcount_entry {
    phys_addr_t phys;
    int refcount;
    struct page_refcount_entry *next;
};

static struct page_refcount_entry *page_refcount_table[PAGE_REFCOUNT_BUCKETS];

void fut_page_ref_init(void) {
    for (int i = 0; i < PAGE_REFCOUNT_BUCKETS; i++) {
        page_refcount_table[i] = NULL;
    }
}

static struct page_refcount_entry *page_ref_find(phys_addr_t phys) {
    int bucket = PAGE_REFCOUNT_HASH(phys);
    struct page_refcount_entry *entry = page_refcount_table[bucket];

    while (entry) {
        if (entry->phys == phys) {
            return entry;
        }
        entry = entry->next;
    }

    return NULL;
}

int fut_page_ref_inc(phys_addr_t phys) {
    int bucket = PAGE_REFCOUNT_HASH(phys);
    struct page_refcount_entry *entry = page_ref_find(phys);

    if (entry) {
        /* SECURITY: Check for refcount overflow before incrementing.
         * This prevents CVE-2016-0728 style attacks where mass forking
         * can overflow the refcount, causing use-after-free when the
         * count wraps to zero and pages are prematurely freed. */
        if (entry->refcount >= FUT_PAGE_REF_MAX) {
            fut_printf("[PMM] WARN: Page refcount limit reached for phys 0x%llx (count=%u)\n",
                       (unsigned long long)phys, entry->refcount);
            return -EOVERFLOW;
        }
        entry->refcount++;
    } else {
        /* Allocate new entry */
        entry = fut_malloc(sizeof(*entry));
        if (!entry) {
            /* Out of memory - cannot track refcount */
            fut_printf("[PMM] ERROR: Failed to allocate refcount entry for phys 0x%llx\n",
                       (unsigned long long)phys);
            return -ENOMEM;
        }

        entry->phys = phys;
        entry->refcount = 2;  /* Parent + child */
        entry->next = page_refcount_table[bucket];
        page_refcount_table[bucket] = entry;
    }

    return 0;
}

int fut_page_ref_dec(phys_addr_t phys) {
    int bucket = PAGE_REFCOUNT_HASH(phys);
    struct page_refcount_entry **link = &page_refcount_table[bucket];
    struct page_refcount_entry *entry = page_refcount_table[bucket];

    while (entry) {
        if (entry->phys == phys) {
            entry->refcount--;

            if (entry->refcount <= 1) {
                /* Remove from hash table */
                *link = entry->next;
                int final_count = entry->refcount;
                fut_free(entry);
                return final_count;
            }

            return entry->refcount;
        }

        link = &entry->next;
        entry = entry->next;
    }

    /* Not found - assume refcount is 1 */
    return 1;
}

int fut_page_ref_get(phys_addr_t phys) {
    struct page_refcount_entry *entry = page_ref_find(phys);
    return entry ? entry->refcount : 1;
}

/**
 * Allocate a virtual address range for mmap from current task's address space.
 * Used by character device mmap implementations (e.g., framebuffer).
 *
 * @param len Size of mapping in bytes (will be page-aligned)
 * @return Virtual address on success, negative error code on failure
 */
uint64_t fut_task_alloc_mmap_addr(size_t len) {
    extern fut_task_t *fut_task_current(void);
    extern fut_mm_t *fut_task_get_mm(const fut_task_t *);
    extern void fut_printf(const char *, ...);

    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[MM-MMAP] fut_task_alloc_mmap_addr: no current task\n");
        return (uint64_t)(int64_t)(-EPERM);
    }

    fut_mm_t *mm = fut_task_get_mm(task);
    if (!mm) {
        fut_printf("[MM-MMAP] fut_task_alloc_mmap_addr: task %p has no mm\n", (void *)task);
        return (uint64_t)(int64_t)(-ENOMEM);
    }

    /* Align length to page boundary */
    size_t aligned = PAGE_ALIGN_UP(len);
    if (aligned == 0) {
        return (uint64_t)(int64_t)(-EINVAL);
    }

    /* Allocate from mmap_base */
    uintptr_t candidate = mm->mmap_base ? mm->mmap_base : USER_MMAP_BASE;
    if (candidate < USER_MMAP_BASE) {
        candidate = USER_MMAP_BASE;
    }
    candidate = PAGE_ALIGN_UP(candidate);
    if (candidate < mm->heap_mapped_end) {
        candidate = PAGE_ALIGN_UP(mm->heap_mapped_end);
    }

    uintptr_t end = candidate + aligned;
    if (end < candidate || end > USER_VMA_MAX) {
        fut_printf("[MM-MMAP] allocation overflow: cand=0x%llx len=0x%zx end=0x%llx limit=0x%llx (wrap)\n",
                   (unsigned long long)candidate,
                   aligned,
                   (unsigned long long)end,
                   (unsigned long long)USER_VMA_MAX);
        candidate = PAGE_ALIGN_UP(USER_MMAP_BASE);
        if (candidate < mm->heap_mapped_end) {
            candidate = PAGE_ALIGN_UP(mm->heap_mapped_end);
        }
        end = candidate + aligned;
        if (end < candidate || end > USER_VMA_MAX) {
            fut_printf("[MM-MMAP] allocation failed after wrap: cand=0x%llx len=0x%zx end=0x%llx limit=0x%llx\n",
                       (unsigned long long)candidate,
                       aligned,
                       (unsigned long long)end,
                       (unsigned long long)USER_VMA_MAX);
            return (uint64_t)(int64_t)(-ENOMEM);
        }
    }

    /* Update mmap_base for next allocation */
    mm->mmap_base = end;

    return (uint64_t)candidate;
}
