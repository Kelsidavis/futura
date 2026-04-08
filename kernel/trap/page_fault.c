// SPDX-License-Identifier: MPL-2.0
/*
 * page_fault.c - Page fault handling helpers
 */

#include "../../include/kernel/trap.h"

#include <kernel/kprintf.h>
#include "../../include/kernel/uaccess.h"
#include "../../include/kernel/errno.h"
#include "../../include/kernel/fut_task.h"
#include "../../include/kernel/fut_mm.h"
#include "../../include/kernel/fut_memory.h"
#include "../../include/kernel/fut_vfs.h"
#include "../../include/kernel/fut_sched.h"
#include "../../include/kernel/signal.h"

#ifdef __x86_64__
#include <platform/x86_64/regs.h>
#include <platform/x86_64/memory/paging.h>
#include <platform/x86_64/memory/pmap.h>
#endif

#ifdef __aarch64__
#include <platform/arm64/regs.h>
#include <platform/arm64/memory/paging.h>
#include <platform/arm64/memory/pmap.h>
#endif

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/* ============================================================
 *   Global VM Statistics Counters
 *
 *   These counters track system-wide page fault and paging events
 *   for /proc/vmstat and /proc/meminfo reporting.
 * ============================================================ */

static uint64_t vmstat_pgfault   = 0;  /* Total page faults (minor + major) */
static uint64_t vmstat_pgmajfault = 0; /* Major page faults (unresolvable) */
static uint64_t vmstat_pgpgin    = 0;  /* Pages paged in (demand paging) */
static uint64_t vmstat_cow_pages = 0;  /* Pages copied for COW */

void vmstat_get_counters(uint64_t *pgfault, uint64_t *pgmajfault,
                         uint64_t *pgpgin, uint64_t *cow_pages) {
    if (pgfault)    *pgfault    = vmstat_pgfault;
    if (pgmajfault) *pgmajfault = vmstat_pgmajfault;
    if (pgpgin)     *pgpgin     = vmstat_pgpgin;
    if (cow_pages)  *cow_pages  = vmstat_cow_pages;
}

/* ============================================================
 *   Shared Page Cache for MAP_SHARED
 *
 *   When multiple processes mmap the same file with MAP_SHARED,
 *   they must share the same physical pages so writes by one
 *   process are immediately visible to others.
 * ============================================================ */

#define SHARED_PAGE_CACHE_BUCKETS 256
#define SHARED_PAGE_CACHE_HASH(vnode, off) \
    ((((uintptr_t)(vnode) >> 4) ^ ((off) >> 12)) % SHARED_PAGE_CACHE_BUCKETS)

struct shared_page_entry {
    struct fut_vnode *vnode;
    uint64_t offset;           /* Page-aligned file offset */
    phys_addr_t phys;          /* Physical page address */
    struct shared_page_entry *next;
};

static struct shared_page_entry *shared_page_cache[SHARED_PAGE_CACHE_BUCKETS];
static fut_spinlock_t shared_page_locks[SHARED_PAGE_CACHE_BUCKETS];
static bool shared_page_cache_inited = false;

static void shared_page_cache_init(void) {
    if (shared_page_cache_inited) return;
    for (int i = 0; i < SHARED_PAGE_CACHE_BUCKETS; i++) {
        shared_page_cache[i] = NULL;
        fut_spinlock_init(&shared_page_locks[i]);
    }
    shared_page_cache_inited = true;
}

phys_addr_t shared_page_lookup(struct fut_vnode *vnode, uint64_t offset) {
    shared_page_cache_init();
    int bucket = SHARED_PAGE_CACHE_HASH(vnode, offset);
    fut_spinlock_acquire(&shared_page_locks[bucket]);
    struct shared_page_entry *e = shared_page_cache[bucket];
    while (e) {
        if (e->vnode == vnode && e->offset == offset) {
            phys_addr_t phys = e->phys;
            fut_spinlock_release(&shared_page_locks[bucket]);
            return phys;
        }
        e = e->next;
    }
    fut_spinlock_release(&shared_page_locks[bucket]);
    return 0;
}

void shared_page_insert(struct fut_vnode *vnode, uint64_t offset, phys_addr_t phys) {
    shared_page_cache_init();
    int bucket = SHARED_PAGE_CACHE_HASH(vnode, offset);
    fut_spinlock_acquire(&shared_page_locks[bucket]);
    /* Check for duplicate */
    struct shared_page_entry *e = shared_page_cache[bucket];
    while (e) {
        if (e->vnode == vnode && e->offset == offset) {
            fut_spinlock_release(&shared_page_locks[bucket]);
            return; /* Already cached */
        }
        e = e->next;
    }
    e = fut_malloc(sizeof(*e));
    if (e) {
        e->vnode = vnode;
        e->offset = offset;
        e->phys = phys;
        e->next = shared_page_cache[bucket];
        shared_page_cache[bucket] = e;
    }
    fut_spinlock_release(&shared_page_locks[bucket]);
}

/**
 * Remove a shared page cache entry for a given vnode+offset.
 * Called when the last mapper unmaps a MAP_SHARED page, preventing
 * stale entries from returning freed physical pages to new mappers.
 */
void shared_page_evict(struct fut_vnode *vnode, uint64_t offset) {
    if (!shared_page_cache_inited || !vnode) return;
    int bucket = SHARED_PAGE_CACHE_HASH(vnode, offset);
    fut_spinlock_acquire(&shared_page_locks[bucket]);
    struct shared_page_entry **link = &shared_page_cache[bucket];
    while (*link) {
        struct shared_page_entry *e = *link;
        if (e->vnode == vnode && e->offset == offset) {
            *link = e->next;
            fut_free(e);
            fut_spinlock_release(&shared_page_locks[bucket]);
            return;
        }
        link = &e->next;
    }
    fut_spinlock_release(&shared_page_locks[bucket]);
}

/**
 * Evict all shared page cache entries for a given vnode within an offset range.
 * Used by munmap to clean up shared page cache entries for unmapped file regions.
 */
void shared_page_evict_range(struct fut_vnode *vnode, uint64_t start_offset, uint64_t end_offset) {
    if (!shared_page_cache_inited || !vnode) return;
    for (uint64_t off = start_offset; off < end_offset; off += PAGE_SIZE) {
        shared_page_evict(vnode, off);
    }
}

/* ============================================================
 *   Architecture-Generic Demand Paging & COW Handling
 * ============================================================ */

/**
 * Load a single demand-paged page and map it.
 * Helper used by demand paging handler and read-ahead.
 */
/**
 * Load a page from file on demand (demand paging).
 *
 * Implements lazy page loading for file-backed memory mappings.
 * Called on page fault for unmapped file pages.
 *
 * Semantics:
 * - MAP_PRIVATE: Each process gets its own copy of the page after write.
 *   Modifications don't affect the file or other mappings.
 *   Implemented via COW (copy-on-write) in the page fault handler.
 *
 * - MAP_SHARED: All processes sharing the mapping see the same physical page.
 *   Writes to the page are visible to all mappers and persist to file.
 *   Dirty page tracking needed for write-back (Phase 4 enhancement).
 *
 * @param page_addr Virtual address to load (must be page-aligned)
 * @param vma Virtual memory area with file mapping info
 * @param ctx Page table context for mapping
 * @return true on success, false on error
 */
static bool load_demand_page(uint64_t page_addr, struct fut_vma *vma, fut_vmem_context_t *ctx) {

    if (!vma || !ctx) {
        return false;
    }

    /* Check if page is already present */
    uint64_t pte = 0;
    if (pmap_probe_pte(ctx, page_addr, &pte) == 0 && (pte & PTE_PRESENT)) {
        return false;  /* Already loaded */
    }

    /* Calculate file offset for this page */
    uint64_t page_offset = (page_addr - vma->start) + vma->file_offset;
    bool is_shared = (vma->flags & 0x01) != 0;  /* MAP_SHARED */

    /* Calculate PTE flags from VMA protection */
    uint64_t pte_flags = PTE_PRESENT | PTE_USER;
    if (vma->prot & 0x2) {
        pte_flags |= PTE_WRITABLE;  /* PROT_WRITE requested */
    }
    if ((vma->prot & 0x4) == 0) {
        pte_flags |= PTE_NX;  /* Execute not allowed */
    }

    extern int fut_page_ref_inc(phys_addr_t phys);

    /* MAP_SHARED: check shared page cache first.
     * Multiple processes mapping the same file with MAP_SHARED must
     * share the same physical pages so writes are immediately visible.
     */
    if (is_shared && vma->vnode) {
        phys_addr_t cached_phys = shared_page_lookup(vma->vnode, page_offset);
        if (cached_phys != 0) {
            /* Found in cache - map the same physical page */
            if (pmap_map_user(ctx, page_addr, cached_phys, PAGE_SIZE, pte_flags) != 0) {
                return false;
            }
            fut_page_ref_inc(cached_phys);
            return true;
        }
    }

    /* Allocate a physical page */
    void *page = fut_pmm_alloc_page();
    if (!page) {
        return false;
    }

    /* Zero-fill the page first */
    memset(page, 0, PAGE_SIZE);

    /* Read file contents into page */
    ssize_t bytes_read = 0;
    if (vma->vnode->ops && vma->vnode->ops->read) {
        bytes_read = vma->vnode->ops->read(vma->vnode, page, PAGE_SIZE, page_offset);
        if (bytes_read < 0) {
            fut_pmm_free_page(page);
            return false;
        }
        /* Partial reads are OK - rest of page remains zero (EOF handling) */
    }

    /* For MAP_PRIVATE with write permission, map as read-only initially.
     * Copy-on-write will handle the page when written to.
     * For MAP_SHARED, map with requested permissions.
     */
    if ((vma->prot & 0x2) && !is_shared) {  /* PROT_WRITE && !MAP_SHARED */
        /* MAP_PRIVATE + writable: Mark VMA as COW and map read-only */
        vma->flags |= VMA_COW;
        pte_flags &= ~PTE_WRITABLE;  /* Map read-only for COW */
    }

    /* Clean D-cache and invalidate I-cache for executable pages.
     * After writing file data to the page (via memset + vnode->read),
     * the data is in the D-cache but the I-cache may have stale (zero)
     * entries.  Without this, the CPU executes old I-cache data instead
     * of the newly loaded code, causing register corruption. */
#if defined(__aarch64__)
    if (vma->prot & 0x4) {  /* PROT_EXEC */
        for (uintptr_t off = 0; off < PAGE_SIZE; off += 64) {
            uintptr_t addr = (uintptr_t)page + off;
            __asm__ volatile("dc cvau, %0" :: "r"(addr) : "memory");
        }
        __asm__ volatile("dsb ish" ::: "memory");
        __asm__ volatile("ic iallu" ::: "memory");
        __asm__ volatile("dsb ish" ::: "memory");
        __asm__ volatile("isb" ::: "memory");
    }
#endif

    /* Map the page */
    phys_addr_t phys = pmap_virt_to_phys((uintptr_t)page);
    if (pmap_map_user(ctx, page_addr, phys, PAGE_SIZE, pte_flags) != 0) {
        fut_pmm_free_page(page);
        return false;
    }

    /* Register in shared page cache for MAP_SHARED so other processes
     * mapping the same file get the same physical page */
    if (is_shared && vma->vnode) {
        shared_page_insert(vma->vnode, page_offset, phys);
    }

    /* Initialize page reference count for COW tracking.
     * When a page is first allocated and mapped, it has exactly one reference.
     * If the mapping is MAP_PRIVATE, COW handling will use this refcount to
     * determine if the page can be made writable in-place (refcount=1) or
     * requires copying (refcount>1 from shared mappings).
     */
    if (fut_page_ref_inc(phys) != 0) {
        /* Refcount tracking failed - unmap and free the page */
        fut_unmap_range(ctx, page_addr, PAGE_SIZE);
        fut_pmm_free_page(page);
        return false;
    }

    vmstat_pgpgin++;
    return true;
}

/**
 * Read-ahead prefetching: Load adjacent pages on demand page fault.
 * Detects sequential access patterns and preloads nearby pages.
 */
static void readahead_prefetch(uint64_t fault_addr, struct fut_vma *vma, fut_vmem_context_t *ctx) {

    if (!vma || !ctx) {
        return;
    }

    /* Prefetch up to 4 adjacent pages (16KB on 4K pages) */
    #define READAHEAD_COUNT 4

    uint64_t page_addr = PAGE_ALIGN_DOWN(fault_addr);

    /* Try to prefetch next pages (forward direction) */
    for (int i = 1; i <= READAHEAD_COUNT; i++) {
        uint64_t prefetch_addr = page_addr + (i * PAGE_SIZE);

        /* Stop if outside VMA */
        if (prefetch_addr >= vma->end) {
            break;
        }

        /* Try to load, but don't fail if it can't be loaded */
        if (!load_demand_page(prefetch_addr, vma, ctx)) {
            /* If we can't load a prefetch page, stop - might be at EOF */
            break;
        }
    }
}

static bool handle_demand_paging_fault(uint64_t fault_addr, fut_mm_t *mm) {
    extern void fut_vnode_ref(struct fut_vnode *);

    if (!mm) {
        return false;
    }

    /* Find VMA containing fault address.
     * Hold mm_lock during lookup to prevent concurrent munmap from
     * freeing the VMA while we're using it (CVE-2018-17182 class). */
    uint64_t page_addr = PAGE_ALIGN_DOWN(fault_addr);
    fut_spinlock_acquire(&mm->mm_lock);
    struct fut_vma *vma = mm->vma_list;
    while (vma) {
        if (page_addr >= vma->start && page_addr < vma->end) {
            break;
        }
        vma = vma->next;
    }

    /* Not in any VMA */
    if (!vma) {
        fut_spinlock_release(&mm->mm_lock);
        return false;
    }

    /* Anonymous VMA (MAP_ANONYMOUS): allocate a zero-filled page on demand.
     * This handles pages that were never mapped (lazy allocation), pages
     * freed after fork/exec COW teardown, or pages reclaimed by the kernel. */
    if (!vma->vnode) {
        if (vma->prot == 0) {
            fut_spinlock_release(&mm->mm_lock);
            return false;
        }
        fut_vmem_context_t *ctx = fut_mm_context(mm);
        if (!ctx) {
            fut_spinlock_release(&mm->mm_lock);
            return false;
        }
        void *page = fut_pmm_alloc_page();
        if (!page) {
            fut_spinlock_release(&mm->mm_lock);
            return false;
        }
        memset(page, 0, PAGE_SIZE);
        phys_addr_t phys = pmap_virt_to_phys((uintptr_t)page);
        uint64_t pte_flags = PTE_PRESENT | PTE_USER;
        if (vma->prot & 0x2) pte_flags |= PTE_WRITABLE;
        if (!(vma->prot & 0x4)) pte_flags |= PTE_NX;
        if (pmap_map_user(ctx, page_addr, phys, PAGE_SIZE, pte_flags) != 0) {
            fut_pmm_free_page(page);
            fut_spinlock_release(&mm->mm_lock);
            return false;
        }
        fut_spinlock_release(&mm->mm_lock);
        return true;
    }

    /* PROT_NONE: VMA exists but access is forbidden.  Do NOT load the page —
     * return false so the caller delivers SIGSEGV (SEGV_ACCERR). */
    if (vma->prot == 0) {
        fut_spinlock_release(&mm->mm_lock);
        return false;
    }

    /* Get memory context for paging operations */
    fut_vmem_context_t *ctx = fut_mm_context(mm);
    if (!ctx) {
        fut_spinlock_release(&mm->mm_lock);
        return false;
    }

    /* Load the faulting page (VMA is stable under mm_lock) */
    bool loaded = load_demand_page(page_addr, vma, ctx);
    fut_spinlock_release(&mm->mm_lock);
    if (!loaded) {
        return false;
    }

    /* Prefetch adjacent pages for sequential access optimization */
    readahead_prefetch(fault_addr, vma, ctx);

    return true;
}

/**
 * Handle copy-on-write page fault (architecture-generic).
 * Returns true if handled, false if not a COW fault.
 *
 * Per-page COW tracking: Only process pages that are still mapped read-only.
 * Once a page is made writable (through copy or sole ownership), subsequent
 * faults won't trigger COW handling because the page is already writable.
 *
 * @param fault_addr Virtual address that faulted
 * @param is_write Whether the fault was a write (vs read)
 * @param is_present Whether the page is present (vs not mapped)
 */
static bool handle_cow_fault_generic(uint64_t fault_addr, bool is_write, bool is_present) {
    /* Check if this is a write fault */
    if (!is_write) {
        return false;  /* Not a write fault */
    }

    /* Check if page is present (COW pages are present but read-only) */
    if (!is_present) {
        return false;  /* Page not present - not COW */
    }

    /* Get current task and MM */
    fut_task_t *task = fut_task_current();
    if (!task) {
        return false;
    }

    fut_mm_t *mm = fut_task_get_mm(task);
    if (!mm) {
        return false;
    }

    /* Find VMA containing fault address */
    uint64_t page_addr = PAGE_ALIGN_DOWN(fault_addr);
    struct fut_vma *vma = mm->vma_list;
    while (vma) {
        if (page_addr >= vma->start && page_addr < vma->end) {
            break;
        }
        vma = vma->next;
    }

    if (!vma || !(vma->flags & VMA_COW)) {
        return false;  /* Not a COW VMA */
    }

    /* PROT_NONE: VMA exists but all access is forbidden — do not perform
     * COW; let the caller deliver SIGSEGV. */
    if (vma->prot == 0) {
        return false;
    }

    /* Get the current physical page */
    fut_vmem_context_t *ctx = fut_mm_context(mm);
    uint64_t pte = 0;
    if (pmap_probe_pte(ctx, page_addr, &pte) != 0) {
        return false;
    }

    /* Per-page COW tracking: Check if page is actually read-only (still needs COW)
     * Use architecture-specific helper to check writability */
    if (fut_pte_is_writable(pte)) {
        /* Page is already writable - COW already processed */
        fut_printf("[COW] Page already writable: va=0x%llx (COW already processed)\n",
                   page_addr);
        return false;  /* This shouldn't cause a fault - return false to handle normally */
    }

    phys_addr_t old_phys = pte & PTE_PHYS_ADDR_MASK;

    /* Check reference count */
    int refcount = fut_page_ref_get(old_phys);

    if (refcount > 1) {
        /* Multiple references - need to copy */
        void *new_page = fut_pmm_alloc_page();
        if (!new_page) {
            fut_printf("[COW] Failed to allocate page for COW\n");
            return false;
        }

        /* Copy old page to new page */
        void *old_page = (void *)pmap_phys_to_virt(old_phys);
        memcpy(new_page, old_page, PAGE_SIZE);

        /* Map new page with write permission */
        phys_addr_t new_phys = pmap_virt_to_phys((uintptr_t)new_page);
        uint64_t flags = (pte & (PTE_PRESENT | PTE_USER | PTE_NX)) | PTE_WRITABLE;

        fut_unmap_range(ctx, page_addr, PAGE_SIZE);
        if (pmap_map_user(ctx, page_addr, new_phys, PAGE_SIZE, flags) != 0) {
            fut_pmm_free_page(new_page);
            return false;
        }

        /* Initialize refcount for the new page (now owned by this process) */
        extern int fut_page_ref_inc(phys_addr_t phys);
        if (fut_page_ref_inc(new_phys) != 0) {
            /* Refcount tracking failed - unmap and free the new page */
            fut_unmap_range(ctx, page_addr, PAGE_SIZE);
            fut_pmm_free_page(new_page);
            return false;
        }

        /* Decrement old page refcount */
        int new_refcount = fut_page_ref_dec(old_phys);
        if (new_refcount == 0) {
            /* Last reference gone - free the old page */
            fut_pmm_free_page(old_page);
        }

        vmstat_cow_pages++;
    } else {
        /* Only one reference - just make it writable (sole owner optimization) */
        uint64_t flags = (pte & (PTE_PRESENT | PTE_USER | PTE_NX)) | PTE_WRITABLE;

        fut_unmap_range(ctx, page_addr, PAGE_SIZE);
        if (pmap_map_user(ctx, page_addr, old_phys, PAGE_SIZE, flags) != 0) {
            return false;
        }

        /* Decrement refcount to remove from tracking (refcount was 1, now goes to 0) */
        fut_page_ref_dec(old_phys);

        /* COW: sole owner, page made writable in place */
    }

    /* Per-page COW tracking achieved through PTE flags:
     * - Writable pages won't trigger write faults, so no further COW processing
     * - Read-only pages will trigger faults and be processed
     * - Page reference counting tracks multi-process sharing
     * This provides fine-grained COW tracking per-page without additional metadata.
     */

    return true;
}

/* ============================================================
 *   Architecture-Specific Page Fault Handlers
 * ============================================================ */

#ifdef __x86_64__

bool fut_trap_handle_page_fault(fut_interrupt_frame_t *frame) {
    const uint64_t fault_addr = fut_read_cr2();
    const struct fut_uaccess_window *window = fut_uaccess_window_current();

    if (window && window->resume && window->length != 0) {
        const uintptr_t start = (uintptr_t)window->user_ptr;
        const uintptr_t end = start + window->length;
        if (fault_addr >= start && fault_addr < end) {
            fut_uaccess_window_fault(-EFAULT);
            frame->rip = (uint64_t)window->resume;
            frame->rax = (uint64_t)(-EFAULT);
            return true;
        }
    }

    /* Try to handle as COW fault */
    if ((frame->cs & 0x3u) != 0) {  /* User mode fault */
        bool is_write = (frame->error_code & 0x2) != 0;
        bool is_present = (frame->error_code & 0x1) != 0;
        if (handle_cow_fault_generic(fault_addr, is_write, is_present)) {
            /* Minor fault: resolved without I/O */
            fut_task_t *cow_task = fut_task_current();
            if (cow_task) cow_task->minflt++;
            vmstat_pgfault++;
            return true;
        }
    }

    /* Try to handle as demand paging fault */
    if ((frame->cs & 0x3u) != 0) {  /* User mode fault */
        fut_mm_t *mm = fut_mm_current();
        if (handle_demand_paging_fault(fault_addr, mm)) {
            /* Minor fault: resolved without I/O (no swap in Futura) */
            fut_task_t *dp_task = fut_task_current();
            if (dp_task) dp_task->minflt++;
            vmstat_pgfault++;
            return true;
        }
    }

    if ((frame->cs & 0x3u) != 0) {
        /* Major fault: unresolvable — would require I/O in a full system */
        fut_task_t *maj_task = fut_task_current();
        if (maj_task) maj_task->majflt++;
        vmstat_pgfault++;
        vmstat_pgmajfault++;

        /* Log the unhandled user page fault */
        uint64_t cr2 = fut_read_cr2();
        fut_task_t *pf_dbg = fut_task_current();
        fut_printf("[#PF-USER] Unhandled user page fault: addr=0x%llx rip=0x%llx err=0x%llx pid=%d comm=%s\n",
                   (unsigned long long)cr2,
                   (unsigned long long)frame->rip,
                   (unsigned long long)frame->error_code,
                   pf_dbg ? (int)pf_dbg->pid : -1,
                   pf_dbg ? pf_dbg->comm : "?");
        fut_printf("[#PF-USER] RAX=0x%llx RBX=0x%llx RCX=0x%llx RDX=0x%llx\n",
                   (unsigned long long)frame->rax, (unsigned long long)frame->rbx,
                   (unsigned long long)frame->rcx, (unsigned long long)frame->rdx);
        fut_printf("[#PF-USER] RSP=0x%llx RBP=0x%llx RSI=0x%llx RDI=0x%llx\n",
                   (unsigned long long)frame->rsp, (unsigned long long)frame->rbp,
                   (unsigned long long)frame->rsi, (unsigned long long)frame->rdi);
        fut_printf("[#PF-USER] R8=0x%llx R9=0x%llx R10=0x%llx R11=0x%llx\n",
                   (unsigned long long)frame->r8, (unsigned long long)frame->r9,
                   (unsigned long long)frame->r10, (unsigned long long)frame->r11);
        fut_printf("[#PF-USER] R12=0x%llx R13=0x%llx R14=0x%llx R15=0x%llx\n",
                   (unsigned long long)frame->r12, (unsigned long long)frame->r13,
                   (unsigned long long)frame->r14, (unsigned long long)frame->r15);

        /* Deliver SIGSEGV: if a user handler is installed, redirect the interrupt
         * frame so the handler runs when we return from the exception.
         * Default action (no handler): terminate the faulting task immediately. */
        fut_task_t *pf_task = fut_task_current();
        if (pf_task) {
            sighandler_t pf_handler = fut_signal_get_handler(pf_task, SIGSEGV);
            if (pf_handler != SIG_DFL && pf_handler != SIG_IGN) {
                bool is_prot_fault = (frame->error_code & 0x1) != 0;
                siginfo_t pf_info;
                __builtin_memset(&pf_info, 0, sizeof(pf_info));
                pf_info.si_signum = SIGSEGV;
                pf_info.si_code   = is_prot_fault ? SEGV_ACCERR : SEGV_MAPERR;
                pf_info.si_addr   = (void *)(uintptr_t)cr2;
                fut_signal_send_with_info(pf_task, SIGSEGV, &pf_info);
                fut_signal_deliver(pf_task, frame);
                return true;
            }
        }
        /* SIG_DFL: terminate */
        fut_task_signal_exit(SIGSEGV);
        return true;
    }

    return false;
}

#elif defined(__aarch64__)

#include <platform/arm64/regs.h>
#include <platform/arm64/memory/paging.h>
#include <platform/arm64/memory/pmap.h>

/**
 * Handle ARM64 data/instruction abort (page fault).
 * Parses ESR (Exception Syndrome Register) to determine fault type.
 * Supports demand paging and copy-on-write.
 */
bool fut_trap_handle_page_fault(fut_interrupt_frame_t *frame) {

    if (!frame) {
        return false;
    }

    /* Extract exception class from ESR */
    uint64_t esr = frame->esr;
    uint32_t ec = (esr >> 26) & 0x3F;  /* Exception Class [31:26] */

    /* Get fault address from FAR */
    uint64_t fault_addr = frame->far;

    /* Check if this is a data abort or instruction abort (page fault) */
    bool is_lower_el  = (ec == 0x24);  /* ESR_EC_DABT_LOWER */
    bool is_current_el = (ec == 0x25); /* ESR_EC_DABT_CURRENT */
    bool is_iabt_el0  = (ec == 0x20);  /* ESR_EC_IABT_LOWER: instruction fetch fault */

    if (!is_lower_el && !is_current_el && !is_iabt_el0) {
        return false;  /* Not a page fault we can handle */
    }

    /* For instruction aborts, the faulting address is in PC (same as FAR for IABT).
     * Use frame->pc as the fault address for accurate demand-paging lookups. */
    if (is_iabt_el0) {
        fault_addr = frame->pc;
    }

    /* Extract fault status code (FSC) from ESR bits [5:0] */
    uint32_t fsc = esr & 0x3F;

    /* FSC encoding for page faults:
     * 0x0C (Level 0 translation fault)
     * 0x0E (Level 1 translation fault)
     * 0x0F (Level 2 translation fault)
     * 0x10 (Level 3 translation fault)
     * 0x14 (Level 1 access fault)
     * 0x15 (Level 2 access fault)
     * 0x16 (Level 3 access fault)
     * 0x04-0x07 (Level 0-3 translation fault)
     */
    bool is_translation_fault = ((fsc & 0x3C) == 0x04) || ((fsc & 0x3C) == 0x0C) ||
                                ((fsc & 0x3F) == 0x0F) || ((fsc & 0x3F) == 0x10);
    bool is_access_fault = ((fsc & 0x3C) == 0x14) || ((fsc & 0x3F) == 0x16);

    bool is_permission_fault = ((fsc & 0x3C) == 0x0C);  /* L1-L3 permission faults */

    if (!is_translation_fault && !is_access_fault && !is_permission_fault) {
        return false;  /* Not a fault type we can handle */
    }

    /* For EL1 faults (kernel accessing user memory via copy_from/to_user):
     * Check if there's an active uaccess window — if so, signal the fault
     * and redirect to the recovery label instead of crashing. */
    if (!is_lower_el && !is_iabt_el0) {
        const struct fut_uaccess_window *window = fut_uaccess_window_current();
        if (window && window->resume) {
            fut_uaccess_window_fault(-EFAULT);
            frame->pc = (uint64_t)(uintptr_t)window->resume;
            return true;  /* Redirect to copy fault handler */
        }
        return false;  /* Kernel fault without uaccess window — unhandled */
    }

    /* Extract write flag from ESR bit 6 (WnR: Write not Read).
     * Instruction fetches are never writes. */
    bool is_write = is_iabt_el0 ? false : (bool)((esr >> 6) & 1);

    /* Get current process memory context */
    fut_mm_t *mm = fut_mm_current();
    if (!mm) {
        return false;
    }

    /* Determine if page is present (for access faults) */
    bool is_present = is_access_fault;

    /* Try to handle as COW fault if write */
    if (is_write && handle_cow_fault_generic(fault_addr, is_write, is_present)) {
        fut_task_t *cow_task = fut_task_current();
        if (cow_task) cow_task->minflt++;
        vmstat_pgfault++;
        return true;  /* COW fault handled successfully */
    }

    /* Try to handle as demand paging fault */
    if (handle_demand_paging_fault(fault_addr, mm)) {
        fut_task_t *dp_task = fut_task_current();
        if (dp_task) dp_task->minflt++;
        vmstat_pgfault++;
        return true;  /* Demand paging fault handled successfully */
    }

    /* Major fault: unresolvable */
    {
        fut_task_t *maj_task = fut_task_current();
        if (maj_task) maj_task->majflt++;
        vmstat_pgfault++;
        vmstat_pgmajfault++;
    }

    fut_printf("[#PF-ARM64] user fault addr=0x%llx esr=0x%llx pc=0x%llx\n",
               (unsigned long long)fault_addr,
               (unsigned long long)esr,
               (unsigned long long)frame->pc);
    fut_printf("[#PF-ARM64] Registers: x0=0x%llx x1=0x%llx x2=0x%llx x3=0x%llx\n",
               (unsigned long long)frame->x[0], (unsigned long long)frame->x[1],
               (unsigned long long)frame->x[2], (unsigned long long)frame->x[3]);
    fut_printf("[#PF-ARM64] x4=0x%llx x5=0x%llx x6=0x%llx x7=0x%llx\n",
               (unsigned long long)frame->x[4], (unsigned long long)frame->x[5],
               (unsigned long long)frame->x[6], (unsigned long long)frame->x[7]);
    fut_printf("[#PF-ARM64] x8=0x%llx x9=0x%llx x10=0x%llx x11=0x%llx x12=0x%llx\n",
               (unsigned long long)frame->x[8], (unsigned long long)frame->x[9],
               (unsigned long long)frame->x[10], (unsigned long long)frame->x[11],
               (unsigned long long)frame->x[12]);
    fut_printf("[#PF-ARM64] sp=0x%llx sp_el0=0x%llx\n",
               (unsigned long long)frame->sp, (unsigned long long)frame->sp_el0);

    /* Deliver SIGSEGV: if a user handler is installed, redirect the exception frame
     * so the handler runs on ERET.  Default action: terminate immediately. */
    {
        fut_task_t *pf_task = fut_task_current();
        if (pf_task) {
            sighandler_t pf_handler = fut_signal_get_handler(pf_task, SIGSEGV);
            if (pf_handler != SIG_DFL && pf_handler != SIG_IGN) {
                siginfo_t pf_info;
                __builtin_memset(&pf_info, 0, sizeof(pf_info));
                pf_info.si_signum = SIGSEGV;
                pf_info.si_code   = is_access_fault ? SEGV_ACCERR : SEGV_MAPERR;
                pf_info.si_addr   = (void *)(uintptr_t)fault_addr;
                fut_signal_send_with_info(pf_task, SIGSEGV, &pf_info);
                fut_signal_deliver(pf_task, frame);
                return true;
            }
        }
    }
    fut_task_signal_exit(SIGSEGV);
    return true;
}

#else
#error "Unsupported architecture for page fault handling"
#endif
