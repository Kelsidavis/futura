/* sys_fork.c - fork() syscall implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements process cloning via fork().
 */

#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
#include <kernel/fut_mm.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_vfs.h>
#include <kernel/errno.h>
#include <kernel/uaccess.h>
#include <arch/x86_64/paging.h>
#include <arch/x86_64/pmap.h>
#include <string.h>

extern void fut_printf(const char *fmt, ...);

/* Forward declarations */
static fut_mm_t *clone_mm(fut_mm_t *parent_mm);
static fut_thread_t *clone_thread(fut_thread_t *parent_thread, fut_task_t *child_task);

/* Dummy entry point for cloned threads - should never be called */
static void dummy_entry(void *arg) {
    (void)arg;
    /* This should never be called since we override the context */
    for (;;);
}

/**
 * fork() syscall - Create a new process by duplicating the calling process.
 *
 * Returns:
 *   - Child PID in parent process
 *   - 0 in child process
 *   - -errno on error
 */
long sys_fork(void) {
    fut_thread_t *parent_thread = fut_thread_current();
    if (!parent_thread) {
        return -ESRCH;
    }

    fut_task_t *parent_task = parent_thread->task;
    if (!parent_task) {
        return -ESRCH;
    }

    /* Create new child task */
    fut_task_t *child_task = fut_task_create();
    if (!child_task) {
        return -ENOMEM;
    }

    /* Clone address space (for now, create new empty one - COW can be added later) */
    fut_mm_t *parent_mm = fut_task_get_mm(parent_task);
    fut_mm_t *child_mm = NULL;

    if (parent_mm && parent_mm != fut_mm_kernel()) {
        child_mm = clone_mm(parent_mm);
        if (!child_mm) {
            fut_task_destroy(child_task);
            return -ENOMEM;
        }
        fut_task_set_mm(child_task, child_mm);
    }

    /* Clone the current thread into the child task */
    fut_thread_t *child_thread = clone_thread(parent_thread, child_task);
    if (!child_thread) {
        if (child_mm) {
            fut_mm_release(child_mm);
        }
        fut_task_destroy(child_task);
        return -ENOMEM;
    }

    /*
     * Set return value for child to 0
     * On x86_64: child will see RAX=0 when it starts running
     * On ARM64: return value in x0 is handled by thread entry point
     */
#ifdef __x86_64__
    child_thread->context.rax = 0;
#elif defined(__aarch64__)
    /* On ARM64, x0 is caller-saved and not in context struct.
     * The thread entry point will need to set this appropriately. */
    (void)child_thread;  /* Silence unused warning for now */
#endif

    fut_printf("[FORK] Created child: parent_pid=%llu parent_tid=%llu child_pid=%llu child_tid=%llu\n",
               parent_task->pid, parent_thread->tid,
               child_task->pid, child_thread->tid);

    /* Return child PID to parent */
    return (long)child_task->pid;
}

/**
 * Clone memory management context.
 * Copies all user page mappings from parent to child.
 * TODO: Implement copy-on-write (COW) for efficiency.
 */
static fut_mm_t *clone_mm(fut_mm_t *parent_mm) {
    if (!parent_mm) {
        return NULL;
    }

    /* Create a new userspace MM */
    fut_mm_t *child_mm = fut_mm_create();
    if (!child_mm) {
        return NULL;
    }

    /* Copy heap settings */
    child_mm->brk_start = parent_mm->brk_start;
    child_mm->brk_current = parent_mm->brk_current;
    child_mm->heap_limit = parent_mm->heap_limit;
    child_mm->mmap_base = parent_mm->mmap_base;

    /* Copy all user page mappings from parent to child */
    /* Scan a minimal region around typical program load address (0x400000).
     * Programs are typically loaded at 0x400000, so scan 0x400000 to 0x500000 (1MB).
     * TODO: Implement proper VMA (Virtual Memory Area) tracking to only copy actually-mapped regions. */
    fut_vmem_context_t *parent_ctx = fut_mm_context(parent_mm);
    fut_vmem_context_t *child_ctx = fut_mm_context(child_mm);

    #define CLONE_SCAN_START 0x400000ULL   /* Typical userspace load address */
    #define CLONE_SCAN_END   0x500000ULL   /* +1MB from start */

    /* Scan the program region (typically 0x400000-0x500000) */
    for (uint64_t page = CLONE_SCAN_START; page < CLONE_SCAN_END; page += FUT_PAGE_SIZE) {
        uint64_t pte = 0;

        /* Check if this page is mapped in parent */
        if (pmap_probe_pte(parent_ctx, page, &pte) != 0) {
            continue;  /* Not mapped or error */
        }

        if ((pte & PTE_PRESENT) == 0) {
            continue;  /* Page not present */
        }

        /* Allocate new physical page for child */
        void *child_page = fut_pmm_alloc_page();
        if (!child_page) {
            /* Out of memory - clean up and fail */
            fut_mm_release(child_mm);
            return NULL;
        }

        /* Get parent's physical page and copy contents */
        phys_addr_t parent_phys = pte & PTE_PHYS_ADDR_MASK;
        void *parent_page = (void *)pmap_phys_to_virt(parent_phys);
        memcpy(child_page, parent_page, FUT_PAGE_SIZE);

        /* Map the new page in child's address space with same permissions */
        phys_addr_t child_phys = pmap_virt_to_phys((uintptr_t)child_page);
        uint64_t flags = pte & (PTE_PRESENT | PTE_WRITABLE | PTE_USER | PTE_NX);

        if (pmap_map_user(child_ctx, page, child_phys, FUT_PAGE_SIZE, flags) != 0) {
            /* Mapping failed - clean up */
            fut_pmm_free_page(child_page);
            fut_mm_release(child_mm);
            return NULL;
        }
    }

    /* Also scan the stack region at the top of user space */
    /* Stack is typically at 0x7FFFFFFFE000 down to 0x7FFFFFF00000 (around 1 MB) */
    #define STACK_SCAN_START 0x7FFFFFF00000ULL
    #define STACK_SCAN_END   (STACK_SCAN_START + (1 * 1024 * 1024))  /* +1MB from start */

    for (uint64_t vaddr = STACK_SCAN_START; vaddr < STACK_SCAN_END; vaddr += (2 * 1024 * 1024)) {
        for (uint64_t page = vaddr; page < vaddr + (2 * 1024 * 1024) && page < STACK_SCAN_END; page += FUT_PAGE_SIZE) {
            uint64_t pte = 0;

            if (pmap_probe_pte(parent_ctx, page, &pte) != 0) {
                continue;
            }

            if ((pte & PTE_PRESENT) == 0) {
                continue;
            }

            void *child_page = fut_pmm_alloc_page();
            if (!child_page) {
                fut_mm_release(child_mm);
                return NULL;
            }

            phys_addr_t parent_phys = pte & PTE_PHYS_ADDR_MASK;
            void *parent_page = (void *)pmap_phys_to_virt(parent_phys);
            memcpy(child_page, parent_page, FUT_PAGE_SIZE);

            phys_addr_t child_phys = pmap_virt_to_phys((uintptr_t)child_page);
            uint64_t flags = pte & (PTE_PRESENT | PTE_WRITABLE | PTE_USER | PTE_NX);

            if (pmap_map_user(child_ctx, page, child_phys, FUT_PAGE_SIZE, flags) != 0) {
                fut_pmm_free_page(child_page);
                fut_mm_release(child_mm);
                return NULL;
            }
        }
    }

    return child_mm;
}

/**
 * Clone thread structure.
 * Creates a new thread in the child task with copied register state.
 */
static fut_thread_t *clone_thread(fut_thread_t *parent_thread, fut_task_t *child_task) {
    if (!parent_thread || !child_task) {
        return NULL;
    }

    /*
     * Create a new thread in the child task.
     * Use a dummy entry point - we'll override the context below.
     */
    fut_thread_t *child_thread = fut_thread_create(
        child_task,
        dummy_entry,
        NULL,
        parent_thread->stack_size,
        parent_thread->priority
    );

    if (!child_thread) {
        return NULL;
    }

    /* Copy the entire CPU context from parent to child */
    /* This makes the child resume execution at the same point as parent */
    memcpy(&child_thread->context, &parent_thread->context, sizeof(fut_cpu_context_t));

    /*
     * Note: We don't copy the stack contents.
     * In a proper fork(), we would:
     * 1. Copy all stack pages
     * 2. Adjust stack pointer
     * 3. Set up COW for stack
     *
     * For now, this works for fork+exec pattern where exec replaces everything.
     */

    return child_thread;
}
