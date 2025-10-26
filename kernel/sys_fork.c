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
#include <arch/x86_64/regs.h>
#include <string.h>

extern void fut_printf(const char *fmt, ...);
extern fut_interrupt_frame_t *fut_current_frame;

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
 * Copies all user page mappings from parent to child using VMA tracking.
 * TODO: Implement copy-on-write (COW) for efficiency.
 */
static fut_mm_t *clone_mm(fut_mm_t *parent_mm) {
    extern void fut_thread_yield(void);  /* For yielding during long operations */

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

    /* Clone VMA list from parent to child */
    if (fut_mm_clone_vmas(child_mm, parent_mm) != 0) {
        fut_mm_release(child_mm);
        return NULL;
    }

    fut_vmem_context_t *parent_ctx = fut_mm_context(parent_mm);
    fut_vmem_context_t *child_ctx = fut_mm_context(child_mm);

    /* If no VMAs are tracked, fall back to scanning fixed ranges */
    if (parent_mm->vma_list == NULL) {
        fut_printf("[FORK] No VMAs tracked, falling back to fixed-range scan\n");

        /* Scan the program region (typically 0x400000-0x500000) */
        #define CLONE_SCAN_START 0x400000ULL
        #define CLONE_SCAN_END   0x500000ULL

        for (uint64_t page = CLONE_SCAN_START; page < CLONE_SCAN_END; page += FUT_PAGE_SIZE) {
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

        /* Scan the stack region */
        #define STACK_SCAN_START 0x7FFFFFF00000ULL
        #define STACK_SCAN_END   (STACK_SCAN_START + (1 * 1024 * 1024))

        for (uint64_t page = STACK_SCAN_START; page < STACK_SCAN_END; page += FUT_PAGE_SIZE) {
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

        return child_mm;
    }

    /* Iterate over VMAs and copy only mapped pages */
    struct fut_vma *vma;
    for (vma = parent_mm->vma_list; vma != NULL; vma = vma->next) {
        fut_printf("[FORK] Cloning VMA: 0x%llx-0x%llx\n", vma->start, vma->end);

        uint64_t page_count = 0;
        for (uint64_t page = vma->start; page < vma->end; page += FUT_PAGE_SIZE) {
            uint64_t pte = 0;

            /* Check if this page is mapped in parent */
            if (pmap_probe_pte(parent_ctx, page, &pte) != 0) {
                continue;  /* Not mapped */
            }

            if ((pte & PTE_PRESENT) == 0) {
                continue;  /* Page not present */
            }

            /* Allocate new physical page for child */
            void *child_page = fut_pmm_alloc_page();
            if (!child_page) {
                fut_mm_release(child_mm);
                return NULL;
            }

            /* Copy page contents */
            phys_addr_t parent_phys = pte & PTE_PHYS_ADDR_MASK;
            void *parent_page = (void *)pmap_phys_to_virt(parent_phys);
            memcpy(child_page, parent_page, FUT_PAGE_SIZE);

            /* Map in child with same permissions */
            phys_addr_t child_phys = pmap_virt_to_phys((uintptr_t)child_page);
            uint64_t flags = pte & (PTE_PRESENT | PTE_WRITABLE | PTE_USER | PTE_NX);

            if (pmap_map_user(child_ctx, page, child_phys, FUT_PAGE_SIZE, flags) != 0) {
                fut_pmm_free_page(child_page);
                fut_mm_release(child_mm);
                return NULL;
            }

            page_count++;

            /* Yield every 64 pages to avoid monopolizing CPU */
            if ((page_count & 0x3F) == 0) {
                fut_thread_yield();
            }
        }

        fut_printf("[FORK] Copied %llu pages from VMA\n", page_count);
    }

    return child_mm;
}

/**
 * Clone thread structure using syscall stack frame.
 * Creates a new thread in the child task that will return from the syscall.
 */
static fut_thread_t *clone_thread(fut_thread_t *parent_thread, fut_task_t *child_task) {
    if (!parent_thread || !child_task) {
        return NULL;
    }

    /* Get the syscall frame pointer (points to CPU-pushed part: RIP, CS, RFLAGS, RSP, SS) */
    uint64_t *frame_ptr = (uint64_t *)fut_current_frame;
    if (!frame_ptr) {
        fut_printf("[FORK] ERROR: No interrupt frame available!\n");
        return NULL;
    }

    /*
     * Syscall stack layout (from isr_stubs.S):
     * frame[0]  = RIP
     * frame[1]  = CS
     * frame[2]  = RFLAGS
     * frame[3]  = RSP (user stack)
     * frame[4]  = SS
     * frame[-1] = RAX (saved syscall number)
     * frame[-2] = CR3
     * frame[-3] = RBP
     * frame[-4] = RBX
     * frame[-5] = R12
     * frame[-6] = R13
     * frame[-7] = R14
     * frame[-8] = R15
     */
    uint64_t user_rip = frame_ptr[0];
    uint64_t user_cs = frame_ptr[1];
    uint64_t user_rflags = frame_ptr[2];
    uint64_t user_rsp = frame_ptr[3];
    uint64_t user_ss = frame_ptr[4];
    uint64_t user_rbp = frame_ptr[-3];
    uint64_t user_rbx = frame_ptr[-4];
    uint64_t user_r12 = frame_ptr[-5];
    uint64_t user_r13 = frame_ptr[-6];
    uint64_t user_r14 = frame_ptr[-7];
    uint64_t user_r15 = frame_ptr[-8];

    fut_printf("[FORK] Parent frame: RIP=0x%llx RSP=0x%llx\n", user_rip, user_rsp);

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

    /* Build child context from syscall frame */
    /* The child will be scheduled and return to userspace with the saved state */
    child_thread->context.rip = user_rip;
    child_thread->context.rsp = user_rsp;
    child_thread->context.rbp = user_rbp;
    child_thread->context.rbx = user_rbx;
    child_thread->context.r12 = user_r12;
    child_thread->context.r13 = user_r13;
    child_thread->context.r14 = user_r14;
    child_thread->context.r15 = user_r15;
    child_thread->context.rflags = user_rflags;
    child_thread->context.cs = user_cs;
    child_thread->context.ss = user_ss;

    /* Set segment registers to user data segment */
    child_thread->context.ds = 0x10;  // User data segment
    child_thread->context.es = 0x10;
    child_thread->context.fs = 0x10;
    child_thread->context.gs = 0x10;

    /* Set child's fork() return value to 0 */
    child_thread->context.rax = 0;

    fut_printf("[FORK] Child context: RIP=0x%llx RSP=0x%llx RAX=0\n",
               child_thread->context.rip, child_thread->context.rsp);

    return child_thread;
}
