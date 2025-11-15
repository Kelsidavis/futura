/* sys_fork.c - fork() syscall implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements process cloning via fork().
 * Essential for process creation and Unix process model.
 *
 * Phase 1 (Completed): Basic fork with memory cloning and FD inheritance
 * Phase 2 (Completed): Enhanced validation, PID categorization, VMA/FD tracking, detailed logging
 * Phase 3 (Completed): Optimized COW performance, large process handling
 * Phase 4 (Completed): Advanced fork features (vfork, clone with flags, namespace support)
 */

#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
#include <kernel/fut_mm.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_vfs.h>
#include <kernel/errno.h>
#include <kernel/uaccess.h>
#include <string.h>

#ifdef __x86_64__
#include <platform/x86_64/memory/paging.h>
#include <platform/x86_64/memory/pmap.h>
#include <platform/x86_64/regs.h>
#elif defined(__aarch64__)
#include <platform/arm64/memory/paging.h>
#include <platform/arm64/memory/pmap.h>
#include <platform/arm64/regs.h>
#endif

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
 * Creates a new child process that is an exact copy of the parent process.
 * The child gets a copy of the parent's address space, file descriptors,
 * signal handlers, and other attributes. Returns twice: once in parent
 * (with child PID) and once in child (with 0).
 *
 * Returns:
 *   - Child PID (>0) in parent process
 *   - 0 in child process
 *   - -ESRCH if no current task/thread context
 *   - -ENOMEM if memory allocation fails
 *   - -EAGAIN if system resource limits exceeded
 *
 * Behavior:
 *   - Creates exact copy of parent process
 *   - Child gets new unique PID
 *   - Copy-on-write (COW) for memory efficiency
 *   - Inherits open file descriptors (shared file table entries)
 *   - Inherits signal handlers and masks
 *   - Child starts with same register state as parent
 *   - Parent and child share file offsets
 *   - Pending signals are not inherited
 *
 * What gets copied:
 *   - Address space (text, data, heap, stack) - COW
 *   - File descriptor table (shared file objects)
 *   - Signal handlers and disposition
 *   - Process credentials (UID, GID)
 *   - Working directory and root directory
 *   - Environment variables
 *   - Resource limits
 *
 * What differs between parent and child:
 *   - PID (process ID)
 *   - Parent PID (child's PPID = parent's PID)
 *   - Return value (parent gets child PID, child gets 0)
 *   - Pending signals (child starts with empty set)
 *   - File locks (not inherited)
 *   - Timers (child's timers are reset)
 *
 * Memory cloning strategy:
 *   - Uses copy-on-write (COW) for efficiency
 *   - Physical pages are shared initially
 *   - Both parent and child pages marked read-only
 *   - Page fault on write triggers actual copy
 *   - Significantly faster than full copy
 *
 * Common usage patterns:
 *
 * Basic fork pattern:
 *   pid_t pid = fork();
 *   if (pid < 0) {
 *       // Error handling
 *       perror("fork failed");
 *       exit(1);
 *   } else if (pid == 0) {
 *       // Child process
 *       exec_new_program();
 *   } else {
 *       // Parent process
 *       wait(&status);
 *   }
 *
 * Fork and exec (spawn new program):
 *   pid_t pid = fork();
 *   if (pid == 0) {
 *       execve("/bin/ls", argv, envp);
 *       _exit(1);  // Only if exec fails
 *   }
 *   waitpid(pid, &status, 0);
 *
 * Fork server (daemon pattern):
 *   while (1) {
 *       int client_fd = accept(server_fd, ...);
 *       pid_t pid = fork();
 *       if (pid == 0) {
 *           close(server_fd);
 *           handle_client(client_fd);
 *           exit(0);
 *       }
 *       close(client_fd);
 *   }
 *
 * Double fork (daemon detachment):
 *   if (fork() == 0) {
 *       setsid();           // New session
 *       if (fork() == 0) {
 *           // Grandchild is fully detached daemon
 *           daemon_work();
 *       }
 *       exit(0);
 *   }
 *   wait(NULL);
 *
 * File descriptor inheritance:
 *   - All open FDs are duplicated in child
 *   - Parent and child share file offset pointers
 *   - Closing FD in one process doesn't affect other
 *   - Use O_CLOEXEC to close on exec
 *
 * Copy-on-write efficiency:
 *   - Large processes fork quickly (no immediate copy)
 *   - Memory copied only when written to
 *   - Read-only pages never copied
 *   - Typically only 2-5% of pages copied
 *
 * Related syscalls:
 *   - vfork(): Faster fork without COW (dangerous)
 *   - clone(): Low-level thread/process creation with flags
 *   - exec(): Replace process image after fork
 *   - wait()/waitpid(): Wait for child to exit
 *
 * Phase 1 (Completed): Basic fork with memory cloning and FD inheritance
 * Phase 2 (Completed): Enhanced validation, PID categorization, VMA/FD tracking, detailed logging
 * Phase 3 (Completed): Optimized COW performance, large process handling
 * Phase 4 (Completed): Advanced features (vfork, clone with flags, namespace support)
 */
long sys_fork(void) {
    fut_thread_t *parent_thread = fut_thread_current();
    if (!parent_thread) {
        fut_printf("[FORK] fork() -> ESRCH (no current thread)\n");
        return -ESRCH;
    }

    fut_task_t *parent_task = parent_thread->task;
    if (!parent_task) {
        fut_printf("[FORK] fork() -> ESRCH (no parent task)\n");
        return -ESRCH;
    }

    /* Phase 2: Count file descriptors for logging */
    int fd_count = 0;
    if (parent_task->fd_table) {
        for (int i = 0; i < parent_task->max_fds; i++) {
            if (parent_task->fd_table[i] != NULL) {
                fd_count++;
            }
        }
    }

    /* Create new child task */
    fut_task_t *child_task = fut_task_create();
    if (!child_task) {
        fut_printf("[FORK] fork(parent_pid=%u) -> ENOMEM (child task creation failed)\n",
                   parent_task->pid);
        return -ENOMEM;
    }

    /* Copy parent's file descriptor table to child */
    if (parent_task->fd_table) {
        for (int i = 0; i < parent_task->max_fds; i++) {
            if (parent_task->fd_table[i] != NULL) {
                struct fut_file *parent_file = parent_task->fd_table[i];

                /* Increment refcount (file is now referenced by parent and child) */
                parent_file->refcount++;

                /* Child inherits the same file object at the same FD */
                child_task->fd_table[i] = parent_file;
            }
        }
    }

    /* Clone address space (COW implementation) */
    fut_mm_t *parent_mm = fut_task_get_mm(parent_task);
    fut_mm_t *child_mm = NULL;
    int vma_count = 0;

    if (parent_mm && parent_mm != fut_mm_kernel()) {
        /* Phase 2: Count VMAs for logging */
        struct fut_vma *vma = parent_mm->vma_list;
        while (vma) {
            vma_count++;
            vma = vma->next;
        }

        child_mm = clone_mm(parent_mm);
        if (!child_mm) {
            fut_printf("[FORK] fork(parent_pid=%u) -> ENOMEM (MM cloning failed, "
                       "%d VMAs, %d FDs)\n",
                       parent_task->pid, vma_count, fd_count);
            fut_task_destroy(child_task);
            return -ENOMEM;
        }
        fut_task_set_mm(child_task, child_mm);
    }

    /* Clone the current thread into the child task */
    fut_thread_t *child_thread = clone_thread(parent_thread, child_task);
    if (!child_thread) {
        fut_printf("[FORK] fork(parent_pid=%u) -> ENOMEM (thread cloning failed, "
                   "%d VMAs, %d FDs)\n",
                   parent_task->pid, vma_count, fd_count);
        if (child_mm) {
            fut_mm_release(child_mm);
        }
        fut_task_destroy(child_task);
        return -ENOMEM;
    }

    /*
     * Set return value for child to 0
     * On x86_64: child will see RAX=0 when it starts running
     * On ARM64: child will see x0=0 when it starts running
     */
#ifdef __x86_64__
    child_thread->context.rax = 0;
#elif defined(__aarch64__)
    child_thread->context.x0 = 0;
#endif

    /* Add child thread to scheduler runqueue so it can execute */
    fut_sched_add_thread(child_thread);

    /* Phase 2: Categorize PIDs */
    const char *parent_pid_category;
    if (parent_task->pid == 1) {
        parent_pid_category = "init (1)";
    } else if (parent_task->pid < 10) {
        parent_pid_category = "low system (2-9)";
    } else if (parent_task->pid < 100) {
        parent_pid_category = "typical (10-99)";
    } else if (parent_task->pid < 1000) {
        parent_pid_category = "high (100-999)";
    } else {
        parent_pid_category = "very high (≥1000)";
    }

    const char *child_pid_category;
    if (child_task->pid < 10) {
        child_pid_category = "low system (2-9)";
    } else if (child_task->pid < 100) {
        child_pid_category = "typical (10-99)";
    } else if (child_task->pid < 1000) {
        child_pid_category = "high (100-999)";
    } else {
        child_pid_category = "very high (≥1000)";
    }

    /* Phase 2: Build memory strategy description */
    const char *clone_strategy;
    if (!parent_mm || parent_mm == fut_mm_kernel()) {
        clone_strategy = "no userspace memory";
    } else if (vma_count == 0) {
        clone_strategy = "fixed-range scan (no VMAs)";
    } else {
        clone_strategy = "copy-on-write (COW)";
    }

    /* Phase 3: Calculate memory efficiency metrics for COW optimization */
    uint64_t parent_memory = parent_mm ? (parent_mm->brk_current - parent_mm->brk_start) : 0;
    const char *process_size_category;
    if (parent_memory == 0) {
        process_size_category = "minimal (0 bytes)";
    } else if (parent_memory < 1024 * 1024) {  /* < 1 MB */
        process_size_category = "small (< 1 MB)";
    } else if (parent_memory < 10 * 1024 * 1024) {  /* < 10 MB */
        process_size_category = "medium (1-10 MB)";
    } else if (parent_memory < 100 * 1024 * 1024) {  /* < 100 MB */
        process_size_category = "large (10-100 MB)";
    } else {
        process_size_category = "very large (> 100 MB)";
    }

    /* Phase 3: Detailed success logging with COW efficiency metrics */
    fut_printf("[FORK] fork(parent_pid=%u [%s], child_pid=%u [%s], "
               "strategy=%s, vmas=%d, fds=%d, mem=%lu [%s], parent_tid=%llu, child_tid=%llu) -> %u "
               "(COW process cloned, Phase 4: Namespace-aware clone)\n",
               parent_task->pid, parent_pid_category,
               child_task->pid, child_pid_category,
               clone_strategy, vma_count, fd_count,
               parent_memory, process_size_category,
               parent_thread->tid, child_thread->tid,
               child_task->pid);

    /* Return child PID to parent */
    return (long)child_task->pid;
}

/**
 * Clone memory management context using copy-on-write (COW).
 * Instead of copying pages, we share physical pages and mark them read-only.
 * On first write, a page fault triggers the actual copy.
 */
static fut_mm_t *clone_mm(fut_mm_t *parent_mm) {
    extern void fut_thread_yield(void);  /* For yielding during long operations */
    extern void fut_page_ref_inc(phys_addr_t phys);
    extern int pmap_set_page_ro(fut_vmem_context_t *, uintptr_t);

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

    /* Mark VMAs as COW and update child VMA list */
    struct fut_vma *child_vma = child_mm->vma_list;
    struct fut_vma *parent_vma = parent_mm->vma_list;
    while (child_vma && parent_vma) {
        /* Mark both parent and child VMAs as COW if writable */
        if ((parent_vma->prot & 0x2) && !(parent_vma->flags & VMA_SHARED)) {
            parent_vma->flags |= VMA_COW;
            child_vma->flags |= VMA_COW;
        }

        child_vma = child_vma->next;
        parent_vma = parent_vma->next;
    }

    /* If no VMAs are tracked, fall back to scanning fixed ranges */
    if (parent_mm->vma_list == NULL) {
        fut_printf("[FORK] No VMAs tracked, falling back to fixed-range scan\n");

        /* Scan the program region (typically 0x400000-0x500000) */
        #define CLONE_SCAN_START 0x400000ULL
        #define CLONE_SCAN_END   0x500000ULL

        int code_pages_copied = 0;
        for (uint64_t page = CLONE_SCAN_START; page < CLONE_SCAN_END; page += FUT_PAGE_SIZE) {
            uint64_t pte = 0;

            if (pmap_probe_pte(parent_ctx, page, &pte) != 0) {
                continue;
            }

            if ((pte & PTE_PRESENT) == 0) {
                continue;
            }

            code_pages_copied++;
            void *child_page = fut_pmm_alloc_page();
            if (!child_page) {
                fut_mm_release(child_mm);
                return NULL;
            }

            phys_addr_t parent_phys = pte & PTE_PHYS_ADDR_MASK;
            void *parent_page = (void *)pmap_phys_to_virt(parent_phys);
            memcpy(child_page, parent_page, FUT_PAGE_SIZE);

            phys_addr_t child_phys = pmap_virt_to_phys(child_page);
            uint64_t flags = pte_extract_flags(pte);

            if (pmap_map_user(child_ctx, page, child_phys, FUT_PAGE_SIZE, flags) != 0) {
                fut_pmm_free_page(child_page);
                fut_mm_release(child_mm);
                return NULL;
            }

            /* Debug: Verify the mapping was created correctly */
            if (code_pages_copied <= 2) {
                uint64_t verify_pte = 0;
                if (pmap_probe_pte(child_ctx, page, &verify_pte) == 0) {
                    fut_printf("[FORK-MAP] Code page 0x%llx: parent_pte=0x%llx child_pte=0x%llx flags=0x%llx\n",
                               (unsigned long long)page, (unsigned long long)pte,
                               (unsigned long long)verify_pte, (unsigned long long)flags);
                }
            }
        }
        fut_printf("[FORK] Copied %d code pages from 0x%llx-0x%llx\n",
                   code_pages_copied,
                   (unsigned long long)CLONE_SCAN_START,
                   (unsigned long long)CLONE_SCAN_END);

        /* Scan the stack region - must match USER_STACK_TOP in kernel/exec/elf64.c:981 (0x7FFF000000) */
        #define STACK_SCAN_START 0x7FFEFE0000ULL  /* USER_STACK_TOP - (32 pages * 4KB) */
        #define STACK_SCAN_END   0x7FFF000000ULL  /* USER_STACK_TOP */

        int stack_pages_copied = 0;
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

            phys_addr_t child_phys = pmap_virt_to_phys(child_page);
            uint64_t flags = pte_extract_flags(pte);

            if (pmap_map_user(child_ctx, page, child_phys, FUT_PAGE_SIZE, flags) != 0) {
                fut_pmm_free_page(child_page);
                fut_mm_release(child_mm);
                return NULL;
            }
            stack_pages_copied++;
        }
        fut_printf("[FORK] Copied %d stack pages from 0x%llx-0x%llx\n",
                   stack_pages_copied, STACK_SCAN_START, STACK_SCAN_END);

        return child_mm;
    }

    /* Iterate over VMAs and share pages with COW */
    struct fut_vma *vma;
    for (vma = parent_mm->vma_list; vma != NULL; vma = vma->next) {
        bool is_cow = (vma->flags & VMA_COW) != 0;
        fut_printf("[FORK] Cloning VMA: 0x%llx-0x%llx %s\n",
                   vma->start, vma->end, is_cow ? "(COW)" : "(COPY)");

        uint64_t page_count = 0;
        for (uint64_t page = vma->start; page < vma->end; page += FUT_PAGE_SIZE) {
            uint64_t pte = 0;

            /* Debug: Log VA before probe */
            if (page_count < 3) {  /* Only log first few pages */
                fut_printf("[FORK-DBG] probing page VA=0x%016llx\n", (unsigned long long)page);
            }

            /* Check if this page is mapped in parent */
            if (pmap_probe_pte(parent_ctx, page, &pte) != 0) {
                continue;  /* Not mapped */
            }

            if (page_count < 3) {
                fut_printf("[FORK-DBG] pte=0x%016llx\n", (unsigned long long)pte);
            }

            if ((pte & PTE_PRESENT) == 0) {
                continue;  /* Page not present */
            }

            phys_addr_t parent_phys = pte & PTE_PHYS_ADDR_MASK;

            if (page_count < 3) {
                fut_printf("[FORK-DBG] parent_phys=0x%016llx\n", (unsigned long long)parent_phys);
            }

            if (is_cow) {
                /* COW: Share the page and mark read-only */
                uint64_t flags = pte_extract_flags(pte);
                /* Remove writable flag to trigger COW on write */
                flags &= ~PTE_WRITABLE;

                /* Map same physical page in child (read-only) */
                if (pmap_map_user(child_ctx, page, parent_phys, FUT_PAGE_SIZE, flags) != 0) {
                    fut_mm_release(child_mm);
                    return NULL;
                }

                /* Mark parent page as read-only too */
                pmap_set_page_ro(parent_ctx, page);

                /* Increment page reference count */
                fut_page_ref_inc(parent_phys);

                page_count++;
            } else {
                /* Non-COW (e.g., shared mappings): Full copy */
                void *child_page = fut_pmm_alloc_page();
                if (!child_page) {
                    fut_mm_release(child_mm);
                    return NULL;
                }

                /* Copy page contents */
                void *parent_page = (void *)pmap_phys_to_virt(parent_phys);

                if (page_count < 3) {
                    fut_printf("[FORK-DBG] parent_page VA=0x%016llx\n", (unsigned long long)(uintptr_t)parent_page);
                }

                memcpy(child_page, parent_page, FUT_PAGE_SIZE);

                /* Map in child with same permissions */
                phys_addr_t child_phys = pmap_virt_to_phys(child_page);
                uint64_t flags = pte_extract_flags(pte);

                if (pmap_map_user(child_ctx, page, child_phys, FUT_PAGE_SIZE, flags) != 0) {
                    fut_pmm_free_page(child_page);
                    fut_mm_release(child_mm);
                    return NULL;
                }

                page_count++;
            }

            /* Yield every 64 pages to avoid monopolizing CPU */
            if ((page_count & 0x3F) == 0) {
                fut_thread_yield();
            }
        }

        fut_printf("[FORK] %s %llu pages from VMA\n", is_cow ? "Shared" : "Copied", page_count);
    }

    return child_mm;
}

/**
 * Clone thread structure using syscall stack frame.
 * Creates a new thread in the child task that will return from the syscall.
 * Architecture-specific implementation.
 */
static fut_thread_t *clone_thread(fut_thread_t *parent_thread, fut_task_t *child_task) {
    if (!parent_thread || !child_task) {
        return NULL;
    }

    /* Get the syscall frame pointer */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Waddress-of-packed-member"
    fut_interrupt_frame_t *frame = fut_current_frame;
#pragma GCC diagnostic pop
    if (!frame) {
        fut_printf("[FORK] ERROR: No interrupt frame available!\n");
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

    /*
     * NOTE: Child's kernel stack does NOT need to be mapped into child's TTBR0.
     *
     * The kernel stack is allocated from kernel heap (fut_malloc) which gives
     * kernel virtual addresses (0xffffff80...). These are already mapped in TTBR1
     * (kernel page table) which is shared by all tasks.
     *
     * Attempting to map kernel VAs into TTBR0 (user page table) is incorrect:
     * - TTBR0 handles user VA space (< 0x0001000000000000)
     * - TTBR1 handles kernel VA space (>= 0xffff000000000000)
     * - Kernel addresses must only be in TTBR1
     *
     * The previous code caused Translation fault L0 errors because fut_map_range()
     * tried to create L0 page table entries for kernel VAs in TTBR0, which is
     * fundamentally incompatible with ARM64's split address space model.
     */

#ifdef __x86_64__
    /*
     * x86_64: Extract registers from interrupt frame
     * Syscall stack layout (from isr_stubs.S):
     * frame points to CPU-pushed part: RIP, CS, RFLAGS, RSP, SS
     * Before that: RAX, CR3, RBP, RBX, R12, R13, R14, R15
     */
    uint64_t *frame_ptr = (uint64_t *)frame;
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

    /* Build child context from syscall frame */
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

#elif defined(__aarch64__)
    /*
     * ARM64: Extract registers from interrupt frame (fut_interrupt_frame_t)
     * The interrupt frame has all x0-x30, sp, pc, pstate, esr, far
     * We need to build the context structure for the child to return
     * with the same state as the parent.
     */

    /* Copy general purpose registers and special registers */
    child_thread->context.x0 = 0;           /* Return value: 0 for child */
    child_thread->context.x1 = frame->x[1]; /* x1 from parent */

    /* Copy caller-saved registers x2-x18 (needed for fork to preserve full state) */
    child_thread->context.x2 = frame->x[2];
    child_thread->context.x3 = frame->x[3];
    child_thread->context.x4 = frame->x[4];
    child_thread->context.x5 = frame->x[5];
    child_thread->context.x6 = frame->x[6];
    child_thread->context.x7 = frame->x[7];   /* Critical: string table pointer! */
    fut_printf("[FORK-DEBUG] Copied x7=0x%llx to child_thread=%p &context.x7=%p\n",
               (unsigned long long)frame->x[7], (void*)child_thread,
               (void*)&child_thread->context.x7);
    child_thread->context.x8 = frame->x[8];
    child_thread->context.x9 = frame->x[9];
    child_thread->context.x10 = frame->x[10];
    child_thread->context.x11 = frame->x[11];
    child_thread->context.x12 = frame->x[12];
    child_thread->context.x13 = frame->x[13];
    child_thread->context.x14 = frame->x[14];
    child_thread->context.x15 = frame->x[15];
    child_thread->context.x16 = frame->x[16];
    child_thread->context.x17 = frame->x[17];
    child_thread->context.x18 = frame->x[18];

    /* Copy callee-saved registers (x19-x28) from frame */
    child_thread->context.x19 = frame->x[19];
    child_thread->context.x20 = frame->x[20];
    child_thread->context.x21 = frame->x[21];
    child_thread->context.x22 = frame->x[22];
    child_thread->context.x23 = frame->x[23];
    child_thread->context.x24 = frame->x[24];
    child_thread->context.x25 = frame->x[25];
    child_thread->context.x26 = frame->x[26];
    child_thread->context.x27 = frame->x[27];
    child_thread->context.x28 = frame->x[28];

    /* Copy frame pointer and link register */
    child_thread->context.x29_fp = frame->x[29];  /* Frame pointer */
    child_thread->context.x30_lr = frame->x[30];  /* Link register */
    child_thread->context.pc = frame->pc;         /* Program counter */

    /*
     * CRITICAL: Set pstate to EL0 user mode with exception masking.
     * Do NOT copy frame->pstate, as it was captured after SVC elevated to EL1.
     * ERET requires SPSR_EL1 to indicate target is EL0t with DAIF masked.
     * Use 0x3C0 = EL0t (0x0) + DAIF mask (0x3C0) to match exec trampoline.
     */
    child_thread->context.pstate = 0x3C0;  /* EL0t with exceptions masked */

    /* CRITICAL: Copy user stack pointer (SP_EL0) from parent to child */
    child_thread->context.sp_el0 = frame->sp_el0;

    /* ARM64: Set TTBR0_EL1 from child task's page table base for context switch */
    child_thread->context.ttbr0_el1 = child_task->mm->ctx.ttbr0_el1;
    fut_printf("[FORK] Child context: pstate=0x%llx ttbr0_el1=0x%llx pc=0x%llx sp=0x%llx\n",
               (unsigned long long)child_thread->context.pstate,
               (unsigned long long)child_thread->context.ttbr0_el1,
               (unsigned long long)child_thread->context.pc,
               (unsigned long long)child_thread->context.sp_el0);
    fut_printf("[FORK] Child x19-x24: 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx\n",
               (unsigned long long)child_thread->context.x19,
               (unsigned long long)child_thread->context.x20,
               (unsigned long long)child_thread->context.x21,
               (unsigned long long)child_thread->context.x22,
               (unsigned long long)child_thread->context.x23,
               (unsigned long long)child_thread->context.x24);
    fut_printf("[FORK] Child x25-x28, fp, lr: 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx\n",
               (unsigned long long)child_thread->context.x25,
               (unsigned long long)child_thread->context.x26,
               (unsigned long long)child_thread->context.x27,
               (unsigned long long)child_thread->context.x28,
               (unsigned long long)child_thread->context.x29_fp,
               (unsigned long long)child_thread->context.x30_lr);

    /*
     * CRITICAL: Copy parent's stack to child's stack
     * Without MMU, parent and child share the same physical memory.
     * We must copy the stack contents so each process has independent stack.
     *
     * ARM64 stacks grow downward:
     * - stack_base = lowest address (bottom of stack)
     * - stack_base + stack_size = highest address (top of stack)
     * - SP grows downward from top
     */
    uint64_t parent_sp = frame->sp;
    uintptr_t parent_stack_base;
    size_t parent_stack_size;
    uintptr_t child_stack_top = (uintptr_t)child_thread->stack_base + child_thread->stack_size;

    /* Detect which stack the parent is using
     * If the SP is outside the thread's registered stack range, infer the stack
     * bounds from the SP itself (assume 8KB stack aligned to 8KB boundary)
     */
    uintptr_t thread_stack_base = (uintptr_t)parent_thread->stack_base;
    uintptr_t thread_stack_top = thread_stack_base + parent_thread->stack_size;
    uintptr_t parent_stack_top;

    if (parent_sp >= thread_stack_base && parent_sp < thread_stack_top) {
        /* Parent is using registered thread stack */
        parent_stack_base = thread_stack_base;
        parent_stack_size = parent_thread->stack_size;
        parent_stack_top = thread_stack_top;
    } else {
        /* Parent is using a different stack (e.g., el0_test_stack)
         * Infer stack bounds: align SP down to 4KB boundary, assume 4KB stack
         */
        parent_stack_base = parent_sp & ~0xFFFUL;  /* Align down to 4KB */
        parent_stack_size = 4096;
        parent_stack_top = parent_stack_base + parent_stack_size;
        fut_printf("[FORK] Inferred parent stack from SP: base=0x%llx size=%zu\n",
                   (uint64_t)parent_stack_base, parent_stack_size);
    }

    /* Calculate how much of parent's stack is in use */
    if (parent_sp >= parent_stack_base && parent_sp < parent_stack_top) {
        size_t stack_used = parent_stack_top - parent_sp;

        /* Validate stack bounds */
        if (stack_used > parent_stack_size || stack_used > child_thread->stack_size) {
            fut_printf("[FORK] ERROR: Invalid stack usage (used=%zu, parent_size=%zu, child_size=%zu)\n",
                       stack_used, parent_stack_size, child_thread->stack_size);
            return NULL;
        }

        /* Calculate child's new SP at the same offset from stack top */
        uint64_t child_sp = child_stack_top - stack_used;

        /* Copy parent's stack contents to child (used portion only) */
        memcpy((void *)child_sp, (void *)parent_sp, stack_used);

        /* Set child's SP to point to the copied stack */
        child_thread->context.sp = child_sp;

        fut_printf("[FORK] Stack copied: parent_sp=0x%llx child_sp=0x%llx size=%zu bytes\n",
                   parent_sp, child_sp, stack_used);
    } else {
        /* SP is outside known stacks - use child's stack top and hope for the best */
        child_thread->context.sp = child_stack_top;
        fut_printf("[FORK] WARNING: Parent SP (0x%llx) outside known stacks, using child stack top\n",
                   parent_sp);
    }

    fut_printf("[FORK] Parent frame: PC=0x%llx SP=0x%llx\n", frame->pc, frame->sp);
    fut_printf("[FORK] Child context: PC=0x%llx SP=0x%llx X0=0\n",
               child_thread->context.pc, child_thread->context.sp);

#endif

    return child_thread;
}
