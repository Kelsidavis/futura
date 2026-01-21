/* fut_thread.c - Futura OS Thread Implementation (C23)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Thread creation, lifecycle management, and synchronization primitives.
 * Migrated to x86-64 long mode architecture.
 */

#include "../../include/kernel/fut_thread.h"
#include "../../include/kernel/fut_task.h"
#include "../../include/kernel/fut_sched.h"
#include "../../include/kernel/fut_memory.h"
#include "../../include/kernel/fut_mm.h"
#include "../../include/kernel/fut_percpu.h"
#include <kernel/errno.h>
#if defined(__x86_64__)
#include <platform/x86_64/gdt.h>
#endif
#include <string.h>
#include <stdatomic.h>

[[noreturn]] static void fut_thread_trampoline(void (*entry)(void *), void *arg) __attribute__((used));

/* External declarations */
extern void fut_printf(const char *fmt, ...);
extern void fut_sleep_until(fut_thread_t *thread, uint64_t wake_time);

/* Thread ID counter (64-bit) */
/* TID 1 is reserved for the boot/bootstrap thread on all platforms.
 * Start allocation at TID 2 to avoid collision. */
static _Atomic uint64_t next_tid __attribute__((aligned(8))) = 2;  /* 8-byte aligned for ARM64 atomics */

/* Thread count tracking and safety limit to prevent runaway thread creation */
static _Atomic uint64_t thread_count __attribute__((aligned(8))) = 0;
#define MAX_THREADS 500   /* Safety limit to prevent infinite thread creation bugs */

/* Current thread pointer is now per-CPU (see fut_percpu_t in fut_percpu.h) */

/* Global thread list (for stats/debugging) */
fut_thread_t *fut_thread_list = NULL;

#if defined(__x86_64__)
/* Clean FPU state template for initializing new threads.
 * This is captured once at boot with a valid FPU state (FCW=0x037F, MXCSR=0x1F80).
 * All new threads get a copy of this state instead of zeroed memory. */
static uint8_t clean_fpu_state[512] __attribute__((aligned(16))) = {0};
static bool clean_fpu_state_initialized = false;

/**
 * Initialize the clean FPU state template.
 * This should be called once during thread subsystem initialization.
 */
static void init_clean_fpu_state(void) {
    if (clean_fpu_state_initialized) {
        return;
    }

    /* Initialize both x87 FPU and SSE state to known good values.
     * finit only initializes x87, so we must explicitly zero XMM registers
     * and set MXCSR to the default value. */
    __asm__ volatile(
        "finit\n"                  /* Initialize x87 FPU to default state */
        "pxor %%xmm0, %%xmm0\n"    /* Zero all XMM registers */
        "pxor %%xmm1, %%xmm1\n"
        "pxor %%xmm2, %%xmm2\n"
        "pxor %%xmm3, %%xmm3\n"
        "pxor %%xmm4, %%xmm4\n"
        "pxor %%xmm5, %%xmm5\n"
        "pxor %%xmm6, %%xmm6\n"
        "pxor %%xmm7, %%xmm7\n"
        "pxor %%xmm8, %%xmm8\n"
        "pxor %%xmm9, %%xmm9\n"
        "pxor %%xmm10, %%xmm10\n"
        "pxor %%xmm11, %%xmm11\n"
        "pxor %%xmm12, %%xmm12\n"
        "pxor %%xmm13, %%xmm13\n"
        "pxor %%xmm14, %%xmm14\n"
        "pxor %%xmm15, %%xmm15\n"
        "fxsave64 %0\n"            /* Save complete clean state to template */
        : "=m"(clean_fpu_state)    /* Output: memory operand */
        :                           /* No inputs */
        : "memory"                  /* Clobbers memory */
    );

    /* Verify MXCSR was set to default value by fxsave64. */
    uint32_t *mxcsr_ptr = (uint32_t *)(clean_fpu_state + FXSAVE_MXCSR_OFFSET);

    /* Ensure MXCSR is set to default value */
    if (*mxcsr_ptr == 0) {
        *mxcsr_ptr = MXCSR_DEFAULT;
    }

    clean_fpu_state_initialized = true;
}
#endif

/* ============================================================
 *   Thread Creation
 * ============================================================ */

/**
 * Create a new thread within a task.
 */
fut_thread_t *fut_thread_create(
    fut_task_t *task,
    void (*entry)(void *),
    void *arg,
    size_t stack_size,
    int priority
) {
    if (!task || !entry || stack_size == 0) {
        return NULL;
    }

    /* Safety check: prevent runaway thread creation */
    uint64_t current_count = atomic_load_explicit(&thread_count, memory_order_acquire);
    if (current_count >= MAX_THREADS) {
        fut_printf("[THREAD-LIMIT] Cannot create thread: limit reached (%llu/%d)\n",
                   (unsigned long long)current_count, MAX_THREADS);
        return NULL;
    }

#if defined(__x86_64__)
    // Initialize clean FPU state template on first call
    init_clean_fpu_state();
#endif

    // Clamp priority
    if (priority < 0) priority = 0;
    if (priority >= FUT_MAX_PRIORITY) priority = FUT_MAX_PRIORITY - 1;

    // Allocate thread structure with proper alignment (16-byte for FXSAVE/FXRSTOR)
    // Round up size to multiple of 16 and allocate extra space for alignment
    size_t thread_size = sizeof(fut_thread_t);
    size_t alloc_size = thread_size + 16;  // Extra space for alignment
    void *raw_thread = fut_malloc(alloc_size);
    if (!raw_thread) {
        return NULL;
    }

    // Align to 16-byte boundary
    uintptr_t thread_addr = (uintptr_t)raw_thread;
    uintptr_t aligned_addr = (thread_addr + 15) & ~15ULL;
    fut_thread_t *thread = (fut_thread_t *)aligned_addr;

    // CRITICAL: Save original pointer for proper free later
    // This must be set immediately after alignment, before any error paths
    thread->alloc_base = raw_thread;

    // Allocate stack (page-aligned)
    size_t aligned_stack_size = FUT_PAGE_ALIGN(stack_size);
    void *stack = fut_malloc(aligned_stack_size);
    if (!stack) {
        fut_free(raw_thread);  // Free original pointer, not aligned one
        return NULL;
    }

    // Place guard canary at bottom of stack (lowest address)
    // This helps detect stack overflow during debugging
    *(uint64_t *)stack = FUT_STACK_CANARY;

    // Get new TID (ARM64 workaround for atomic intrinsics)
#if defined(__aarch64__)
    uint64_t new_tid, tmp_tid;
    __asm__ volatile(
        "1: ldxr    %0, [%2]\n"
        "   add     %1, %0, #1\n"
        "   stxr    w3, %1, [%2]\n"
        "   cbnz    w3, 1b\n"
        : "=&r"(new_tid), "=&r"(tmp_tid)
        : "r"(&next_tid)
        : "w3", "memory"
    );
#else
    uint64_t new_tid = atomic_fetch_add_explicit(&next_tid, 1, memory_order_seq_cst);
#endif

    // Initialize thread structure
    *thread = (fut_thread_t){
        .tid = new_tid,
        .task = task,
        .stack_base = stack,
        .stack_size = aligned_stack_size,
        .alloc_base = raw_thread,     // Save original pointer for proper free
        ._padding = 0,                // Explicit padding for 16-byte alignment
        .context = {0},               // Will be initialized below
        .irq_frame = NULL,            // No saved interrupt frame initially
        .state = FUT_THREAD_READY,
        .priority = priority,
        .base_priority = priority,
        .pi_saved_priority = priority,
        .pi_boosted = false,
        .deadline_tick = 0,
        .wake_time = 0,
        .stats = {0},                 // Initialize performance counters to zero
        .next = NULL,
        .prev = NULL,
        .wait_next = NULL
    };

#if defined(__aarch64__)
    fut_printf("[THREAD-CREATE] tid=%llu priority=%d entry=%p thread=%p\n",
               (unsigned long long)new_tid, priority, entry, (void*)thread);
#endif

    // Calculate stack top (grows downward)
    void *stack_top = (void *)((uintptr_t)stack + aligned_stack_size);

    // Initialize CPU context for this thread
    fut_cpu_context_t *ctx = &thread->context;
    memset(ctx, 0, sizeof(*ctx));

#if defined(__x86_64__)
    uintptr_t aligned_top = ((uintptr_t)stack_top) & ~0xFULL;

    /* CRITICAL FIX: Push a dummy return address onto the stack.
     * When we IRETQ to fut_thread_trampoline, we're JUMPING to it, not CALLING it.
     * The C function expects a proper call with return address on stack.
     * Without this, the function prologue will crash when setting up the stack frame.
     * We push fut_thread_exit as the return address so if trampoline returns, we exit cleanly. */
    extern void fut_thread_exit(void);
    aligned_top -= 8;  // Make room for return address
    *(uint64_t *)aligned_top = (uint64_t)(uintptr_t)&fut_thread_exit;

    // Stack is now 16-byte aligned (after the "return address" push)
    ctx->rsp = aligned_top;
    ctx->rip = (uint64_t)(uintptr_t)&fut_thread_trampoline;

    fut_printf("[THREAD-CREATE] tid=%llu rip=0x%llx (trampoline=0x%llx entry=0x%llx)\n",
               (unsigned long long)thread->tid, (unsigned long long)ctx->rip,
               (unsigned long long)(uintptr_t)&fut_thread_trampoline,
               (unsigned long long)(uintptr_t)entry);

    /* RFLAGS: reserved bit 1 must be 1. Start with interrupts DISABLED (IF=0)
     * to prevent the timer from interrupting before the trampoline executes.
     * The trampoline will enable interrupts after critical setup is complete. */
    ctx->rflags = RFLAGS_KERNEL_INIT;

    /* ALL threads (kernel and user) start in kernel mode (ring 0).
     * For user threads, the entry point is fut_user_trampoline (a kernel function)
     * which executes in kernel mode and then uses IRETQ to switch to user mode.
     * The trampoline itself handles the transition to ring 3. */
    ctx->cs = GDT_KERNEL_CODE;
    ctx->ss = GDT_KERNEL_DATA;
    /* In 64-bit mode, DS/ES/FS/GS should be set to valid kernel selectors.
     * While NULL selectors (0) are valid to load, we set them to kernel data
     * segment for consistency with the ISR and to avoid potential issues. */
    ctx->ds = GDT_KERNEL_DATA;
    ctx->es = GDT_KERNEL_DATA;
    ctx->fs = GDT_KERNEL_DATA;
    ctx->gs = GDT_KERNEL_DATA;

    ctx->rdi = (uint64_t)entry;
    ctx->rsi = (uint64_t)arg;
    ctx->rax = 0;
    ctx->rcx = 0;
    ctx->rdx = 0;

    /* Initialize FPU/XMM state with a valid clean state.
     * This is critical: fxrstor64 requires a properly formatted FXSAVE area.
     * Using memset(0) creates an invalid FPU state (FCW=0, MXCSR=0) which
     * causes undefined behavior when restored. Instead, we copy a clean state
     * captured from finit (FCW=0x037F, MXCSR=MXCSR_DEFAULT). */
    memcpy(ctx->fx_area, clean_fpu_state, sizeof(ctx->fx_area));
#elif defined(__aarch64__)
    // ARM64 stack grows downward - point to the end of the stack
    uintptr_t aligned_top = ((uintptr_t)stack_top) & ~0xFULL;
    ctx->sp = aligned_top;
    ctx->pc = (uint64_t)(uintptr_t)&fut_thread_trampoline;
    ctx->pstate = 0x3C5; // EL1h mode with IRQ/FIQ enabled (bits 6,7 clear for enabled)

    // ARM64: Store parameters in x0/x1 for trampoline
    // x0 = entry function pointer, x1 = argument
    ctx->x0 = (uint64_t)entry;
    ctx->x1 = (uint64_t)arg;

    // Debug: log the trampoline address
    extern void fut_printf(const char *, ...);
    fut_printf("[THREAD-CTX] PC set to fut_thread_trampoline=%p x0=%p x1=%p\n",
               (void*)(uintptr_t)ctx->pc, (void*)ctx->x0, (void*)ctx->x1);

#ifdef DEBUG_THREAD
    extern void fut_printf(const char *, ...);
    fut_printf("[THREAD-CREATE] ARM64 thread %llu: entry=%p arg=%p\n",
               (unsigned long long)thread->tid, (void*)entry, arg);
#endif

    // Set TTBR0_EL1 from task's memory manager for user-space page table
    if (task->mm) {
        ctx->ttbr0_el1 = task->mm->ctx.ttbr0_el1;
#ifdef DEBUG_THREAD
        extern void fut_printf(const char *, ...);
        fut_printf("[THREAD-CREATE] Set ttbr0_el1=%llx from task mm\n",
                   (unsigned long long)ctx->ttbr0_el1);
#endif
    } else {
        ctx->ttbr0_el1 = 0;  // No page table for kernel-only tasks
    }

    // FPU state already zeroed by memset above
#endif

    // Add to parent task
    fut_task_add_thread(task, thread);

    // Add to scheduler ready queue
    fut_sched_add_thread(thread);

    // Add to global thread list (uses separate global_next pointer)
    thread->global_next = fut_thread_list;
    fut_thread_list = thread;

    // Increment global thread count
    uint64_t new_count = atomic_fetch_add_explicit(&thread_count, 1, memory_order_acq_rel) + 1;
    (void)new_count;  // Avoid unused variable warning

    return thread;
}

/* ============================================================
 *   Thread Lifecycle
 * ============================================================ */

/**
 * Voluntarily yield CPU to another thread.
 */
void fut_thread_yield(void) {
    fut_schedule();
}

/**
 * Exit current thread (does not return).
 */
[[noreturn]] void fut_thread_exit(void) {
    fut_thread_t *self = fut_thread_current();
    if (!self) {
        for (;;) {
#ifdef __x86_64__
            __asm__ volatile("hlt");
#elif defined(__aarch64__)
            __asm__ volatile("wfi");
#else
            __asm__ volatile("pause");
#endif
        }  // Should never happen
    }

    // Mark as terminated
    self->state = FUT_THREAD_TERMINATED;

    // Remove from scheduler
    fut_sched_remove_thread(self);

    // Remove from parent task
    fut_task_remove_thread(self->task, self);

    // Remove from global thread list
    fut_thread_t **prev = &fut_thread_list;
    for (fut_thread_t *t = fut_thread_list; t; t = t->global_next) {
        if (t == self) {
            *prev = t->global_next;
            break;
        }
        prev = &t->global_next;
    }
    self->wait_next = NULL;

    // Decrement global thread count
    uint64_t old_count = atomic_fetch_sub_explicit(&thread_count, 1, memory_order_acq_rel);
    (void)old_count;  // Avoid unused variable warning

    // Schedule next thread (this never returns)
    fut_schedule();

    // Should never reach here
    for (;;) {
#ifdef __x86_64__
        __asm__ volatile("hlt");
#elif defined(__aarch64__)
        __asm__ volatile("wfi");
#else
        __asm__ volatile("pause");
#endif
    }
}

/**
 * Sleep for specified milliseconds.
 */
void fut_thread_sleep(uint64_t millis) {
    if (millis == 0) {
        fut_thread_yield();
        return;
    }

    fut_thread_t *self = fut_thread_current();
    if (!self) {
        return;
    }

    // Let timer subsystem handle sleep
    fut_sleep_until(self, millis);

    // This will context switch to another thread
    fut_schedule();
}

/* ============================================================
 *   Thread Queries
 * ============================================================ */

/* Global flag to track if per-CPU data is safe to access */
static volatile bool percpu_safe = false;

void fut_thread_mark_percpu_safe(void) {
    percpu_safe = true;
}

/**
 * Get current running thread.
 * Uses per-CPU data accessed via GS segment on x86_64.
 */
fut_thread_t *fut_thread_current(void) {
    /* Don't access per-CPU until it's properly initialized */
    if (!percpu_safe) {
        return NULL;
    }
    fut_percpu_t *percpu = fut_percpu_get();
    return percpu ? percpu->current_thread : NULL;
}

/**
 * Set current thread (internal scheduler use only).
 * Uses per-CPU data accessed via GS segment on x86_64.
 */
void fut_thread_set_current(fut_thread_t *thread) {
    fut_percpu_t *percpu = fut_percpu_get();
    if (percpu) {
        percpu->current_thread = thread;
    }
}

#if defined(__x86_64__)
void fut_thread_init_bootstrap(void) {
    fut_percpu_t *percpu = fut_percpu_get();
    if (!percpu) {
        fut_printf("[THREAD] bootstrap init failed: percpu unavailable\n");
        return;
    }
    if (percpu->current_thread) {
        return;  /* Already have a current thread (scheduler running) */
    }

    static bool bootstrap_ready = false;
    static fut_task_t bootstrap_task;
    static fut_thread_t bootstrap_thread;
    static uint8_t bootstrap_stack[8192] __attribute__((aligned(16)));

    if (!bootstrap_ready) {
        memset(&bootstrap_task, 0, sizeof(bootstrap_task));
        bootstrap_task.pid = 1;
        bootstrap_task.state = FUT_TASK_RUNNING;
        bootstrap_task.current_dir_ino = 1;  /* Root */
        bootstrap_task.uid = 0;
        bootstrap_task.gid = 0;
        bootstrap_task.max_fds = FUT_FD_TABLE_INITIAL_SIZE;
        bootstrap_task.fd_table = fut_malloc(sizeof(struct fut_file *) * bootstrap_task.max_fds);
        if (!bootstrap_task.fd_table) {
            fut_printf("[THREAD] bootstrap init failed: no fd table\n");
            return;
        }
        memset(bootstrap_task.fd_table, 0, sizeof(struct fut_file *) * bootstrap_task.max_fds);
        bootstrap_task.next_fd = 0;

        memset(&bootstrap_thread, 0, sizeof(bootstrap_thread));
        bootstrap_thread.tid = 1;
        bootstrap_thread.task = &bootstrap_task;
        bootstrap_thread.state = FUT_THREAD_RUNNING;
        bootstrap_thread.priority = FUT_DEFAULT_PRIORITY;
        bootstrap_thread.stack_base = bootstrap_stack;
        bootstrap_thread.stack_size = sizeof(bootstrap_stack);

        bootstrap_task.threads = &bootstrap_thread;
        bootstrap_task.thread_count = 1;

        bootstrap_ready = true;
    }

    percpu->current_thread = &bootstrap_thread;
}
#else
void fut_thread_init_bootstrap(void) {
    /* ARM64 platform wires up its boot thread via arm64_init_boot_thread(). */
}
#endif

fut_thread_t *fut_thread_find(uint64_t tid) {
    for (fut_thread_t *t = fut_thread_list; t; t = t->global_next) {
        if (t->tid == tid) {
            return t;
        }
    }
    return NULL;
}

void fut_thread_set_deadline(uint64_t abs_tick) {
    fut_thread_t *self = fut_thread_current();
    if (!self) {
        return;
    }
    self->deadline_tick = abs_tick;
}

uint64_t fut_thread_get_deadline(void) {
    fut_thread_t *self = fut_thread_current();
    if (!self) {
        return 0;
    }
    return self->deadline_tick;
}

int fut_thread_priority_raise(fut_thread_t *thread, int new_priority) {
    if (!thread) {
        return -EINVAL;
    }
    if (new_priority < thread->priority) {
        return 0;
    }
    thread->pi_saved_priority = thread->priority;
    thread->priority = new_priority;
    thread->pi_boosted = true;
    return 0;
}

int fut_thread_priority_restore(fut_thread_t *thread) {
    if (!thread) {
        return -EINVAL;
    }
    if (!thread->pi_boosted) {
        return 0;
    }
    thread->priority = thread->pi_saved_priority;
    thread->pi_boosted = false;
    return 0;
}
/* Forward declare the actual trampoline implementation */
__attribute__((used)) static void fut_thread_trampoline_impl(void (*entry)(void *), void *arg);

#if defined(__x86_64__)
/* x86_64: Naked assembly wrapper that receives the IRETQ and calls the C implementation.
 * CRITICAL: naked attribute prevents compiler from generating prologue/epilogue.
 * We manually set up the stack frame and then call the C function. */
[[noreturn]] __attribute__((naked)) static void fut_thread_trampoline(void (*entry)(void *) __attribute__((unused)), void *arg __attribute__((unused))) {
    __asm__ volatile(
        /* Set up stack frame */
        "pushq %%rbp\n"
        "movq %%rsp, %%rbp\n"

        /* DO NOT enable interrupts here!
         * New threads start with IF=0 and run to completion with interrupts
         * disabled until they reach a point where they can safely be preempted.
         * For user threads, fut_user_trampoline handles the transition and
         * enables interrupts when entering user mode via IRETQ.
         * For kernel threads, the entry function can enable interrupts when ready. */

        /* Parameters are already in RDI and RSI (x86-64 calling convention) */
        /* Call the C implementation */
        "call fut_thread_trampoline_impl\n"

        /* Should never return, but if it does, infinite loop */
        "1: hlt\n"
        "jmp 1b\n"
        ::: "memory"
    );
}
#elif defined(__aarch64__)
/* ARM64: Simple wrapper that calls the implementation.
 * The ARM64 calling convention (X0, X1 for parameters) is handled by the compiler. */
[[noreturn]] static void fut_thread_trampoline(void (*entry)(void *), void *arg) {
    fut_thread_trampoline_impl(entry, arg);
    /* Should never return, but if it does, infinite loop */
    while (1) {
        __asm__ volatile("wfi");  // Wait for interrupt
    }
}
#endif

/* The actual C implementation, called by the assembly wrapper */
[[noreturn]] __attribute__((optimize("O0"))) static void fut_thread_trampoline_impl(void (*entry)(void *), void *arg) {
    if (!entry) {
        fut_thread_exit();
    }

    /* Check if entry is in kernel space */
#if defined(__x86_64__)
    const uintptr_t kernel_base = 0xFFFFFFFF80000000ULL;
#elif defined(__aarch64__)
    const uintptr_t kernel_base = 0xFFFFFF8000000000ULL;
#endif

    if ((uintptr_t)entry < kernel_base) {
        fut_thread_exit();
    }

    /* Call the entry function */
    entry(arg);

    /* If entry returns (doesn't call fut_thread_exit), we exit here */
    fut_thread_exit();
}

/* ============================================================
 *   CPU Affinity API Implementation
 * ============================================================ */

/**
 * Set CPU affinity to a single CPU (hard pin).
 */
int fut_thread_set_affinity(fut_thread_t *thread, uint32_t cpu_id) {
    if (!thread || cpu_id >= FUT_MAX_CPUS) {
        return -EINVAL;
    }

    /* Set single-CPU mask and hard affinity */
    thread->cpu_affinity_mask = (1ULL << cpu_id);
    thread->preferred_cpu = cpu_id;
    thread->hard_affinity = true;

    return 0;
}

/**
 * Set CPU affinity mask (soft preference).
 */
int fut_thread_set_affinity_mask(fut_thread_t *thread, uint64_t mask) {
    if (!thread || mask == 0) {
        return -EINVAL;  /* Must have at least one CPU allowed */
    }

    thread->cpu_affinity_mask = mask;
    thread->hard_affinity = false;

    /* Set preferred CPU to the lowest numbered CPU in mask */
    for (uint32_t i = 0; i < FUT_MAX_CPUS; i++) {
        if (mask & (1ULL << i)) {
            thread->preferred_cpu = i;
            break;
        }
    }

    return 0;
}

/**
 * Get current CPU affinity mask for a thread.
 */
uint64_t fut_thread_get_affinity_mask(fut_thread_t *thread) {
    if (!thread) {
        return 0;
    }
    return thread->cpu_affinity_mask;
}

/**
 * Get preferred CPU for a thread.
 */
uint32_t fut_thread_get_preferred_cpu(fut_thread_t *thread) {
    if (!thread) {
        return 0;
    }
    return thread->preferred_cpu;
}

/**
 * Set hard affinity mode (pin vs soft preference).
 */
void fut_thread_set_hard_affinity(fut_thread_t *thread, bool hard_pin) {
    if (thread) {
        thread->hard_affinity = hard_pin;
    }
}

/**
 * Check if thread has hard affinity enforced.
 */
bool fut_thread_is_hard_affinity(fut_thread_t *thread) {
    if (!thread) {
        return false;
    }
    return thread->hard_affinity;
}
