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
static _Atomic uint64_t next_tid __attribute__((aligned(8))) = 1;  /* 8-byte aligned for ARM64 atomics */

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

    /* Verify MXCSR was set to default 0x1F80 by fxsave64.
     * MXCSR is at offset 24 in the FXSAVE area. */
    uint32_t *mxcsr_ptr = (uint32_t *)(clean_fpu_state + 24);

    /* Ensure MXCSR is set to default value */
    if (*mxcsr_ptr == 0) {
        *mxcsr_ptr = 0x1F80;
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
    *(uint64_t *)stack = 0xCAFEBABEDEADBEEFULL;  // FUT_STACK_CANARY

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
    // Provide 16-byte alignment at the point of entry (post-ret => %rsp % 16 == 8)
    ctx->rsp = aligned_top - 8;
    ctx->rip = (uint64_t)(uintptr_t)&fut_thread_trampoline;
    // RFLAGS bit 1 must be 1 (reserved), bit 9 is interrupt enable
    ctx->rflags = 0x202;  // Bit 1 (reserved=1) | Bit 9 (IF=1)
    ctx->cs = 0x08; // Kernel code segment
    ctx->ss = 0x10; // Kernel data segment
    ctx->rdi = (uint64_t)entry;
    ctx->rsi = (uint64_t)arg;
    ctx->rax = 0;
    ctx->rcx = 0;
    ctx->rdx = 0;

    /* Initialize data segment registers to kernel data segment */
    ctx->ds = 0x10;
    ctx->es = 0x10;
    ctx->fs = 0x10;
    ctx->gs = 0x10;

    /* Initialize FPU/XMM state with a valid clean state.
     * This is critical: fxrstor64 requires a properly formatted FXSAVE area.
     * Using memset(0) creates an invalid FPU state (FCW=0, MXCSR=0) which
     * causes undefined behavior when restored. Instead, we copy a clean state
     * captured from finit (FCW=0x037F, MXCSR=0x1F80). */
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

    extern void fut_printf(const char *, ...);
    fut_printf("[THREAD-CREATE] ARM64 thread %llu: entry=%p arg=%p\n",
               (unsigned long long)thread->tid, (void*)entry, arg);

    // Set TTBR0_EL1 from task's memory manager for user-space page table
    if (task->mm) {
        ctx->ttbr0_el1 = task->mm->ctx.ttbr0_el1;
        fut_printf("[THREAD-CREATE] Set ttbr0_el1=%llx from task mm\n",
                   (unsigned long long)ctx->ttbr0_el1);
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
        return -1;
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
        return -1;
    }
    if (!thread->pi_boosted) {
        return 0;
    }
    thread->priority = thread->pi_saved_priority;
    thread->pi_boosted = false;
    return 0;
}
[[noreturn]] static void fut_thread_trampoline(void (*entry)(void *), void *arg) {
    extern void fut_printf(const char *, ...);
    extern void serial_puts(const char *);

    serial_puts("[TRAMPOLINE] Entered trampoline!\n");
    fut_printf("[TRAMPOLINE] Called with entry=%llx arg=%p\n", (uint64_t)(uintptr_t)entry, arg);

    if (!entry) {
        serial_puts("[TRAMPOLINE-ERROR] NULL entry function!\n");
        fut_thread_exit();
    }

    fut_printf("[TRAMPOLINE] Calling entry(arg)...\n");
    /* Call the entry function */
    entry(arg);
    fut_printf("[TRAMPOLINE] entry() returned\n");

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
        return -1;
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
        return -1;  /* Must have at least one CPU allowed */
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
