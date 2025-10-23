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
#include <arch/x86_64/gdt.h>
#include <string.h>
#include <stdatomic.h>

[[noreturn]] static void fut_thread_trampoline(void (*entry)(void *), void *arg) __attribute__((used));

/* External declarations */
extern void fut_printf(const char *fmt, ...);
extern void fut_sleep_until(fut_thread_t *thread, uint64_t wake_time);

/* Thread ID counter (64-bit) */
static _Atomic uint64_t next_tid = 1;

/* Current thread pointer (per-CPU, single CPU for now) */
static fut_thread_t *current_thread = NULL;

/* Global thread list (for stats/debugging) */
fut_thread_t *fut_thread_list = NULL;

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

    // Clamp priority
    if (priority < 0) priority = 0;
    if (priority >= FUT_MAX_PRIORITY) priority = FUT_MAX_PRIORITY - 1;

    // Allocate thread structure
    fut_thread_t *thread = (fut_thread_t *)fut_malloc(sizeof(fut_thread_t));
    if (!thread) {
        return NULL;
    }

    // Allocate stack (page-aligned)
    size_t aligned_stack_size = FUT_PAGE_ALIGN(stack_size);
    void *stack = fut_malloc(aligned_stack_size);
    if (!stack) {
        fut_free(thread);
        return NULL;
    }

    // Place guard canary at bottom of stack (lowest address)
    // This helps detect stack overflow during debugging
    *(uint64_t *)stack = 0xCAFEBABEDEADBEEFULL;  // FUT_STACK_CANARY

    // Initialize thread structure
    *thread = (fut_thread_t){
        .tid = atomic_fetch_add_explicit(&next_tid, 1, memory_order_seq_cst),
        .task = task,
        .stack_base = stack,
        .stack_size = aligned_stack_size,
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

    // Calculate stack top (grows downward)
    void *stack_top = (void *)((uintptr_t)stack + aligned_stack_size);

    // Initialize CPU context for this thread
    fut_cpu_context_t *ctx = &thread->context;
    memset(ctx, 0, sizeof(*ctx));

    uintptr_t aligned_top = ((uintptr_t)stack_top) & ~0xFULL;
    // Provide 16-byte alignment at the point of entry (post-ret => %rsp % 16 == 8)
    ctx->rsp = aligned_top - 8;
    ctx->rip = (uint64_t)(uintptr_t)&fut_thread_trampoline;
    ctx->rflags = RFLAGS_IF;
    ctx->cs = 0x08; // Kernel code segment
    ctx->ss = 0x10; // Kernel data segment
    ctx->rdi = (uint64_t)entry;
    ctx->rsi = (uint64_t)arg;
    ctx->rax = 0;
    ctx->rcx = 0;
    ctx->rdx = 0;

    // Zeroed above but be explicit about SIMD state alignment
    memset(ctx->fx_area, 0, sizeof(ctx->fx_area));

    // Add to parent task
    fut_task_add_thread(task, thread);

    // Add to scheduler ready queue
    fut_sched_add_thread(thread);

    // Add to global thread list
    thread->next = fut_thread_list;
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
    for (fut_thread_t *t = fut_thread_list; t; t = t->next) {
        if (t == self) {
            *prev = t->next;
            break;
        }
        prev = &t->next;
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

/**
 * Get current running thread.
 */
fut_thread_t *fut_thread_current(void) {
    return current_thread;
}

/**
 * Set current thread (internal scheduler use only).
 */
void fut_thread_set_current(fut_thread_t *thread) {
    current_thread = thread;
}

fut_thread_t *fut_thread_find(uint64_t tid) {
    for (fut_thread_t *t = fut_thread_list; t; t = t->next) {
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
    entry(arg);
    fut_thread_exit();
}
