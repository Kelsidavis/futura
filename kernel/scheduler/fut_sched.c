/* fut_sched.c - Futura OS Scheduler Implementation (C23)
 *
 * Copyright (c) 2025 Kelsi Davis / Licensed under the MPL v2.0 — see LICENSE for details
 *
 * Preemptive, priority-based round-robin scheduler.
 */

#include "../../include/kernel/fut_sched.h"
#include "../../include/kernel/fut_task.h"
#include "../../include/kernel/fut_mm.h"
#include "../../include/kernel/fut_memory.h"
#include "../../include/kernel/fut_stats.h"
#include <arch/x86_64/gdt.h>
#include <arch/x86_64/paging.h>
#include <platform/platform.h>
#include <stdint.h>
#include <stdatomic.h>

/* External context switch from platform/x86_64/context_switch.S */
extern void fut_switch_context(fut_cpu_context_t *old, fut_cpu_context_t *new);
extern void fut_switch_context_irq(fut_thread_t *prev, fut_thread_t *next, fut_interrupt_frame_t *prev_frame);

/* External printf for debugging */
extern void fut_printf(const char *fmt, ...);

/* ============================================================
 *   Interrupt Context Detection
 * ============================================================ */

/* Tracks whether we're currently executing in interrupt context */
_Atomic bool fut_in_interrupt = false;

/* Points to the current interrupt frame when in interrupt context */
fut_interrupt_frame_t *fut_current_frame = NULL;

/* ============================================================
 *   Scheduler State
 * ============================================================ */

/* Ready queue (simple linked list for now) */
static fut_thread_t *ready_queue_head = NULL;
static fut_thread_t *ready_queue_tail = NULL;

/* Idle thread */
static fut_thread_t *idle_thread = NULL;

/* Scheduler lock */
static fut_spinlock_t sched_lock = { .locked = 0 };

/* Statistics */
static uint64_t ready_count = 0;

/* ============================================================
 *   Idle Thread
 * ============================================================ */

static void idle_thread_entry(void *arg) {
    (void)arg;
    for (;;) {
        __asm__ volatile("sti\n\thlt" ::: "memory");
    }
}

/* ============================================================
 *   Scheduler Implementation
 * ============================================================ */

/**
 * Initialize scheduler subsystem.
 */
void fut_sched_init(void) {
    // Initialize performance instrumentation
    fut_stats_init();

    // Create idle task and thread
    fut_task_t *idle_task = fut_task_create();
    if (!idle_task) {
        fut_printf("[SCHED] Failed to create idle task\n");
        return;
    }

    // Create idle thread
    idle_thread = fut_thread_create(
        idle_task,
        idle_thread_entry,
        NULL,
        4096,  // Small stack for idle
        FUT_IDLE_PRIORITY
    );

    if (!idle_thread) {
        fut_printf("[SCHED] Failed to create idle thread\n");
        return;
    }

    // Remove idle from ready queue - we'll schedule it manually
    fut_sched_remove_thread(idle_thread);

    fut_printf("[SCHED] Scheduler initialized\n");
}

/**
 * Add thread to ready queue (priority-sorted).
 */
void fut_sched_add_thread(fut_thread_t *thread) {
    if (!thread || thread->state != FUT_THREAD_READY) {
        return;
    }

    fut_spinlock_acquire(&sched_lock);

    // Simple FIFO for now - insert at tail
    thread->next = NULL;
    thread->prev = ready_queue_tail;

    if (ready_queue_tail) {
        ready_queue_tail->next = thread;
    } else {
        ready_queue_head = thread;
    }

    ready_queue_tail = thread;
    ready_count++;

    fut_spinlock_release(&sched_lock);
}

/**
 * Remove thread from ready queue.
 */
void fut_sched_remove_thread(fut_thread_t *thread) {
    if (!thread) {
        return;
    }

    fut_spinlock_acquire(&sched_lock);

    // Unlink from ready queue
    if (thread->prev) {
        thread->prev->next = thread->next;
    } else {
        ready_queue_head = thread->next;
    }

    if (thread->next) {
        thread->next->prev = thread->prev;
    } else {
        ready_queue_tail = thread->prev;
    }

    thread->next = NULL;
    thread->prev = NULL;

    if (ready_count > 0) {
        ready_count--;
    }

    fut_spinlock_release(&sched_lock);
}

/**
 * Select next thread to run (round-robin).
 */
static fut_thread_t *select_next_thread(void) {
    fut_spinlock_acquire(&sched_lock);

    fut_thread_t *next = ready_queue_head;

    // If no ready threads, use idle
    if (!next) {
        fut_spinlock_release(&sched_lock);
        return idle_thread;
    }

    // Remove from head of ready queue
    ready_queue_head = next->next;
    if (ready_queue_head) {
        ready_queue_head->prev = NULL;
    } else {
        ready_queue_tail = NULL;
    }

    next->next = NULL;
    next->prev = NULL;

    if (ready_count > 0) {
        ready_count--;
    }

    fut_spinlock_release(&sched_lock);

    return next;
}

/**
 * Main scheduler - select and switch to next thread.
 */
void fut_schedule(void) {
    fut_thread_t *prev = fut_thread_current();
    fut_thread_t *next = select_next_thread();

    if (!next) {
        next = idle_thread;
    }

    // If current thread is still runnable, put it back in ready queue
    if (prev && prev != idle_thread && prev->state == FUT_THREAD_RUNNING) {
        prev->state = FUT_THREAD_READY;
        fut_sched_add_thread(prev);
    }

    // Mark next thread as running
    next->state = FUT_THREAD_RUNNING;
    fut_thread_set_current(next);

    if (next->stack_base && next->stack_size) {
        uintptr_t stack_top = (uintptr_t)next->stack_base + next->stack_size;
        fut_tss_set_kernel_stack(stack_top);
    }

    // Record context switch for performance instrumentation
    fut_stats_record_switch(prev, next);

    // Context switch if different thread
    if (prev != next) {
        extern void serial_puts(const char *s);

        // Check if we're in interrupt context
        bool in_irq = atomic_load_explicit(&fut_in_interrupt, memory_order_acquire);

        fut_mm_t *prev_mm = (prev && prev->task) ? fut_task_get_mm(prev->task) : NULL;
        fut_mm_t *next_mm = (next && next->task) ? fut_task_get_mm(next->task) : NULL;

        if (prev_mm != next_mm) {
            fut_mm_switch(next_mm);
        }

        if (in_irq && prev) {
            // IRQ-safe context switch (uses IRET)
            // NOTE: Only valid when switching between threads, not from kernel to first thread
            // Cannot use serial_puts/fut_printf from IRQ context (not reentrant)

            // Placeholder for page table switch
            // Perform IRQ-safe context switch
            fut_switch_context_irq(prev, next, fut_current_frame);

            // NOTE: We never return here! The context switch returns via IRET
            // to the new thread's saved context.
        } else {
            // Regular cooperative context switch (uses RET)
            // Safe to use serial I/O here (not in IRQ context)
            extern void serial_puts(const char *s);
            if (!prev) {
                serial_puts("[SCHED] First context switch to thread\n");
            }

            fut_printf("[SCHED] switch to rip=0x%llx rsp=0x%llx entry=%p\n",
                       next->context.rip,
                       next->context.rsp,
                       (void *)next->context.rdi);
            if (next->context.rip < KERNEL_VIRTUAL_BASE) {
                fut_platform_panic("[SCHED] bad RIP for next thread");
            }
            if (((next->context.rsp + 8ULL) & 0xFULL) != 0) {
                fut_platform_panic("[SCHED] stack misaligned for next thread");
            }

            // Placeholder for page table switch
            // Perform regular context switch
            serial_puts("[SCHED] About to call fut_switch_context\n");
            if (prev) {
                fut_switch_context(&prev->context, &next->context);
            } else {
                // First time - just jump to thread
                fut_switch_context(NULL, &next->context);
            }
            serial_puts("[SCHED] Returned from fut_switch_context\n");
        }
    }
}

/**
 * Get scheduler statistics.
 */
void fut_sched_stats(uint64_t *ready_cnt, uint64_t *running_cnt) {
    if (ready_cnt) {
        *ready_cnt = ready_count;
    }
    if (running_cnt) {
        *running_cnt = fut_thread_current() ? 1 : 0;
    }
}

/**
 * Scheduler tick handler - called from timer interrupt.
 *
 * Handles timer-driven preemption.
 * This is the entry point from the timer interrupt handler.
 */
void fut_sched_tick(void) {
    // Update global tick counter for performance instrumentation
    fut_stats_tick();

    // Don't try to schedule if no thread is currently running
    // (can't launch first thread from IRQ context)
    fut_thread_t *curr = fut_thread_current();
    if (!curr) {
        // Silent return - can't use serial_puts from IRQ context
        return;
    }

    // Future enhancements:
    // - Decrement time slices
    // - Handle deadline scheduling

    // Trigger preemptive reschedule
    fut_schedule();
}
