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
#if defined(__x86_64__)
#include <arch/x86_64/gdt.h>
#include <arch/x86_64/paging.h>
#elif defined(__aarch64__)
#include <arch/arm64/paging.h>
#endif
#include <platform/platform.h>
#include <stdint.h>
#include <stdatomic.h>

/* External context switch from platform/x86_64/context_switch.S */
extern void fut_switch_context(fut_cpu_context_t *old, fut_cpu_context_t *new);
extern void fut_switch_context_irq(fut_thread_t *prev, fut_thread_t *next, fut_interrupt_frame_t *prev_frame);

/* External printf for debugging */
extern void fut_printf(const char *fmt, ...);

/* Per-CPU data access */
#include "../../include/kernel/fut_percpu.h"

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

/* All scheduler state is now per-CPU (in fut_percpu_t):
 * - ready_queue_head/tail: Per-CPU ready queue
 * - queue_lock: Per-CPU scheduler lock
 * - ready_count: Per-CPU thread count
 * - idle_thread: Per-CPU idle thread
 */

/* ============================================================
 *   Idle Thread
 * ============================================================ */

static void idle_thread_entry(void *arg) {
    (void)arg;
    for (;;) {
#ifdef __x86_64__
        __asm__ volatile("sti\n\thlt" ::: "memory");  /* Enable interrupts and halt */
#elif defined(__aarch64__)
        __asm__ volatile("msr daifset, #2\nwfi" ::: "memory");  /* Enable IRQ and wait for interrupt */
#else
        /* Generic idle: just loop */
        __asm__ volatile("" ::: "memory");
#endif
    }
}

/* ============================================================
 *   Scheduler Implementation
 * ============================================================ */

/**
 * Initialize scheduler subsystem (for BSP).
 * Creates idle thread for the boot processor.
 */
void fut_sched_init(void) {
    // Initialize performance instrumentation
    fut_stats_init();

    // Get per-CPU data for BSP
    fut_percpu_t *percpu = fut_percpu_get();
    if (!percpu) {
        fut_printf("[SCHED] ERROR: No per-CPU data available\n");
        return;
    }

    // Create idle task and thread for BSP
    fut_task_t *idle_task = fut_task_create();
    if (!idle_task) {
        fut_printf("[SCHED] Failed to create idle task\n");
        return;
    }

    // Create idle thread (we'll add it to the ready queue manually later if needed)
    // Note: We create with priority FUT_IDLE_PRIORITY but don't add to scheduler queue
    fut_thread_t *idle_thread = fut_thread_create(
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
    // This removes the idle thread that was automatically added by fut_thread_create()
    // Disable interrupts to prevent deadlock (timer interrupt could fire and try to acquire sched_lock)
    __asm__ volatile("cli");
    fut_sched_remove_thread(idle_thread);
    __asm__ volatile("sti");

    // Store idle thread in per-CPU data
    percpu->idle_thread = idle_thread;

    fut_printf("[SCHED] Scheduler initialized for CPU %u\n", percpu->cpu_id);
}

/**
 * Initialize scheduler for a specific CPU (for APs).
 * Creates idle thread for the application processor.
 */
void fut_sched_init_cpu(void) {
    // Get per-CPU data for this CPU
    fut_percpu_t *percpu = fut_percpu_get();
    if (!percpu) {
        fut_printf("[SCHED] ERROR: No per-CPU data available for AP\n");
        return;
    }

    // Create idle task and thread for this AP
    fut_task_t *idle_task = fut_task_create();
    if (!idle_task) {
        fut_printf("[SCHED] Failed to create idle task for CPU %u\n", percpu->cpu_id);
        return;
    }

    // Create idle thread
    fut_thread_t *idle_thread = fut_thread_create(
        idle_task,
        idle_thread_entry,
        NULL,
        4096,  // Small stack for idle
        FUT_IDLE_PRIORITY
    );

    if (!idle_thread) {
        fut_printf("[SCHED] Failed to create idle thread for CPU %u\n", percpu->cpu_id);
        return;
    }

    // Remove idle from ready queue - we'll schedule it manually
    __asm__ volatile("cli");
    fut_sched_remove_thread(idle_thread);
    __asm__ volatile("sti");

    // Store idle thread in per-CPU data
    percpu->idle_thread = idle_thread;

    // Set as current thread for this CPU
    fut_thread_set_current(idle_thread);
    idle_thread->state = FUT_THREAD_RUNNING;

    fut_printf("[SCHED] Scheduler initialized for CPU %u\n", percpu->cpu_id);
}

/**
 * Add thread to ready queue (per-CPU).
 * Adds the thread to the current CPU's ready queue.
 */
void fut_sched_add_thread(fut_thread_t *thread) {
    if (!thread || thread->state != FUT_THREAD_READY) {
        return;
    }

    // Get current CPU's per-CPU data
    fut_percpu_t *percpu = fut_percpu_get();
    if (!percpu) {
        return; // No per-CPU data available
    }

    fut_spinlock_acquire(&percpu->queue_lock);

    // Simple FIFO for now - insert at tail
    thread->next = NULL;
    thread->prev = percpu->ready_queue_tail;

    if (percpu->ready_queue_tail) {
        percpu->ready_queue_tail->next = thread;
    } else {
        percpu->ready_queue_head = thread;
    }

    percpu->ready_queue_tail = thread;
    percpu->ready_count++;

    // Set CPU affinity to current CPU for cache locality
    thread->cpu_affinity = percpu->cpu_index;

    fut_spinlock_release(&percpu->queue_lock);
}

/**
 * Remove thread from ready queue.
 * Searches the thread's affinity CPU queue.
 */
void fut_sched_remove_thread(fut_thread_t *thread) {
    if (!thread) {
        return;
    }

    // Use thread's CPU affinity to find the right queue
    uint32_t cpu_index = thread->cpu_affinity;
    if (cpu_index >= FUT_MAX_CPUS) {
        cpu_index = 0; // Fallback to CPU 0
    }

    fut_percpu_t *percpu = &fut_percpu_data[cpu_index];

    fut_spinlock_acquire(&percpu->queue_lock);

    // Check if thread is actually in the list
    // If both prev and next are NULL, thread might not be in list
    // We need to verify it's not an isolated node
    bool in_list = (thread->prev != NULL || thread->next != NULL ||
                    percpu->ready_queue_head == thread);

    if (!in_list) {
        // Thread not in list, nothing to remove
        fut_spinlock_release(&percpu->queue_lock);
        return;
    }

    // Unlink from ready queue
    if (thread->prev) {
        thread->prev->next = thread->next;
    } else {
        percpu->ready_queue_head = thread->next;
    }

    if (thread->next) {
        thread->next->prev = thread->prev;
    } else {
        percpu->ready_queue_tail = thread->prev;
    }

    thread->next = NULL;
    thread->prev = NULL;

    if (percpu->ready_count > 0) {
        percpu->ready_count--;
    }

    fut_spinlock_release(&percpu->queue_lock);
}

/**
 * Select next thread to run (round-robin from per-CPU queue).
 */
static fut_thread_t *select_next_thread(void) {
    fut_percpu_t *percpu = fut_percpu_get();
    if (!percpu) {
        return NULL;
    }

    fut_spinlock_acquire(&percpu->queue_lock);

    fut_thread_t *next = percpu->ready_queue_head;

    // If no ready threads, use per-CPU idle thread
    if (!next) {
        fut_spinlock_release(&percpu->queue_lock);
        return percpu->idle_thread;
    }

    // Remove from head of ready queue
    percpu->ready_queue_head = next->next;
    if (percpu->ready_queue_head) {
        percpu->ready_queue_head->prev = NULL;
    } else {
        percpu->ready_queue_tail = NULL;
    }

    next->next = NULL;
    next->prev = NULL;

    if (percpu->ready_count > 0) {
        percpu->ready_count--;
    }

    fut_spinlock_release(&percpu->queue_lock);

    return next;
}

/**
 * Main scheduler - select and switch to next thread.
 */
void fut_schedule(void) {
    fut_thread_t *prev = fut_thread_current();
    fut_thread_t *next = select_next_thread();

    // Get per-CPU data for idle thread check
    fut_percpu_t *percpu = fut_percpu_get();
    fut_thread_t *idle = percpu ? percpu->idle_thread : NULL;

    if (!next) {
        next = idle;
    }

    // If current thread is still runnable, put it back in ready queue
    if (prev && prev != idle && prev->state == FUT_THREAD_RUNNING) {
        prev->state = FUT_THREAD_READY;
        fut_sched_add_thread(prev);
    }

    // Mark next thread as running
    next->state = FUT_THREAD_RUNNING;

#if defined(__x86_64__)
    if (next->stack_base && next->stack_size) {
        uintptr_t stack_top = (uintptr_t)next->stack_base + next->stack_size;
        fut_tss_set_kernel_stack(stack_top);
    }
#elif defined(__aarch64__)
    // ARM64: TSS not needed, stack is in SP register
#endif

    // Record context switch for performance instrumentation
    fut_stats_record_switch(prev, next);

    // Context switch if different thread
    if (prev != next) {
        extern void serial_puts(const char *s);

        // Check if we're in interrupt context
        bool in_irq = atomic_load_explicit(&fut_in_interrupt, memory_order_acquire);

        fut_mm_t *prev_mm = (prev && prev->task) ? fut_task_get_mm(prev->task) : NULL;
        fut_mm_t *next_mm = (next && next->task) ? fut_task_get_mm(next->task) : NULL;

        // Only set current_thread if we're actually going to context switch
        fut_thread_set_current(next);

        // Switch MM if needed
        if (prev_mm != next_mm) {
            fut_mm_switch(next_mm);
        }

        if (in_irq && prev && fut_current_frame) {
            // IRQ-safe context switch (uses IRET)
            // This modifies the interrupt frame on the stack so IRET returns to next thread
            fut_switch_context_irq(prev, next, fut_current_frame);
        } else {
            // Regular cooperative context switch (uses RET)
            if (prev) {
                fut_switch_context(&prev->context, &next->context);
            } else {
                // First time - just jump to thread
                fut_switch_context(NULL, &next->context);
            }
        }
    }
}

/**
 * Get scheduler statistics (aggregated across all CPUs).
 */
void fut_sched_stats(uint64_t *ready_cnt, uint64_t *running_cnt) {
    uint64_t total_ready = 0;
    uint64_t total_running = 0;

    // Aggregate counts across all CPUs
    for (uint32_t i = 0; i < FUT_MAX_CPUS; i++) {
        fut_percpu_t *percpu = &fut_percpu_data[i];
        if (percpu->self) {  // Check if this CPU is initialized
            total_ready += percpu->ready_count;
            if (percpu->current_thread && percpu->current_thread != percpu->idle_thread) {
                total_running++;
            }
        }
    }

    if (ready_cnt) {
        *ready_cnt = total_ready;
    }
    if (running_cnt) {
        *running_cnt = total_running;
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
