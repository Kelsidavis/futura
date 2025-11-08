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
#include <platform/x86_64/gdt.h>
#include <platform/x86_64/memory/paging.h>
#elif defined(__aarch64__)
#include <platform/arm64/memory/paging.h>
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

/* Tracks whether we're currently executing in interrupt context
 * Note: On ARM64 bare metal, C11 atomics cause alignment faults.
 * For bools, volatile is sufficient as stores/loads are naturally atomic.
 */
#if defined(__aarch64__)
volatile bool fut_in_interrupt = false;
#else
_Atomic bool fut_in_interrupt = false;
#endif

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
    fut_disable_interrupts();
    fut_sched_remove_thread(idle_thread);
    fut_enable_interrupts();

    // Store idle thread in per-CPU data
    percpu->idle_thread = idle_thread;

    // Set idle thread as current thread so kernel_main has a task context
    // This allows opening /dev/console and other operations that need a task
    fut_thread_set_current(idle_thread);
    idle_thread->state = FUT_THREAD_RUNNING;

    fut_printf("[SCHED] Scheduler initialized for CPU %u (current thread set to idle)\n", percpu->cpu_id);
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
    fut_disable_interrupts();
    fut_sched_remove_thread(idle_thread);
    fut_enable_interrupts();

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
 * Uses load-aware placement if affinity mask is not yet set.
 */
void fut_sched_add_thread(fut_thread_t *thread) {
    if (!thread || thread->state != FUT_THREAD_READY) {
        return;
    }

    fut_percpu_t *target_percpu = NULL;

    // If thread has no affinity mask set, find least-loaded CPU within default mask
    if (thread->cpu_affinity_mask == 0) {
        // Default: unrestricted affinity - all CPUs allowed
        thread->cpu_affinity_mask = ~0ULL;  // All bits set (up to FUT_MAX_CPUS)

        // Find least-loaded CPU for initial placement
        // Note: Affinity mask only supports 64 CPUs (bits 0-63)
        uint64_t min_queue_depth = UINT64_MAX;
        uint32_t best_cpu = 0;

        for (uint32_t i = 0; i < FUT_MAX_CPUS && i < 64; i++) {
            fut_percpu_t *percpu = &fut_percpu_data[i];
            if (percpu->self == NULL) {
                continue;  // CPU not initialized
            }

            fut_spinlock_acquire(&percpu->queue_lock);
            uint64_t queue_depth = percpu->ready_count;
            fut_spinlock_release(&percpu->queue_lock);

            if (queue_depth < min_queue_depth) {
                min_queue_depth = queue_depth;
                best_cpu = i;
            }
        }

        target_percpu = &fut_percpu_data[best_cpu];
        thread->preferred_cpu = best_cpu;
    } else {
        // Thread has affinity constraint - add to preferred CPU within mask
        uint32_t preferred = thread->preferred_cpu;

        // Verify preferred CPU is within affinity mask (and < 64 for bitmask)
        if (preferred < 64 && (thread->cpu_affinity_mask & (1ULL << preferred))) {
            target_percpu = &fut_percpu_data[preferred];
        } else {
            // Find first CPU in affinity mask (limited to 64 CPUs)
            for (uint32_t i = 0; i < 64; i++) {
                if (thread->cpu_affinity_mask & (1ULL << i)) {
                    target_percpu = &fut_percpu_data[i];
                    thread->preferred_cpu = i;
                    break;
                }
            }
        }
    }

    // Fallback to current CPU if no suitable target found
    if (!target_percpu) {
        target_percpu = fut_percpu_get();
    }
    if (!target_percpu) {
        return;  // No per-CPU data available
    }

    fut_spinlock_acquire(&target_percpu->queue_lock);

    // Check if thread is already in the ready queue by walking the list
    // NOTE: Can't use thread->next/prev check because those are also used for task thread list
    fut_thread_t *walker = target_percpu->ready_queue_head;
    while (walker) {
        if (walker == thread) {
            // Thread already in queue - this is benign and can happen during normal
            // cooperative scheduling when multiple code paths try to ready the same thread
            fut_spinlock_release(&target_percpu->queue_lock);
            return;
        }
        walker = walker->next;
    }

    // Simple FIFO - insert at tail
    thread->next = NULL;
    thread->prev = target_percpu->ready_queue_tail;

    if (target_percpu->ready_queue_tail) {
        target_percpu->ready_queue_tail->next = thread;
    } else {
        target_percpu->ready_queue_head = thread;
    }

    target_percpu->ready_queue_tail = thread;
    target_percpu->ready_count++;
    target_percpu->queue_depth = target_percpu->ready_count;

    fut_spinlock_release(&target_percpu->queue_lock);
}

/**
 * Remove thread from ready queue.
 * Uses thread's preferred_cpu (current affinity location).
 */
void fut_sched_remove_thread(fut_thread_t *thread) {
    if (!thread) {
        return;
    }

    // Use thread's preferred CPU (where it was likely added)
    uint32_t cpu_index = thread->preferred_cpu;
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
    percpu->queue_depth = percpu->ready_count;

    fut_spinlock_release(&percpu->queue_lock);
}

/* ============================================================
 *   Work-Stealing Load Balancing
 * ============================================================ */

/**
 * Find the most loaded CPU within the affinity mask.
 * Used to identify which CPU to steal from.
 *
 * @param affinity_mask  Bitmask of CPUs to consider (limited to 64 CPUs)
 * @param exclude_cpu    Don't steal from this CPU (avoid stealing from self)
 * @return CPU index with highest queue depth, or UINT32_MAX if no overloaded CPU
 */
static uint32_t find_most_loaded_cpu(uint64_t affinity_mask, uint32_t exclude_cpu) {
    uint64_t max_queue_depth = 0;
    uint32_t victim_cpu = UINT32_MAX;

    // Find CPU with most threads within affinity mask
    // Note: affinity_mask only supports 64 CPUs (bits 0-63)
    for (uint32_t i = 0; i < FUT_MAX_CPUS && i < 64; i++) {
        // Skip excluded CPU and check affinity mask
        if (i == exclude_cpu || !(affinity_mask & (1ULL << i))) {
            continue;
        }

        fut_percpu_t *percpu = &fut_percpu_data[i];
        if (percpu->self == NULL) {
            continue;  // CPU not initialized
        }

        fut_spinlock_acquire(&percpu->queue_lock);
        uint64_t queue_depth = percpu->ready_count;
        fut_spinlock_release(&percpu->queue_lock);

        if (queue_depth > max_queue_depth) {
            max_queue_depth = queue_depth;
            victim_cpu = i;
        }
    }

    // Only return if victim has threads to steal
    return (max_queue_depth > 0) ? victim_cpu : UINT32_MAX;
}

/**
 * Steal a thread from the specified victim CPU.
 * Respects hard affinity - won't steal threads hard-pinned to other CPUs.
 *
 * @param victim_cpu  CPU to steal from
 * @return Stolen thread, or NULL if no stealable thread
 */
static fut_thread_t *steal_work_from_cpu(uint32_t victim_cpu) {
    if (victim_cpu >= FUT_MAX_CPUS) {
        return NULL;
    }

    fut_percpu_t *victim_percpu = &fut_percpu_data[victim_cpu];
    fut_percpu_t *thief_percpu = fut_percpu_get();

    if (!thief_percpu) {
        return NULL;
    }

    fut_spinlock_acquire(&victim_percpu->queue_lock);

    // Find a stealable thread (skip hard-affinity threads pinned to victim)
    fut_thread_t *current = victim_percpu->ready_queue_head;
    fut_thread_t *stealable = NULL;

    // Prefer stealing from middle/tail to reduce contention
    // but also check if we can steal at least something
    while (current) {
        // Can steal if:
        // 1. Thread is not hard-affinity pinned, OR
        // 2. Thread has soft affinity and can run elsewhere
        if (!current->hard_affinity) {
            // Soft affinity - can steal if unrestricted or if includes current CPU
            uint64_t affinity_mask = current->cpu_affinity_mask;
            // Check bounds: thief_percpu->cpu_index must be < 64 for bitmask operations
            if (affinity_mask == 0 ||
                (thief_percpu->cpu_index < 64 && (affinity_mask & (1ULL << thief_percpu->cpu_index)))) {
                stealable = current;
                break;  // Take first stealable thread we find
            }
        }
        current = current->next;
    }

    if (!stealable) {
        fut_spinlock_release(&victim_percpu->queue_lock);
        return NULL;
    }

    // Remove the thread from victim's queue
    if (stealable->prev) {
        stealable->prev->next = stealable->next;
    } else {
        victim_percpu->ready_queue_head = stealable->next;
    }

    if (stealable->next) {
        stealable->next->prev = stealable->prev;
    } else {
        victim_percpu->ready_queue_tail = stealable->prev;
    }

    stealable->next = NULL;
    stealable->prev = NULL;

    if (victim_percpu->ready_count > 0) {
        victim_percpu->ready_count--;
    }
    victim_percpu->queue_depth = victim_percpu->ready_count;
    victim_percpu->work_stolen_count++;

    fut_spinlock_release(&victim_percpu->queue_lock);

    // Update thief's statistics and preferred CPU
    thief_percpu->work_steal_count++;
    stealable->preferred_cpu = thief_percpu->cpu_index;

    return stealable;
}

/**
 * Select next thread to run with work-stealing load balancing.
 * First tries local queue, then attempts to steal from overloaded CPUs.
 */
static fut_thread_t *select_next_thread(void) {
    fut_percpu_t *percpu = fut_percpu_get();
    if (!percpu) {
        return NULL;
    }

    fut_spinlock_acquire(&percpu->queue_lock);

    fut_thread_t *next = percpu->ready_queue_head;

#if defined(__aarch64__)
    // Debug: Show all threads in ready queue
    extern void fut_printf(const char *, ...);
    fut_printf("[SELECT] Ready queue head=%p, count=%u\n", (void*)next, percpu->ready_count);
    fut_thread_t *walker = next;
    int walk_count = 0;
    while (walker && walk_count < 10) {
        fut_printf("[SELECT]   Thread @%p tid=%llu state=%d priority=%d next=%p\n",
                   (void*)walker, (unsigned long long)walker->tid, walker->state, walker->priority, (void*)walker->next);
        walker = walker->next;
        walk_count++;
    }
#endif

    // If no ready threads locally, try work-stealing
    if (!next) {
        fut_spinlock_release(&percpu->queue_lock);

        // Try to steal work from another CPU
        // Start by looking for the most loaded CPU within unrestricted affinity
        uint32_t victim_cpu = find_most_loaded_cpu(~0ULL, percpu->cpu_index);

        if (victim_cpu != UINT32_MAX) {
            next = steal_work_from_cpu(victim_cpu);
        }

        // If we couldn't steal, return idle thread
        return next ? next : percpu->idle_thread;
    }

    // Remove from head of ready queue (local thread available)
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
    percpu->queue_depth = percpu->ready_count;

    fut_spinlock_release(&percpu->queue_lock);

    return next;
}

/**
 * Main scheduler - select and switch to next thread.
 */
void fut_schedule(void) {
    fut_thread_t *prev = fut_thread_current();
    fut_thread_t *next = select_next_thread();

#if defined(__aarch64__)
    extern void fut_printf(const char *, ...);
    fut_printf("[SCHED] fut_schedule called: prev=%p next=%p\n", (void*)prev, (void*)next);
#endif

    // Get per-CPU data for idle thread check
    fut_percpu_t *percpu = fut_percpu_get();
    fut_thread_t *idle = percpu ? percpu->idle_thread : NULL;

    if (!next) {
        next = idle;
#if defined(__aarch64__)
        fut_printf("[SCHED] No next thread, using idle=%p\n", (void*)idle);
#endif
    }

    // If scheduler not initialized yet (no idle thread), just return
    // This can happen if timer IRQs fire during early boot
    if (!next) {
#if defined(__aarch64__)
        fut_printf("[SCHED] No threads available, returning early\n");
#endif
        return;
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
#if defined(__aarch64__)
        bool in_irq = fut_in_interrupt;  /* Simple load for volatile bool */
#else
        bool in_irq = atomic_load_explicit(&fut_in_interrupt, memory_order_acquire);
#endif

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
#if defined(__aarch64__)
            fut_printf("[SCHED] About to context switch: prev=%p next=%p next->tid=%llu next->context.pc=%llx\n",
                       (void*)prev, (void*)next, (unsigned long long)(next ? next->tid : 0),
                       (unsigned long long)(next ? next->context.pc : 0));
#endif
            if (prev) {
                fut_switch_context(&prev->context, &next->context);
            } else {
                // First time - just jump to thread
                fut_switch_context(NULL, &next->context);
            }
            // Context switch returns when this thread is switched back to (cooperative threading)
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
