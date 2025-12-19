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
#include <arch/x86_64/msr.h>  /* For rdmsr/wrmsr for FS_BASE TLS support */
#define MSR_FS_BASE 0xC0000100
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

/* Tracks whether the scheduler has been explicitly started.
 * This prevents premature context switches during early boot when
 * timer interrupts are already enabled but kernel_main hasn't finished. */
static volatile bool scheduler_started = false;

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

    // CRITICAL: Idle thread should NEVER use saved interrupt frames
    // Always construct frames from context to avoid stale frame issues
    idle_thread->irq_frame = NULL;

    // IMPORTANT: Load idle thread's segment registers BEFORE marking it as running
    // This ensures the first hardware interrupt will capture correct segment values
#if defined(__x86_64__)
    fut_printf("[SCHED-IDLE] Loading idle thread segments: DS=0x%04x SS=0x%04x\n",
               (unsigned int)idle_thread->context.ds, (unsigned int)idle_thread->context.ss);

    // Read current SS before modification
    uint16_t ss_before = 0;
    __asm__ volatile("movw %%ss, %0" : "=r"(ss_before));
    fut_printf("[SCHED-IDLE] SS before load: 0x%04x\n", (unsigned int)ss_before);

    __asm__ volatile(
        "movw %0, %%ds\n"
        "movw %0, %%es\n"
        "movw %0, %%fs\n"
        "movw %1, %%ss\n"
        : /* no outputs */
        : "r"((uint16_t)idle_thread->context.ds), "r"((uint16_t)idle_thread->context.ss)
        : "memory"
    );

    // Read SS after modification to verify
    uint16_t ss_after = 0;
    __asm__ volatile("movw %%ss, %0" : "=r"(ss_after));
    fut_printf("[SCHED-IDLE] SS after load: 0x%04x\n", (unsigned int)ss_after);
#endif

    // Set idle thread as current thread so kernel_main has a task context
    // This allows opening /dev/console and other operations that need a task
    fut_thread_set_current(idle_thread);
    idle_thread->state = FUT_THREAD_RUNNING;

    fut_printf("[SCHED] Scheduler initialized for CPU %u (current thread set to idle)\n", percpu->cpu_id);
}

/**
 * Start the scheduler, allowing context switches to occur.
 * Must be called after all kernel initialization is complete.
 */
void fut_sched_start(void) {
    scheduler_started = true;
    fut_printf("[SCHED] Scheduler started - preemptive scheduling now enabled\n");
}

/**
 * Check if scheduler is started.
 */
bool fut_sched_is_started(void) {
    return scheduler_started;
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

    // Debug: Log when threads are added (limited for perf)
    static int add_count = 0;
    if (add_count < 20) {
        fut_printf("[SCHED] Added thread tid=%llu to ready queue (count now %llu)\n",
                   (unsigned long long)thread->tid, (unsigned long long)target_percpu->ready_count);
        add_count++;
    }
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
    // Don't allow context switches until scheduler is explicitly started
    if (!scheduler_started) {
        return;
    }

    fut_thread_t *prev = fut_thread_current();
    fut_thread_t *next = select_next_thread();

    // Debug: Log scheduler calls to understand preemption (disabled for perf)
    static int sched_call_count = 0;
    if (sched_call_count < 50) {
        fut_percpu_t *dbg_percpu = fut_percpu_get();
        fut_printf("[SCHED-DBG] schedule called: prev_tid=%llu next_tid=%llu queue=%llu\n",
                   prev ? (unsigned long long)prev->tid : 0ULL,
                   next ? (unsigned long long)next->tid : 0ULL,
                   dbg_percpu ? (unsigned long long)dbg_percpu->ready_count : 0ULL);
        sched_call_count++;
    }

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

    // Debug: Log first few context switches (limited for perf)
    static int switch_count = 0;
    if (switch_count < 30 && prev != next) {
        fut_printf("[SCHED] Switching: tid=%llu -> tid=%llu (queue_count=%llu)\n",
                   prev ? (unsigned long long)prev->tid : 0ULL,
                   (unsigned long long)next->tid,
                   percpu ? (unsigned long long)percpu->ready_count : 0ULL);
        switch_count++;
    }

#if defined(__x86_64__)
    if (next->stack_base && next->stack_size) {
        uintptr_t stack_top = (uintptr_t)next->stack_base + next->stack_size;
        fut_tss_set_kernel_stack(stack_top);
        /* Also set percpu syscall_kernel_rsp for the SYSCALL instruction fastpath.
         * The SYSCALL instruction doesn't use TSS.rsp0 automatically - we must
         * manually load the kernel stack in the entry code. */
        if (percpu) {
            percpu->syscall_kernel_rsp = stack_top;
        }
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

        // CRITICAL: CR3 switching for user threads being resumed from interrupts
        // - Trampolines handle CR3 for newly created threads
        // - But for threads interrupted mid-execution (e.g., sleeping in syscall),
        //   we MUST switch CR3 here before returning to userspace via IRET
        fut_mm_t *prev_mm = (prev && prev->task) ? fut_task_get_mm(prev->task) : NULL;
        fut_mm_t *next_mm = (next && next->task) ? fut_task_get_mm(next->task) : NULL;

        // Switch CR3 if different address spaces
        // CRITICAL: Must switch CR3 for ANY context switch to a different mm,
        // not just IRQ-based switches. Cooperative switches (e.g., when a sleeping
        // thread wakes up via timer callback and gets scheduled by fut_schedule())
        // also need the correct CR3 before returning to userspace.
        if (prev_mm != next_mm && next_mm) {
            fut_mm_switch(next_mm);
        }

        // Only set current_thread if we're actually going to context switch
        fut_thread_set_current(next);

        // CRITICAL: Idle threads must NEVER use IRETQ-based switching!
        // Their context structures contain stale bootstrap values. Once they start running,
        // we can't construct valid interrupt frames from them. Force cooperative switching.
        // Note: Each CPU has its own idle thread, so we must check against percpu->idle_thread
        // rather than hardcoding tid==1 (which is only the BSP's idle thread).
        bool idle_involved = (prev && prev == idle) || (next && next == idle);

        // CRITICAL: Don't save state for terminated threads!
        // When a thread calls fut_thread_exit(), it marks itself as TERMINATED and then
        // calls fut_schedule(). We must NOT save state for terminated threads because:
        // 1. The thread is being cleaned up and its structures may be freed soon
        // 2. Saving state to a terminated thread's irq_frame can corrupt memory
        // 3. The terminated thread will never be switched back to anyway
        bool prev_terminated = (prev && prev->state == FUT_THREAD_TERMINATED);

        // IRETQ path for preemptive context switching
        // CRITICAL: Only use IRETQ when:
        // 1. We're in an IRQ context (timer interrupt)
        // 2. prev thread exists and has a valid irq_frame OR we can save its state
        // 3. next thread has a valid context to restore (validated by assembly)
        // 4. Neither thread is the idle thread (idle uses cooperative switching)
        // 5. prev thread is NOT terminated (don't save state for exiting threads)
        //
        // The assembly code (fut_switch_context_irq) handles:
        // - Frame validation (RIP, CS, SS checks)
        // - Constructing frames from context when irq_frame is NULL
        // - Clearing corrupted frames to prevent reuse

#if defined(__x86_64__)
        /* Save/restore FS_BASE MSR for TLS (Thread Local Storage) support.
         * User threads use FS:0x28 for stack canary, which requires proper FS_BASE.
         * Kernel threads typically have fs_base=0, which is fine.
         * Don't save for terminated threads - they won't run again. */
        uint64_t saved_fs_base = 0;
        if (prev && !prev_terminated) {
            saved_fs_base = rdmsr(MSR_FS_BASE);
            prev->fs_base = saved_fs_base;
        }
        wrmsr(MSR_FS_BASE, next->fs_base);
#endif

        // CRITICAL: IRETQ vs cooperative context switch decision
        //
        // The IRETQ path (fut_switch_context_irq) is required when:
        // 1. The next thread was preempted in user mode - its state is in irq_frame
        // 2. We're in interrupt context with a valid frame on stack
        //
        // The cooperative path (fut_switch_context) only works for threads that:
        // 1. Were saved via cooperative switch (context structure is valid)
        // 2. Are kernel-only threads (never ran in user mode)
        //
        // When prev is terminated:
        // - Its kernel stack is still valid (not freed until waitpid reaps the task)
        // - We can use IRETQ path with fut_current_frame pointing to prev's stack
        // - Pass NULL for prev so we don't save the terminated thread's state
        // - The IRETQ will switch to next's RSP, abandoning prev's stack safely
        //
        // This is REQUIRED for user threads because their irq_frame contains the
        // correct user-space RIP/RSP, while their context structure may be stale.
        if (in_irq && fut_current_frame && !idle_involved) {
            // IRQ-safe context switch (uses IRET)
            // Pass NULL for prev when terminated to skip saving its state
#if defined(__aarch64__)
            fut_printf("[SCHED] IRQ path: prev=%p next=%p next->pstate=0x%llx next->ttbr0=0x%llx\n",
                       (void*)prev, (void*)next,
                       (unsigned long long)next->context.pstate,
                       (unsigned long long)next->context.ttbr0_el1);
#endif
            fut_switch_context_irq(prev_terminated ? NULL : prev, next, fut_current_frame);
        } else {
            // Regular cooperative context switch (uses RET)
            // For terminated threads, pass NULL to skip saving their state
#if defined(__aarch64__) && defined(DEBUG_SCHED)
            fut_printf("[SCHED] Coop path: prev=%p next=%p &next->context=%p next->pstate=0x%llx next->ttbr0=0x%llx next->x7=0x%llx\n",
                       (void*)prev, (void*)next, (void*)&next->context,
                       (unsigned long long)next->context.pstate,
                       (unsigned long long)next->context.ttbr0_el1,
                       (unsigned long long)next->context.x7);
#endif
            // CRITICAL FIX: When doing cooperative switch from within ISR context
            // (e.g., when terminating a thread and switching to idle), we must clear
            // the interrupt context flags BEFORE the switch. Otherwise, fut_in_interrupt
            // remains 1 and fut_current_frame points to an abandoned frame on the
            // terminated thread's stack, causing GP faults when later ISRs try to use them.
            if (in_irq) {
#if defined(__aarch64__)
                fut_in_interrupt = false;
#else
                atomic_store_explicit(&fut_in_interrupt, false, memory_order_release);
#endif
                // Clear fut_current_frame to prevent use of stale frame pointer
                extern fut_interrupt_frame_t *fut_current_frame;
                fut_current_frame = NULL;
            }
            if (prev && !prev_terminated) {
                fut_switch_context(&prev->context, &next->context);
            } else {
                // First time or terminated prev - just jump to thread (don't save prev state)
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
