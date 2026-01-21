// SPDX-License-Identifier: MPL-2.0
/*
 * fut_percpu.h - Per-CPU data structures for SMP support
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides per-CPU storage for scheduler state, thread management, and
 * syscall handling in symmetric multiprocessing (SMP) environments. Each
 * CPU has its own instance of fut_percpu_t, allowing lockless access to
 * CPU-local data.
 *
 * Architecture-specific access:
 *   x86_64: Uses GS segment base (IA32_GS_BASE MSR) for fast per-CPU access.
 *           GS:0 always points to the current CPU's fut_percpu_t.
 *   ARM64:  Uses TPIDR_EL1 (Thread Pointer ID Register) for per-CPU access.
 *
 * Why per-CPU data matters:
 *   1. Performance: No locking needed for CPU-local data access
 *   2. Scalability: Eliminates cache line bouncing between CPUs
 *   3. Correctness: Each CPU has isolated scheduler state
 *   4. Syscalls: Provides scratch space for stack switching during SYSCALL
 *
 * Common usage patterns:
 *   // Get current CPU's data
 *   fut_percpu_t *cpu = fut_percpu_get();
 *
 *   // Access current thread (very common operation)
 *   fut_thread_t *cur = cpu->current_thread;
 *
 *   // Check CPU index for debugging
 *   uint32_t idx = fut_percpu_get_cpu_index();
 *
 * Thread safety:
 *   Per-CPU data is inherently thread-safe when accessed from the owning
 *   CPU with interrupts disabled. Cross-CPU access requires proper
 *   synchronization (typically the queue_lock for run queue operations).
 *
 * Memory layout:
 *   The structure is 128-byte aligned to avoid false sharing between
 *   adjacent CPU's data structures. The self pointer MUST be at offset 0
 *   for the GS:0 access pattern to work correctly.
 */

#pragma once

#include <stdint.h>
#include <stdatomic.h>

/* Forward declarations */
struct fut_thread;
struct fut_task;

/* Spinlock for synchronization */
#include "fut_sched.h"

/**
 * Maximum number of CPUs supported by the kernel.
 *
 * This determines the size of the fut_percpu_data array. Can be increased
 * if needed, but larger values consume more memory even on systems with
 * fewer CPUs.
 */
#define FUT_MAX_CPUS 256

/**
 * Per-CPU data structure.
 *
 * Contains all per-CPU state including scheduler queues, current thread
 * reference, and syscall scratch space. Accessed via GS-relative addressing
 * on x86_64 or TPIDR_EL1 on ARM64.
 *
 * Layout requirements:
 *   - `self` MUST be at offset 0 for GS:0 to return the structure pointer
 *   - Aligned to 128 bytes to avoid false sharing
 *   - Field offsets must match PERCPU_OFFSET_* constants for assembly access
 */
typedef struct fut_percpu {
    /* Self-pointer for validation (MUST be at offset 0 for GS:0 access) */
    struct fut_percpu *self;      /* Points to this structure */

    /* CPU identification */
    uint32_t cpu_id;              /* APIC ID or CPU number */
    uint32_t cpu_index;           /* Linear CPU index (0, 1, 2, ...) */

    /* Scheduler state */
    struct fut_thread *current_thread;   /* Currently running thread */
    struct fut_thread *idle_thread;      /* This CPU's idle thread */

    /* Per-CPU run queue */
    struct fut_thread *ready_queue_head; /* Head of ready queue */
    struct fut_thread *ready_queue_tail; /* Tail of ready queue */
    uint64_t ready_count;                /* Number of ready threads */
    fut_spinlock_t queue_lock;           /* Lock for this CPU's queue */

    /* Load balancing and statistics */
    uint64_t queue_depth;                /* Current queue depth for load tracking */
    uint64_t work_steal_count;           /* Number of times work stolen from this CPU */
    uint64_t work_stolen_count;          /* Number of times this CPU stole work */
    uint64_t last_balance_tick;          /* Tick when last load balance occurred */

    /* SYSCALL scratch space - for saving user RSP during syscall entry
     * The SYSCALL instruction doesn't switch stacks, so we need a safe place
     * to store user RSP before loading kernel stack pointer. */
    uint64_t syscall_user_rsp;           /* Temporary storage for user RSP */
    uint64_t syscall_kernel_rsp;         /* Kernel RSP to use for syscalls */

    /* Padding to 128-byte cache line for alignment */
} __attribute__((aligned(128))) fut_percpu_t;

/**
 * Structure field offsets for assembly access.
 *
 * These constants MUST be kept in sync with the fut_percpu struct layout.
 * Assembly code (e.g., syscall entry, context switch) uses these offsets
 * to access per-CPU fields via GS-relative addressing.
 *
 * Example assembly usage (x86_64):
 *   mov %rsp, %gs:PERCPU_OFFSET_SYSCALL_USER_RSP   # Save user RSP
 *   mov %gs:PERCPU_OFFSET_SYSCALL_KERNEL_RSP, %rsp # Load kernel RSP
 *   mov %gs:PERCPU_OFFSET_CURRENT_THREAD, %rax    # Get current thread
 *
 * If the struct layout changes, update these offsets and recompile all
 * assembly files. A mismatch will cause subtle and hard-to-debug failures.
 */
#define PERCPU_OFFSET_SELF              0   /**< struct fut_percpu *self */
#define PERCPU_OFFSET_CPU_ID            8   /**< uint32_t cpu_id */
#define PERCPU_OFFSET_CPU_INDEX         12  /**< uint32_t cpu_index */
#define PERCPU_OFFSET_CURRENT_THREAD    16  /**< struct fut_thread *current_thread */
#define PERCPU_OFFSET_IDLE_THREAD       24  /**< struct fut_thread *idle_thread */
#define PERCPU_OFFSET_READY_QUEUE_HEAD  32  /**< struct fut_thread *ready_queue_head */
#define PERCPU_OFFSET_READY_QUEUE_TAIL  40  /**< struct fut_thread *ready_queue_tail */
#define PERCPU_OFFSET_READY_COUNT       48  /**< uint64_t ready_count */
#define PERCPU_OFFSET_QUEUE_LOCK        56  /**< fut_spinlock_t queue_lock */
#define PERCPU_OFFSET_QUEUE_DEPTH       64  /**< uint64_t queue_depth */
#define PERCPU_OFFSET_WORK_STEAL_COUNT  72  /**< uint64_t work_steal_count */
#define PERCPU_OFFSET_WORK_STOLEN_COUNT 80  /**< uint64_t work_stolen_count */
#define PERCPU_OFFSET_LAST_BALANCE_TICK 88  /**< uint64_t last_balance_tick */
#define PERCPU_OFFSET_SYSCALL_USER_RSP  96  /**< uint64_t syscall_user_rsp */
#define PERCPU_OFFSET_SYSCALL_KERNEL_RSP 104 /**< uint64_t syscall_kernel_rsp */

/**
 * Global array of per-CPU data structures.
 *
 * Contains one fut_percpu_t for each possible CPU (0 to FUT_MAX_CPUS-1).
 * Use fut_percpu_get() to access the current CPU's data; direct array
 * access should only be used during initialization or for cross-CPU
 * inspection (with appropriate locking).
 */
extern fut_percpu_t fut_percpu_data[FUT_MAX_CPUS];

/**
 * Get pointer to current CPU's per-CPU data.
 *
 * Returns the per-CPU structure for the CPU executing this code. This is
 * the primary interface for accessing per-CPU data and is extremely fast
 * (single memory read via segment register).
 *
 * @return Pointer to current CPU's fut_percpu_t
 *
 * Architecture implementation:
 *   x86_64: Reads GS:0 which contains the self-pointer
 *   ARM64:  Reads TPIDR_EL1 which stores the structure pointer
 *   Other:  Falls back to fut_percpu_data[0] (single-CPU mode)
 *
 * Warning: The returned pointer is only valid for the current CPU. If
 * preemption or migration is possible, disable interrupts first or use
 * the pointer only for atomic operations.
 *
 * Example:
 *   fut_percpu_t *cpu = fut_percpu_get();
 *   fut_thread_t *cur = cpu->current_thread;
 */
static inline fut_percpu_t *fut_percpu_get(void) {
#if defined(__x86_64__)
    fut_percpu_t *percpu;
    __asm__ volatile("mov %%gs:0, %0" : "=r"(percpu));
    return percpu;
#elif defined(__aarch64__)
    /* ARM64: Read TPIDR_EL1 (Thread Pointer ID Register for EL1)
     * The kernel stores the per-CPU structure pointer in TPIDR_EL1
     */
    fut_percpu_t *percpu;
    __asm__ volatile("mrs %0, tpidr_el1" : "=r"(percpu));
    return percpu;
#else
    /* Fallback to single CPU */
    return &fut_percpu_data[0];
#endif
}

/**
 * Set per-CPU pointer for the current CPU.
 *
 * Configures the architecture-specific register to point to this CPU's
 * per-CPU data structure. Must be called once during CPU initialization
 * before any other per-CPU operations.
 *
 * @param percpu  Pointer to this CPU's fut_percpu_t (from fut_percpu_data[])
 *
 * Architecture implementation:
 *   x86_64: Writes to IA32_GS_BASE MSR (0xC0000101)
 *   ARM64:  Writes to TPIDR_EL1 system register
 *   Other:  No-op (single-CPU mode uses array directly)
 *
 * Warning: This function should only be called during early CPU bring-up.
 * Calling it at runtime could corrupt per-CPU state.
 *
 * Example (in CPU init code):
 *   uint32_t cpu_idx = get_cpu_index();
 *   fut_percpu_t *percpu = &fut_percpu_data[cpu_idx];
 *   percpu->self = percpu;  // Self-pointer for validation
 *   percpu->cpu_index = cpu_idx;
 *   fut_percpu_set(percpu);
 */
static inline void fut_percpu_set(fut_percpu_t *percpu) {
#if defined(__x86_64__)
    uint64_t addr = (uint64_t)percpu;

    /* In x86_64 long mode, GS base comes from GS_BASE MSR.
     * IMPORTANT: Don't change the GS selector - just write the MSR.
     * Interrupt handlers must NOT reload GS to preserve this setup. */

    /* Write to IA32_GS_BASE MSR (0xC0000101) */
    __asm__ volatile(
        "wrmsr"
        :
        : "c"(0xC0000101), "a"((uint32_t)addr), "d"((uint32_t)(addr >> 32))
        : "memory"
    );
#elif defined(__aarch64__)
    /* ARM64: Write to TPIDR_EL1 (Thread Pointer ID Register for EL1)
     * This register is used to store the per-CPU data structure pointer.
     * It's accessible from EL1 (kernel mode) and EL0 (user mode) can have its own
     * TPIDR_EL0, but kernel uses EL1 for per-CPU access.
     */
    __asm__ volatile(
        "msr tpidr_el1, %0"
        :
        : "r"((uint64_t)percpu)
        : "memory"
    );
#else
    (void)percpu;
#endif
}

/**
 * Initialize per-CPU data for a given CPU.
 *
 * Sets up the per-CPU structure with initial values and configures the
 * architecture-specific per-CPU access mechanism (GS base on x86_64,
 * TPIDR_EL1 on ARM64).
 *
 * @param cpu_id     Hardware CPU ID (e.g., APIC ID on x86)
 * @param cpu_index  Linear CPU index (0, 1, 2, ...) used for array indexing
 *
 * This function initializes:
 *   - Self pointer for validation
 *   - CPU identification fields
 *   - Run queue (empty)
 *   - Queue lock (unlocked)
 *   - Statistics counters (zero)
 *
 * Must be called on each CPU during boot, before the scheduler starts.
 *
 * Example (BSP boot sequence):
 *   // Initialize BSP (CPU 0)
 *   fut_percpu_init(local_apic_id(), 0);
 *
 *   // Initialize APs (CPU 1+) via IPI or startup protocol
 *   for (int i = 1; i < num_cpus; i++) {
 *       // AP calls fut_percpu_init(its_apic_id, i) during its init
 *   }
 */
void fut_percpu_init(uint32_t cpu_id, uint32_t cpu_index);

/**
 * Get current CPU's hardware ID.
 *
 * Returns the hardware-specific CPU identifier (e.g., APIC ID on x86_64,
 * MPIDR on ARM64). This is useful for hardware-level operations like
 * sending IPIs.
 *
 * @return Hardware CPU ID, or 0 if per-CPU data not initialized
 *
 * Example:
 *   uint32_t target_cpu = some_thread->affinity_cpu;
 *   if (target_cpu != fut_percpu_get_cpu_id()) {
 *       send_ipi(target_cpu, IPI_RESCHEDULE);
 *   }
 */
static inline uint32_t fut_percpu_get_cpu_id(void) {
    fut_percpu_t *percpu = fut_percpu_get();
    return percpu ? percpu->cpu_id : 0;
}

/**
 * Get current CPU's linear index.
 *
 * Returns the zero-based CPU index (0, 1, 2, ...) which can be used
 * directly for array indexing. This is distinct from cpu_id which
 * may have gaps or non-sequential values.
 *
 * @return CPU index (0 to num_cpus-1), or 0 if not initialized
 *
 * Example:
 *   uint32_t idx = fut_percpu_get_cpu_index();
 *   per_cpu_stats[idx].context_switches++;
 */
static inline uint32_t fut_percpu_get_cpu_index(void) {
    fut_percpu_t *percpu = fut_percpu_get();
    return percpu ? percpu->cpu_index : 0;
}
