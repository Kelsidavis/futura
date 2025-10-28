/* fut_percpu.h - Per-CPU data structures for SMP support
 *
 * Copyright (c) 2025 Kelsi Davis / Licensed under the MPL v2.0 — see LICENSE for details
 *
 * Provides per-CPU storage for scheduler and thread state.
 * On x86_64, uses GS segment base to access per-CPU data.
 */

#pragma once

#include <stdint.h>
#include <stdatomic.h>

/* Forward declarations */
struct fut_thread;
struct fut_task;

/* Spinlock for synchronization */
#include "fut_sched.h"

/* Maximum supported CPUs */
#define FUT_MAX_CPUS 256

/**
 * Per-CPU data structure.
 * Accessed via GS-relative addressing on x86_64.
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

    /* Padding to cache line (64 bytes total: 8+4+4+40+8 = 64, so no padding needed) */
} __attribute__((aligned(64))) fut_percpu_t;

/* Array of per-CPU data structures (one per CPU) */
extern fut_percpu_t fut_percpu_data[FUT_MAX_CPUS];

/**
 * Get pointer to current CPU's per-CPU data.
 * Uses GS segment base on x86_64.
 */
static inline fut_percpu_t *fut_percpu_get(void) {
#if defined(__x86_64__)
    fut_percpu_t *percpu;
    __asm__ volatile("mov %%gs:0, %0" : "=r"(percpu));
    return percpu;
#elif defined(__aarch64__)
    /* ARM64: Use TPIDR_EL1 or similar */
    #error "ARM64 per-CPU not yet implemented"
#else
    /* Fallback to single CPU */
    return &fut_percpu_data[0];
#endif
}

/**
 * Set GS base to point to per-CPU data for the current CPU.
 */
static inline void fut_percpu_set(fut_percpu_t *percpu) {
#if defined(__x86_64__)
    /* Write to IA32_GS_BASE MSR (0xC0000101) */
    uint64_t addr = (uint64_t)percpu;
    __asm__ volatile(
        "wrmsr"
        :
        : "c"(0xC0000101), "a"((uint32_t)addr), "d"((uint32_t)(addr >> 32))
        : "memory"
    );
#elif defined(__aarch64__)
    #error "ARM64 per-CPU not yet implemented"
#else
    (void)percpu;
#endif
}

/**
 * Initialize per-CPU data for a given CPU.
 */
void fut_percpu_init(uint32_t cpu_id, uint32_t cpu_index);

/**
 * Get current CPU's ID.
 */
static inline uint32_t fut_percpu_get_cpu_id(void) {
    fut_percpu_t *percpu = fut_percpu_get();
    return percpu ? percpu->cpu_id : 0;
}

/**
 * Get current CPU's index.
 */
static inline uint32_t fut_percpu_get_cpu_index(void) {
    fut_percpu_t *percpu = fut_percpu_get();
    return percpu ? percpu->cpu_index : 0;
}
