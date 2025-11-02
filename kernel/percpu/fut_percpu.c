/* fut_percpu.c - Per-CPU data implementation
 *
 * Copyright (c) 2025 Kelsi Davis / Licensed under the MPL v2.0 — see LICENSE for details
 */

#include "../../include/kernel/fut_percpu.h"
#include <string.h>

extern void fut_printf(const char *fmt, ...);

/* Array of per-CPU data structures */
fut_percpu_t fut_percpu_data[FUT_MAX_CPUS] __attribute__((aligned(64)));

/**
 * Initialize per-CPU data for a given CPU.
 */
void fut_percpu_init(uint32_t cpu_id, uint32_t cpu_index) {
    if (cpu_index >= FUT_MAX_CPUS) {
        fut_printf("[PERCPU] ERROR: CPU index %u exceeds FUT_MAX_CPUS\n", cpu_index);
        return;
    }

    fut_percpu_t *percpu = &fut_percpu_data[cpu_index];

    /* Clear the structure */
    memset(percpu, 0, sizeof(fut_percpu_t));

    /* Initialize fields */
    percpu->cpu_id = cpu_id;
    percpu->cpu_index = cpu_index;
    percpu->current_thread = NULL;
    percpu->idle_thread = NULL;
    percpu->self = percpu;

    /* Initialize per-CPU ready queue */
    percpu->ready_queue_head = NULL;
    percpu->ready_queue_tail = NULL;
    percpu->ready_count = 0;

    /* Initialize per-CPU lock */
    extern void fut_spinlock_init(fut_spinlock_t *lock);
    fut_spinlock_init(&percpu->queue_lock);

    /* Minimal output - just confirm initialization */
    fut_printf("[PERCPU] CPU %u ready\n", cpu_id);
}
