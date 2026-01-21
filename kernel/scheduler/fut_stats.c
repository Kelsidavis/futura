/* fut_stats.c - Futura OS Performance Instrumentation Implementation
 *
 * Copyright (c) 2025 Kelsi Davis / Licensed under the MPL v2.0 — see LICENSE for details
 *
 * Tracks per-thread CPU usage and context switch frequency.
 */

#include "../../include/kernel/fut_stats.h"
#include "../../include/kernel/fut_thread.h"
#include "../../include/kernel/fut_task.h"

/* External dependencies */
#include <kernel/kprintf.h>
extern fut_thread_t *fut_thread_current(void);

/* Global statistics */
static fut_global_stats_t global_stats = {0};

/**
 * Initialize the statistics subsystem.
 */
void fut_stats_init(void) {
    global_stats.total_context_switches = 0;
    global_stats.total_cpu_ticks = 0;
    global_stats.start_tick = 0;
}

/**
 * Record a context switch from prev to next.
 * Called by scheduler during every context switch.
 */
void fut_stats_record_switch(fut_thread_t *prev, fut_thread_t *next) {
    uint64_t now = global_stats.total_cpu_ticks;

    /* Update previous thread's CPU time */
    if (prev && fut_thread_current() == prev) {
        uint64_t delta = now - prev->stats.last_scheduled_tick;
        prev->stats.cpu_ticks += delta;
    }

    /* Increment next thread's context switch count */
    if (next) {
        next->stats.context_switches++;
        next->stats.last_scheduled_tick = now;
    }

    /* Update global counter */
    global_stats.total_context_switches++;
}

/**
 * Update tick count (called from timer IRQ).
 */
void fut_stats_tick(void) {
    global_stats.total_cpu_ticks++;

    /* Attribute this tick to the currently running thread */
    if (fut_thread_current()) {
        /* Tick attribution happens at context switch, not here */
        /* This avoids double-counting ticks */
    }
}

/**
 * Get current tick count.
 */
uint64_t fut_stats_get_ticks(void) {
    return global_stats.total_cpu_ticks;
}

/**
 * Reset all statistics counters to zero.
 */
void fut_stats_reset(void) {
    global_stats.total_context_switches = 0;
    global_stats.total_cpu_ticks = 0;
    global_stats.start_tick = 0;
}

/**
 * Helper: 64-bit division (avoids libgcc __udivdi3 dependency).
 * Uses shift-and-subtract algorithm.
 */
static uint64_t div64(uint64_t dividend, uint64_t divisor) {
    if (divisor == 0) return 0;
    if (divisor == 1) return dividend;
    if (dividend < divisor) return 0;

    uint64_t quotient = 0;
    uint64_t remainder = dividend;

    /* Find highest set bit in divisor */
    int shift = 0;
    uint64_t temp = divisor;
    while (temp < remainder) {
        temp <<= 1;
        shift++;
    }

    /* Perform division by repeated subtraction */
    for (int i = shift; i >= 0; i--) {
        uint64_t shifted_divisor = divisor << i;
        if (remainder >= shifted_divisor) {
            remainder -= shifted_divisor;
            quotient |= (1ULL << i);
        }
    }

    return quotient;
}

/**
 * Helper: Get thread name for display.
 */
static const char *get_thread_name(fut_thread_t *thread) {
    if (!thread) return "NULL";

    /* Idle thread detection */
    if (thread->priority == 255) return "IDLE";

    /* Test threads A/B/C heuristic (TID 2/3/4) */
    if (thread->tid == 2) return "A";
    if (thread->tid == 3) return "B";
    if (thread->tid == 4) return "C";

    /* Fallback: TID_N */
    static char tid_buf[16];
    fut_printf("TID_%u", thread->tid);
    return tid_buf;
}

/**
 * Dump comprehensive scheduler statistics to serial console.
 */
void fut_debug_dump_stats(void) {
    uint64_t total_ticks = global_stats.total_cpu_ticks;
    uint64_t total_switches = global_stats.total_context_switches;

    fut_printf("\n");
    fut_printf("========================================\n");
    fut_printf("  Scheduler Telemetry Report\n");
    fut_printf("========================================\n");
    fut_printf("\n");

    /* Global statistics */
    fut_printf("[GLOBAL STATS]\n");
    fut_printf("  Total CPU Ticks:      %llu\n", total_ticks);
    fut_printf("  Total Context Switches: %llu\n", total_switches);
    if (total_ticks > 0 && total_switches > 0) {
        uint64_t avg_quantum = div64(total_ticks, total_switches);
        fut_printf("  Avg Quantum Duration: %llu ticks\n", avg_quantum);
    }
    fut_printf("\n");

    /* Per-thread statistics */
    fut_printf("[PER-THREAD STATS]\n");
    fut_printf("%-8s %12s %12s %8s %12s\n",
              "Thread", "Switches", "CPU Ticks", "CPU %", "Avg Quantum");
    fut_printf("------------------------------------------------------------\n");

    /* Walk all tasks and their threads */
    extern fut_task_t *fut_task_list;
    for (fut_task_t *task = fut_task_list; task != NULL; task = task->next) {
        for (fut_thread_t *t = task->threads; t != NULL; t = t->next) {
        uint64_t switches = t->stats.context_switches;
        uint64_t ticks = t->stats.cpu_ticks;

        /* Calculate CPU percentage (with 2 decimal places) */
        uint32_t cpu_pct_int = 0;
        uint32_t cpu_pct_frac = 0;
        if (total_ticks > 0) {
            cpu_pct_int = (uint32_t)div64(ticks * 100, total_ticks);
            cpu_pct_frac = (uint32_t)div64(ticks * 10000, total_ticks) % 100;
        }

        /* Calculate average quantum duration */
        uint64_t avg_quantum = switches > 0 ? div64(ticks, switches) : 0;

        /* Print thread stats */
        fut_printf("%-8s %12llu %12llu %3u.%02u%% %12llu\n",
                  get_thread_name(t),
                  switches,
                  ticks,
                  cpu_pct_int,
                  cpu_pct_frac,
                  avg_quantum);
        }
    }

    fut_printf("\n");
    fut_printf("========================================\n");
    fut_printf("\n");
}
