/* kernel/tests/perf.c - Performance Benchmarking Tests
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#include "perf.h"

#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
#include <kernel/fut_timer.h>

#include <stdatomic.h>
#include <stdbool.h>

#include "tests/test_api.h"

extern void fut_printf(const char *fmt, ...);

#ifdef DEBUG_PERF
#define PERFDBG(...) fut_printf(__VA_ARGS__)
#else
#define PERFDBG(...) do { } while (0)
#endif

#define PERF_FAIL(code_) \
    fut_test_fail((uint16_t)(((uint16_t)'P' << 8) | (uint16_t)(code_)))

/* Thread count tracking to prevent runaway thread creation */
static _Atomic uint32_t perf_thread_count = 0;

bool fut_perf_can_create_thread(void) {
    uint32_t count = atomic_load_explicit(&perf_thread_count, memory_order_acquire);
    if (count >= PERF_MAX_THREADS) {
        fut_printf("[PERF-SAFETY] Thread limit reached: %u/%u\n", count, PERF_MAX_THREADS);
        return false;
    }
    return true;
}

void fut_perf_thread_created(void) {
    uint32_t count = atomic_fetch_add_explicit(&perf_thread_count, 1, memory_order_acq_rel) + 1;
    (void)count;
    PERFDBG("[PERF-SAFETY] Thread created, count=%u\n", count);
}

void fut_perf_thread_destroyed(void) {
    uint32_t count = atomic_fetch_sub_explicit(&perf_thread_count, 1, memory_order_acq_rel) - 1;
    (void)count;
    PERFDBG("[PERF-SAFETY] Thread destroyed, count=%u\n", count);
}

uint32_t fut_perf_get_thread_count(void) {
    return atomic_load_explicit(&perf_thread_count, memory_order_acquire);
}

static void fut_perf_print_line(const char *tag, const struct fut_perf_stats *stats) {
    uint64_t p50_ns = fut_cycles_to_ns(stats->p50);
    uint64_t p90_ns = fut_cycles_to_ns(stats->p90);
    uint64_t p99_ns = fut_cycles_to_ns(stats->p99);
    fut_printf("[PERF] %s p50=%llu p90=%llu p99=%llu\n",
               tag,
               (unsigned long long)p50_ns,
               (unsigned long long)p90_ns,
               (unsigned long long)p99_ns);
}

static void fut_perf_thread(void *arg) {
    (void)arg;

    fut_printf("[PERF] Starting benchmark suite (max threads: %u)\n", PERF_MAX_THREADS);

    struct fut_perf_stats ipc_stats = {0};
    struct fut_perf_stats ctx_stats = {0};
    struct fut_perf_stats blk_read = {0};
    struct fut_perf_stats blk_write = {0};
    struct fut_perf_stats net_small = {0};
    struct fut_perf_stats net_mtu = {0};

    int rc;
    rc = fut_perf_run_ipc(&ipc_stats);
    if (rc != 0) {
        fut_printf("[PERF] ipc benchmark failed: %d\n", rc);
        PERF_FAIL(1);
        fut_perf_thread_destroyed();
        return;
    }
    fut_perf_print_line("ipc_rtt_ns", &ipc_stats);

    rc = fut_perf_run_ctx_switch(&ctx_stats);
    if (rc != 0) {
        fut_printf("[PERF] ctx-switch benchmark failed: %d\n", rc);
        PERF_FAIL(2);
        fut_perf_thread_destroyed();
        return;
    }
    fut_perf_print_line("ctx_switch_ns", &ctx_stats);

    rc = fut_perf_run_blk(&blk_read, &blk_write);
    if (rc != 0) {
        fut_printf("[PERF] block benchmark failed: %d\n", rc);
        PERF_FAIL(3);
        fut_perf_thread_destroyed();
        return;
    }
    fut_perf_print_line("blk_read_4k_ns", &blk_read);
    fut_perf_print_line("blk_write_4k_ns", &blk_write);

    rc = fut_perf_run_net(&net_small, &net_mtu);
    if (rc != 0) {
        fut_printf("[PERF] net benchmark failed: %d\n", rc);
        PERF_FAIL(4);
        fut_perf_thread_destroyed();
        return;
    }
    fut_perf_print_line("net_loop_small_ns", &net_small);
    fut_perf_print_line("net_loop_mtu_ns", &net_mtu);

    fut_printf("[PERF] All benchmarks completed successfully\n");
    fut_test_pass();
    fut_perf_thread_destroyed();
}

void fut_perf_selftest_schedule(struct fut_task *task) {
    if (!task) {
        return;
    }

    if (!fut_perf_can_create_thread()) {
        fut_printf("[PERF] Thread limit reached, cannot schedule harness\n");
        return;
    }

    fut_thread_t *thread = fut_thread_create(task,
                                             fut_perf_thread,
                                             NULL,
                                             12 * 1024,
                                             180);
    if (!thread) {
        fut_printf("[PERF] failed to schedule harness thread\n");
        return;
    }
    fut_perf_thread_created();
    fut_printf("[PERF] Harness thread scheduled\n");
}
