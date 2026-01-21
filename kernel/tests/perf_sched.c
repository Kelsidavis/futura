/* kernel/tests/perf_sched.c - Scheduler Performance Benchmarking Tests
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#include "perf.h"

#include <kernel/fut_memory.h>
#include <kernel/fut_thread.h>
#include <kernel/fut_waitq.h>
#include <kernel/kprintf.h>
#include <kernel/errno.h>

#include <stdbool.h>
#include <stdint.h>


#ifdef DEBUG_PERF
#define PERFDBG(...) fut_printf(__VA_ARGS__)
#else
#define PERFDBG(...) do { } while (0)
#endif


#define CTX_WARMUP  1000u
#define CTX_ITERS   10000u

typedef struct {
    fut_waitq_t wait_a;
    fut_waitq_t wait_b;
    fut_spinlock_t lock_a;
    fut_spinlock_t lock_b;
    size_t total_iters;
    volatile bool ready;
    volatile bool finished;
} fut_perf_ctx_t;

static void fut_perf_ctx_partner(void *arg) {
    fut_perf_ctx_t *ctx = (fut_perf_ctx_t *)arg;
    if (!ctx) {
        fut_perf_thread_destroyed();
        return;
    }

    ctx->ready = true;

    for (size_t i = 0; i < ctx->total_iters; ++i) {
        fut_spinlock_acquire(&ctx->lock_b);
        fut_waitq_sleep_locked(&ctx->wait_b, &ctx->lock_b, FUT_THREAD_BLOCKED);

        fut_spinlock_acquire(&ctx->lock_a);
        fut_waitq_wake_one(&ctx->wait_a);
        fut_spinlock_release(&ctx->lock_a);
    }

    ctx->finished = true;
    fut_perf_thread_destroyed();
}

static void fut_perf_ctx_ping(fut_perf_ctx_t *ctx) {
    fut_spinlock_acquire(&ctx->lock_b);
    fut_waitq_wake_one(&ctx->wait_b);
    fut_spinlock_release(&ctx->lock_b);

    fut_spinlock_acquire(&ctx->lock_a);
    fut_waitq_sleep_locked(&ctx->wait_a, &ctx->lock_a, FUT_THREAD_BLOCKED);
}

int fut_perf_run_ctx_switch(struct fut_perf_stats *out) {
    if (!out) {
        return -EINVAL;
    }

    fut_perf_ctx_t ctx;
    fut_waitq_init(&ctx.wait_a);
    fut_waitq_init(&ctx.wait_b);
    fut_spinlock_init(&ctx.lock_a);
    fut_spinlock_init(&ctx.lock_b);
    ctx.total_iters = CTX_WARMUP + CTX_ITERS;
    ctx.ready = false;
    ctx.finished = false;

    fut_thread_t *self = fut_thread_current();
    fut_task_t *task = self ? self->task : NULL;

    if (!fut_perf_can_create_thread()) {
        fut_printf("[PERF-SCHED] Thread limit reached, cannot create partner\n");
        return -EAGAIN;
    }

    fut_thread_t *partner = fut_thread_create(task,
                                              fut_perf_ctx_partner,
                                              &ctx,
                                              8 * 1024,
                                              140);
    if (!partner) {
        return -ENOMEM;
    }
    fut_perf_thread_created();

    /* Wait for partner to be ready with timeout */
    uint32_t wait_iterations = 0;
    const uint32_t max_wait_iterations = 10000;  /* ~10 seconds at 1ms per iteration */
    while (!ctx.ready && wait_iterations < max_wait_iterations) {
        fut_thread_sleep(1);
        wait_iterations++;
    }
    if (!ctx.ready) {
        fut_printf("[PERF-SCHED] Timeout waiting for partner ready\n");
        return -ETIMEDOUT;
    }

    uint64_t *samples = (uint64_t *)fut_malloc(sizeof(uint64_t) * CTX_ITERS);
    if (!samples) {
        return -ENOMEM;
    }

    for (size_t i = 0; i < CTX_WARMUP; ++i) {
        fut_perf_ctx_ping(&ctx);
    }

    for (size_t i = 0; i < CTX_ITERS; ++i) {
        uint64_t start = fut_rdtsc();
        fut_perf_ctx_ping(&ctx);
        uint64_t end = fut_rdtsc();
        samples[i] = end - start;
    }

    fut_perf_sort(samples, CTX_ITERS);
    fut_perf_compute_stats(samples, CTX_ITERS, out);
    fut_free(samples);

    /* Wait for partner to finish with timeout */
    wait_iterations = 0;
    while (!ctx.finished && wait_iterations < max_wait_iterations) {
        fut_thread_sleep(1);
        wait_iterations++;
    }
    if (!ctx.finished) {
        fut_printf("[PERF-SCHED] Timeout waiting for partner finish\n");
        return -ETIMEDOUT;
    }

    return 0;
}
