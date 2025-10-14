#include "perf.h"

#include <kernel/fut_memory.h>
#include <kernel/fut_thread.h>
#include <kernel/fut_waitq.h>
#include <kernel/errno.h>

#include <stdbool.h>
#include <stdint.h>

#ifdef DEBUG_PERF
#define PERFDBG(...) fut_printf(__VA_ARGS__)
#else
#define PERFDBG(...) do { } while (0)
#endif

extern void fut_printf(const char *fmt, ...);

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

    fut_thread_t *partner = fut_thread_create(task,
                                              fut_perf_ctx_partner,
                                              &ctx,
                                              8 * 1024,
                                              140);
    if (!partner) {
        return -ENOMEM;
    }

    while (!ctx.ready) {
        fut_thread_sleep(1);
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

    while (!ctx.finished) {
        fut_thread_sleep(1);
    }

    return 0;
}
