/* kernel/tests/perf_ipc.c - IPC Performance Benchmarking Tests
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#include "perf.h"

#include <kernel/fut_fipc.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
#include <kernel/kprintf.h>
#include <kernel/errno.h>

#include <stdbool.h>
#include <stdint.h>
#include <string.h>


#ifdef DEBUG_PERF
#define PERFDBG(...) fut_printf(__VA_ARGS__)
#else
#define PERFDBG(...) do { } while (0)
#endif


#define IPC_WARMUP  1000u
#define IPC_ITERS   10000u

typedef struct {
    struct fut_fipc_channel *channel;
    size_t total_iters;
    volatile bool ready;
    volatile bool error;
    volatile bool finished;
} fut_perf_ipc_peer_t;

static void fut_perf_ipc_responder(void *arg) {
    fut_perf_ipc_peer_t *ctx = (fut_perf_ipc_peer_t *)arg;
    if (!ctx) {
        fut_perf_thread_destroyed();
        return;
    }

    uint8_t buffer[sizeof(struct fut_fipc_msg) + 16];
    ctx->ready = true;

    for (size_t i = 0; i < ctx->total_iters; ++i) {
        ssize_t got = fut_fipc_recv(ctx->channel, buffer, sizeof(buffer));
        if (got < (ssize_t)sizeof(struct fut_fipc_msg)) {
            ctx->error = true;
            break;
        }
        int rc = fut_fipc_send(ctx->channel, 0xBEEF0001u, "A", 1);
        if (rc != 0) {
            ctx->error = true;
            break;
        }
    }
    ctx->finished = true;
    fut_perf_thread_destroyed();
}

int fut_perf_run_ipc(struct fut_perf_stats *out) {
    if (!out) {
        return -EINVAL;
    }

    struct fut_fipc_channel *channel = NULL;
    int rc = fut_fipc_channel_create(NULL, NULL, 4096, FIPC_CHANNEL_BLOCKING, &channel);
    if (rc != 0 || !channel) {
        return -EIO;
    }

    const size_t measure_iters = IPC_ITERS;
    const size_t total_iters = IPC_WARMUP + measure_iters;

    fut_thread_t *self = fut_thread_current();
    fut_task_t *task = self ? self->task : NULL;

    fut_perf_ipc_peer_t ctx = {
        .channel = channel,
        .total_iters = total_iters,
        .ready = false,
        .error = false,
        .finished = false,
    };

    if (!fut_perf_can_create_thread()) {
        fut_printf("[PERF-IPC] Thread limit reached, cannot create responder\n");
        fut_fipc_channel_destroy(channel);
        return -EAGAIN;
    }

    fut_thread_t *peer = fut_thread_create(task,
                                           fut_perf_ipc_responder,
                                           &ctx,
                                           8 * 1024,
                                           160);
    if (!peer) {
        fut_fipc_channel_destroy(channel);
        return -ENOMEM;
    }
    fut_perf_thread_created();

    /* Wait for responder to be ready with timeout */
    uint32_t wait_iterations = 0;
    const uint32_t max_wait_iterations = 10000;  /* ~10 seconds at 1ms per iteration */
    while (!ctx.ready && wait_iterations < max_wait_iterations) {
        fut_thread_sleep(1);
        wait_iterations++;
    }
    if (!ctx.ready) {
        fut_printf("[PERF-IPC] Timeout waiting for responder ready\n");
        fut_fipc_channel_destroy(channel);
        return -ETIMEDOUT;
    }

    uint64_t *samples = (uint64_t *)fut_malloc(sizeof(uint64_t) * measure_iters);
    if (!samples) {
        fut_fipc_channel_destroy(channel);
        return -ENOMEM;
    }

    uint8_t buffer[sizeof(struct fut_fipc_msg) + 16];

    for (size_t i = 0; i < IPC_WARMUP; ++i) {
        rc = fut_fipc_send(channel, 0xBEEF0000u, "W", 1);
        if (rc != 0) {
            fut_free(samples);
            fut_fipc_channel_destroy(channel);
            return rc;
        }
        ssize_t got = fut_fipc_recv(channel, buffer, sizeof(buffer));
        if (got < (ssize_t)sizeof(struct fut_fipc_msg)) {
            fut_free(samples);
            fut_fipc_channel_destroy(channel);
            return -EIO;
        }
    }

    for (size_t i = 0; i < measure_iters; ++i) {
        uint64_t start = fut_rdtsc();
        rc = fut_fipc_send(channel, 0xBEEF1000u, &i, sizeof(i));
        if (rc != 0) {
            fut_free(samples);
            fut_fipc_channel_destroy(channel);
            return rc;
        }
        ssize_t got = fut_fipc_recv(channel, buffer, sizeof(buffer));
        if (got < (ssize_t)sizeof(struct fut_fipc_msg)) {
            fut_free(samples);
            fut_fipc_channel_destroy(channel);
            return -EIO;
        }
        uint64_t end = fut_rdtsc();
        samples[i] = end - start;
    }

    fut_perf_sort(samples, measure_iters);
    fut_perf_compute_stats(samples, measure_iters, out);

    fut_free(samples);

    /* Wait for responder to finish with timeout */
    wait_iterations = 0;
    while (!ctx.finished && wait_iterations < max_wait_iterations) {
        fut_thread_sleep(1);
        wait_iterations++;
    }
    if (!ctx.finished) {
        fut_printf("[PERF-IPC] Timeout waiting for responder finish\n");
        fut_fipc_channel_destroy(channel);
        return -ETIMEDOUT;
    }

    fut_fipc_channel_destroy(channel);

    if (ctx.error) {
        return -EIO;
    }
    return 0;
}
