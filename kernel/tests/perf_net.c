/* kernel/tests/perf_net.c - Network Performance Benchmarking Tests
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#include "perf.h"

#include <futura/net.h>

#include <kernel/errno.h>
#include <kernel/fut_memory.h>

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#ifdef DEBUG_PERF
#define PERFDBG(...) fut_printf(__VA_ARGS__)
#else
#define PERFDBG(...) do { } while (0)
#endif

#include <kernel/kprintf.h>

#define NET_WARMUP_SMALL 32u
#define NET_ITERS_SMALL  256u
#define NET_WARMUP_MTU   16u
#define NET_ITERS_MTU    64u

static int fut_perf_net_series(fut_socket_t *socket,
                               const uint8_t *payload,
                               size_t payload_len,
                               size_t warmup,
                               size_t iters,
                               uint64_t *samples) {
    uint8_t rx_buf[FUT_NET_DEFAULT_MTU + 32];

    for (size_t i = 0; i < warmup; ++i) {
        int rc = fut_net_send(socket, payload, payload_len);
        if (rc != 0) {
            return rc;
        }
        size_t recv_bytes = 0;
        rc = fut_net_recv_timed(socket, rx_buf, sizeof(rx_buf), &recv_bytes, FUT_NET_RECV_TIMEOUT_MS);
        if (rc != 0 || recv_bytes != payload_len) {
            return rc ? rc : -EIO;
        }
    }

    for (size_t i = 0; i < iters; ++i) {
        uint64_t start = fut_rdtsc();
        int rc = fut_net_send(socket, payload, payload_len);
        if (rc != 0) {
            return rc;
        }
        size_t recv_bytes = 0;
        rc = fut_net_recv_timed(socket, rx_buf, sizeof(rx_buf), &recv_bytes, FUT_NET_RECV_TIMEOUT_MS);
        if (rc != 0 || recv_bytes != payload_len) {
            return rc ? rc : -EIO;
        }
        uint64_t end = fut_rdtsc();
        samples[i] = end - start;
    }
    return 0;
}

int fut_perf_run_net(struct fut_perf_stats *small_stats,
                     struct fut_perf_stats *mtu_stats) {
    if (!small_stats || !mtu_stats) {
        return -EINVAL;
    }

    fut_socket_t *listener = NULL;
    fut_status_t rc = fut_net_listen(0, &listener);
    if (rc != 0 || !listener) {
        return -EIO;
    }

    fut_socket_t *socket = NULL;
    rc = fut_net_accept(listener, &socket);
    if (rc != 0 || !socket) {
        fut_net_close(listener);
        return -EIO;
    }

    uint8_t small_payload[64];
    memset(small_payload, 0x5A, sizeof(small_payload));

    uint8_t mtu_payload[FUT_NET_DEFAULT_MTU - 4];
    memset(mtu_payload, 0xA5, sizeof(mtu_payload));

    uint64_t *small_samples = (uint64_t *)fut_malloc(sizeof(uint64_t) * NET_ITERS_SMALL);
    uint64_t *mtu_samples = (uint64_t *)fut_malloc(sizeof(uint64_t) * NET_ITERS_MTU);
    if (!small_samples || !mtu_samples) {
        if (small_samples) fut_free(small_samples);
        if (mtu_samples) fut_free(mtu_samples);
        fut_net_close(socket);
        fut_net_close(listener);
        return -ENOMEM;
    }

    rc = fut_perf_net_series(socket,
                             small_payload,
                             sizeof(small_payload),
                             NET_WARMUP_SMALL,
                             NET_ITERS_SMALL,
                             small_samples);
    if (rc != 0) {
        fut_free(small_samples);
        fut_free(mtu_samples);
        fut_net_close(socket);
        fut_net_close(listener);
        return rc;
    }

    rc = fut_perf_net_series(socket,
                             mtu_payload,
                             sizeof(mtu_payload),
                             NET_WARMUP_MTU,
                             NET_ITERS_MTU,
                             mtu_samples);
    if (rc != 0) {
        fut_free(small_samples);
        fut_free(mtu_samples);
        fut_net_close(socket);
        fut_net_close(listener);
        return rc;
    }

    fut_perf_sort(small_samples, NET_ITERS_SMALL);
    fut_perf_sort(mtu_samples, NET_ITERS_MTU);
    fut_perf_compute_stats(small_samples, NET_ITERS_SMALL, small_stats);
    fut_perf_compute_stats(mtu_samples, NET_ITERS_MTU, mtu_stats);

    fut_free(small_samples);
    fut_free(mtu_samples);
    fut_net_close(socket);
    fut_net_close(listener);

    return 0;
}
