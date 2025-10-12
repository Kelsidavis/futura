// SPDX-License-Identifier: MPL-2.0
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include <kernel/fut_fipc.h>

static double timespec_diff(const struct timespec *start,
                            const struct timespec *end) {
    double sec = (double)(end->tv_sec - start->tv_sec);
    double nsec = (double)(end->tv_nsec - start->tv_nsec) / 1e9;
    return sec + nsec;
}

static int fill_channel(struct fut_fipc_channel *ch,
                        uint32_t type,
                        size_t payload_len,
                        size_t count) {
    uint8_t payload[16] = {0};
    for (size_t i = 0; i < payload_len && i < sizeof(payload); ++i) {
        payload[i] = (uint8_t)i;
    }
    for (size_t i = 0; i < count; ++i) {
        if (fut_fipc_send(ch, type, payload, payload_len) != 0) {
            fprintf(stderr, "[BATCH] failed to populate channel\n");
            return -1;
        }
    }
    return 0;
}

int main(void) {
    fut_fipc_init();

    struct fut_fipc_channel *ch = NULL;
    if (fut_fipc_channel_create(NULL, NULL, 8 * 1024 * 1024, FIPC_CHANNEL_NONBLOCKING, &ch) != 0 || !ch) {
        fprintf(stderr, "[BATCH] channel create failed\n");
        return 1;
    }

    const size_t total_msgs = 100000;
    const uint32_t type = 0xC001u;
    const size_t payload_len = 8;

    if (fill_channel(ch, type, payload_len, total_msgs) != 0) {
        fut_fipc_channel_destroy(ch);
        return 1;
    }

    uint8_t single_buf[128];
    size_t single_received = 0;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    while (single_received < total_msgs) {
        ssize_t r = fut_fipc_recv(ch, single_buf, sizeof(single_buf));
        if (r > 0) {
            single_received++;
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double single_time = timespec_diff(&t0, &t1);
    double single_rate = (double)total_msgs / (single_time > 0 ? single_time : 1e-9);

    if (fill_channel(ch, type, payload_len, total_msgs) != 0) {
        fut_fipc_channel_destroy(ch);
        return 1;
    }

    uint8_t batch_buf[64 * 1024];
    size_t offsets[1024];
    size_t lengths[1024];
    size_t batch_received = 0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    while (batch_received < total_msgs) {
        int rc = fut_fipc_recv_batch(ch,
                                     batch_buf,
                                     sizeof(batch_buf),
                                     offsets,
                                     lengths,
                                     1024);
        if (rc == FIPC_EAGAIN) {
            continue;
        }
        if (rc < 0) {
            fprintf(stderr, "[BATCH] recv_batch failed (%d)\n", rc);
            return 1;
        }
        batch_received += (size_t)rc;
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double batch_time = timespec_diff(&t0, &t1);
    double batch_rate = (double)total_msgs / (batch_time > 0 ? batch_time : 1e-9);

    printf("[BATCH] single=%.2f msgs/s, batch=%.2f msgs/s\n",
           single_rate, batch_rate);

    fut_fipc_channel_destroy(ch);

    if (batch_rate < single_rate * 1.2) {
        fprintf(stderr, "[BATCH] improvement below expectation (need >=20%%)\n");
        return 1;
    }

    printf("[BATCH] batch receive speedup ≥20%% — PASS\n");
    return 0;
}
