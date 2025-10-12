// SPDX-License-Identifier: MPL-2.0
// fipc_sys_kernel_metrics.c - Validate system metrics dual publishers

#define _POSIX_C_SOURCE 200809L

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include <kernel/fut_fipc.h>
#include <kernel/fut_fipc_sys.h>
#include <kernel/fut_memory.h>

#include "../src/user/netd/netd_core.h"
#include "../src/user/sys/fipc_sys.h"
#include "../src/user/sys/fipc_idlv0_codegen.h"

#define FIPC_IDL_TABLE_SYS(M) \
    M(FIPC_SYS_T_LOOKUP_ATT, lookup_attempts) \
    M(FIPC_SYS_T_LOOKUP_HIT, lookup_hits) \
    M(FIPC_SYS_T_TX_FRAMES, tx_frames)

FIPC_IDL_DEF_STRUCT(sys_view, FIPC_IDL_TABLE_SYS)
FIPC_IDL_DEF_DECODE_BOUNDED(sys_view, FIPC_IDL_TABLE_SYS, FIPC_SYS_T_METRIC_BEGIN, FIPC_SYS_T_METRIC_END)

#define FIPC_IDL_TABLE_KERNEL(M) \
    M(FIPC_SYS_K_PMM_TOTAL, pmm_total) \
    M(FIPC_SYS_K_PMM_FREE, pmm_free) \
    M(FIPC_SYS_K_FIPC_CHANNELS, channels)

FIPC_IDL_DEF_STRUCT(kernel_view, FIPC_IDL_TABLE_KERNEL)
FIPC_IDL_DEF_DECODE_BOUNDED(kernel_view, FIPC_IDL_TABLE_KERNEL, FIPC_SYS_K_METRIC_BEGIN, FIPC_SYS_K_METRIC_END)

static int recv_once(struct fut_fipc_channel *channel, uint8_t *buffer, size_t capacity) {
    for (int i = 0; i < 256; ++i) {
        ssize_t rc = fut_fipc_recv(channel, buffer, capacity);
        if (rc > 0) {
            return (int)rc;
        }
        if (rc < 0 && rc != FIPC_EAGAIN) {
            return -1;
        }
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 1 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    return -1;
}

int main(void) {
    fut_fipc_init();

    struct fut_fipc_channel *sys_channel = fut_fipc_channel_lookup(FIPC_SYS_CHANNEL_ID);
    if (!sys_channel) {
        if (fut_fipc_channel_create(NULL, NULL, 4096, FIPC_CHANNEL_NONBLOCKING, &sys_channel) != 0) {
            fprintf(stderr, "[SYSK] failed to prepare system channel\n");
            return 1;
        }
        sys_channel->id = FIPC_SYS_CHANNEL_ID;
        sys_channel->type = FIPC_CHANNEL_SYSTEM;
    }

    struct netd *nd = netd_bootstrap("127.0.0.1", 29600);
    if (!nd) {
        fprintf(stderr, "[SYSK] netd bootstrap failed\n");
        return 1;
    }

    if (!fipc_sys_publish_metrics(nd)) {
        fprintf(stderr, "[SYSK] system metrics publish failed\n");
        netd_shutdown(nd);
        return 1;
    }

    if (fut_fipc_publish_kernel_metrics() != 0) {
        fprintf(stderr, "[SYSK] kernel metrics publish failed\n");
        netd_shutdown(nd);
        return 1;
    }

    uint8_t buffer[256];

    int bytes = recv_once(sys_channel, buffer, sizeof(buffer));
    if (bytes <= 0) {
        fprintf(stderr, "[SYSK] failed to receive system metrics frame\n");
        netd_shutdown(nd);
        return 1;
    }

    struct fut_fipc_msg *msg = (struct fut_fipc_msg *)buffer;
    if (msg->type != FIPC_SYS_MSG_SYSTEM_METRICS) {
        fprintf(stderr, "[SYSK] unexpected message type 0x%x\n", msg->type);
        netd_shutdown(nd);
        return 1;
    }

    sys_view sys_metrics;
    if (sys_view_decode(msg->payload, msg->length, &sys_metrics) != 0) {
        fprintf(stderr, "[SYSK] failed to decode system metrics record\n");
        netd_shutdown(nd);
        return 1;
    }

    bytes = recv_once(sys_channel, buffer, sizeof(buffer));
    if (bytes <= 0) {
        fprintf(stderr, "[SYSK] failed to receive kernel metrics frame\n");
        netd_shutdown(nd);
        return 1;
    }

    msg = (struct fut_fipc_msg *)buffer;
    if (msg->type != FIPC_SYS_MSG_KERNEL_METRICS) {
        fprintf(stderr, "[SYSK] unexpected kernel message type 0x%x\n", msg->type);
        netd_shutdown(nd);
        return 1;
    }

    kernel_view kernel_metrics;
    if (kernel_view_decode(msg->payload, msg->length, &kernel_metrics) != 0) {
        fprintf(stderr, "[SYSK] failed to decode kernel metrics record\n");
        netd_shutdown(nd);
        return 1;
    }

    uint64_t expected_pmm_total = fut_pmm_total_pages();
    uint64_t expected_pmm_free = fut_pmm_free_pages();
    if (kernel_metrics.pmm_total != expected_pmm_total ||
        kernel_metrics.pmm_free != expected_pmm_free) {
        fprintf(stderr, "[SYSK] kernel metrics unexpected values (pmm_total=%llu expected %llu, pmm_free=%llu expected %llu)\n",
                (unsigned long long)kernel_metrics.pmm_total,
                (unsigned long long)expected_pmm_total,
                (unsigned long long)kernel_metrics.pmm_free,
                (unsigned long long)expected_pmm_free);
        netd_shutdown(nd);
        return 1;
    }

    uint64_t expected_channels = fut_fipc_channel_count();
    if (kernel_metrics.channels != expected_channels) {
        fprintf(stderr, "[SYSK] channel count mismatch (got %llu expected %llu)\n",
                (unsigned long long)kernel_metrics.channels,
                (unsigned long long)expected_channels);
        netd_shutdown(nd);
        return 1;
    }

    netd_shutdown(nd);
    printf("[SYSK] kernel+netd system metrics decoded — PASS\n");
    return 0;
}
