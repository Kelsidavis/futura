/* fipc_sys_pub_kernelshim.c - Host shim publisher for kernel metrics
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides a placeholder set of kernel counters and publishes them over
 * the system metrics FIPC channel using the IDL-v0 encoding.
 */

#include "fipc_sys.h"

#include <stdbool.h>
#include <stddef.h>

#include <kernel/fut_fipc.h>
#include <kernel/fut_fipc_sys.h>

struct fipc_sys_kernel_snapshot {
    uint64_t pmm_pages_total;
    uint64_t pmm_pages_free;
    uint64_t fipc_channels;
};

static struct fut_fipc_channel *fipc_sys_get_or_create_channel(void) {
    struct fut_fipc_channel *channel = fut_fipc_channel_lookup(FIPC_SYS_CHANNEL_ID);
    if (channel) {
        return channel;
    }

    if (fut_fipc_channel_create(NULL,
                                NULL,
                                4096,
                                FIPC_CHANNEL_NONBLOCKING,
                                &channel) != 0 || !channel) {
        return NULL;
    }

    channel->id = FIPC_SYS_CHANNEL_ID;
    channel->type = FIPC_CHANNEL_SYSTEM;
    return channel;
}

static void fipc_sys_kernel_snapshot(struct fipc_sys_kernel_snapshot *out) {
    if (!out) {
        return;
    }

    out->pmm_pages_total = 1024; /* TODO: wire to real PMM accounting */
    out->pmm_pages_free = 512;
    out->fipc_channels = fut_fipc_channel_count();
}

bool fipc_sys_publish_kernel_metrics(void) {
    struct fut_fipc_channel *channel = fipc_sys_get_or_create_channel();
    if (!channel) {
        return false;
    }

    struct fipc_sys_kernel_snapshot snapshot;
    fipc_sys_kernel_snapshot(&snapshot);

    uint8_t buffer[128];
    uint8_t *cursor = buffer;
    const uint8_t *const end = buffer + sizeof(buffer);

    if (cursor >= end) {
        return false;
    }
    *cursor++ = FIPC_SYS_K_METRIC_BEGIN;

#define FIPC_SYS_WRITE(tag, value)                                      \
    do {                                                                \
        if ((size_t)(end - cursor) < 11) {                              \
            return false;                                               \
        }                                                               \
        *cursor++ = (uint8_t)(tag);                                     \
        cursor = fipc_sys_varint_u64(cursor, (uint64_t)(value));        \
        if (cursor > end) {                                             \
            return false;                                               \
        }                                                               \
    } while (0)

    FIPC_SYS_WRITE(FIPC_SYS_K_PMM_TOTAL, snapshot.pmm_pages_total);
    FIPC_SYS_WRITE(FIPC_SYS_K_PMM_FREE, snapshot.pmm_pages_free);
    FIPC_SYS_WRITE(FIPC_SYS_K_FIPC_CHANNELS, snapshot.fipc_channels);

#undef FIPC_SYS_WRITE

    if (cursor >= end) {
        return false;
    }
    *cursor++ = FIPC_SYS_K_METRIC_END;

    size_t payload_len = (size_t)(cursor - buffer);

    return fut_fipc_channel_inject(channel,
                                   FIPC_SYS_MSG_KERNEL_METRICS,
                                   buffer,
                                   payload_len,
                                   0,
                                   0,
                                   0) == 0;
}
