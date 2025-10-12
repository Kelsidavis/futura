/* fipc_sys_pub.c - System metrics publisher
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#include "fipc_sys.h"

#include <kernel/fut_fipc.h>
#include <kernel/fut_fipc_sys.h>

#include "../netd/netd_core.h"

static struct fut_fipc_channel *ensure_system_channel(void) {
    struct fut_fipc_channel *channel = fut_fipc_channel_lookup(FIPC_SYS_CHANNEL_ID);
    if (channel) {
        return channel;
    }

    if (fut_fipc_channel_create(NULL,
                                NULL,
                                4096,
                                FIPC_CHANNEL_NONBLOCKING,
                                &channel) != 0) {
        return NULL;
    }

    channel->id = FIPC_SYS_CHANNEL_ID;
    channel->type = FIPC_CHANNEL_SYSTEM;
    return channel;
}

bool fipc_sys_publish_metrics(struct netd *nd) {
    if (!nd) {
        return false;
    }

    struct fut_fipc_channel *sys_channel = ensure_system_channel();
    if (!sys_channel) {
        return false;
    }

    struct netd_metrics metrics;
    if (!netd_metrics_snapshot(nd, &metrics)) {
        return false;
    }

    uint8_t buffer[256];
    uint8_t *cursor = buffer;
    const uint8_t *end = buffer + sizeof(buffer);

    if (cursor >= end) {
        return false;
    }
    *cursor++ = FIPC_SYS_T_METRIC_BEGIN;

#define FIPC_SYS_EMIT(tag, value) \
    do { \
        if (cursor >= end) { \
            return false; \
        } \
        *cursor++ = (uint8_t)(tag); \
        cursor = fipc_sys_varint_u64(cursor, (uint64_t)(value)); \
        if (cursor > end) { \
            return false; \
        } \
    } while (0)

    FIPC_SYS_EMIT(FIPC_SYS_T_LOOKUP_ATT, metrics.lookup_attempts);
    FIPC_SYS_EMIT(FIPC_SYS_T_LOOKUP_HIT, metrics.lookup_hits);
    FIPC_SYS_EMIT(FIPC_SYS_T_LOOKUP_MISS, metrics.lookup_miss);
    FIPC_SYS_EMIT(FIPC_SYS_T_SEND_EAGAIN, metrics.send_eagain);
    FIPC_SYS_EMIT(FIPC_SYS_T_TX_FRAMES, metrics.tx_frames);
    FIPC_SYS_EMIT(FIPC_SYS_T_TX_BLK_CRED, metrics.tx_blocked_credits);
    FIPC_SYS_EMIT(FIPC_SYS_T_AUTH_FAIL, metrics.auth_fail);
    FIPC_SYS_EMIT(FIPC_SYS_T_REPLAY_DROP, metrics.replay_drop);

#undef FIPC_SYS_EMIT

    if (cursor >= end) {
        return false;
    }
    *cursor++ = FIPC_SYS_T_METRIC_END;

    size_t payload_len = (size_t)(cursor - buffer);

    return fut_fipc_channel_inject(sys_channel,
                                   FIPC_SYS_MSG_SYSTEM_METRICS,
                                   buffer,
                                   payload_len,
                                   0,
                                   0,
                                   0) == 0;
}
