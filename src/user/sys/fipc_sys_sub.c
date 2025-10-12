/* fipc_sys_sub.c - System metrics consumer utilities
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#include "fipc_sys.h"

#include <kernel/fut_fipc_sys.h>

#include "../netd/netd_core.h"

static const uint8_t *fipc_sys_varint_decode(const uint8_t *cursor,
                                             const uint8_t *end,
                                             uint64_t *out_value) {
    uint64_t value = 0;
    uint32_t shift = 0;

    while (cursor < end) {
        uint8_t byte = *cursor++;
        value |= (uint64_t)(byte & 0x7Fu) << shift;
        if ((byte & 0x80u) == 0) {
            if (out_value) {
                *out_value = value;
            }
            return cursor;
        }
        shift += 7;
        if (shift >= 64) {
            break;
        }
    }

    return NULL;
}

bool fipc_sys_decode_metrics(const uint8_t *buffer,
                             size_t length,
                             struct netd_metrics *out) {
    if (!buffer || !out || length < 2) {
        return false;
    }

    const uint8_t *cursor = buffer;
    const uint8_t *const end = buffer + length;

    if (*cursor++ != FIPC_SYS_T_METRIC_BEGIN) {
        return false;
    }

    struct netd_metrics metrics = {0};

    while (cursor < end) {
        uint8_t tag = *cursor++;
        if (tag == FIPC_SYS_T_METRIC_END) {
            *out = metrics;
            return true;
        }

        uint64_t value = 0;
        cursor = fipc_sys_varint_decode(cursor, end, &value);
        if (!cursor) {
            return false;
        }

        switch (tag) {
            case FIPC_SYS_T_LOOKUP_ATT:
                metrics.lookup_attempts = value;
                break;
            case FIPC_SYS_T_LOOKUP_HIT:
                metrics.lookup_hits = value;
                break;
            case FIPC_SYS_T_LOOKUP_MISS:
                metrics.lookup_miss = value;
                break;
            case FIPC_SYS_T_SEND_EAGAIN:
                metrics.send_eagain = value;
                break;
            case FIPC_SYS_T_TX_FRAMES:
                metrics.tx_frames = value;
                break;
            case FIPC_SYS_T_TX_BLK_CRED:
                metrics.tx_blocked_credits = value;
                break;
            case FIPC_SYS_T_AUTH_FAIL:
                metrics.auth_fail = value;
                break;
            case FIPC_SYS_T_REPLAY_DROP:
                metrics.replay_drop = value;
                break;
            default:
                /* Ignore unknown tags to allow forward compatibility. */
                break;
        }
    }

    return false;
}
