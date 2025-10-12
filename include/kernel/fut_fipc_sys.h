/* fut_fipc_sys.h - System FIPC helpers (metrics stream)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Encodings and constants for the reserved system metrics channel.
 */

#pragma once

#include <stdint.h>

/* Reserved channel identifier for the system metrics feed. */
#define FIPC_SYS_CHANNEL_ID 1u

/* IDL-v0 tags (one-byte identifiers followed by varints unless noted). */
enum fipc_sys_tag {
    FIPC_SYS_T_METRIC_BEGIN = 0x10,
    FIPC_SYS_T_LOOKUP_ATT   = 0x11,
    FIPC_SYS_T_LOOKUP_HIT   = 0x12,
    FIPC_SYS_T_LOOKUP_MISS  = 0x13,
    FIPC_SYS_T_SEND_EAGAIN  = 0x14,
    FIPC_SYS_T_TX_FRAMES    = 0x15,
    FIPC_SYS_T_TX_BLK_CRED  = 0x16,
    FIPC_SYS_T_AUTH_FAIL    = 0x17,
    FIPC_SYS_T_REPLAY_DROP  = 0x18,
    FIPC_SYS_T_METRIC_END   = 0x1F,
};

static inline uint8_t *fipc_sys_varint_u64(uint8_t *cursor, uint64_t value) {
    while (value >= 0x80u) {
        *cursor++ = (uint8_t)((value & 0x7Fu) | 0x80u);
        value >>= 7;
    }
    *cursor++ = (uint8_t)value;
    return cursor;
}
