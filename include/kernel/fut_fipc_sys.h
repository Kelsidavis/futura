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

enum fipc_sys_kernel_tag {
    FIPC_SYS_K_METRIC_BEGIN = 0x20,
    FIPC_SYS_K_PMM_TOTAL    = 0x21,
    FIPC_SYS_K_PMM_FREE     = 0x22,
    FIPC_SYS_K_FIPC_CHANNELS= 0x23,
    FIPC_SYS_K_TX_CREDITS   = 0x24,
    FIPC_SYS_K_DROPS_BP     = 0x25,
    FIPC_SYS_K_METRIC_END   = 0x2F,
};

enum fipc_sys_fway_tag {
    FIPC_FWAY_BEGIN      = 0x30,
    FIPC_FWAY_EVT        = 0x31,
    FIPC_FWAY_SURF_ID    = 0x32,
    FIPC_FWAY_CLIENT_PID = 0x33,
    FIPC_FWAY_T_START    = 0x34,
    FIPC_FWAY_T_END      = 0x35,
    FIPC_FWAY_DUR_MS     = 0x36,
    FIPC_FWAY_END        = 0x3F,
};

enum fipc_fway_evt_kind {
    FIPC_FWAY_SURFACE_CREATE = 1,
    FIPC_FWAY_SURFACE_COMMIT = 2,
    FIPC_FWAY_INPUT_EVENT    = 3,
};

#define FIPC_SYS_MSG_SYSTEM_METRICS 0x5359534Du /* 'SYSM' */
#define FIPC_SYS_MSG_KERNEL_METRICS 0x4B4D4554u /* 'KMET' */
#define FIPC_SYS_MSG_FWAY_METRICS   0x46574159u /* 'FWAY' */
#define FIPC_SYS_MSG_VFS_METRICS    0x5646534Du /* 'VFSM' */

enum fipc_sys_vfs_tag {
    FIPC_VFS_BEGIN      = 0x40,
    FIPC_VFS_EVT        = 0x41,
    FIPC_VFS_PATH_HASH  = 0x42,
    FIPC_VFS_BYTES      = 0x43,
    FIPC_VFS_RESULT     = 0x44,
    FIPC_VFS_T_START    = 0x45,
    FIPC_VFS_T_END      = 0x46,
    FIPC_VFS_DUR_MS     = 0x47,
    FIPC_VFS_END        = 0x4F,
};

enum fipc_vfs_evt_kind {
    FIPC_VFS_OPEN  = 1,
    FIPC_VFS_READ  = 2,
    FIPC_VFS_WRITE = 3,
    FIPC_VFS_CLOSE = 4,
};

static inline uint8_t *fipc_sys_varint_u64(uint8_t *cursor, uint64_t value) {
    while (value >= 0x80u) {
        *cursor++ = (uint8_t)((value & 0x7Fu) | 0x80u);
        value >>= 7;
    }
    *cursor++ = (uint8_t)value;
    return cursor;
}
