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
/* Reserved channel identifier for admin control operations. */
#define FIPC_CTL_CHANNEL_ID 2u

/* Admin/control authentication defaults */
#define FIPC_ADMIN_TOKEN_LEN 32u
#define FIPC_ADMIN_TOKEN_DEFAULT_INIT \
    { 0x42, 0x6f, 0x6c, 0x54, 0x2d, 0x41, 0x64, 0x6d, \
      0x69, 0x6e, 0x2d, 0x54, 0x6f, 0x6b, 0x65, 0x6e, \
      0xa5, 0xa5, 0x5a, 0x5a, 0x01, 0x23, 0x45, 0x67, \
      0x89, 0xab, 0xcd, 0xef, 0xde, 0xad, 0xbe, 0xef }
#define FIPC_ADMIN_TOKEN_DEFAULT_HEX "426f6c542d41646d696e2d546f6b656ea5a55a5a0123456789abcdefdeadbeef"

#define FIPC_ADMIN_HMAC_KEY_LEN 32u
#define FIPC_ADMIN_HMAC_KEY_DEFAULT_INIT \
    { 0x73, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x2d, 0x63, \
      0x61, 0x70, 0x2d, 0x6b, 0x65, 0x79, 0x21, 0x21, \
      0x90, 0x47, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, \
      0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee }
#define FIPC_ADMIN_HMAC_KEY_DEFAULT_HEX "7369676e65642d6361702d6b657921219047112233445566778899aabbccddee"

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
    FIPC_SYS_K_DROPS_DEADLINE = 0x26,
    FIPC_SYS_K_PI_APPLIED   = 0x27,
    FIPC_SYS_K_PI_RESTORED  = 0x28,
    FIPC_SYS_K_RL_TOKENS    = 0x29,
    FIPC_SYS_K_DROPS_RL     = 0x2A,
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
#define FIPC_SYS_MSG_ADMIN_OP       0x41444D49u /* 'ADMI' */
#define FIPC_SYS_MSG_ADMIN_RP       0x41524C59u /* 'ARLY' */

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

enum fipc_admin_tag {
    FIPC_ADM_BEGIN    = 0x50,
    FIPC_ADM_OP       = 0x51,
    FIPC_ADM_TARGET   = 0x52,
    FIPC_ADM_RIGHTS   = 0x53,
    FIPC_ADM_MAX_MSGS = 0x54,
    FIPC_ADM_MAX_BYTES= 0x55,
    FIPC_ADM_EXP_TICK = 0x56,
    FIPC_ADM_REVOKE   = 0x57,
    FIPC_ADM_RATE     = 0x58,
    FIPC_ADM_BURST    = 0x59,
    FIPC_ADM_TOKEN    = 0x5A,
    FIPC_ADM_LEASE    = 0x5B,
    FIPC_ADM_HMAC     = 0x5C,
    FIPC_ADM_END      = 0x5F,

    FIPC_ADM_RP_BEGIN = 0x60,
    FIPC_ADM_RP_CODE  = 0x61,
    FIPC_ADM_RP_END   = 0x6F,
};

enum fipc_admin_op {
    FIPC_ADM_CAP_BIND   = 1,
    FIPC_ADM_CAP_UNBIND = 2,
    FIPC_ADM_CAP_REVOKE = 3,
    FIPC_ADM_RATE_SET   = 4,
};

static inline uint8_t *fipc_sys_varint_u64(uint8_t *cursor, uint64_t value) {
    while (value >= 0x80u) {
        *cursor++ = (uint8_t)((value & 0x7Fu) | 0x80u);
        value >>= 7;
    }
    *cursor++ = (uint8_t)value;
    return cursor;
}
