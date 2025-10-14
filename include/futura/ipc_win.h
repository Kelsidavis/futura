/* ipc_win.h - Minimal window protocol shared definitions
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * Shared message identifiers and payload layouts for the Step 2 desktop
 * prototype (winsrv ↔ winstub). The structures are tightly packed and
 * intentionally trivial to keep the bootstrap deterministic.
 */

#pragma once

#include <stdint.h>

#define WIN_PROTO_VERSION 1u
#define WIN_TITLE_MAX     32u
#define WIN_SURFACE_ID_PRIMARY 1u
#define WIN_FORMAT_ARGB8888    1u

enum win_msg_id {
    WIN_MSG_HELLO = 0x57494E00u,       /* 'WIN\0' client handshake */
    WIN_MSG_READY = 0x57494E01u,       /* server→client: framebuffer ready */
    WIN_MSG_CREATE = 0x57494E02u,      /* client→server: create surface */
    WIN_MSG_CREATED = 0x57494E03u,     /* server→client: surface info */
    WIN_MSG_DAMAGE_RECT = 0x57494E04u, /* client→server: dirty rect */
    WIN_MSG_CLOSE = 0x57494E05u        /* bidirectional: shutdown surface */
};

#pragma pack(push, 1)

struct win_msg_hdr {
    uint32_t id;    /* enum win_msg_id */
    uint32_t size;  /* Bytes that follow this header */
};

struct win_msg_hello {
    uint32_t version;
};

struct win_msg_ready {
    uint32_t fb_w;
    uint32_t fb_h;
    uint32_t fb_bpp;
};

struct win_msg_create {
    uint32_t width;
    uint32_t height;
    char title[WIN_TITLE_MAX];
};

struct win_msg_created {
    uint32_t surface_id;
    uint32_t width;
    uint32_t height;
    uint32_t pitch;
    uint32_t format;
};

struct win_msg_damage {
    uint32_t surface_id;
    uint32_t x;
    uint32_t y;
    uint32_t width;
    uint32_t height;
    uint32_t argb;
};

#pragma pack(pop)

