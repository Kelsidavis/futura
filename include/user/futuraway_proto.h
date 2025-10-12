/* futuraway_proto.h - FuturaWay protocol helpers (M1+M2)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#pragma once

#include <stdint.h>

enum fw_op {
    FW_OP_SURFACE_CREATE = 0x2300,
    FW_OP_SURFACE_CREATE2 = 0x2301,
    FW_OP_SURFACE_COMMIT = 0x2302,
    FW_OP_SURFACE_SET_Z = 0x2303,
    FW_OP_SURFACE_DAMAGE = 0x2304,
    FW_OP_INPUT_EVENT = 0x2305,
};

enum fw_pixel_format {
    FW_FORMAT_INVALID = 0,
    FW_FORMAT_ARGB32 = 1,
};

struct fw_surface_create_req {
    uint32_t width;
    uint32_t height;
    uint32_t format;
    uint32_t flags;
    uint64_t surface_id;
};

struct fw_surface_create2_req {
    uint32_t width;
    uint32_t height;
    uint32_t format;
    uint32_t flags;
    uint64_t surface_id;
    uint32_t z_index;
    uint8_t alpha_premultiplied;
    uint8_t reserved[3];
    uint64_t shm_bytes;
};

struct fw_surface_set_z_req {
    uint64_t surface_id;
    uint32_t z_index;
};

struct fw_surface_damage {
    uint32_t x;
    uint32_t y;
    uint32_t width;
    uint32_t height;
};

struct fw_surface_damage_req {
    uint64_t surface_id;
    struct fw_surface_damage rect;
};

struct fw_surface_commit_req {
    uint64_t surface_id;
    uint32_t width;
    uint32_t height;
    uint32_t stride_bytes;
    /* Pixel data (width * height * 4 bytes) follows header. */
};
