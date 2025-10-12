/* futuraway_proto.h - Minimal FuturaWay protocol definitions for M1
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#pragma once

#include <stdint.h>

enum fw_op {
    FW_OP_SURFACE_CREATE = 1,
    FW_OP_SURFACE_COMMIT = 2,
    FW_OP_INPUT_EVENT = 3,
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

struct fw_surface_commit_req {
    uint64_t surface_id;
    uint32_t width;
    uint32_t height;
    uint32_t stride_bytes;
    /* Pixel data (width * height * 4 bytes) follows header. */
};
