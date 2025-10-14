// SPDX-License-Identifier: MPL-2.0
#pragma once

#include <stdint.h>

struct fb_info {
    uint32_t width;
    uint32_t height;
    uint32_t pitch;
    uint32_t bpp;
};

int fb_open(struct fb_info *info);
