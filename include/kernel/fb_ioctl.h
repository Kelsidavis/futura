// SPDX-License-Identifier: MPL-2.0
/*
 * fb_ioctl.h - Framebuffer IOCTL definitions
 */

#pragma once

#include <stdint.h>

#define FBIOGET_FSCREENINFO 0x4602u
#define FBIOGET_VSCREENINFO 0x4603u

struct fb_fix_screeninfo {
    uint64_t smem_start;
    uint32_t line_length;
    uint32_t smem_len;
};

struct fb_var_screeninfo {
    uint32_t xres;
    uint32_t yres;
    uint32_t bits_per_pixel;
};
