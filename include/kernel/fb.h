// SPDX-License-Identifier: MPL-2.0
/*
 * fb.h - Platform frame buffer discovery helpers
 *
 * Minimal helpers for exposing the firmware-provided linear framebuffer
 * to the rest of the kernel. Userland access is wired via /dev/fb0 when
 * the probe succeeds.
 */

#pragma once

#include <stdint.h>

struct fut_fb_info {
    uint64_t phys;      /* Physical base address */
    uint32_t width;     /* Width in pixels */
    uint32_t height;    /* Height in pixels */
    uint32_t pitch;     /* Bytes per scanline */
    uint32_t bpp;       /* Bits per pixel (expect 32) */
};

#define FUT_FB_IOCTL_GET_INFO 0x46420101u

int fb_probe_from_multiboot(const void *mb_info);
int fb_get_info(struct fut_fb_info *out);
