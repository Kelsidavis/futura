// SPDX-License-Identifier: MPL-2.0
/*
 * fb_ioctl.h - Userspace framebuffer IOCTL ABI
 *
 * Minimal interface for querying the boot-provided linear framebuffer
 * and configuring compositor hints. The layout intentionally mirrors a
 * subset of the classic Linux FBIO ioctls but remains compact and
 * self-contained for Futura OS.
 */

#pragma once

#include <stdint.h>

/* Lightweight ioctl encoding helpers */
#ifndef _FUT_IO_CONTROL_HELPERS
#define _FUT_IO_CONTROL_HELPERS
#define _FUT_IO(type, nr)        ((((unsigned long)(type)) << 8) | ((nr) & 0xFFu))
#define _FUT_IOR(type, nr, dtype) _FUT_IO(type, nr)
#define _FUT_IOW(type, nr, dtype) _FUT_IO(type, nr)
#endif /* _FUT_IO_CONTROL_HELPERS */

/**
 * FBIOGET_INFO
 *   Query the geometry of the primary linear framebuffer.
 *
 * FBIOSET_VSYNC_MS
 *   Provide a compositor pacing hint in milliseconds. The kernel stores
 *   the value but does not enforce timing (yet).
 *
 * FBIOFLUSH
 *   Flush framebuffer changes to the display (ARM64 VirtIO GPU).
 */
#define FBIOGET_INFO       _FUT_IOR('F', 0x01, struct fut_fb_info)
#define FBIOSET_VSYNC_MS   _FUT_IOW('F', 0x02, uint32_t)
#define FBIOFLUSH          _FUT_IO('F', 0x03)

/* Framebuffer flags */
#define FB_FLAG_LINEAR     0x00000001u

struct fut_fb_info {
    uint32_t width;   /* Width in pixels */
    uint32_t height;  /* Height in pixels */
    uint32_t pitch;   /* Bytes per scanline */
    uint32_t bpp;     /* Bits per pixel */
    uint32_t flags;   /* FB_FLAG_* bitmask */
};

