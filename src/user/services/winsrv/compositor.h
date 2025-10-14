// SPDX-License-Identifier: MPL-2.0
//
// compositor.h - Minimal surface helpers for winsrv

#pragma once

#include <stdint.h>
#include <stddef.h>

struct ui_surface {
    uint32_t width;
    uint32_t height;
    uint32_t pitch;   /* bytes per scanline */
    uint32_t *pixels; /* ARGB32 */
};

struct ui_surface *compositor_surface_create(uint32_t width, uint32_t height);
void compositor_surface_destroy(struct ui_surface *surface);
void compositor_fill_rect(struct ui_surface *surface,
                          uint32_t x,
                          uint32_t y,
                          uint32_t width,
                          uint32_t height,
                          uint32_t argb);
void compositor_blit_to_fb(const struct ui_surface *surface,
                           uint8_t *fb_base,
                           uint32_t fb_pitch,
                           uint32_t fb_width,
                           uint32_t fb_height,
                           uint32_t x,
                           uint32_t y,
                           uint32_t width,
                           uint32_t height);

