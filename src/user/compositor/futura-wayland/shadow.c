// SPDX-License-Identifier: MPL-2.0

#include "shadow.h"

#include <stddef.h>
#include <stdint.h>

#define SHADOW_MAX_ALPHA 96

static inline uint8_t clamp_u8(int value) {
    if (value < 0) {
        return 0;
    }
    if (value > 255) {
        return 255;
    }
    return (uint8_t)value;
}

static inline void shadow_darken_pixel(uint32_t *pixel, uint8_t alpha) {
    if (!pixel || alpha == 0) {
        return;
    }

    uint32_t dst = *pixel;
    uint8_t dr = (uint8_t)(dst >> 16);
    uint8_t dg = (uint8_t)(dst >> 8);
    uint8_t db = (uint8_t)dst;

    uint8_t factor = (uint8_t)(255 - alpha);
    dr = clamp_u8((dr * factor) / 255);
    dg = clamp_u8((dg * factor) / 255);
    db = clamp_u8((db * factor) / 255);

    *pixel = (0xFFu << 24) |
             ((uint32_t)dr << 16) |
             ((uint32_t)dg << 8) |
             (uint32_t)db;
}

void shadow_draw(struct backbuffer *dst,
                 const struct comp_surface *surface,
                 const fut_rect_t *clip) {
    if (!dst || !dst->px || !surface || !clip) {
        return;
    }
    int radius = surface->shadow_px;
    if (radius <= 0) {
        return;
    }

    fut_rect_t window = comp_window_rect(surface);
    if (window.w <= 0 || window.h <= 0) {
        return;
    }

    int left = window.x;
    int top = window.y;
    int right = window.x + window.w - 1;
    int bottom = window.y + window.h - 1;

    int clip_x1 = clip->x;
    int clip_y1 = clip->y;
    int clip_x2 = clip->x + clip->w;
    int clip_y2 = clip->y + clip->h;

    if (clip_x1 < left - radius) {
        clip_x1 = left - radius;
    }
    if (clip_y1 < top - radius) {
        clip_y1 = top - radius;
    }
    if (clip_x2 > right + 1 + radius) {
        clip_x2 = right + 1 + radius;
    }
    if (clip_y2 > bottom + 1 + radius) {
        clip_y2 = bottom + 1 + radius;
    }
    if (clip_x1 < 0) clip_x1 = 0;
    if (clip_y1 < 0) clip_y1 = 0;
    if (clip_x2 > dst->width) {
        clip_x2 = dst->width;
    }
    if (clip_y2 > dst->height) {
        clip_y2 = dst->height;
    }
    if (clip_x2 > left + window.w + radius) {
        clip_x2 = left + window.w + radius;
    }
    if (clip_y2 > top + window.h + radius) {
        clip_y2 = top + window.h + radius;
    }
    if (clip_x1 >= clip_x2 || clip_y1 >= clip_y2) {
        return;
    }

    for (int y = clip_y1; y < clip_y2; ++y) {
        uint8_t *row_ptr = (uint8_t *)dst->px + (size_t)y * (size_t)dst->pitch;
        for (int x = clip_x1; x < clip_x2; ++x) {
            if (x >= window.x && x < window.x + window.w &&
                y >= window.y && y < window.y + window.h) {
                continue;
            }

            int dx = 0;
            if (x < left) {
                dx = left - x;
            } else if (x > right) {
                dx = x - right;
            }

            int dy = 0;
            if (y < top) {
                dy = top - y;
            } else if (y > bottom) {
                dy = y - bottom;
            }

            int dist = dx > dy ? dx : dy;
            if (dist <= 0 || dist > radius) {
                continue;
            }

            int alpha = (radius - dist + 1) * SHADOW_MAX_ALPHA / radius;
            if (alpha <= 0) {
                continue;
            }

            uint32_t *pixel = (uint32_t *)(row_ptr + (size_t)x * 4u);
            shadow_darken_pixel(pixel, (uint8_t)alpha);
        }
    }
}
