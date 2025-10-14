// SPDX-License-Identifier: MPL-2.0
//
// compositor.c - Minimal ARGB32 surface helpers

#include "compositor.h"

#include <user/futura_posix.h>
#include <user/libfutura.h>

struct ui_surface *compositor_surface_create(uint32_t width, uint32_t height) {
    if (width == 0 || height == 0) {
        return NULL;
    }

    struct ui_surface *surface = malloc(sizeof(*surface));
    if (!surface) {
        return NULL;
    }

    surface->width = width;
    surface->height = height;
    surface->pitch = width * sizeof(uint32_t);
    size_t bytes = (size_t)surface->pitch * surface->height;
    surface->pixels = malloc(bytes);
    if (!surface->pixels) {
        free(surface);
        return NULL;
    }
    memset(surface->pixels, 0, bytes);
    return surface;
}

void compositor_surface_destroy(struct ui_surface *surface) {
    if (!surface) {
        return;
    }
    if (surface->pixels) {
        free(surface->pixels);
    }
    free(surface);
}

void compositor_fill_rect(struct ui_surface *surface,
                          uint32_t x,
                          uint32_t y,
                          uint32_t width,
                          uint32_t height,
                          uint32_t argb) {
    if (!surface || !surface->pixels || width == 0 || height == 0) {
        return;
    }

    if (x >= surface->width || y >= surface->height) {
        return;
    }

    uint32_t max_w = surface->width - x;
    uint32_t max_h = surface->height - y;
    if (width > max_w) {
        width = max_w;
    }
    if (height > max_h) {
        height = max_h;
    }

    uint32_t *row = surface->pixels + (size_t)y * surface->width + x;
    for (uint32_t iy = 0; iy < height; ++iy) {
        for (uint32_t ix = 0; ix < width; ++ix) {
            row[ix] = argb;
        }
        row += surface->width;
    }
}

void compositor_blit_to_fb(const struct ui_surface *surface,
                           uint8_t *fb_base,
                           uint32_t fb_pitch,
                           uint32_t fb_width,
                           uint32_t fb_height,
                           uint32_t x,
                           uint32_t y,
                           uint32_t width,
                           uint32_t height) {
    if (!surface || !surface->pixels || !fb_base) {
        return;
    }
    if (width == 0 || height == 0) {
        return;
    }

    if (x >= surface->width || y >= surface->height) {
        return;
    }

    if (x >= fb_width || y >= fb_height) {
        return;
    }

    uint32_t copy_w = surface->width - x;
    uint32_t copy_h = surface->height - y;
    if (width < copy_w) {
        copy_w = width;
    }
    if (height < copy_h) {
        copy_h = height;
    }

    /* Clip to framebuffer bounds */
    if (copy_w > fb_width - x) {
        copy_w = fb_width - x;
    }
    if (copy_h > fb_height - y) {
        copy_h = fb_height - y;
    }

    uint32_t *src_row = surface->pixels + (size_t)y * surface->width + x;
    uint32_t *dst_row = (uint32_t *)(fb_base + (size_t)y * fb_pitch) + x;
    for (uint32_t iy = 0; iy < copy_h; ++iy) {
        memcpy(dst_row, src_row, (size_t)copy_w * sizeof(uint32_t));
        src_row += surface->width;
        dst_row = (uint32_t *)((uint8_t *)dst_row + fb_pitch);
    }
}
