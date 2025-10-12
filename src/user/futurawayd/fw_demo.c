/* fw_demo.c - Futuraway demo client renderer (M2)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#define _POSIX_C_SOURCE 200809L

#include "fw_demo.h"

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <kernel/fut_fipc.h>

#include <user/futuraway_proto.h>

#include "../svc_registryd/registry_client.h"

#define DEMO_DEFAULT_SERVICE "futurawayd"
#define DEMO_DEFAULT_HOST    "127.0.0.1"

struct glyph {
    char ch;
    uint8_t rows[7];
};

static const struct glyph glyph_table[] = {
    { 'F', { 0x1F, 0x10, 0x1E, 0x10, 0x10, 0x10, 0x10 } },
    { 'U', { 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E } },
    { 'T', { 0x1F, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04 } },
    { 'R', { 0x1E, 0x11, 0x11, 0x1E, 0x14, 0x12, 0x11 } },
    { 'A', { 0x0E, 0x11, 0x11, 0x1F, 0x11, 0x11, 0x11 } },
};

static const uint8_t *glyph_rows(char ch) {
    size_t count = sizeof(glyph_table) / sizeof(glyph_table[0]);
    for (size_t i = 0; i < count; ++i) {
        if (glyph_table[i].ch == ch) {
            return glyph_table[i].rows;
        }
    }
    return NULL;
}

static inline uint32_t premul_color(uint8_t a, uint8_t r, uint8_t g, uint8_t b) {
    uint32_t pr = (uint32_t)r * a;
    uint32_t pg = (uint32_t)g * a;
    uint32_t pb = (uint32_t)b * a;
    return ((uint32_t)a << 24) |
           (((pr + 127u) / 255u) << 16) |
           (((pg + 127u) / 255u) << 8) |
           (((pb + 127u) / 255u));
}

static void draw_checkerboard(uint32_t *pixels,
                              uint32_t width,
                              uint32_t height,
                              uint32_t tile) {
    const uint32_t c0 = 0xFF1A2334u;
    const uint32_t c1 = 0xFF242F42u;
    for (uint32_t y = 0; y < height; ++y) {
        uint32_t ty = y / tile;
        for (uint32_t x = 0; x < width; ++x) {
            uint32_t tx = x / tile;
            uint32_t idx = y * width + x;
            pixels[idx] = ((tx + ty) & 1u) ? c0 : c1;
        }
    }
}

static void fill_rect(uint32_t *pixels,
                      uint32_t width,
                      uint32_t height,
                      uint32_t x,
                      uint32_t y,
                      uint32_t w,
                      uint32_t h,
                      uint32_t color) {
    if (!pixels || x >= width || y >= height) {
        return;
    }
    if (x + w > width) {
        w = width - x;
    }
    if (y + h > height) {
        h = height - y;
    }
    for (uint32_t row = 0; row < h; ++row) {
        uint32_t *dst = pixels + (size_t)(y + row) * width + x;
        for (uint32_t col = 0; col < w; ++col) {
            dst[col] = color;
        }
    }
}

static void draw_glyph(uint32_t *pixels,
                       uint32_t width,
                       uint32_t height,
                       uint32_t origin_x,
                       uint32_t origin_y,
                       const uint8_t rows[7],
                       uint32_t scale,
                       uint32_t fg) {
    if (!pixels || !rows) {
        return;
    }
    for (uint32_t r = 0; r < 7; ++r) {
        uint8_t bits = rows[r];
        for (uint32_t c = 0; c < 5; ++c) {
            if (bits & (1u << (4u - c))) {
                fill_rect(pixels,
                          width,
                          height,
                          origin_x + c * scale,
                          origin_y + r * scale,
                          scale,
                          scale,
                          fg);
            }
        }
    }
}

static struct fut_fipc_channel *await_channel(const char *host,
                                              uint16_t port,
                                              const char *service) {
    const struct timespec delay = { .tv_sec = 0, .tv_nsec = 2 * 1000 * 1000 };
    for (int i = 0; i < 500; ++i) {
        uint64_t channel_id = 0;
        if (registry_client_lookup(host, port, service, &channel_id) == 0 && channel_id != 0) {
            struct fut_fipc_channel *channel = fut_fipc_channel_lookup(channel_id);
            if (channel) {
                return channel;
            }
        }
        nanosleep(&delay, NULL);
    }
    return NULL;
}

static int send_surface_create2(struct fut_fipc_channel *channel,
                                uint64_t surface_id,
                                uint32_t width,
                                uint32_t height,
                                uint32_t z_index,
                                bool premult) {
    struct fw_surface_create2_req req = {
        .width = width,
        .height = height,
        .format = FW_FORMAT_ARGB32,
        .flags = 0,
        .surface_id = surface_id,
        .z_index = z_index,
        .alpha_premultiplied = (uint8_t)(premult ? 1 : 0),
        .shm_bytes = (uint64_t)width * height * 4u,
    };
    return fut_fipc_send(channel, FW_OP_SURFACE_CREATE2, &req, sizeof(req));
}

static int send_surface_set_z(struct fut_fipc_channel *channel,
                              uint64_t surface_id,
                              uint32_t z_index) {
    struct fw_surface_set_z_req req = {
        .surface_id = surface_id,
        .z_index = z_index,
    };
    return fut_fipc_send(channel, FW_OP_SURFACE_SET_Z, &req, sizeof(req));
}

static int send_surface_damage(struct fut_fipc_channel *channel,
                               uint64_t surface_id,
                               struct fw_surface_damage rect) {
    struct fw_surface_damage_req req = {
        .surface_id = surface_id,
        .rect = rect,
    };
    return fut_fipc_send(channel, FW_OP_SURFACE_DAMAGE, &req, sizeof(req));
}

static int send_surface_commit(struct fut_fipc_channel *channel,
                               uint64_t surface_id,
                               uint32_t width,
                               uint32_t height,
                               const uint32_t *pixels) {
    size_t stride = (size_t)width * 4u;
    size_t payload_len = sizeof(struct fw_surface_commit_req) + stride * height;
    uint8_t *buffer = (uint8_t *)malloc(payload_len);
    if (!buffer) {
        return -ENOMEM;
    }

    struct fw_surface_commit_req *req = (struct fw_surface_commit_req *)buffer;
    req->surface_id = surface_id;
    req->width = width;
    req->height = height;
    req->stride_bytes = (uint32_t)stride;
    memcpy(req + 1, pixels, stride * height);

    int rc = fut_fipc_send(channel, FW_OP_SURFACE_COMMIT, buffer, payload_len);
    free(buffer);
    return rc;
}

static int render_background(uint32_t width,
                             uint32_t height,
                             uint32_t **out_pixels) {
    size_t count = (size_t)width * height;
    uint32_t *pixels = (uint32_t *)malloc(count * sizeof(uint32_t));
    if (!pixels) {
        return -ENOMEM;
    }
    draw_checkerboard(pixels, width, height, 32u);
    *out_pixels = pixels;
    return 0;
}

static int render_overlay(uint32_t width,
                          uint32_t height,
                          uint32_t **out_pixels,
                          struct fw_surface_damage *label_bounds) {
    size_t count = (size_t)width * height;
    uint32_t *pixels = (uint32_t *)calloc(count, sizeof(uint32_t));
    if (!pixels) {
        return -ENOMEM;
    }

    uint32_t panel_w = width / 2u;
    uint32_t panel_h = height / 4u;
    uint32_t panel_x = width / 4u;
    uint32_t panel_y = height / 5u;
    uint32_t panel_color = premul_color(160, 18, 34, 58);
    fill_rect(pixels, width, height, panel_x, panel_y, panel_w, panel_h, panel_color);

    const char *label = "FUTURA";
    uint32_t scale = 10u;
    uint32_t cursor_x = panel_x + scale * 2u;
    uint32_t cursor_y = panel_y + scale * 2u;
    uint32_t fg = premul_color(220, 226, 237, 249);

    for (const char *p = label; *p; ++p) {
        const uint8_t *rows = glyph_rows(*p);
        if (rows) {
            draw_glyph(pixels, width, height, cursor_x, cursor_y, rows, scale, fg);
        }
        cursor_x += (5u * scale) + scale;
    }

    if (label_bounds) {
        *label_bounds = (struct fw_surface_damage){
            .x = panel_x,
            .y = panel_y,
            .width = panel_w,
            .height = panel_h,
        };
    }

    *out_pixels = pixels;
    return 0;
}

static void apply_highlight(uint32_t *pixels,
                            uint32_t width,
                            uint32_t height,
                            struct fw_surface_damage *rect) {
    if (!pixels || !rect) {
        return;
    }
    uint32_t highlight = premul_color(200, 255, 154, 46);
    uint32_t pad = 16u;
    uint32_t hx = rect->x + pad;
    uint32_t hy = rect->y + pad;
    uint32_t hw = rect->width > 2 * pad ? rect->width - 2 * pad : rect->width;
    uint32_t hh = rect->height > 2 * pad ? rect->height - 2 * pad : rect->height;
    fill_rect(pixels, width, height, hx, hy, hw, hh, highlight);
    rect->x = hx;
    rect->y = hy;
    rect->width = hw;
    rect->height = hh;
}

int fw_demo_run(const struct fw_demo_config *config) {
    if (!config) {
        return -EINVAL;
    }

    struct fw_demo_config cfg = *config;
    if (cfg.width == 0) {
        cfg.width = 800;
    }
    if (cfg.height == 0) {
        cfg.height = 600;
    }
    if (!cfg.service_name) {
        cfg.service_name = DEMO_DEFAULT_SERVICE;
    }
    if (!cfg.registry_host) {
        cfg.registry_host = DEMO_DEFAULT_HOST;
    }
    if (cfg.surface_id == 0) {
        cfg.surface_id = 1;
    }

    struct fut_fipc_channel *channel =
        await_channel(cfg.registry_host, cfg.registry_port, cfg.service_name);
    if (!channel) {
        fprintf(stderr, "[fw_demo] compositor channel lookup failed\n");
        return -EIO;
    }

    uint32_t *bg_pixels = NULL;
    if (render_background(cfg.width, cfg.height, &bg_pixels) != 0) {
        fprintf(stderr, "[fw_demo] background render failed\n");
        return -ENOMEM;
    }

    uint32_t *overlay_pixels = NULL;
    struct fw_surface_damage overlay_bounds = {0};
    if (render_overlay(cfg.width, cfg.height, &overlay_pixels, &overlay_bounds) != 0) {
        free(bg_pixels);
        fprintf(stderr, "[fw_demo] overlay render failed\n");
        return -ENOMEM;
    }

    uint64_t bg_surface = cfg.surface_id;
    uint64_t overlay_surface = cfg.surface_id + 1u;

    if (send_surface_create2(channel, bg_surface, cfg.width, cfg.height, 0, true) != 0 ||
        send_surface_commit(channel, bg_surface, cfg.width, cfg.height, bg_pixels) != 0) {
        fprintf(stderr, "[fw_demo] background submit failed\n");
        free(bg_pixels);
        free(overlay_pixels);
        return -EIO;
    }

    if (send_surface_create2(channel, overlay_surface, cfg.width, cfg.height, 10, true) != 0 ||
        send_surface_set_z(channel, overlay_surface, 10) != 0) {
        fprintf(stderr, "[fw_demo] overlay setup failed\n");
        free(bg_pixels);
        free(overlay_pixels);
        return -EIO;
    }

    struct fw_surface_damage rect1 = overlay_bounds;
    if (rect1.width > 0 && rect1.height > 0) {
        (void)send_surface_damage(channel, overlay_surface, rect1);
        struct fw_surface_damage rect2 = rect1;
        rect2.x += rect2.width / 4u;
        rect2.width /= 2u;
        (void)send_surface_damage(channel, overlay_surface, rect2);
    }

    if (send_surface_commit(channel, overlay_surface, cfg.width, cfg.height, overlay_pixels) != 0) {
        fprintf(stderr, "[fw_demo] overlay commit failed\n");
        free(bg_pixels);
        free(overlay_pixels);
        return -EIO;
    }

    struct fw_surface_damage highlight_rect = overlay_bounds;
    apply_highlight(overlay_pixels, cfg.width, cfg.height, &highlight_rect);
    if (highlight_rect.width > 0 && highlight_rect.height > 0) {
        (void)send_surface_damage(channel, overlay_surface, highlight_rect);
    }
    if (send_surface_commit(channel, overlay_surface, cfg.width, cfg.height, overlay_pixels) != 0) {
        fprintf(stderr, "[fw_demo] overlay highlight commit failed\n");
        free(bg_pixels);
        free(overlay_pixels);
        return -EIO;
    }

    free(bg_pixels);
    free(overlay_pixels);
    return 0;
}
