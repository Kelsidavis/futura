/* fw_demo.c - Futuraway demo client renderer
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
#include <user/futura_way.h>

#include "../svc_registryd/registry_client.h"

#define DEMO_DEFAULT_SERVICE "futurawayd"
#define DEMO_DEFAULT_HOST    "127.0.0.1"
#define DEMO_TILE            32u

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

static const uint8_t *glyph_lookup(char ch) {
    size_t count = sizeof(glyph_table) / sizeof(glyph_table[0]);
    for (size_t i = 0; i < count; ++i) {
        if (glyph_table[i].ch == ch) {
            return glyph_table[i].rows;
        }
    }
    return NULL;
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
    if (!pixels) {
        return;
    }
    if (x >= width || y >= height) {
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
                       uint32_t fg,
                       uint32_t bg) {
    if (!pixels || !rows) {
        return;
    }
    for (uint32_t r = 0; r < 7; ++r) {
        uint8_t bits = rows[r];
        for (uint32_t c = 0; c < 5; ++c) {
            uint32_t color = (bits & (1u << (4u - c))) ? fg : bg;
            fill_rect(pixels,
                      width,
                      height,
                      origin_x + c * scale,
                      origin_y + r * scale,
                      scale,
                      scale,
                      color);
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

static int send_surface_create(struct fut_fipc_channel *channel,
                               uint64_t surface_id,
                               uint32_t width,
                               uint32_t height) {
    struct fw_surface_create_req req = {
        .width = width,
        .height = height,
        .format = FW_FORMAT_ARGB32,
        .flags = 0,
        .surface_id = surface_id,
    };
    return fut_fipc_send(channel, FWAY_MSG_CREATE_SURFACE, &req, sizeof(req));
}

static int send_surface_commit(struct fut_fipc_channel *channel,
                               uint64_t surface_id,
                               uint32_t width,
                               uint32_t height,
                               const uint32_t *pixels) {
    size_t stride = (size_t)width * 4u;
    size_t payload = sizeof(struct fw_surface_commit_req) + stride * (size_t)height;
    uint8_t *buffer = (uint8_t *)malloc(payload);
    if (!buffer) {
        return -ENOMEM;
    }

    struct fw_surface_commit_req *req = (struct fw_surface_commit_req *)buffer;
    req->surface_id = surface_id;
    req->width = width;
    req->height = height;
    req->stride_bytes = (uint32_t)stride;
    memcpy(req + 1, pixels, stride * (size_t)height);

    int rc = fut_fipc_send(channel, FWAY_MSG_COMMIT, buffer, payload);
    free(buffer);
    return rc;
}

static int render_scene(uint32_t width, uint32_t height, uint32_t **pixels_out) {
    size_t count = (size_t)width * (size_t)height;
    uint32_t *pixels = (uint32_t *)malloc(count * sizeof(uint32_t));
    if (!pixels) {
        return -ENOMEM;
    }
    draw_checkerboard(pixels, width, height, DEMO_TILE);

    uint32_t rect_w = width / 2u;
    uint32_t rect_h = height / 3u;
    uint32_t rect_x = width / 4u;
    uint32_t rect_y = height / 5u;
    fill_rect(pixels, width, height, rect_x, rect_y, rect_w, rect_h, 0xCC0B1734u);

    const char *label = "FUTURA";
    uint32_t scale = 8u;
    uint32_t cursor_x = rect_x + scale;
    uint32_t cursor_y = rect_y + scale;
    uint32_t fg = 0xFFE3EAF5u;
    uint32_t bg = 0x00000000u;

    for (const char *p = label; *p; ++p) {
        const uint8_t *rows = glyph_lookup(*p);
        if (rows) {
            draw_glyph(pixels, width, height, cursor_x, cursor_y, rows, scale, fg, bg);
        }
        cursor_x += (5u * scale) + scale;
    }

    *pixels_out = pixels;
    return 0;
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
        fprintf(stderr, "[fw_demo] failed to locate compositor channel\n");
        return -EIO;
    }

    if (send_surface_create(channel, cfg.surface_id, cfg.width, cfg.height) != 0) {
        fprintf(stderr, "[fw_demo] surface create failed\n");
        return -EIO;
    }

    uint32_t *pixels = NULL;
    if (render_scene(cfg.width, cfg.height, &pixels) != 0 || !pixels) {
        fprintf(stderr, "[fw_demo] render failed\n");
        return -ENOMEM;
    }

    int rc = send_surface_commit(channel, cfg.surface_id, cfg.width, cfg.height, pixels);
    free(pixels);
    if (rc != 0) {
        fprintf(stderr, "[fw_demo] commit failed (%d)\n", rc);
        return -EIO;
    }

    return 0;
}
