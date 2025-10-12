// SPDX-License-Identifier: MPL-2.0
// futuraway_m2_bench.c - Measure damage-aware compositing speedup

#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <user/futuraway_proto.h>

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

static int render_background(uint32_t width,
                             uint32_t height,
                             uint32_t **out_pixels) {
    size_t count = (size_t)width * height;
    uint32_t *pixels = (uint32_t *)malloc(count * sizeof(uint32_t));
    if (!pixels) {
        return -1;
    }
    draw_checkerboard(pixels, width, height, 32u);
    *out_pixels = pixels;
    return 0;
}

static int render_overlay(uint32_t width,
                          uint32_t height,
                          uint32_t **out_pixels,
                          struct fw_surface_damage *label_bounds,
                          struct fw_surface_damage *highlight_bounds) {
    size_t count = (size_t)width * height;
    uint32_t *pixels = (uint32_t *)calloc(count, sizeof(uint32_t));
    if (!pixels) {
        return -1;
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

    if (highlight_bounds) {
        uint32_t pad = 16u;
        uint32_t hx = panel_x + pad;
        uint32_t hy = panel_y + pad;
        uint32_t hw = panel_w > 2 * pad ? panel_w - 2 * pad : panel_w;
        uint32_t hh = panel_h > 2 * pad ? panel_h - 2 * pad : panel_h;
        uint32_t highlight = premul_color(200, 255, 154, 46);
        fill_rect(pixels, width, height, hx, hy, hw, hh, highlight);
        *highlight_bounds = (struct fw_surface_damage){
            .x = hx,
            .y = hy,
            .width = hw,
            .height = hh,
        };
    }

    *out_pixels = pixels;
    return 0;
}

static inline uint32_t clamp_u32(uint32_t value) {
    return value > 255u ? 255u : value;
}

static inline uint32_t blend_premult(uint32_t dst, uint32_t src) {
    uint32_t src_a = (src >> 24) & 0xFFu;
    if (src_a == 0u) {
        return dst;
    }
    if (src_a == 255u) {
        return src;
    }
    uint32_t dst_a = (dst >> 24) & 0xFFu;
    uint32_t inv = 255u - src_a;

    uint32_t dst_r = (dst >> 16) & 0xFFu;
    uint32_t dst_g = (dst >> 8) & 0xFFu;
    uint32_t dst_b = dst & 0xFFu;

    uint32_t src_r = (src >> 16) & 0xFFu;
    uint32_t src_g = (src >> 8) & 0xFFu;
    uint32_t src_b = src & 0xFFu;

    uint32_t out_r = src_r + ((dst_r * inv) + 127u) / 255u;
    uint32_t out_g = src_g + ((dst_g * inv) + 127u) / 255u;
    uint32_t out_b = src_b + ((dst_b * inv) + 127u) / 255u;
    uint32_t out_a = src_a + ((dst_a * inv) + 127u) / 255u;

    return (clamp_u32(out_a) << 24) |
           (clamp_u32(out_r) << 16) |
           (clamp_u32(out_g) << 8) |
           clamp_u32(out_b);
}

static void composite_region(uint32_t *framebuffer,
                             uint32_t width,
                             uint32_t height,
                             const uint32_t *background,
                             const uint32_t *overlay,
                             struct fw_surface_damage rect) {
    uint32_t x0 = rect.x;
    uint32_t y0 = rect.y;
    uint32_t x1 = rect.x + rect.width;
    uint32_t y1 = rect.y + rect.height;
    if (x0 >= width || y0 >= height) {
        return;
    }
    if (x1 > width) {
        x1 = width;
    }
    if (y1 > height) {
        y1 = height;
    }
    for (uint32_t y = y0; y < y1; ++y) {
        for (uint32_t x = x0; x < x1; ++x) {
            size_t idx = (size_t)y * width + x;
            uint32_t color = background[idx];
            uint32_t src = overlay[idx];
            framebuffer[idx] = blend_premult(color, src);
        }
    }
}

static double measure_composite(uint32_t iterations,
                                uint32_t *framebuffer,
                                uint32_t width,
                                uint32_t height,
                                const uint32_t *background,
                                const uint32_t *overlay,
                                struct fw_surface_damage rect) {
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (uint32_t i = 0; i < iterations; ++i) {
        composite_region(framebuffer, width, height, background, overlay, rect);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double elapsed = (double)(t1.tv_sec - t0.tv_sec) * 1e6 +
                     (double)(t1.tv_nsec - t0.tv_nsec) / 1e3;
    return elapsed / (double)iterations;
}

int main(void) {
    const uint32_t width = 800;
    const uint32_t height = 600;
    const uint32_t iterations = 250;

    uint32_t *background = NULL;
    uint32_t *overlay = NULL;
    struct fw_surface_damage panel_rect = {0};
    struct fw_surface_damage highlight_rect = {0};

    if (render_background(width, height, &background) != 0 ||
        render_overlay(width, height, &overlay, &panel_rect, &highlight_rect) != 0) {
        free(background);
        free(overlay);
        fprintf(stderr, "[FWAY-M2-BENCH] render failed\n");
        return 1;
    }

    uint32_t *framebuffer = (uint32_t *)malloc((size_t)width * height * sizeof(uint32_t));
    if (!framebuffer) {
        free(background);
        free(overlay);
        fprintf(stderr, "[FWAY-M2-BENCH] framebuffer alloc failed\n");
        return 1;
    }

    struct fw_surface_damage full_rect = {
        .x = 0,
        .y = 0,
        .width = width,
        .height = height,
    };

    double full_us = measure_composite(iterations,
                                       framebuffer,
                                       width,
                                       height,
                                       background,
                                       overlay,
                                       full_rect);

    struct fw_surface_damage small_rect = highlight_rect.width > 0 && highlight_rect.height > 0
                                              ? highlight_rect
                                              : (struct fw_surface_damage){
                                                    .x = width / 3u,
                                                    .y = height / 3u,
                                                    .width = width / 6u,
                                                    .height = height / 6u,
                                                };

    double damage_us = measure_composite(iterations,
                                         framebuffer,
                                         width,
                                         height,
                                         background,
                                         overlay,
                                         small_rect);

    free(framebuffer);
    free(background);
    free(overlay);

    double improvement = (full_us - damage_us) / full_us * 100.0;
    printf("[FWAY-M2-BENCH] full=%.2f us, damage=%.2f us, delta=%.1f%%\n",
           full_us,
           damage_us,
           improvement);

    if (improvement < 30.0) {
        fprintf(stderr, "[FWAY-M2-BENCH] improvement below threshold\n");
        return 1;
    }

    return 0;
}
