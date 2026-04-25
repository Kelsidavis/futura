// SPDX-License-Identifier: MPL-2.0

#include "ui_text.h"

#include "font8x16.h"

#include <stddef.h>
#include <stdint.h>

static size_t safe_strlen(const char *str, size_t max_len) {
    if (!str) {
        return 0;
    }
    size_t len = 0;
    while (len < max_len && str[len] != '\0') {
        ++len;
    }
    return len;
}

static inline const uint8_t *glyph_for_char(unsigned char ch) {
    if (ch < 0x20 || ch > 0x7F) {
        ch = '?';
    }
    return font8x16[ch - 0x20];
}

void ui_draw_text(uint32_t *dst,
                  int dpitch_bytes,
                  int x,
                  int y,
                  uint32_t argb,
                  const char *text,
                  int clip_x,
                  int clip_y,
                  int clip_w,
                  int clip_h) {
    if (!dst || !text || clip_w <= 0 || clip_h <= 0 ||
        dpitch_bytes <= 0 || clip_x < 0 || clip_y < 0) {
        return;
    }

    const size_t max_len = safe_strlen(text, 512);
    if (clip_x > __INT_MAX__ - clip_w || clip_y > __INT_MAX__ - clip_h) {
        return;
    }
    const int clip_x2 = clip_x + clip_w;
    const int clip_y2 = clip_y + clip_h;

    /* Pre-extract source channels and alpha so we don't redo it per pixel.
     * Alpha-blend semi-transparent text against the existing framebuffer
     * pixel — without this, callers passing alpha < 0xFF (e.g. the
     * "Futura" menubar shadow at 0x40000000) got a flat write that
     * stomped the destination instead of a blend. */
    uint32_t sa = (argb >> 24) & 0xFFu;
    uint32_t sr = (argb >> 16) & 0xFFu;
    uint32_t sg = (argb >> 8) & 0xFFu;
    uint32_t sb = argb & 0xFFu;

    for (size_t i = 0; i < max_len; ++i) {
        unsigned char ch = (unsigned char)text[i];
        const uint8_t *glyph = glyph_for_char(ch);
        int glyph_x = x + (int)(i * UI_FONT_WIDTH);
        int glyph_y = y;

        int glyph_x2 = glyph_x + UI_FONT_WIDTH;
        int glyph_y2 = glyph_y + UI_FONT_HEIGHT;
        if (glyph_x2 <= clip_x || glyph_x >= clip_x2 || glyph_y2 <= clip_y || glyph_y >= clip_y2) {
            continue;
        }

        for (int glyph_row = 0; glyph_row < UI_FONT_HEIGHT; ++glyph_row) {
            int gy = glyph_y + glyph_row;
            if (gy < clip_y || gy >= clip_y2) {
                continue;
            }

            uint8_t bits = glyph[glyph_row];
            if (bits == 0) {
                continue;
            }

            /* Use char* for byte arithmetic (allowed to alias per C standard) */
            uint32_t *row_ptr = (uint32_t *)((char *)dst + (size_t)gy * (size_t)dpitch_bytes);
            for (int col = 0; col < UI_FONT_WIDTH; ++col) {
                if ((bits & (uint8_t)(0x80u >> col)) == 0) {
                    continue;
                }
                int gx = glyph_x + col;
                if (gx < clip_x || gx >= clip_x2) {
                    continue;
                }
                if (sa == 0xFFu) {
                    row_ptr[gx] = argb;
                } else if (sa != 0u) {
                    uint32_t da = 255u - sa;
                    uint32_t d = row_ptr[gx];
                    uint32_t or_ = (sr * sa + ((d >> 16) & 0xFFu) * da) / 255u;
                    uint32_t og = (sg * sa + ((d >> 8) & 0xFFu) * da) / 255u;
                    uint32_t ob = (sb * sa + (d & 0xFFu) * da) / 255u;
                    row_ptr[gx] = 0xFF000000u | (or_ << 16) | (og << 8) | ob;
                }
            }
        }
    }
}

void ui_draw_text_scaled(uint32_t *dst,
                         int dpitch_bytes,
                         int x, int y,
                         uint32_t argb,
                         const char *text,
                         int scale,
                         int clip_x, int clip_y,
                         int clip_w, int clip_h) {
    if (!dst || !text || clip_w <= 0 || clip_h <= 0 ||
        dpitch_bytes <= 0 || scale < 1 || scale > 8) {
        return;
    }
    const size_t max_len = safe_strlen(text, 512);
    const int clip_x2 = clip_x + clip_w;
    const int clip_y2 = clip_y + clip_h;
    int char_w = UI_FONT_WIDTH * scale;
    int char_h = UI_FONT_HEIGHT * scale;

    for (size_t i = 0; i < max_len; ++i) {
        unsigned char ch = (unsigned char)text[i];
        const uint8_t *glyph = glyph_for_char(ch);
        int gx0 = x + (int)(i * char_w);
        if (gx0 + char_w <= clip_x || gx0 >= clip_x2) continue;
        if (y + char_h <= clip_y || y >= clip_y2) continue;

        for (int grow = 0; grow < UI_FONT_HEIGHT; ++grow) {
            uint8_t bits = glyph[grow];
            if (bits == 0) continue;
            for (int s_y = 0; s_y < scale; ++s_y) {
                int gy = y + grow * scale + s_y;
                if (gy < clip_y || gy >= clip_y2) continue;
                uint32_t *row_ptr = (uint32_t *)((char *)dst + (size_t)gy * (size_t)dpitch_bytes);
                for (int col = 0; col < UI_FONT_WIDTH; ++col) {
                    if ((bits & (uint8_t)(0x80u >> col)) == 0) continue;
                    for (int s_x = 0; s_x < scale; ++s_x) {
                        int gx = gx0 + col * scale + s_x;
                        if (gx >= clip_x && gx < clip_x2) {
                            /* Alpha blend for semi-transparent text */
                            uint32_t sa = (argb >> 24) & 0xFF;
                            if (sa == 0xFF) {
                                row_ptr[gx] = argb;
                            } else if (sa > 0) {
                                uint32_t da = 255u - sa;
                                uint32_t d = row_ptr[gx];
                                uint32_t or_ = (((argb >> 16) & 0xFF) * sa +
                                               ((d >> 16) & 0xFF) * da) / 255u;
                                uint32_t og = (((argb >> 8) & 0xFF) * sa +
                                              ((d >> 8) & 0xFF) * da) / 255u;
                                uint32_t ob = ((argb & 0xFF) * sa +
                                              (d & 0xFF) * da) / 255u;
                                row_ptr[gx] = 0xFF000000u | (or_ << 16) | (og << 8) | ob;
                            }
                        }
                    }
                }
            }
        }
    }
}
