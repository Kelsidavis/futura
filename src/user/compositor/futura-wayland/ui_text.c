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
    if (!dst || !text || clip_w <= 0 || clip_h <= 0) {
        return;
    }

    const size_t max_len = safe_strlen(text, 512);
    const int clip_x2 = clip_x + clip_w;
    const int clip_y2 = clip_y + clip_h;

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
                row_ptr[gx] = argb;
            }
        }
    }
}
