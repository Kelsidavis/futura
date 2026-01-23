/* font.h - Simple bitmap font for terminal
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#ifndef WL_TERM_FONT_H
#define WL_TERM_FONT_H

#include <stdint.h>
#include <stdbool.h>

/* Font dimensions */
#define FONT_WIDTH  8
#define FONT_HEIGHT 16

/* Get font bitmap for character (returns 16 bytes, one per row) */
const uint8_t *font_get_glyph(char ch);

/* Render character to pixel buffer
 * buf_width and buf_height are used for bounds checking to prevent overflows */
void font_render_char(char ch, uint32_t *pixels, int32_t x, int32_t y,
                     int32_t stride, int32_t buf_width, int32_t buf_height,
                     uint32_t fg_color, uint32_t bg_color);

#endif /* WL_TERM_FONT_H */
