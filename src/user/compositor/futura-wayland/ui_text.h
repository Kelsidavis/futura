// SPDX-License-Identifier: MPL-2.0
#pragma once

#include <stdint.h>

#define UI_FONT_WIDTH 8
#define UI_FONT_HEIGHT 16

void ui_draw_text(uint32_t *dst,
                  int dpitch_bytes,
                  int x,
                  int y,
                  uint32_t argb,
                  const char *text,
                  int clip_x,
                  int clip_y,
                  int clip_w,
                  int clip_h);
