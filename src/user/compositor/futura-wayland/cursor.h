#pragma once

#include <stdint.h>

struct fut_fb_info;

struct cursor_state;

struct cursor_state *cursor_create(void);
void cursor_destroy(struct cursor_state *cursor);
void cursor_set_position(struct cursor_state *cursor, int32_t x, int32_t y);
int32_t cursor_get_width(const struct cursor_state *cursor);
int32_t cursor_get_height(const struct cursor_state *cursor);
void cursor_draw(const struct cursor_state *cursor,
                 uint8_t *fb_base,
                 const struct fut_fb_info *info);
