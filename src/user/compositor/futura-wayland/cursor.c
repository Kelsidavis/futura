#include "cursor.h"

#include <stdlib.h>
#include <string.h>

#include <futura/fb_ioctl.h>

struct cursor_state {
    int32_t x;
    int32_t y;
    int32_t width;
    int32_t height;
};

#define CURSOR_W 16
#define CURSOR_H 16

/* Arrow cursor bitmap — white fill with black outline, hotspot at (0,0).
 * _ = transparent, K = black outline, W = white fill, G = light gray fill.
 * Layout is a classic left-pointing arrow. */
#define _ 0x00000000u
#define K 0xFF000000u
#define W 0xFFFFFFFFu
#define G 0xFFD0D0D0u
static const uint32_t cursor_pixels[CURSOR_W * CURSOR_H] = {
    K,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,
    K,K,_,_,_,_,_,_,_,_,_,_,_,_,_,_,
    K,W,K,_,_,_,_,_,_,_,_,_,_,_,_,_,
    K,W,W,K,_,_,_,_,_,_,_,_,_,_,_,_,
    K,W,W,W,K,_,_,_,_,_,_,_,_,_,_,_,
    K,W,W,W,W,K,_,_,_,_,_,_,_,_,_,_,
    K,W,W,W,W,W,K,_,_,_,_,_,_,_,_,_,
    K,W,W,W,W,W,W,K,_,_,_,_,_,_,_,_,
    K,W,W,W,W,W,W,W,K,_,_,_,_,_,_,_,
    K,W,W,W,W,W,W,W,W,K,_,_,_,_,_,_,
    K,W,W,W,W,W,K,K,K,K,K,_,_,_,_,_,
    K,W,W,K,W,W,K,_,_,_,_,_,_,_,_,_,
    K,W,K,_,K,W,W,K,_,_,_,_,_,_,_,_,
    K,K,_,_,K,W,W,K,_,_,_,_,_,_,_,_,
    K,_,_,_,_,K,W,W,K,_,_,_,_,_,_,_,
    _,_,_,_,_,K,K,K,_,_,_,_,_,_,_,_,
};
#undef _
#undef K
#undef W
#undef G

struct cursor_state *cursor_create(void) {
    struct cursor_state *cursor = malloc(sizeof(*cursor));
    if (!cursor) {
        return NULL;
    }
    cursor->x = 0;
    cursor->y = 0;
    cursor->width = CURSOR_W;
    cursor->height = CURSOR_H;
    return cursor;
}

void cursor_destroy(struct cursor_state *cursor) {
    if (!cursor) {
        return;
    }
    free(cursor);
}

void cursor_set_position(struct cursor_state *cursor, int32_t x, int32_t y) {
    if (!cursor) {
        return;
    }
    cursor->x = x;
    cursor->y = y;
}

int32_t cursor_get_width(const struct cursor_state *cursor) {
    return cursor ? cursor->width : 0;
}

int32_t cursor_get_height(const struct cursor_state *cursor) {
    return cursor ? cursor->height : 0;
}

/* Blend channel disabled - uses the problematic blend LUT
#if 0
static inline uint8_t blend_channel(uint8_t src, uint8_t dst, uint8_t alpha) {
    uint8_t inv = 255u - alpha;
    return cursor_blend_lut[src][alpha] + cursor_blend_lut[dst][inv];
}
#endif
*/

void cursor_draw(const struct cursor_state *cursor,
                 uint8_t *fb_base,
                 const struct fut_fb_info *info) {
    if (!cursor || !fb_base || !info) {
        return;
    }

    /* Defensive check: reject suspiciously low pointer values (likely corruption) */
    if ((uintptr_t)cursor < 0x10000 || (uintptr_t)fb_base < 0x10000 ||
        (uintptr_t)info < 0x10000) {
        return;
    }

    /* Validate info fields to prevent overflow */
    if (info->width == 0 || info->height == 0 || info->pitch == 0) {
        return;
    }

    int32_t fb_w = (int32_t)info->width;
    int32_t fb_h = (int32_t)info->height;

    /* Simple cursor drawing without alpha blending LUT (avoids potential issues) */
    for (int32_t y = 0; y < cursor->height; ++y) {
        int32_t dst_y = cursor->y + y;
        if (dst_y < 0 || dst_y >= fb_h) {
            continue;
        }
        uint8_t *dst_row = fb_base + (size_t)dst_y * info->pitch;
        for (int32_t x = 0; x < cursor->width; ++x) {
            int32_t dst_x = cursor->x + x;
            if (dst_x < 0 || dst_x >= fb_w) {
                continue;
            }

            uint32_t src = cursor_pixels[y * CURSOR_W + x];
            uint8_t alpha = (uint8_t)(src >> 24);
            if (alpha == 0) {
                continue;
            }

            uint8_t *dst_px = dst_row + (size_t)dst_x * 4u;
            uint8_t src_r = (uint8_t)((src >> 16) & 0xFFu);
            uint8_t src_g = (uint8_t)((src >> 8) & 0xFFu);
            uint8_t src_b = (uint8_t)(src & 0xFFu);

            if (alpha == 0xFF) {
                dst_px[0] = src_b;
                dst_px[1] = src_g;
                dst_px[2] = src_r;
                dst_px[3] = 0xFFu;
            } else {
                /* Alpha blend cursor over background */
                uint8_t inv = (uint8_t)(255u - alpha);
                dst_px[0] = (uint8_t)((src_b * alpha + dst_px[0] * inv) / 255u);
                dst_px[1] = (uint8_t)((src_g * alpha + dst_px[1] * inv) / 255u);
                dst_px[2] = (uint8_t)((src_r * alpha + dst_px[2] * inv) / 255u);
                dst_px[3] = 0xFFu;
            }
        }
    }
}
