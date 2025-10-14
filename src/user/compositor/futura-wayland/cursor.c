#include "cursor.h"

#include <stdlib.h>

#include <futura/fb_ioctl.h>

struct cursor_state {
    int32_t x;
    int32_t y;
    int32_t width;
    int32_t height;
};

#define CURSOR_W 16
#define CURSOR_H 16

/* Simple ARGB arrow cursor (white with dark outline) */
static const uint32_t cursor_pixels[CURSOR_W * CURSOR_H] = {
    0x00000000, 0x55000000, 0x55000000, 0x55000000, 0x55000000, 0x55000000, 0x55000000, 0x55000000,
    0x55000000, 0x55000000, 0x55000000, 0x55000000, 0x55000000, 0x55000000, 0x55000000, 0x00000000,
    0x55000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFEEEEEE, 0xFFE6E6E6, 0xFFDCDCDC, 0xFFD4D4D4,
    0xFFCCCCCC, 0xFFC3C3C3, 0xFFB9B9B9, 0xFFAFAFAF, 0xFFA6A6A6, 0xFF9C9C9C, 0x55000000, 0x00000000,
    0x55000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFECECEC, 0xFFE2E2E2, 0xFFD9D9D9,
    0xFFD0D0D0, 0xFFC7C7C7, 0xFFBEBEBE, 0xFFB4B4B4, 0xFFABABAB, 0xFF9F9F9F, 0x55000000, 0x00000000,
    0x55000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFEDEDED, 0xFFE4E4E4,
    0xFFDBDBDB, 0xFFD2D2D2, 0xFFC8C8C8, 0xFFBFBFBF, 0xFFB5B5B5, 0xFFA5A5A5, 0x55000000, 0x00000000,
    0x55000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFEFEFEF,
    0xFFE6E6E6, 0xFFDCDCDC, 0xFFD3D3D3, 0xFFC9C9C9, 0xFFBEBEBE, 0xFFA1A1A1, 0x55000000, 0x00000000,
    0x55000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFF0F0F0, 0xFFE7E7E7, 0xFFDDDDDD, 0xFFD3D3D3, 0xFFC2C2C2, 0xFF9D9D9D, 0x55000000, 0x00000000,
    0x55000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFF1F1F1, 0xFFE7E7E7, 0xFFD9D9D9, 0xFFC0C0C0, 0xFF9A9A9A, 0x55000000, 0x00000000,
    0x55000000, 0xFFFAFAFA, 0xFFFAFAFA, 0xFFFAFAFA, 0xFFFAFAFA, 0xFFF5F5F5, 0xFFEFEFEF, 0xFFE9E9E9,
    0xFFE2E2E2, 0xFFDCDCDC, 0xFFD4D4D4, 0xFFC4C4C4, 0xFFADADAD, 0xFF909090, 0x55000000, 0x00000000,
    0x55000000, 0xFFEEEEEE, 0xFFEEEEEE, 0xFFEEEEEE, 0xFFEEEEEE, 0xFFE8E8E8, 0xFFE1E1E1, 0xFFDBDBDB,
    0xFFD4D4D4, 0xFFCDCDCD, 0xFFC6C6C6, 0xFFB8B8B8, 0xFFA0A0A0, 0xFF7B7B7B, 0x55000000, 0x00000000,
    0x55000000, 0xFFE2E2E2, 0xFFE2E2E2, 0xFFE2E2E2, 0xFFE2E2E2, 0xFFDBDBDB, 0xFFD5D5D5, 0xFFCECECE,
    0xFFC8C8C8, 0xFFC1C1C1, 0xFFBABABA, 0xFFAFAFAF, 0xFF999999, 0xFF6D6D6D, 0x55000000, 0x00000000,
    0x55000000, 0xFFD5D5D5, 0xFFD5D5D5, 0xFFD5D5D5, 0xFFD5D5D5, 0xFFCECECE, 0xFFC8C8C8, 0xFFC2C2C2,
    0xFFBCBCBC, 0xFFB6B6B6, 0xFFB0B0B0, 0xFFA7A7A7, 0xFF8F8F8F, 0xFF626262, 0x55000000, 0x00000000,
    0x55000000, 0xFFC7C7C7, 0xFFC7C7C7, 0xFFC7C7C7, 0xFFC7C7C7, 0xFFC1C1C1, 0xFFBBBBBB, 0xFFB5B5B5,
    0xFFB0B0B0, 0xFFA9A9A9, 0xFFA3A3A3, 0xFF9C9C9C, 0xFF868686, 0xFF585858, 0x55000000, 0x00000000,
    0x00000000, 0x55000000, 0x55000000, 0x55000000, 0x55000000, 0x55000000, 0x55000000, 0x55000000,
    0x55000000, 0x55000000, 0x55000000, 0x55000000, 0x55000000, 0x55000000, 0x55000000, 0x00000000,
};

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

static inline uint8_t blend_channel(uint8_t src, uint8_t dst, uint8_t alpha) {
    uint32_t inv = 255u - alpha;
    uint32_t value = (uint32_t)src * alpha + (uint32_t)dst * inv;
    return (uint8_t)(value / 255u);
}

void cursor_draw(const struct cursor_state *cursor,
                 uint8_t *fb_base,
                 const struct fut_fb_info *info) {
    if (!cursor || !fb_base || !info) {
        return;
    }

    int32_t fb_w = (int32_t)info->width;
    int32_t fb_h = (int32_t)info->height;

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

            if (alpha == 0xFFu) {
                dst_px[0] = src_b;
                dst_px[1] = src_g;
                dst_px[2] = src_r;
                dst_px[3] = 0xFFu;
            } else {
                uint8_t dst_b = dst_px[0];
                uint8_t dst_g = dst_px[1];
                uint8_t dst_r = dst_px[2];

                dst_px[0] = blend_channel(src_b, dst_b, alpha);
                dst_px[1] = blend_channel(src_g, dst_g, alpha);
                dst_px[2] = blend_channel(src_r, dst_r, alpha);
                dst_px[3] = 0xFFu;
            }
        }
    }
}
